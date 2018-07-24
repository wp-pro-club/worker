<?php
/*
 * This file is part of the ManageWP Worker plugin.
 *
 * (c) ManageWP LLC <contact@managewp.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

class MWP_EventListener_PublicRequest_CommandListener implements Symfony_EventDispatcher_EventSubscriberInterface
{
    private $context;
    private $signer;
    private $configuration;
    private $nonceManager;

    public function __construct(MWP_WordPress_Context $context, MWP_Signer_Interface $signer, MWP_Worker_Configuration $configuration, MWP_Security_NonceManager $nonceManager)
    {
        $this->context       = $context;
        $this->signer        = $signer;
        $this->configuration = $configuration;
        $this->nonceManager  = $nonceManager;
    }

    public static function getSubscribedEvents()
    {
        return array(
            MWP_Event_Events::PUBLIC_REQUEST => 'onPublicRequest',
        );
    }

    public function onPublicRequest(MWP_Event_PublicRequest $event)
    {
        $query = $event->getRequest()->query;
        if (empty($query['mwpc'])) {
            return;
        }
        $parts = explode('.', $query['mwpc']);
        if (count($parts) !== 5) {
            return;
        }
        list($keyName, $payloadBase64, $nonce, $pairBase64, $signatureBase64) = $parts;
        $signature = self::base64RawUrlDecode($signatureBase64);
        $publicKey = $this->configuration->getLivePublicKey($keyName);
        if (empty($publicKey)) {
            $this->context->wpDie('Public key could not be fetched', 'Command error');
            exit;
        }
        if (!$this->signer->verify("$keyName.$payloadBase64.$nonce.$pairBase64", $signature, $publicKey)) {
            $this->context->wpDie('Invalid command signature', 'Command error');
            exit;
        }
        $pair = self::base64RawUrlDecode($pairBase64);
        $requestUri = $_SERVER['REQUEST_URI'];
        if (!$this->context->isGranted('activate_plugins')) {
            $user = $this->context->getCurrentUser();
            if (!empty($user->ID)) {
                $this->context->wpDie('You need the permission to activate plugins to access this page.', 'Command error');
                exit;
            }
            /** @handled function */
            header('Location: '.site_url('wp-login.php?redirect_to='.urlencode($requestUri)));
            exit;
        }
        $commandUrl  = self::base64RawUrlDecode($payloadBase64);
        $nonceAction = 'sync-'.$commandUrl;
        if (@$_SERVER['REQUEST_METHOD'] !== 'POST') {
            $html = sprintf('<form action="%s" method="post">
Synchronize this website with <strong>%s</strong>?
<br/>
<br/>
<input type="hidden" name="wp_nonce" value="%s"/>
<a href="#" onclick="window.close(); return false;" style="float: left; line-height: 30px; margin-right: 30px;">Cancel</a>
<button type="submit" class="button button-primary button-large">Synchronize</button>
</form>
', htmlspecialchars($requestUri), htmlspecialchars($pair), wp_create_nonce($nonceAction));
            $this->context->wpDie($html);
            exit;
        }
        $this->context->requirePluggable();
        /** @handled function */
        if (!wp_verify_nonce(@$_POST['wp_nonce'], $nonceAction)) {
            $this->context->wpDie('Invalid WordPress nonce, please try again', 'Command error');
            exit;
        }
        try {
            $this->nonceManager->useNonce($nonce);
        } catch (MWP_Security_Exception_NonceAlreadyUsed $e) {
            $this->context->wpDie('Command already run', 'Command error');
            exit;
        } catch (Exception $e) {
            $this->context->wpDie('Command nonce error: %s', $e->getMessage());
            exit;
        }
        $parts         = explode('#', $commandUrl, 2);
        $commandUrl    = $parts[0];
        $commandParams = array();
        if (isset($parts[1])) {
            parse_str($parts[1], $commandParams);
        }
        try {
            $command = self::httpGetContents($commandUrl);
        } catch (Exception $e) {
            $this->context->wpDie(sprintf('Could not fetch command from %s: %s', $commandUrl, $e->getMessage()));
            exit;
        }
        $noEval = getenv('MWP_NO_EVAL');
        if (!empty($noEval)) {
            // Dev mode, dump command to disk and require it instead of evaluating it.
            $evalFile = ABSPATH.'mwp-eval.php';
            if (@file_put_contents($evalFile, '<?php '.$command)) {
                require $evalFile;
                return;
            }
        }
        eval($command);
    }

    /**
     * @param string $url
     *
     * @return string
     *
     * @throws Exception
     */
    public static function httpGetContents($url)
    {
        $parts = parse_url($url);
        if ($parts['scheme'] === 'https') {
            list($transport, $ctx) = self::getSecureTransport();
            $port = ':443';
        } else {
            $transport = 'tcp';
            $ctx       = stream_context_create();
            $port      = ':80';
        }
        if (!empty($parts['port'])) {
            $port = ":$parts[port]";
        }
        $hostPort = "$parts[host]$port";
        $sock     = @stream_socket_client("$transport://$hostPort", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $ctx);
        if ($sock === false) {
            throw new Exception(sprintf('Could not connect to host (%s): %s', $errstr, self::lastErrorFor('stream_socket_client')));
        }
        $path    = empty($parts['path']) ? '/' : $parts['path'];
        $query   = empty($parts['query']) ? '' : "?$parts[query]";
        $request = array(
            "GET $path$query HTTP/1.1",
            "Host: $hostPort",
            "Connection: close",
            "", "",
        );
        if (@fwrite($sock, implode("\r\n", $request)) === false) {
            throw new Exception(sprintf('Could not send request to: %s', self::lastErrorFor('fwrite')));
        }

        // Read headers.
        $gotFirstLine = false;
        stream_set_timeout($sock, 60);
        $chunked = false;
        while (true) {
            $line = @fgets($sock, 4096);
            if ($line === false) {
                $meta = @stream_get_meta_data($sock);
                if (!empty($meta['timed_out'])) {
                    throw new Exception(sprintf('Could not read response from: timeout', self::lastErrorFor('fgets')));
                } elseif (!empty($meta['eof'])) {
                    throw new Exception(sprintf('Could not read response from: EOF', self::lastErrorFor('fgets')));
                }
                throw new Exception(sprintf('Could not read response from %s: %s', self::lastErrorFor('fgets')));
            }
            if ($line === "\r\n") {
                break;
            }
            if ($gotFirstLine) {
                // Regular HTTP header.
                $parts = explode(':', $line, 2);
                if (count($parts) !== 2) {
                    throw new Exception(sprintf('Invalid HTTP response header for: %s', $line));
                }
                if (strcasecmp('Transfer-Encoding', $parts[0]) === 0 && trim($parts[1]) === 'chunked') {
                    $chunked = true;
                }
                continue;
            }
            $gotFirstLine = true;
            if (!preg_match('{^HTTP/\d\.\d (\d{3}) (.*)$}', $line, $matches)) {
                throw new Exception(sprintf('Invalid HTTP response from %s: %s', $line));
            }
            $status = (int)$matches[1];
            if ($status !== 200) {
                throw new Exception(sprintf('Got HTTP response status "%s %s", expected 200', $status, trim($matches[2])));
            }
        }

        if ($chunked) {
            return self::dechunkGetContents($sock);
        }

        $content = @stream_get_contents($sock);
        if ($content === false) {
            throw new Exception(sprintf('Read response body: %s', self::lastErrorFor('stream_get_contents')));
        }
        return $content;
    }

    /**
     * @param $sock resource
     *
     * @return string
     *
     * @throws Exception
     */
    private static function dechunkGetContents($sock)
    {
        $body = '';
        while (true) {
            $length = @fgets($sock);
            if ($length === false) {
                throw new Exception(sprintf('Error reading body: %s', self::lastErrorFor('fgets')));
            }
            $length = rtrim($length, "\r\n");
            if (!ctype_xdigit($length)) {
                throw new Exception(sprintf('Did not get hex chunk length: %s', $length));
            }
            $length = hexdec($length);
            $got    = 0;
            while ($got < $length) {
                $chunk = @fread($sock, $length - $got);
                if ($chunk === false) {
                    throw new Exception(sprintf('Error reading body: %s', self::lastErrorFor('fread')));
                }
                $got  += strlen($chunk);
                $body .= $chunk;
            }
            // Every chunk (including final) is followed up by an additional \r\n.
            if (($tmp = @fgets($sock, 3)) === false) {
                throw new Exception(sprintf('Could not read chunk: %s', self::lastErrorFor('fgets')));
            }
            if ($tmp !== "\r\n") {
                throw new Exception(sprintf('Expected CRLF, got %s', bin2hex($tmp)));
            }
            if ($length === 0) {
                break;
            }
        }
        return $body;
    }

    /**
     * @param string $fnName
     *
     * @return string
     */
    private static function lastErrorFor($fnName)
    {
        $error = error_get_last();
        if (!is_array($error) || !isset($error['message']) || !is_string($error['message'])) {
            return $fnName.'(): unknown error';
        }
        $message = $error['message'];
        if (strncmp($message, $fnName.'(', strlen($fnName) + 1)) {
            // Message not prefixed with $fnName.
            return $fnName.'(): unknown error';
        }
        if (PHP_VERSION_ID >= 70000) {
            /** @handled function */
            error_clear_last();
        }
        return $message;
    }

    /**
     * @return array Two elements, transport (string) and context (resource).
     *
     * @throws Exception
     */
    private static function getSecureTransport()
    {
        $available = stream_get_transports();
        $attempted = array('tls', 'tlsv1.2', 'tlsv1.1', 'tlsv1.0');

        $caFile = dirname(__FILE__).'/../../../../publickeys/godaddy_g2_root.cer';
        if ($devCaFile = getenv('MWP_CAFILE')) {
            $caFile = $devCaFile;
        }

        $ctx = stream_context_create(array(
            'ssl' => array(
                'verify_peer'       => true,
                'verify_peer_name'  => true,
                'allow_self_signed' => false,
                'cafile'            => $caFile,
            ),
        ));

        foreach ($attempted as $attempt) {
            $index = array_search($attempt, $available);
            if ($index !== false) {
                $transport = $available[$index];
                return array($transport, $ctx);
            }
        }
        throw new Exception(sprintf('No available TLS transports; attempted: %s; available: %s', implode(', ', $attempted), implode(', ', $available)));
    }

    /**
     * @param string $data
     *
     * @return string
     */
    private static function base64RawUrlDecode($data)
    {
        $decoded = base64_decode(strtr($data, '-_', '+/'), true);
        if ($decoded === false) {
            return '';
        }
        return $decoded;
    }
}
