<?php
/*
 * This file is part of the ManageWP Worker plugin.
 *
 * (c) ManageWP LLC <contact@managewp.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

class MWP_EventListener_PublicRequest_AddConnectionKeyInfo implements Symfony_EventDispatcher_EventSubscriberInterface
{
    private $context;

    private $slug = 'worker/init.php';

    function __construct(MWP_WordPress_Context $context)
    {
        $this->context = $context;
    }

    public static function getSubscribedEvents()
    {
        return array(
            MWP_Event_Events::PUBLIC_REQUEST => 'onPublicRequest',
        );
    }

    public function onPublicRequest()
    {
        $this->context->addAction('admin_init', array($this, 'enqueueConnectionModalOpenScripts'));
        $this->context->addAction('admin_init', array($this, 'enqueueConnectionModalOpenStyles'));
        $this->context->addFilter('plugin_row_meta', array($this, 'addConnectionKeyLink'), 10, 2);
        $this->context->addAction('admin_head', array($this, 'printConnectionModalOpenScript'));
        $this->context->addAction('admin_footer', array($this, 'printConnectionModalDialog'));
    }

    public function enqueueConnectionModalOpenScripts()
    {
        $this->context->enqueueScript('jquery');
        $this->context->enqueueScript('jquery-ui-core');
        $this->context->enqueueScript('jquery-ui-dialog');
    }

    public function enqueueConnectionModalOpenStyles()
    {
        $this->context->enqueueStyle('wp-jquery-ui');
        $this->context->enqueueStyle('wp-jquery-ui-dialog');
    }

    protected function checkForDeletedConnectionKey()
    {
        if (!isset($_GET['mwp_nonce']) || !wp_verify_nonce($_GET['mwp_nonce'], 'mwp_deactivation_key')) {
            return false;
        }

        if (!isset($_GET['action']) || $_GET['action'] !== 'mwp_deactivate_key' || empty($_GET['connection_id'])) {
            return false;
        }

        mwp_remove_communication_key($_GET['connection_id']);

        return true;
    }

    public function printConnectionModalOpenScript()
    {
        if (!$this->userCanViewConnectionKey()) {
            return;
        }

        $deletedKey = $this->checkForDeletedConnectionKey();

        ob_start()
        ?>
        <style type="text/css" media="screen">
            .mwp-dialog > .ui-dialog-content {
                font-family: Helvetica, serif;
                font-size: 16px;
                padding: 40px;
                color: #52565C;
                letter-spacing: 0;
                line-height: 23px;
            }

            .mwp-dialog > .ui-dialog-content p {
                font-family: Helvetica, serif;
                font-size: 16px;
                color: #52565C;
            }

            .mwp-dialog > .ui-dialog-content h2 {
                color: #52565C;
                margin-bottom: 0;
            }

            .mwp-dialog > .ui-dialog-titlebar {
                background-color: #00A0D2;
                padding: 18px 32px;
                color: white;
            }

            .mwp-dialog > .ui-dialog-titlebar > .ui-dialog-titlebar-close {
                position: relative;
                float: right;
                left: 10px;
                top: 1px;
                color: #0989B1;
            }

            .mwp-dialog > .ui-dialog-titlebar > .ui-dialog-titlebar-close:hover {
                color: white;
            }

            .mwp-dialog > .ui-dialog-titlebar > .ui-dialog-titlebar-close:before {
                font-size: 30px;
            }

            .key-block {
                color: #757575;
                background: #FFFFFF !important;
                border: 1px solid #D6D6D6;
                border-radius: 5px;
                padding: 13px;
                width: 420px;
                margin-right: 18px;
            }

            .mwp-dialog .btn {
                background: #00A0D2;
                box-shadow: inset 0 -2px 0 0 rgba(0, 0, 0, 0.20);
                border-radius: 4px;
                font-family: Helvetica, serif;
                font-size: 16px;
                color: #FFFFFF;
                text-align: center;
                cursor: pointer;
            }

            .mwp-dialog table {
                background: #F5F7F8;
                border: 1px solid #D6D6D6;
                border-radius: 5px;
                border-collapse: collapse;
            }

            .mwp-dialog th, .mwp-dialog td {
                padding: 12px 20px 10px;
                text-align: left;
                font-weight: normal;
            }

            .mwp-dialog th {
                border-bottom: 1px solid #D6D6D6;
            }

            .mwp-dialog a {
                color: #0073AA;
                text-decoration: none;
            }

            .mwp-dialog a:hover, .mwp-dialog a:focus {
                color: #009FDA;
            }
        </style>

        <script type="text/javascript">
            <?php if ($deletedKey) { ?>
            window.location.replace(<?php echo json_encode($this->context->getAdminUrl('plugins.php?worker_connections=1')); ?>);
            <?php } ?>

            jQuery(document).ready(function ($) {
                var $connectionKeyDialog = $('#mwp_connection_key_dialog');

                $('#mwp-view-connection-key').click(function (e) {
                    e.preventDefault();
                    $(document).trigger('mwp-connection-dialog');
                });

                $('button.copy-key-button').click(function () {
                    $('#connection-key').select();
                    document.execCommand('copy');
                });

                $(document).on('mwp-connection-dialog', function () {
                    $connectionKeyDialog.dialog({
                        dialogClass: "mwp-dialog",
                        draggable: false,
                        resizable: false,
                        modal: true,
                        width: '600px',
                        height: 'auto',
                        title: 'Connection Management',
                        close: function () {
                            $(this).dialog("destroy");
                        }
                    });
                    $('#connection-key').select();
                });

                if (window.location.search.toLowerCase().indexOf('worker_connections=1') !== -1) {
                    $(document).trigger('mwp-connection-dialog');
                }
            });
        </script>
        <?php

        $content = ob_get_clean();
        $this->context->output($content);
    }

    public function printConnectionModalDialog()
    {
        if ($this->context->isMultisite() && !$this->context->isNetworkAdmin()) {
            return;
        }

        if (!$this->userCanViewConnectionKey()) {
            return;
        }

        ob_start();
        ?>
        <div id="mwp_connection_key_dialog" style="display: none;">
            <?php
            $communicationKeys = mwp_get_communication_keys();
            $currentKey        = mwp_get_communication_key();

            if (!empty($currentKey)) {
                $communicationKeys['any'] = array(
                    'added' => null,
                );
            }

            if (empty($communicationKeys)) { ?>
                <p style="margin-top: 0">There are two ways to connect your website to the management dashboard:</p>

                <h2>Automatic</h2>
                <ol>
                    <li>Log into your <a href="https://managewp.com/" target="_blank">ManageWP</a> or <a
                                href="https://godaddy.com/pro" target="_blank">Pro Sites</a> account.
                    </li>
                    <li>Click the Add website icon at the top left.</li>
                    <li>Enter this website's URL, admin username and password, and the system will take care of
                        everything.
                    </li>
                </ol>

                <h2>Manual</h2>
                <ol>
                    <li>Install and activate the <strong>Worker</strong> plugin.</li>
                    <li>Copy the connection key below.</li>
                    <li>Log into your <a href="https://managewp.com/" target="_blank">ManageWP</a> or <a
                                href="https://godaddy.com/pro" target="_blank">Pro Sites</a> account.
                    </li>
                    <li>Click the Add website icon at the top left.</li>
                    <li>Enter this website's URL. When prompted, paste the connection key.</li>
                </ol>
            <?php } else {
                ?>
                <p style="margin-top: 0">Here is the list of currently active connections to this Worker plugin:</p>

                <table style="width: 100%;">
                    <tr>
                        <th>ID</th>
                        <th>Connected</th>
                        <th>Last Used</th>
                        <th></th>
                    </tr>
                    <?php
                    $time = time();
                    foreach ($communicationKeys as $siteId => $communicationKey) { ?>
                        <tr>
                            <td><?php echo $siteId !== 'any' ? $siteId : '*'; ?></td>
                            <td><?php echo $communicationKey['added'] != null ? human_time_diff($communicationKey['added'], $time).' ago' : 'N/A'; ?></td>
                            <td>
                                <?php
                                $used = $this->context->optionGet('mwp_key_last_used_'.$siteId, null);
                                if (!empty($used)) {
                                    echo human_time_diff($used, $time).' ago';
                                } else {
                                    echo 'N/A';
                                }
                                ?>
                            </td>
                            <td style="text-align: right">
                                <a href="<?php echo $this->context->wpNonceUrl($this->context->getAdminUrl('plugins.php?worker_connections=1&action=mwp_deactivate_key&connection_id='.$siteId), 'mwp_deactivation_key', 'mwp_nonce'); ?>">Disconnect</a>
                            </td>
                        </tr>
                        <?php
                    }
                    ?>
                </table>

                <?php
            } ?>

            <p style="margin-bottom: 7px; margin-top: 27px;">Connection key:</p>
            <input id="connection-key" rows="1" class="key-block" onclick="this.focus();this.select()"
                   readonly="readonly" value="<?php echo mwp_get_potential_key(); ?>">
            <button class="copy-key-button btn" style="width: 76px; height: 44px;"
                    data-clipboard-target="#connection-key">Copy
            </button>
        </div>
        <?php

        $content = ob_get_clean();
        $this->context->output($content);
    }

    /**
     * @wp_filter
     */
    public function addConnectionKeyLink($meta, $slug)
    {
        if ($this->context->isMultisite() && !$this->context->isNetworkAdmin()) {
            return $meta;
        }

        if ($slug !== $this->slug) {
            return $meta;
        }

        if (!$this->userCanViewConnectionKey()) {
            return $meta;
        }

        $meta[] = '<a href="#" id="mwp-view-connection-key" mwp-key="'.mwp_get_potential_key().'">Connection Management</a>';

        return $meta;
    }

    private function userCanViewConnectionKey()
    {
        return $this->context->isGranted('activate_plugins');
    }
}
