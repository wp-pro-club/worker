<?php
/*
 * This file is part of the ManageWP Worker plugin.
 *
 * (c) ManageWP LLC <contact@managewp.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

class MWP_Action_ClearTransient extends MWP_Action_Abstract
{
    public function execute(array $params = array())
    {
        $wpdb = $this->container->getWordPressContext()->getDb();

        $prefix  = $wpdb->prefix;
        $timeout = $params['timeout'];
        $mask    = $params['mask'];

        $deleteTransients        = <<<SQL
DELETE FROM {$prefix}options
WHERE option_name IN (
  SELECT t.transient_name FROM (
    SELECT CONCAT('_site_transient_', SUBSTR(option_name, 25)) AS transient_name
    FROM {$prefix}options
    WHERE option_name LIKE '\_site\_transient\_timeout\_{$mask}'
      AND option_value < {$timeout}
  ) AS t)
SQL;
        $deleteTransientTimeouts = <<<SQL
DELETE FROM {$prefix}options WHERE option_name LIKE '\_site\_transient\_timeout\_{$mask}' AND option_value < {$timeout}
SQL;

        $deletedTransients        = $wpdb->query($deleteTransients);
        $deletedTransientTimeouts = $wpdb->query($deleteTransientTimeouts);

        return array(
            'deletedTransients'        => $deletedTransients,
            'deletedTransientTimeouts' => $deletedTransientTimeouts,
        );
    }
}
