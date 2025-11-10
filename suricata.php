<?php
/*
* Suricata Log Analysis and IP Blocking Functions
* Enhanced Version - pfSense Compatible
 */

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");

function parse_suricata_alerts($log_path = '/var/log/suricata/suricata_em161241/eve.json') {
    $alerts = [];

    if (!file_exists($log_path)) {
        log_error("Suricata log could not be found: {$log_path}");
        return $alerts;
    }

    try {
        $handle = fopen($log_path, 'r');
        if (!$handle) {
            throw new Exception("Log file could not be opened.");
        }

        while (($line = fgets($handle)) !== false) {
            $alert = json_decode($line, true);

            // JSON decode and basic validation
            if (json_last_error() !== JSON_ERROR_NONE) {
                continue;
            }

            // only alert event
            if (isset($alert['event_type']) && $alert['event_type'] == 'alert') {
                $alerts[] = [
                    'timestamp' => $alert['timestamp'] ?? date('c'),
                    'src_ip' => filter_var($alert['src_ip'] ?? '', FILTER_VALIDATE_IP) ?: '0.0.0.0',
                    'dest_ip' => filter_var($alert['dest_ip'] ?? '', FILTER_VALIDATE_IP) ?: '0.0.0.0',
                    'signature' => htmlspecialchars($alert['alert']['signature'] ?? 'Unknown signature'),
                    'severity' => (int)($alert['alert']['severity'] ?? 1),
                    'category' => htmlspecialchars($alert['alert']['category'] ?? 'Unknown category')
                ];
            }
        }
        fclose($handle);
    } catch (Exception $e) {
        log_error("Suricata log parse error: " . $e->getMessage());
    }

    return $alerts;
}

function block_suricata_alert_ip($ip, $reason) {
        return block_ip($ip,$reason);

}

// Auxiliary function: Log recording
function log_event($type, $message) {
    $log_file = '/var/log/suricata_blocker.log';
    $log_msg = sprintf("[%s] %s: %s\n", date("Y-m-d H:i:s"), $type, $message);

    // check for file existence
    if (!file_exists($log_file)) {
       @mkdir('/var/log', 0755, true);
        @touch($log_file);
        @chmod($log_file, 0644);
    }

    @file_put_contents($log_file, $log_msg, FILE_APPEND | LOCK_EX);
}
?>

    

