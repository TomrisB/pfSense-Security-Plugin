#!/bin/sh

# config
CONFIG_FILE="/usr/local/pkg/security_plugin.xml"
LOG_DIR="/var/log/security_plugin"
BLOCK_LOG="$LOG_DIR/blocked.log"
JSON_LOG="$LOG_DIR/suspicious.json"
LOCK_FILE="/var/run/security_plugin.lock"
VT_MIN_MALICIOUS=$(xml sel -t -v "//autoblock_threshold" "$CONFIG_FILE" 2>/dev/null || echo "3")

# error handling
trap 'rm -f "$LOCK_FILE"; exit 1' INT TERM EXIT
set -eo pipefail

# directory controls
mkdir -p "$LOG_DIR"
touch "$BLOCK_LOG" "$JSON_LOG"
chmod 640 "$BLOCK_LOG" "$JSON_LOG"

# lock mechanism
if [ -f "$LOCK_FILE" ]; then
    echo "$(date) - Script is already working." >> "$LOG_DIR/error.log"
    exit 0
fi
touch "$LOCK_FILE"

# data collection
{
    ALERTS=$(php -r '
        include("/usr/local/pkg/security_plugin/suricata.inc");
        include("/usr/local/pkg/security_plugin/virustotal.inc");

        try {
            $alerts = parse_suricata_alerts() ?: [];
            $results = [];

            foreach ($alerts as $alert) {
                if ($alert["severity"] >= 2) {
                    $ip = filter_var($alert["src_ip"], FILTER_VALIDATE_IP);
                    if ($ip) {
                        $vt_data = scan_ip_with_virustotal($ip);
                        $alert["vt_data"] = $vt_data;
                        $results[] = $alert;
                    }
                }
            }
            echo json_encode($results);
        } catch (Exception $e) {
            file_put_contents("'$LOG_DIR'/php_errors.log", $e->getMessage().PHP_EOL, FILE_APPEND);
            exit(1);
        }
    ')

    # JSON
    echo "$ALERTS" | jq -c '.[]' | while read -r alert; do
        ip=$(jq -r '.src_ip' <<< "$alert")
        sig=$(jq -r '.signature' <<< "$alert")
        malicious=$(jq -r '.vt_data.malicious // 0' <<< "$alert")

        if [[ "$malicious" -ge "$VT_MIN_MALICIOUS" ]]; then
            # Thread-safe log
            (
                echo "$(date '+%Y-%m-%d %H:%M:%S') - BLOCKED: $ip - $sig" >> "$BLOCK_LOG"
                jq --arg verdict "BLOCKED" '. + {action: $verdict}' <<< "$alert" >> "$JSON_LOG"
                jq --arg verdict "BLOCKED" '. + {action: $verdict}' <<< "$alert" >> "$JSON_LOG"
            ) 200>"$LOCK_FILE.log"

            # IP block
            php -r "
                include('/usr/local/pkg/security_plugin/suricata.inc');
                try {
                    block_suricata_alert_ip('$ip', '$sig');
                } catch (Exception \$e) {
                    file_put_contents('$LOG_DIR/block_errors.log', \$e->getMessage().PHP_EOL, FILE_APPEND);
                }
            " >/dev/null 2>&1 &
        fi
    done
} | tee -a "$LOG_DIR/processing.log"

# Temizlik
rm -f "$LOCK_FILE"
trap - INT TERM EXIT

    
    
