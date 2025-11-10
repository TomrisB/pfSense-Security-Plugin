<?php
class EnhancedTrafficAnalyzer {
    private $suricataLog = '/var/log/suricata/suricata_em161241/eve.json';
    private $malwarePatterns = [
        '/malware|trojan|exploit|virus|worm|ransomware|spyware|rootkit|backdoor|botnet|c2|command.?control|phishing|bruteforce|sql.?injection|xss/i',
        '/ET.*(CnC|Malware|Exploit|Trojan)/i',
        '/APT|Advanced.Persistent.Threat/i'
    ];

    public function getRealtimeThreats($limit = 50) {
        if (!file_exists($this->suricataLog)) {
            throw new Exception("Suricata log file not found: " . $this->suricataLog);
        }

        $alerts = [];
        $lines = file($this->suricataLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $lines = array_slice(array_reverse($lines), 0, $limit);

        foreach ($lines as $line) {
            $alert = json_decode($line, true);
            if (json_last_error() === JSON_ERROR_NONE && isset($alert['event_type']) && $alert['event_type'] === 'alert') {
                $alerts[] = $alert;
            }
        }

        return $alerts;
    }

    public function detectMaliciousActivity() {
        $alerts = $this->getRealtimeThreats();
        $threats = [
            'scans' => [],
            'malware' => [],
            'exploits' => [],
            'suspicious_ips' => []
        ];

        $ipScore = [];

        foreach ($alerts as $alert) {
            $ip = $alert['src_ip'] ?? null;
            $signature = $alert['alert']['signature'] ?? '';

            // IP score
            if ($ip) {
                $ipScore[$ip] = ($ipScore[$ip] ?? 0) + 1;
            }

            // scan detection
            if (preg_match('/SCAN|Portscan|Scanner/i', $signature)) {
                $threats['scans'][$ip] = ($threats['scans'][$ip] ?? 0) + 1;
            }

            // malware detection
            foreach ($this->malwarePatterns as $pattern) {
                if (preg_match($pattern, $signature)) {
                    $threats['malware'][] = [
                        'ip' => $ip,
                        'signature' => $signature,
                        'timestamp' => $alert['timestamp'] ?? null
                    ];
                    break;
                }
            }
                                        }
    
        // suspicious IPs
        $threats['suspicious_ips'] = array_filter($ipScore, fn($score) => $score >= 5);
        
        return $threats;
    }
    
    public function generateThreatReport() {
        try {
            $threats = $this->detectMaliciousActivity();
            $report = [];
        
            if (!empty($threats['scans'])) {
                $report[] = "Port Scan Detections:";
                foreach ($threats['scans'] as $ip => $count) {
                    $report[] = sprintf("  - %s: %d scan attempt", $ip, $count);
                }
            }
                
            if (!empty($threats['malware'])) {
                $report[] = "\nMalware Detections:";
                foreach ($threats['malware'] as $malware) {
                    $report[] = sprintf("  - %s: %s (%s)",
                        $malware['ip'],
                        $malware['signature'],
                        $malware['timestamp']
                    );
                }
            }
            
            if (!empty($threats['suspicious_ips'])) {
                $report[] = "\nSuspicious IP Addresses:";
                foreach ($threats['suspicious_ips'] as $ip => $score) {
                    $report[] = sprintf("  - %s: %d suspicious activity", $ip, $score);
                }
            }
        
            return implode("\n", $report);
        } catch (Exception $e) {
            return "Error: " . $e->getMessage();
        }
    }
}
             

// $analyzer = new EnhancedTrafficAnalyzer();
// echo $analyzer->generateThreatReport();
?>
             
                                                           
