<?php
/*
 * IP Blocker Functions (fixed)
 */
    
require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");
            
define('IPBLOCKER_TABLE', 'ipblocker_blacklist');
define('IPBLOCKER_LOG', '/var/log/ipblocker.log');             
                        
/**
 * Normalize ipblocker config to expected array-of-entries format.
 * Safe to call before any read/write operations.
 */
function normalize_ipblocker_config() {
    global $config;
        
    if (!is_array($config['installedpackages']['ipblocker']['config'] ?? null)) {
        // initialize if missing
        init_config_arr(array('installedpackages', 'ipblocker', 'config', '0'));
    }
        
    // Shortcut ref
    $cfg0 = &$config['installedpackages']['ipblocker']['config'][0];
            
    if (!isset($cfg0['blocked_ips'])) {
        $cfg0['blocked_ips'] = array();
        return;
    }
                    
    // If blocked_ips is a string (old/incompatible), convert to array of entries
    if (!is_array($cfg0['blocked_ips'])) {
        $old = trim((string)$cfg0['blocked_ips']);
        $entries = array();
        if ($old !== '') {
            // support comma-separated or newline-separated lists
          $parts = preg_split('/[,\s]+/', $old, -1, PREG_SPLIT_NO_EMPTY);
            foreach ($parts as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    $entries[] = array(
                        'ip' => $ip,
                        'timestamp' => time(),
                        'reason' => 'Migrated from scalar config',
                        'expire' => 0
                    );
                }
            }       
        }               
        $cfg0['blocked_ips'] = $entries;
        // Persist migration to config.xml safely
        write_config("IP Blocker: migrated scalar blocked_ips to structured format");
    } else {
        // further ensure each element is structured (if someone left a plain ip string inside array)
        $normalized = array();
        foreach ($cfg0['blocked_ips'] as $entry) {
            if (is_array($entry) && isset($entry['ip'])) {
                $normalized[] = $entry;
            } elseif (is_string($entry) && filter_var($entry, FILTER_VALIDATE_IP)) {
                $normalized[] = array(
                    'ip' => $entry,
                    'timestamp' => time(),
                    'reason' => 'Migrated single-string-entry',
                    'expire' => 0
                );
            }
        }
        $cfg0['blocked_ips'] = $normalized;
    }
}
            /**
 * IP blocking function
 */
function block_ip($ip, $reason = '', $expire = 0) {
    normalize_ipblocker_config();
    global $config;
                        
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        log_error("IP Blocker: invalid IP format - {$ip}");
        return false;
    }
                        
    // Ensure config structure exists
    init_config_arr(array('installedpackages', 'ipblocker', 'config', '0'));
        
    if (!isset($config['installedpackages']['ipblocker']['config'][0]['blocked_ips']) || !is_array($config['installedpackages']['ipblocker']['config'][0]['blocked_ips'])) {
        $config['installedpackages']['ipblocker']['config'][0]['blocked_ips'] = array();
    }
        
    $blocked_ips = &$config['installedpackages']['ipblocker']['config'][0]['blocked_ips'];
                
    // Prevent duplicate (case-insensitive)
    foreach ($blocked_ips as $entry) {
        if (is_array($entry) && isset($entry['ip']) && strtolower($entry['ip']) === strtolower($ip)) {
            return false; // already blocked
        }
    }
                
    $new_entry = array(
        'ip' => $ip,
        'timestamp' => time(),
        'reason' => substr(htmlspecialchars($reason), 0, 255),
        'expire' => $expire > 0 ? (time() + $expire) : 0
    );              
    
    $blocked_ips[] = $new_entry;
        
    // apply firewall rule
    add_firewall_rule($ip);
        
    
   // save Config
    write_config("IP Blocker: {$ip} is blocked. Reason: {$reason}");
 
    // Log record
    log_ip_action($ip, 'BLOCK', $reason);
    
    return true;        
}
        
/**
 * IP unblocking function
 */                     
function unblock_ip($ip) {
    global $config;
        
    if (!isset($config['installedpackages']['ipblocker']['config'][0]['blocked_ips']) || !is_array($config['installedpackages']['ipblocker']['config'][0]['blocked_ips'])) {
        return false;
    }
        
    $blocked_ips = &$config['installedpackages']['ipblocker']['config'][0]['blocked_ips'];
    $found = false;
    
    foreach ($blocked_ips as $key => $entry) {
        if (is_array($entry) && isset($entry['ip']) && $entry['ip'] === $ip) {
            // Remove firewall rule first
            remove_firewall_rule($ip);
     
            // Log record
            log_ip_action($ip, 'UNBLOCK', $entry['reason'] ?? '');
        
            // Remove from config
            unset($blocked_ips[$key]);
            $found = true;
            break;  
        }
    }
        
    // Reindex array to avoid sparse arrays
    if ($found) {
        $blocked_ips = array_values($blocked_ips);
       write_config("IP Blocker: {$ip} unblocked.");
        return true;
    }

    return false;
}

/**
 * Add firewall rule - fixed spacing + mwexecf usage
 */
function add_firewall_rule($ip) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return false;
    }
    
    // add pf table (use constant)
    $cmd = sprintf('/sbin/pfctl -t %s -T add %s', escapeshellarg(IPBLOCKER_TABLE), escapeshellarg($ip));
    mwexec($cmd);
    filter_configure();

    return true;
}

/**
 * Remove firewall rule
 */
function remove_firewall_rule($ip) {
    mwexecf('/sbin/pfctl -t %s -T delete %s', array(IPBLOCKER_TABLE, $ip));
    filter_configure();
}

/**
 * Clear expired IP blocks
 */
function cleanup_expired_ips() {
    global $config;

    if (!isset($config['installedpackages']['ipblocker']['config'][0]['blocked_ips']) || !is_array($config['installedpackages']['ipblocker']['config'][0]['blocked_ips'])) {
        return 0;
    }

    $blocked_ips = &$config['installedpackages']['ipblocker']['config'][0]['blocked_ips'];
    $count = 0;
    $now = time();

    foreach ($blocked_ips as $key => $entry) {
        if (is_array($entry) && !empty($entry['expire']) && $entry['expire'] > 0 && $entry['expire'] < $now) {
            unblock_ip($entry['ip']);
            $count++;
        }
    }

    if ($count > 0) {
        write_config("IP Blocker: {$count} expired IP(s) cleared.");
    }

    return $count;
}
/**
 * log func
 */
function log_ip_action($ip, $action, $reason = '') {
    $log_msg = sprintf(
        "[%s] %s %s - %s\n",
        date("Y-m-d H:i:s"),
        str_pad($action, 7),
        $ip,
        $reason
    );
    
    @file_put_contents(IPBLOCKER_LOG, $log_msg, FILE_APPEND | LOCK_EX);
}
    
/**
 * Get blocked IP list - normalized output for UI
 */
 

function get_blocked_ips() {
    global $config;
    normalize_ipblocker_config();

    $result = array();
    
    $blocked = $config['installedpackages']['ipblocker']['config'][0]['blocked_ips'] ?? [];
    foreach ($blocked as $entry) {
        if (is_array($entry) && !empty($entry['ip'])) {
            $result[] = array(
                'ip' => $entry['ip'],
                'reason' => $entry['reason'] ?? 'Manual Block',
                'timestamp' => $entry['timestamp'] ?? time()
            );
        }
    }
     
    // Merge live pf table entries (use IPBLOCKER_TABLE constant)
    $live_ips = [];
    exec("/sbin/pfctl -t " . escapeshellarg(IPBLOCKER_TABLE) . " -T show 2>/dev/null", $live_ips);
    foreach ($live_ips as $ip) {
        if (!in_array($ip, array_column($result, 'ip'))) {
            $result[] = array('ip' => $ip, 'reason' => 'Firewall Block', 'timestamp' => time());
        }
    }
            
    return $result;
}

    
        
?>
