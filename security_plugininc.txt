<?php
/*
 * Security Plugin Master Include File
 * pfSense 2.6+ Compatibility
 * Version: 1.5.0
 */

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");
require_once("filter.inc");
define('VT_KEY_FILE','/usr/local/pkg/security_plugin/api.key');

// Plugin config
if (!defined('SECURITY_PLUGIN_CONFIG')) {
    define('SECURITY_PLUGIN_CONFIG', '/usr/local/pkg/security_plugin.xml');
}
if (!defined('PLUGIN_LOG_DIR')) {
    define('PLUGIN_LOG_DIR', '/var/log/security_plugin');
}
if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', '/var/cache/security_plugin');
}

/**
 * Registers a plugin service in pfSense config
 */
function register_service($name, $description) {
    global $config;

    // Ensure array initialized
    init_config_arr(['installedpackages', 'security_plugin_services']);
    $services = &$config['installedpackages']['security_plugin_services'];

    // Prevent duplicates
    foreach ($services as $svc) {
        if ($svc['name'] === $name) {
            return;
        }
    }

    // Add new service
    $services[] = [
        'name' => $name,
        'description' => $description
    ];

    write_config("Security Plugin: Service '$name' registered.");
}

/**
 * Initialization: create directories, config, and register services
 */
function security_plugin_init() {
    global $config;

    // Create required directories
    safe_mkdir(PLUGIN_LOG_DIR, 0755);
    safe_mkdir(CACHE_DIR, 0700);

    // Initialize plugin config array
    init_config_arr(['installedpackages', 'security_plugin']);

    // Register plugin services

    // Register plugin services
    register_service('security_plugin', 'Security Plugin Daemon');
    register_service('virustotal_scanner', 'VirusTotal Scanner');
}
 
/**
 * Load plugin configuration from XML
 */
function load_plugin_config() {
    static $plugin_config;
    if (!isset($plugin_config)) {
        if (file_exists(SECURITY_PLUGIN_CONFIG)) {
            $plugin_config = parse_xml_config(SECURITY_PLUGIN_CONFIG, 'security_plugin');
        } else {
            $plugin_config = array();
        }
    }
    return $plugin_config;
}

/**
 * Write message to plugin log and system log
 */
function security_log($message, $type = 'info') {
    $log_file = PLUGIN_LOG_DIR . '/security.log';
    $log_msg = sprintf("[%s] %s: %s\n", date("Y-m-d H:i:s"), strtoupper($type), $message);
    @file_put_contents($log_file, $log_msg, FILE_APPEND | LOCK_EX);
    log_error("Security Plugin: {$message}");
}
    
/**
 * Check if an IP is already blocked
 */
function is_ip_blocked($ip) {
    global $config;
    if (!isset($config['installedpackages']['ipblocker']['config'][0]['blocked_ips'])) {
        return false;
    }
    foreach ($config['installedpackages']['ipblocker']['config'][0]['blocked_ips'] as $entry) {
        if (is_array($entry) && $entry['ip'] === $ip) {
            return true;
        }
    }
    return false;
}

/**
 * Retrieve VirusTotal API key from config
 */
function get_virustotal_api_key() {
        if (file_exists(VT_KEY_FILE)){
                return trim(file_get_contents(VT_KEY_FILE));
        }
        return '';
}
    
    
    
function set_virustotal_api_key($key){
        file_put_contents(VT_KEY_FILE, trim($key));
        @chmod(VT_KEY_FILE,0600);
}
/**
 * Perform health checks for plugin
 */
function check_plugin_health() {
    return [
        'log_dir'         => is_writable(PLUGIN_LOG_DIR),
        'cache_dir'       => is_writable(CACHE_DIR),
        'virustotal_key'  => (get_virustotal_api_key() !== ''),
        'ipblocker_table' => is_ipblocker_table_active()
    ];
}
         
/**
 * Check if IP blocker pf table exists
 */
function is_ipblocker_table_active() {
    exec('/sbin/pfctl -t ipblocker_blacklist -T show 2>&1', $output, $retval);
    return ($retval === 0);
}

/**
 * Schedule cron jobs for plugin
 */
function setup_plugin_cron_jobs() {
    global $config;
    init_config_arr(['cron']);
    $cron_jobs = [[
        'minute'  => '*/5',
        'hour'    => '*',
        'mday'    => '*',
        'month'   => '*',
        'wday'    => '*',
        'who'     => 'root',
        'command' => '/usr/local/bin/php -f /usr/local/pkg/security_plugin_cron.php'
    ]];
    foreach ($cron_jobs as $job) {
        if (!is_cron_job_exists($job['command'])) {
            $config['cron']['item'][] = $job;
        }
    }
}
    
/**
 * Check if cron job already exists
 */
function is_cron_job_exists($command) {
    global $config;
    if (!is_array($config['cron']['item'] ?? null)) {
        return false;
    }
    foreach ($config['cron']['item'] as $item) {
        if (strpos($item['command'], $command) !== false) {
            return true;
        }
    }
    return false;
}

/**
 * Actions to perform after plugin installation
 */
function security_plugin_post_install() {
    security_plugin_init();
    setup_plugin_cron_jobs();
    write_config("Security Plugin: Initial configuration applied");
    security_log("Plugin successfully installed", 'info');
}

/**
 * Cleanup before plugin uninstall
 */
function security_plugin_pre_uninstall() {
    exec('/sbin/pfctl -t ipblocker_blacklist -T flush 2>&1');
    filter_configure();
    security_log("Plugin uninstalled", 'warning');
}   
 
/**
 * Generate navigation tabs for GUI
 */
function generate_plugin_nav($current_tab) {
    $tabs = [
        ['Dashboard',     'security_plugin.php',          'dashboard'],
        ['IP Blocker',    'security_plugin.php?tab=ipblocker', 'ipblocker'],
        ['VirusTotal',    'security_plugin.php?tab=virustotal', 'virustotal'],
        ['Suricata',      'security_plugin.php?tab=suricata', 'suricata']
    ];
    echo '<ul class="nav nav-tabs">';
    foreach ($tabs as $tab) {
        $active = ($current_tab === $tab[2]) ? 'active' : '';
        echo '<li class="nav-item">';
        echo '<a class="nav-link ' . $active . '" href="' . $tab[1] . '">' . $tab[0] . '</a>';
        echo '</li>';
    }
    echo '</ul>';
}
    
    
function get_stats(){
        return[
                'status'=>'active',
                'timestamp'=>time(),
                'memory'=>memory_get_usage()
];  
}
 
 

    
// Initialize plugin when included
security_plugin_init();
?>
    
        
