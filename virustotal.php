<?php
/*
 * VirusTotal API integration
 */

require_once("config.inc");
require_once("util.inc");

define('VT_API_ENDPOINT', 'https://www.virustotal.com/api/v3');
define('VT_CACHE_DIR', '/var/cache/virustotal/');
define('VT_CACHE_TTL', 3600); // 1 hour cache
define('VT_FILE_SIZE_LIMIT', 32 * 1024 * 1024); // 32MB

function guess_mime_type($file_path) {
    $ext = strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
    $mime_types = [
        'txt' => 'text/plain',
        'html'=> 'text/html',
        'csv' => 'text/csv',
        'jpg' => 'image/jpeg',
        'png' => 'image/png',
        'pdf' => 'application/pdf',
        'doc' => 'application/msword',
        'docx'=> 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'exe' => 'application/octet-stream',
    ];
    return $mime_types[$ext] ?? 'application/octet-stream';
}

/**
 * IP analysis with VirusTotal
 */
function scan_ip_with_virustotal($ip, $api_key) {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        log_error("[VirusTotal] Invalid IP format:".$ip);
        return ['error' => 'Invalid IP addres'];
    }

    // cache control
    $cache_key = 'ip_' . md5($ip);
    if ($cached = get_vt_cache($cache_key)) {
        return $cached;
    }

    $url = VT_API_ENDPOINT . '/ip_addresses/' . urlencode($ip);
    $response = vt_api_request($url, $api_key);

    if (!isset($response['error'])) {
       set_vt_cache($cache_key, $response);
 
        // output for pfSense
        return [
            'malicious' => $response['data']['attributes']['last_analysis_stats']['malicious'] ?? 0,
            'suspicious' => $response['data']['attributes']['last_analysis_stats']['suspicious'] ?? 0,
            'reputation' => $response['data']['attributes']['reputation'] ?? 0,
            'country' => $response['data']['attributes']['country'] ?? 'Unknown'
        ];
    }

    return $response;
}

/**
 * file scan
 */
    
    
        
        
        
// virustotal.inc – replacement for virustotal_scan_file()
function virustotal_scan_file($file_path, $api_key) {
    // file validation
    if (!file_exists($file_path)) {
        log_error("[VirusTotal] File could not be found: {$file_path}");
        return ['error' => 'File could not be found'];
    }

    if (filesize($file_path) > VT_FILE_SIZE_LIMIT) {
        log_error("[VirusTotal] File size exceeded: {$file_path}");
        return ['error' => 'File size limit exceeded (32MB)'];
    }

    // cache control (SHA256 hash)
    $file_hash = hash_file('sha256', $file_path);
    if ($cached = get_vt_cache($file_hash)) {
        return $cached;
    }

    $url = VT_API_ENDPOINT . '/files';
    $file = new CURLFile($file_path, guess_mime_type($file_path), basename($file_path));

    $response = vt_api_request($url, $api_key, ['file' => $file]);

    if (!isset($response['error'])) {
        // Normalize returned data so caller can find either analysis id or sha256
        // Some responses include meta->file_info->sha256 or data->attributes->sha256
        $sha256 = null;
        if (isset($response['meta']['file_info']['sha256'])) {
            $sha256 = $response['meta']['file_info']['sha256'];
        } elseif (isset($response['data']['attributes']['sha256'])) {
            $sha256 = $response['data']['attributes']['sha256'];
        }
       // If response contains analysis id, keep it. If not, but we have sha256, wrap it.
        $out = $response;
        if ($sha256) {
            // Ensure normalized place for UI code
            $out['data']['attributes']['sha256'] = $sha256;
        }
            
        // cache raw response
        set_vt_cache($file_hash, $out);

        return $out;
    }

    return $response;
}

// virustotal.inc – fix vt_api_request()
function vt_api_request($url, $api_key, $post_data = null) {
    $ch = curl_init();
    $options = [
        CURLOPT_URL => $url,
        CURLOPT_HTTPHEADER => [
            'x-apikey: ' . $api_key,
            'accept: application/json'
        ],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 30,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FAILONERROR => false
    ];
    
    if ($post_data) {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = $post_data;
    }
    
    curl_setopt_array($ch, $options);
    $response = curl_exec($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    // treat any 2xx as success
    if ($http_code >= 200 && $http_code < 300) {
        $decoded = json_decode($response, true);
        return $decoded === null ? ['error' => 'Invalid JSON response', 'raw' => $response] : $decoded;
    }
        
    @file_put_contents('/var/log/security_plugin/vt_response.log', date("c") . " REQUEST: {$url} CODE: $http_code RESP: " . substr($response, 0, 4000) . "\n", FILE_APPEND | LOCK_EX);
    $decoded = json_decode($response, true);
    $error_msg = $decoded['error']['message'] ?? $error ?? 'Unknown error';
    log_error("[VirusTotal] API Error ({$http_code}): {$error_msg}");
        
    return [
        'error' => "API Error ({$http_code})",
        'http_code' => $http_code,
        'message' => $error_msg,
        'raw' => substr($response, 0, 4000)
    ];
}
            
         
            
/**
 * VirusTotal API request centralizing function
 */
        
     

    
 



    
/**
 * cache management
 */
function set_vt_cache($key, $data) {
    if (!is_dir(VT_CACHE_DIR)) {
        mkdir(VT_CACHE_DIR, 0755, true);
    }
        
    file_put_contents(
        VT_CACHE_DIR . $key,
        json_encode([
            'data' => $data,
            'timestamp' => time()
        ]),
        LOCK_EX
    );
}   
    
function get_vt_cache($key) {
    $cache_file = VT_CACHE_DIR . $key;
    
    if (file_exists($cache_file)) {
        $cache = json_decode(file_get_contents($cache_file), true);
    
        if (time() - $cache['timestamp'] < VT_CACHE_TTL) {
            return $cache['data'];
        }
        unlink($cache_file);
    }   
    return null;
}
    
/**
 * cleaning Log function
 */
function vt_clean_cache($days = 7) {
    $files = glob(VT_CACHE_DIR . '*');
   $cutoff = time() - ($days * 86400);
        
    foreach ($files as $file) {
        if (filemtime($file) < $cutoff) {
            unlink($file);
        }
    }       
}
?>
