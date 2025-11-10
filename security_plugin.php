<?php
require_once("guiconfig.inc");
require_once("/usr/local/pkg/security_plugin/security_plugin.inc");
require_once("/usr/local/pkg/security_plugin/ip_blocker.inc");
require_once("/usr/local/pkg/security_plugin/virustotal.inc");
require_once("/usr/local/pkg/security_plugin/suricata.inc");
define('VT_API_ENDPOINT','https://www.virustotal.com/api/v3');

header('Content-Type: text/html; charset=utf-8');
ini_set('default_charset', 'UTF-8');

if (isset($_SERVER['HTTP_CACHE_CONTROL']) && $_SERVER['HTTP_CACHE_CONTROL'] === 'max-age=0') {
    unset($_SERVER['HTTP_CACHE_CONTROL']);
}

// Tab menu
$tab_array = [
    ['Dashboard', 'security_plugin.php', 'dashboard'],
    ['IP Blocker', 'security_plugin.php?tab=ipblocker', 'ipblocker'],
    ['VirusTotal', 'security_plugin.php?tab=virustotal', 'virustotal'],
    ['Settings',    'security_plugin.php?tab=settings',  'settings'],
   ['Suricata', 'security_plugin.php?tab=suricata', 'suricata']
];
$current_tab = isset($_GET['tab']) ? $_GET['tab'] : 'dashboard';

// VirusTotal API key
$vt_api_key_path = "/usr/local/pkg/security_plugin/api.key";

$vt_api_key = is_readable($vt_api_key_path) ? trim(file_get_contents($vt_api_key_path)) : null;


if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['view_details']) && !empty($_POST['analysis_id'])) {
    $analysis_id = trim($_POST['analysis_id']);
    $vt_api_key = is_readable($vt_api_key_path) ? trim(file_get_contents($vt_api_key_path)) : null;

    if (!$vt_api_key) {
        $input_errors[] = "VirusTotal API key is missing!";
    } else {
        // If user posted a 64-hex string -> treat as SHA256 and query /files/{sha256}
        if (ctype_xdigit($analysis_id) && strlen($analysis_id) === 64) {
            $details_url = VT_API_ENDPOINT . '/files/' . $analysis_id;
            $detailed_result = vt_api_request($details_url, $vt_api_key);
        } else {
            // Try analyses endpoint first
            $details_url = VT_API_ENDPOINT . '/analyses/' . urlencode($analysis_id);
            $detailed_result = vt_api_request($details_url, $vt_api_key);

            // If 404 or error and the original token looks like a file-id (non hex id returned by /files upload),
            // try files/{sha256} using cache (we saved sha256 in cache earlier on upload)
            if ((isset($detailed_result['error']) && $detailed_result['http_code'] == 404) || isset($detailed_result['error'])) {
                // try fallback: if scan_result had sha256, use that; otherwise try files/{analysis_id}
                // First try: files/{analysis_id}
                $details_url2 = VT_API_ENDPOINT . '/files/' . urlencode($analysis_id);
                $detailed_result2 = vt_api_request($details_url2, $vt_api_key);
                if (!isset($detailed_result2['error'])) {
                    $detailed_result = $detailed_result2;
                }
            }
        }

        if (isset($detailed_result['error'])) {
            $input_errors[] = "Unable to fetch detailed results: " . ($detailed_result['message'] ?? $detailed_result['error']);
        } else {
            // success: $detailed_result is available to render below
        }
    }
}


    
    
    
// IP Blocker
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['block_ip'])) {
    $ip = $_POST['ip'];
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        $input_errors[] = "Invalid IP address format!";
    } elseif (block_ip($ip, $_POST['reason'] ?? '')) {
        $savemsg = sprintf("IP is successfully blocked: %s", htmlspecialchars($ip));
    } else {
        $input_errors[] = "Already blocked!";
    }
}



if (isset($_GET['action']) && $_GET['action'] == 'unblock' && isset($_GET['ip'])) {
    if (unblock_ip($_GET['ip'])) {
        $savemsg = sprintf("IP unblocked: %s", htmlspecialchars($_GET['ip']));
        header("Location: security_plugin.php?tab=ipblocker&savemsg=" . urlencode($savemsg));
        exit;
    } else {
        $input_errors[] = "Unblock failed!";
    } 
}
        
            
            
        
// VirusTotal file scan
            
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file']) && $current_tab == 'virustotal') {
    if (empty($vt_api_key)) {
        $input_errors[] = "VirusTotal API key is not defined.";
    } else {
        $upload_dir = '/tmp/virustotal_uploads/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
                
        $file_path = $upload_dir . basename($_FILES['file']['name']);
        if (move_uploaded_file($_FILES['file']['tmp_name'], $file_path)) {
            $scan_result = virustotal_scan_file($file_path, $vt_api_key);
             
            if (!empty($scan_result['data']['id'] ?? null) || !empty($scan_result['data']['attributes']['sha256'] ?? null)) {
                $savemsg = sprintf("File is scanned! Analysis ID: %s", htmlspecialchars($scan_result['data']['id'] ?? $scan_result['data']['attributes']['sha256']));
            } else {
                $input_errors[] = sprintf("Unsuccessful scan: %s", $scan_result['error'] ?? 'Unknown error');
                @unlink($file_path);
            }
        } else {
            $input_errors[] = "Load file error!";
        }
    }
}
    
    
    
// Suricata Alarm Manag.
if (isset($_GET['block']) && $current_tab == 'suricata') {
    $ip = $_GET['block'];
    $reason = $_GET['reason'] ?? 'Suricata Alarm';
    if (block_suricata_alert_ip($ip, $reason)) {
        $savemsg = sprintf("IP blocked: %s (reason: %s)",
                          htmlspecialchars($ip),
                          htmlspecialchars($reason));
    }
}
 
$pgtitle = array("Services", "Security Plugin");
include("head.inc");

// show error/Message
if (!empty($input_errors)) {
    print_input_errors($input_errors);
}
if (!empty($savemsg)) {
    print_info_box($savemsg, 'success');
}
      
 
        
            
            
        

// Settings sekmesi için kaydetme
if ($_SERVER['REQUEST_METHOD']==='POST' && $current_tab==='settings' && isset($_POST['save_api_key'])) {
    $new_key = trim($_POST['vt_api_key']);
    if(!empty($new_key)){
        file      file_put_contents("/usr/local/pkg/security_plugin/api.key",$new_key);
        $vt_api_key = $new_key;
        $savemsg = "VirusTotal API key saved successfully.";
    }else{
        $input_errors[] = "API key cannot be empty.";
  }             
}
        
// ...
             
// Tab menüsünü oluştur
generate_plugin_nav($current_tab);
            
// SETTINGS TAB
if ($current_tab === 'settings'): ?>
  <div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title">Plugin Settings</h2></div>
    <div class="panel-body">
      <form method="post" class="form-horizontal">
        <div class="form-group">
          <label class="col-sm-2 control-label">VirusTotal API Key</label>
          <div class="col-sm-8">
            <input type="text" class="form-control" name="vt_api_key"
                   value="<?=htmlspecialchars($vt_api_key);?>"
                   placeholder="Enter your VT API Key" required>
          </div>
          <div class="col-sm-2">
            <button type="submit" class="btn btn-primary" name="save_api_key" >Save</button>
          </div>
        </div>
      </form>
    </div>
  </div>
<?php endif; ?>
 


<!-- DASHBOARD -->
<?php if ($current_tab == 'dashboard'): ?>
<div class="row">
    <div class="col-md-6">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h2 class="panel-title">System Status</h2>
            </div>
            <div class="panel-body">
                <div class="table-responsive">
                    <table class="table table-striped table-condensed">
                        <tr>
                            <td>Blocked IPs</td>
                            <td><strong><?=  $blocked= $config['installedpackages']['ipblocker']['config'][0]['blocked_ips'] ?? array();
                                                $ip_count=is_array($blocked) ? count($blocked) : 0;
                                        ?></strong></td>
                        </tr>
                        <tr>
                            <td>VirusTotal Integration</td>
                            <td>
_put_contents("/usr/local/pkg/security_plugin/api.key",$new_key);
                            <td>
                                <span class="label label-<?=empty($vt_api_key) ? 'danger' : 'success'?>">
                                    <?=empty($vt_api_key) ? 'Passive' : 'Active'?>
                                </span>
                            </td>
                        </tr>
                        <tr>
                            <td>Latest Suricata Alert</td>
                            <td>
                                <?php
                                $last_alert = parse_suricata_alerts()[0] ?? null;
                                echo $last_alert ? date("d.m.Y H:i", strtotime($last_alert['timestamp'])) : 'Not available';
                                ?>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
        </div>
    </div>
    <div class="col-md-6">
        <div class="panel panel-default">
            <div class="panel-heading">
                <h2 class="panel-title">Last Suricata Alarms</h2>
            </div>
            <div class="panel-body">
                <?php
                $alerts = array_slice(parse_suricata_alerts(), 0, 5);
                if (!empty($alerts)): ?>
                    <div class="table-responsive">
                        <table class="table table-striped table-condensed">
                            <?php foreach ($alerts as $alert): ?>
                            <tr>
                                <td><?=htmlspecialchars($alert['src_ip'])?></td>
                                <td><?=htmlspecialchars($alert['signature'])?></td>
                                <td>
                                    <span class="label label-<?=($alert['severity'] >= 2 ? 'danger' : 'warning')?>">
                                        Level <?=$alert['severity']?>
                                    </span>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </table>
                    </div>
                <?php else: ?>
                    <div class="alert alert-info">No last alarm record found</div>
                <?php endif; ?>
            </div>
        </div>
    </div>
</div>
                                                
<!-- IP BLOCKER -->
<?php elseif ($current_tab == 'ipblocker'): ?>
<?php
        $blocked_ips = $config['installedpackages']['ipblocker']['config'][0]['blocked_ips'] ?? [];
        foreach ($blocked_ips as &$entry) {
            $entry['vt_result'] = scan_ip_with_virustotal($entry['ip'],$vt_api_key);}
?>
<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">IP Blocker</h2>
    </div>
    <div class="panel-body">
        <form method="post" class="form-horizontal">
            <div class="form-group">
                <label class="col-sm-2 control-label">IP Addres</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" name="ip" placeholder="192.168.1.100" required
                           pattern="\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}">
                </div>
            </div>
            <div class="form-group">
                <label class="col-sm-2 control-label">Reason</label>
                <div class="col-sm-10">
                    <input type="text" class="form-control" name="reason" placeholder="Send spam">
                </div>
            </div>
            <div class="form-group">
                <div class="col-sm-offset-2 col-sm-10">
                    <button type="submit" name="block_ip" class="btn btn-danger">Block</button>
                </div>
            </div>
        </form>
                
        <hr>
        <h4>Blocked IPs</h4>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>IP Addres</th>
                        <th>Reason</th>
                        <th>Date</th>
                        <th>Process</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach (get_blocked_ips() as $entry): ?>
                    <tr>
                        <td><?=htmlspecialchars($entry['ip'])?></td>
                        <td><?=htmlspecialchars($entry['reason'])?></td>
                        <td><?=date("d.m.Y H:i", $entry['timestamp'])?></td>
                        <td>
                            <a href="?tab=ipblocker&action=unblock&ip=<?=urlencode($entry['ip'])?>"
                               class="btn btn-xs btn-success">Unblock</a>
                        </td>
                    </tr>                       
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>




<!-- VIRUSTOTAL -->


            
<?php elseif ($current_tab == 'virustotal'): ?>
<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">VirusTotal File Scan</h2>
    </div>
    <div class="panel-body">
        <?php if (empty($vt_api_key)): ?>
            <div class="alert alert-danger">
                VirusTotal API key is not configured! Please go to <a href="?tab=settings">Settings</a>.
            </div>
        <?php else: ?>
            <!-- File Upload Section -->
            <div class="text-center" style="border: 2px dashed #ddd; padding: 30px; margin-bottom: 20px;">
                <form method="post" enctype="multipart/form-data" id="vtForm">
                    <div id="dropArea">
                        <i class="fa fa-cloud-upload fa-3x" style="color: #3498db;"></i>
                        <h4>Drag and drop files here or click to select</h4>
                        <p class="text-muted">Maximum file size: 32MB</p>
                        <input type="file" name="file" id="fileInput" style="display: none;">
                        <?php if (isset($_FILES['file']['name'])): ?>
                            <div class="alert alert-info">
                                Scanning file: <?=htmlspecialchars($_FILES['file']['name'])?>
                            </div>
                        <?php endif; ?>
                    </div>
                </form>
            </div>
                        
        <?php if (isset($detailed_result) && !isset($detailed_result['error'])): ?>
<div class="panel panel-info">
    <div class="panel-heading"><h3 class="panel-title">Detailed Scan Results</h3></div>
    <div class="panel-body">
        <div class="row">
            <div class="col-md-6">
                <h4>Detection Summary</h4>
                <table class="table table-bordered">
                    <?php foreach ($detailed_result['data']['attributes']['stats'] as $type => $count): ?>
                    <tr>
                        <td><?=ucfirst(str_replace('-', ' ', $type))?></td>
                        <td class="<?=($type === 'malicious') ? 'danger' : ''?>">
                            <strong><?=$count?></strong>
                        </td>
                    </tr>                       
                    <?php endforeach; ?>
                </table>
            </div>
            <div class="col-md-6">
                <h4>File Info</h4>
                <ul class="list-group">
                    <?php foreach ($detailed_result['meta']['file_info'] as $key => $value): ?>
                    <li class="list-group-item">
                        <strong><?=strtoupper($key)?>:</strong>
                        <code><?=htmlspecialchars($value)?></code>
                    </li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </div>
    
        <h4 class="mt-4">Engine Results</h4>
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Engine</th>
                        <th>Version</th>
                        <th>Category</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($detailed_result['data']['attributes']['results'] as $engine => $result): ?>
                    <?php if (!empty($result['category']) || !empty($result['result'])): ?>
                    <tr>
                        <td><?=htmlspecialchars($engine)?></td>
                        <td><?=htmlspecialchars($result['engine_version'] ?? 'N/A')?></td>
                        <td>
                            <span class="label label-<?=($result['category'] === 'malicious') ? 'danger' : 'info'?>">
                                <?=htmlspecialchars($result['category'])?>
                            </span>
                        </td>
                        <td><?=htmlspecialchars($result['result'] ?? 'N/A')?></td>
                    </tr>
                    <?php endif; ?>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
</div>
<?php endif; ?>
                
                    
  <!-- Scan Results -->
   <!-- Scan Results -->
            <?php if (isset($scan_result)): ?>
            <?php if (isset($detailed_result) && !isset($detailed_result['error'])): ?>
                <div class="panel panel-info">
                <div class="panel-heading"><h3 class="panel-title">Detailed Analysis</h3></div>
                        <div class="panel-body">
                                <pre><?=htmlspecialchars(print_r($detailed_result, true))?></pre>
                        </div>

               </div>
            <?php elseif (isset($detailed_result['error'])): ?>
    <div class="alert alert-danger">Error: <?=htmlspecialchars($detailed_result['error']['message'] ?? 'Unknown error')?></div>
           <?php endif; ?>
                    
           <div class="panel panel-<?=(($scan_result['data']['attributes']['last_analysis_stats']['malicious'] ?? 0) > 0 ? 'danger' : 'success')?>">
                <div class="panel-heading">
                    <h3 class="panel-title">Scan Summary</h3>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <div class="col-md-6">
                            <h4>Detection Results</h4>
                           <ul class="list-group">
                                <li class="list-group-item">
                                    Malicious: <span class="badge alert-danger"><?=$scan_result['data']['attributes']['last_analysis_stats']['malicious'] ?? 0?></span>
                                </li>
                                <li class="list-group-item">
                                    Suspicious: <span class="badge alert-warning"><?=$scan_result['data']['attributes']['last_analysis_stats']['suspicious'] ?? 0?></span>
                                </li>
                                <li class="list-group-item">
                                    Harmless: <span class="badge alert-success"><?=$scan_result['data']['attributes']['last_analysis_stats']['harmless'] ?? 0?></span>
                                </li>
                                <li class="list-group-item">
                                    Undetected: <span class="badge"><?=$scan_result['data']['attributes']['last_analysis_stats']['undetected'] ?? 0?></span>
                                </li>
                            </ul>
                        </div>
                        <div class="col-md-6">
                            <h4>File Information</h4>
                            <ul class="list-group">
                                <li class="list-group-item">SHA256: <code><?=$scan_result['data']['attributes']['sha256']?></code></li>
                                <li class="list-group-item">File Type: <?=$scan_result['data']['attributes']['type_description']?></li>
                                <li class="list-group-item">File Size: <?=round($scan_result['data']['attributes']['size']/1024, 2)?> KB</li>
                            </ul>
                        </div>
                    </div>
                    
                    <div class="text-center" style="margin-top: 20px;">
                        <a href="?tab=virustotal" class="btn btn-primary">
                            <i class="fa fa-refresh"></i> New Scan
                        </a>
                        <?php
                                $view_token = '';
                                if (!empty($scan_result['data']['id'])) {
                                        $view_token = $scan_result['data']['id'];
                                } elseif (!empty($scan_result['data']['attributes']['sha256'])) {
                                        $view_token = $scan_result['data']['attributes']['sha256']; }?>
                        <?php if (!empty($view_token)): ?>
                                <form method="post" class="inline-form">
                                        <input type="hidden" name="analysis_id" value="<?=htmlspecialchars($view_token)?>">
                                        <button type="submit" name="view_details" class="btn btn-info">View Detailed Results</button>
                                </form>
                        <?php endif; ?>
        <?php endif; ?>
    </div>
</div>
                    
                
                
                    
                        
<script>
// Drag and drop functionality
document.addEventListener('DOMContentLoaded', function() {
    const dropArea = document.getElementById('dropArea');
    const fileInput = document.getElementById('fileInput');
                                
    // Highlight drop area when item is dragged over it
    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });
                                
    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });
                            
    function highlight(e) {
        dropArea.style.borderColor = '#3498db';
        dropArea.style.backgroundColor = '#f8f9fa';
    }
                                
    function unhighlight(e) {
        dropArea.style.borderColor = '#ddd';
        dropArea.style.backgroundColor = '';
    }
                    
    // Handle dropped files
    dropArea.addEventListener('drop', handleDrop, false);
                        
    function handleDrop(e) {
        e.preventDefault();
        if (e.dataTransfer.files.length) {
            fileInput.files = e.dataTransfer.files;
            document.getElementById('vtForm').submit();
        }
    }
                                        
    // Click to select files
    dropArea.addEventListener('click', () => fileInput.click());
                                        
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length) {
            document.getElementById('vtForm').submit();
        }                       
    });                 
</script>





<!-- SURICATA -->
                                
                        
                    
<?php elseif ($current_tab == 'suricata'): ?>
<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">Latest Suricata Alarms (Last 50)</h2>
    </div>
    <div class="panel-body">
        <?php       
        $alerts = parse_suricata_alerts('/var/log/suricata/suricata_em161241/eve.json', 50);
        if (!empty($alerts)): ?>
            <div class="table-responsive">
                <table class="table table-striped table-hover" id="suricata-table">
                    <thead>     
                        <tr>
                            <th>Time</th>
                            <th>Source IP</th>
                            <th>Signature</th>
                            <th>Severity</th>
                            <th>Action</th> <!-- Block butonu için sütun eklendi -->
                        </tr>
                    </thead>
                    <tbody>     
                        <?php foreach ($alerts as $alert): ?>
                        <tr>
                            <td><?=date("Y-m-d H:i:s", strtotime($alert['timestamp']))?></td>
                            <td><?=htmlspecialchars($alert['src_ip'])?></td>
                            <td><?=htmlspecialchars($alert['signature'])?></td>
                            <td>
                                <span class="label label-<?=($alert['severity'] >= 2 ? 'danger' : 'warning')?>">
                                    Level <?=$alert['severity']?>
                                </span>
                            </td>
                            <td>
                                <!-- BLOCK BUTONU -->
                                <a href="?tab=suricata&block=<?=urlencode($alert['src_ip'])?>&reason=<?=urlencode($alert['signature'])?>"
                                   class="btn btn-xs btn-danger"
                                   title="Block This IP">
                                    <i class="fa fa-ban"></i> Block
                                </a>
                            </td>
                        </tr>           
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>              
        <?php else: ?>  
            <div class="alert alert-info">No recent alerts found.</div>
        <?php endif; ?>
    </div>
</div>
        
        
<?php endif; ?>
            
<?php include("foot.inc"); ?>
                    
                        
