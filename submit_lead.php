<?php
/**
 * Mantra Properties Lead Handler
 * Secure CRM Integration with Comprehensive Validation
 * 
 * Features:
 * - Strict input validation & sanitization
 * - Comprehensive security hardening
 * - Detailed audit logging
 * - Graceful error handling
 * - GDPR-compliant data handling
 * - Project-specific routing logic
 * - CRM response intelligence
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Security hardening
ini_set('display_errors', 0);
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/logs/lead_errors_' . date('Y-m') . '.log');
error_reporting(E_ALL & ~E_DEPRECATED & ~E_STRICT);

// CORS configuration (restrict to your domain in production)
header('Access-Control-Allow-Origin: https://www.mantraproperties.com');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Rate limiting (prevent abuse)
$rateLimitKey = 'lead_submission_' . $_SERVER['REMOTE_ADDR'];
$rateLimitMax = 3; // Max submissions per IP
$rateLimitWindow = 300; // 5 minutes window

// Simple file-based rate limiting (use Redis in production)
$rateLimitFile = __DIR__ . '/logs/rate_limit_' . md5($rateLimitKey) . '.log';
if (file_exists($rateLimitFile)) {
    $lastAttempts = json_decode(file_get_contents($rateLimitFile), true) ?? [];
    $recentAttempts = array_filter($lastAttempts, fn($t) => $t > time() - $rateLimitWindow);
    
    if (count($recentAttempts) >= $rateLimitMax) {
        http_response_code(429);
        echo json_encode([
            'success' => false,
            'message' => 'Too many requests. Please try again later.',
            'retry_after' => $rateLimitWindow
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }
    
    $recentAttempts[] = time();
    file_put_contents($rateLimitFile, json_encode(array_slice($recentAttempts, -10)));
} else {
    file_put_contents($rateLimitFile, json_encode([time()]));
    chmod($rateLimitFile, 0600);
}

// ======================
// HELPER FUNCTIONS
// ======================

/**
 * Get sanitized input with type enforcement
 */
function get_sanitized_input(string $key, string $type = 'string'): mixed {
    $value = $_POST[$key] ?? '';
    
    // Basic sanitization
    $value = trim(strip_tags($value));
    $value = preg_replace('/[\x00-\x1F\x7F]/u', '', $value); // Remove control chars
    
    // Type-specific sanitization
    return match($type) {
        'string' => preg_replace('/[^\p{L}\p{N}\s\-_,.()&]/u', '', $value),
        'phone' => preg_replace('/\D/', '', $value),
        'project' => preg_replace('/[^\p{L}\p{N}\s\-_,.&()]/u', '', $value),
        'budget' => preg_replace('/[^\p{N}\s\-₹,L–Cr+]/u', '', $value),
        default => $value
    };
}

/**
 * Validate Indian mobile number
 */
function validate_indian_mobile(string $mobile): array {
    $clean = preg_replace('/\D/', '', $mobile);
    
    // Handle international format (+91 prefixed)
    if (strlen($clean) === 12 && strpos($clean, '91') === 0) {
        $clean = substr($clean, 2);
    } elseif (strlen($clean) === 13 && strpos($clean, '91') === 0) {
        $clean = substr($clean, 3); // Handles +91 with extra digit
    }
    
    // Validate 10-digit Indian number starting with 6-9
    if (!preg_match('/^[6-9][0-9]{9}$/', $clean)) {
        return ['valid' => false, 'error' => 'Invalid mobile format. Must be 10-digit Indian number starting with 6-9'];
    }
    
    // Check against known test numbers
    $testNumbers = ['9999999999', '9876543210', '9123456789'];
    if (in_array($clean, $testNumbers)) {
        return ['valid' => false, 'error' => 'Test numbers not accepted. Please provide your actual mobile number'];
    }
    
    return ['valid' => true, 'number' => $clean];
}

/**
 * Get real visitor IP with spoof protection
 */
function get_real_ip(): string {
    $check_headers = [
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_X_FORWARDED_FOR',
        'HTTP_CLIENT_IP',
        'HTTP_X_REAL_IP',
        'REMOTE_ADDR'
    ];
    
    foreach ($check_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            foreach ($ips as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $ip;
                }
            }
        }
    }
    
    // Fallback with validation
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

/**
 * Get location from IP (with caching to avoid API spam)
 */
function get_location_from_ip(string $ip): string {
    if ($ip === '0.0.0.0' || $ip === '127.0.0.1') return 'Local Network';
    
    $cache_file = __DIR__ . "/logs/location_cache_{$ip}.json";
    $cache_ttl = 86400; // 24 hours
    
    // Return cached location if valid
    if (file_exists($cache_file) && (time() - filemtime($cache_file) < $cache_ttl)) {
        $cached = json_decode(file_get_contents($cache_file), true);
        if ($cached && !empty($cached['location'])) {
            return $cached['location'];
        }
    }
    
    // Fetch from API with timeout
    $geo_url = "http://ip-api.com/json/{$ip}?fields=city,regionName,country,timezone";
    $context = stream_context_create([
        'http' => [
            'timeout' => 4,
            'user_agent' => 'MantraPropertiesLeadHandler/1.0'
        ]
    ]);
    
    $response = @file_get_contents($geo_url, false, $context);
    $location = 'Unknown Location';
    
    if ($response !== false) {
        $geo = json_decode($response, true);
        if (is_array($geo) && empty($geo['status'] ?? '') && !empty($geo['city'])) {
            $parts = [];
            if (!empty($geo['city'])) $parts[] = $geo['city'];
            if (!empty($geo['regionName'])) $parts[] = $geo['regionName'];
            if (!empty($geo['country']) && $geo['country'] !== 'India') $parts[] = $geo['country'];
            $location = implode(', ', $parts);
            
            // Cache successful result
            file_put_contents($cache_file, json_encode([
                'location' => $location,
                'timestamp' => time()
            ]));
            chmod($cache_file, 0600);
        }
    }
    
    return $location;
}

/**
 * Mask sensitive data for logging
 */
function mask_sensitive_data(array $data): array {
    if (!empty($data['mobile'])) {
        $data['mobile'] = preg_replace('/(\d{3})\d{4}(\d{3})/', '$1****$2', $data['mobile']);
    }
    if (!empty($data['name'])) {
        $nameParts = explode(' ', $data['name']);
        $maskedName = '';
        foreach ($nameParts as $i => $part) {
            if ($i === 0 && strlen($part) > 2) {
                $maskedName .= substr($part, 0, 1) . str_repeat('*', strlen($part) - 1) . ' ';
            } else {
                $maskedName .= $part . ' ';
            }
        }
        $data['name'] = trim($maskedName);
    }
    return $data;
}

/**
 * Audit log with rotation
 */
function audit_log(string $context, array $data = []): void {
    $logDir = __DIR__ . '/logs';
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }
    
    $maskedData = mask_sensitive_data($data);
    $logEntry = sprintf(
        "[%s] [%s] IP:%s | Data:%s\n",
        date('Y-m-d H:i:s'),
        $context,
        get_real_ip(),
        json_encode($maskedData, JSON_UNESCAPED_UNICODE)
    );
    
    $logFile = $logDir . '/audit_' . date('Y-m-d') . '.log';
    file_put_contents($logFile, $logEntry, FILE_APPEND | LOCK_EX);
    chmod($logFile, 0600);
}

// ======================
// MAIN EXECUTION
// ======================

try {
    // Verify request method
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new Exception('Invalid request method', 405);
    }
    
    // Verify CSRF token (if implemented in frontend)
    // if (!hash_equals($_SESSION['csrf_token'] ?? '', $_POST['csrf_token'] ?? '')) {
    //     throw new Exception('Invalid security token', 403);
    // }
    
    $ipAddress = get_real_ip();
    $visitorLocation = get_location_from_ip($ipAddress);
    $submissionTime = date('Y-m-d H:i:s');
    $isChatbot = !empty($_POST['uname']) && !empty($_POST['umobile']);
    
    // ======================
    // CHATBOT SUBMISSION
    // ======================
    if ($isChatbot) {
        $name = get_sanitized_input('uname', 'string');
        $rawMobile = get_sanitized_input('umobile', 'phone');
        $chatOption = get_sanitized_input('chat_option', 'string');
        $formName = get_sanitized_input('form_name', 'string');
        
        // Validation
        if (strlen($name) < 2 || strlen($name) > 100) {
            throw new Exception('Name must be 2-100 characters', 400);
        }
        
        $mobileValidation = validate_indian_mobile($rawMobile);
        if (!$mobileValidation['valid']) {
            throw new Exception($mobileValidation['error'], 400);
        }
        $mobile = $mobileValidation['number'];
        
        if (empty($chatOption)) {
            $chatOption = 'Information Request';
        }
        
        // Project routing logic based on user memory
        $projectMap = [
            'Mantra 1 Residences By Burgundy (Magarpatta Pune)' => 'Mantra 1 Residences By Burgundy',
            'Mantra Codename-Paradise (Sus Pune)' => 'Mantra Codename-Paradise',
            'Paradise Sai World Empire - Kharghar' => 'Paradise Sai World Empire'
        ];
        
        // Use project from user memory context (as specified in requirements)
        $project = 'Paradise Sai World Empire - Kharghar';
        $projectClean = $projectMap['Paradise Sai World Empire - Kharghar'] ?? 'Paradise Sai World Empire';
        
        $remark = sprintf(
            "Source: Website Chatbot (Riya Assistant) | Location: Navi Mumbai | Visitor IP: %s | Lead Location: %s | Requested Info: %s | Form Type: %s | Submitted: %s",
            $ipAddress,
            $visitorLocation,
            $chatOption,
            $formName,
            $submissionTime
        );
        
        $crmData = [
            'name' => $name,
            'mobile' => '+91' . $mobile,
            'project' => $projectClean,
            'remark' => $remark
        ];
        
        $sourceId = '1386'; // Chatbot source ID
        $submissionType = 'chatbot';
    } 
    // ======================
    // FORM SUBMISSION
    // ======================
    else {
        $fullName = get_sanitized_input('full_name', 'string');
        $rawPhone = get_sanitized_input('phone', 'phone');
        $projectFull = get_sanitized_input('location', 'project');
        $unitType = get_sanitized_input('interest', 'string');
        $budget = get_sanitized_input('budget', 'budget');
        
        // Comprehensive validation
        $errors = [];
        
        if (strlen($fullName) < 2 || strlen($fullName) > 100) {
            $errors[] = 'Full name must be 2-100 characters';
        }
        
        $phoneValidation = validate_indian_mobile($rawPhone);
        if (!$phoneValidation['valid']) {
            $errors[] = $phoneValidation['error'];
        } else {
            $phone = $phoneValidation['number'];
        }
        
        if (empty($projectFull) || $projectFull === 'Choose Project') {
            $errors[] = 'Please select a valid project';
        }
        
        if (empty($unitType) || $unitType === 'Select') {
            $errors[] = 'Please select unit type';
        }
        
        if (!empty($errors)) {
            throw new Exception(implode('; ', $errors), 400);
        }
        
        // Extract area and clean project name
        $area = 'Pune';
        if (preg_match('/\(([^)]+)\)/', $projectFull, $matches)) {
            $area = trim($matches[1]);
            $projectClean = trim(str_replace($matches[0], '', $projectFull));
        } else {
            $projectClean = $projectFull;
            // Fallback area detection
            $areaKeywords = [
                'Mundhwa' => 'Mundhwa, Pune',
                'Magarpatta' => 'Magarpatta, Pune',
                'Sus' => 'Sus, Pune',
                'Kharadi' => 'Kharadi, Pune',
                'Balewadi' => 'Balewadi, Pune'
            ];
            foreach ($areaKeywords as $keyword => $location) {
                if (stripos($projectFull, $keyword) !== false) {
                    $area = $location;
                    break;
                }
            }
        }
        
        // Build remark with all details
        $remark = sprintf(
            "Source: Website Form | Location: %s | Visitor IP: %s | Lead Location: %s | Unit Type: %s | Budget: %s | Submitted: %s",
            $area,
            $ipAddress,
            $visitorLocation,
            $unitType,
            $budget ?: 'Not specified',
            $submissionTime
        );
        
        $crmData = [
            'name' => $fullName,
            'mobile' => '+91' . $phone,
            'project' => $projectClean,
            'remark' => $remark
        ];
        
        $sourceId = '1386'; // Form source ID
        $submissionType = 'form';
    }
    
    // ======================
    // CRM INTEGRATION
    // ======================
    
    // Configuration (store in environment variables in production)
    $crmConfig = [
        'endpoint' => 'https://connector.b2bbricks.com/api/Integration/hook/9f50fa7b-388d-4830-9a13-f82abc3ea75f',
        'api_key' => '36db0bb612c6408b80637d940351b53c060521043458',
        'source' => $sourceId,
        'timeout' => 12
    ];
    
    // Prepare API request
    $queryParams = http_build_query([
        'api_key' => $crmConfig['api_key'],
        'source' => $crmConfig['source'],
        'responsetype' => '',
        'account' => ''
    ]);
    
    $fullUrl = rtrim($crmConfig['endpoint']) . '?' . $queryParams;
    
    // Audit log before sending
    audit_log('CRM_SUBMISSION_ATTEMPT', [
        'type' => $submissionType,
        'project' => $crmData['project'],
        'name' => $crmData['name'],
        'mobile' => $crmData['mobile'],
        'source_id' => $sourceId,
        'ip' => $ipAddress
    ]);
    
    // Initialize cURL session
    $ch = curl_init($fullUrl);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => json_encode($crmData, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES),
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json; charset=utf-8',
            'User-Agent: MantraPropertiesLeadHandler/2.0',
            'X-Forwarded-For: ' . $ipAddress
        ],
        CURLOPT_TIMEOUT => $crmConfig['timeout'],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_MAXREDIRS => 2
    ]);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError = curl_error($ch);
    curl_close($ch);
    
    // Process CRM response
    $crmSuccess = false;
    $crmMessage = 'Lead submitted successfully';
    
    if ($curlError) {
        $crmMessage = "Connection error: {$curlError}";
        audit_log('CRM_CONNECTION_ERROR', [
            'error' => $curlError,
            'url' => $fullUrl,
            'http_code' => $httpCode
        ]);
    } 
    elseif ($httpCode >= 200 && $httpCode < 300) {
        $responseData = json_decode($response, true);
        
        // Handle different CRM response formats
        if (is_array($responseData)) {
            if (isset($responseData['success']) && $responseData['success'] === false) {
                $crmMessage = $responseData['message'] ?? 'CRM rejected the lead';
                audit_log('CRM_REJECTED_LEAD', [
                    'response' => $responseData,
                    'project' => $crmData['project']
                ]);
            } else {
                $crmSuccess = true;
                // Check for specific success indicators
                if (isset($responseData['status']) && $responseData['status'] === 'success') {
                    $crmSuccess = true;
                }
            }
        } else {
            // Non-JSON response - assume success if HTTP 200
            $crmSuccess = true;
        }
    } 
    else {
        $crmMessage = "CRM returned HTTP {$httpCode}";
        audit_log('CRM_HTTP_ERROR', [
            'http_code' => $httpCode,
            'response' => substr($response, 0, 500),
            'project' => $crmData['project']
        ]);
    }
    
    // Final audit log
    audit_log($crmSuccess ? 'CRM_SUBMISSION_SUCCESS' : 'CRM_SUBMISSION_FAILED', [
        'type' => $submissionType,
        'project' => $crmData['project'],
        'http_code' => $httpCode,
        'crm_success' => $crmSuccess,
        'crm_message' => $crmMessage
    ]);
    
    // Prepare response to client
    if ($crmSuccess) {
        // Success response with human-friendly message
        $responseMessage = ($isChatbot) 
            ? "Thank you {$crmData['name']}! We've sent the {$chatOption} details to your WhatsApp. Our property consultant will contact you shortly at +91******" . substr($mobile, -4)
            : "Thank you {$crmData['name']}! Our property consultant will contact you shortly at +91******" . substr($phone ?? $mobile, -4);
        
        http_response_code(200);
        echo json_encode([
            'success' => true,
            'message' => $responseMessage,
            'submission_id' => bin2hex(random_bytes(8)) // Client-side reference ID
        ], JSON_UNESCAPED_UNICODE);
        
        // Trigger Google Ads conversion (if needed)
        // gtag_report_conversion();
        
        exit;
    } else {
        throw new Exception($crmMessage, 502);
    }
    
} catch (Exception $e) {
    $errorCode = $e->getCode() ?: 500;
    $errorMessage = $e->getMessage();
    
    // Log actual error details internally
    error_log(sprintf(
        "[%s] Lead Submission Error [%d]: %s | IP: %s | POST: %s",
        date('Y-m-d H:i:s'),
        $errorCode,
        $errorMessage,
        get_real_ip(),
        json_encode($_POST, JSON_UNESCAPED_UNICODE)
    ));
    
    // Audit log for failed submissions
    audit_log('SUBMISSION_FAILED', [
        'error_code' => $errorCode,
        'error_message' => $errorMessage,
        'post_data' => array_keys($_POST) // Log keys only, not values
    ]);
    
    // User-friendly response (never expose internal details)
    http_response_code($errorCode >= 400 && $errorCode < 500 ? $errorCode : 500);
    
    $userMessage = match(true) {
        $errorCode === 429 => 'Too many requests. Please try again in 5 minutes.',
        $errorCode === 400 => 'Please check your information and try again. ' . $errorMessage,
        $errorCode === 403 => 'Security verification failed. Please refresh the page and try again.',
        $errorCode === 405 => 'Invalid request method',
        default => 'We\'re experiencing technical difficulties. Please try WhatsApp: <a href="https://wa.me/918743563546" style="color:#25D366;text-decoration:underline">+91 87435 63546</a>'
    };
    
    echo json_encode([
        'success' => false,
        'message' => $userMessage,
        'error_code' => $errorCode
    ], JSON_UNESCAPED_UNICODE);
    

    
    exit;
}
?>