<?php
/**
 * Nginx 환경에 최적화된 SQL Injection 탐지 및 로깅 시스템
 */

// SQL Injection 공격 패턴들
$injection_patterns = [
    '/\bunion\b.*\bselect\b/i',
    '/\bunion\b.*\ball\b.*\bselect\b/i',
    '/\'.*or.*\'.*=.*\'/i',
    '/\".*or.*\".*=.*\"/i',
    '/\bor\b.*1\s*=\s*1/i',
    '/\band\b.*1\s*=\s*1/i',
    '/\bsleep\s*\(/i',
    '/\bwaitfor\b.*\bdelay\b/i',
    '/\bbenchmark\s*\(/i',
    '/\binformation_schema\b/i',
    '/\bsys\.databases\b/i',
    '/\/\*.*\*\//i',
    '/--.*$/m',
    '/\#.*$/m',
    '/\'.*;\s*drop\b/i',
    '/\'.*;\s*delete\b/i',
    '/\'.*;\s*update\b/i',
    '/\'.*;\s*insert\b/i',
    '/\bload_file\s*\(/i',
    '/\binto\s+outfile\b/i',
    '/\bchar\s*\(/i',
    '/\bconcat\s*\(/i',
    '/\bsubstring\s*\(/i',
    '/\bascii\s*\(\s*substring\s*\(/i',
    '/\blength\s*\(/i',
];

/**
 * Nginx 환경용 클라이언트 IP 획득 (Reverse Proxy 대응)
 */
function getNginxClientIP() {
    // Nginx Reverse Proxy 헤더 순서대로 확인
    $ip_headers = [
        'HTTP_X_REAL_IP',        // Nginx proxy_set_header X-Real-IP
        'HTTP_X_FORWARDED_FOR',  // Nginx proxy_set_header X-Forwarded-For
        'HTTP_CF_CONNECTING_IP', // Cloudflare
        'HTTP_CLIENT_IP',        // 기타 프록시
        'REMOTE_ADDR'            // 직접 연결
    ];
    
    foreach ($ip_headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            $ip = trim($ips[0]);
            
            // IP 유효성 검증 (Private IP도 허용 - 내부 네트워크 고려)
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_RES_RANGE)) {
                return $ip;
            }
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * Nginx 로그 형식에 맞춘 로깅 함수
 */
function logToNginxErrorLog($message, $level = 'warn') {
    // Nginx error_log 형식: 2025/06/24 15:30:45 [level] pid#tid: message
    $timestamp = date('Y/m/d H:i:s');
    $pid = getmypid();
    $formatted_message = "{$timestamp} [{$level}] {$pid}#0: {$message}";
    
    // 🎯 방법 1: PHP error_log 사용 (권장)
    error_log($formatted_message);
    
    // 🎯 방법 2: 직접 Nginx 로그 파일에 기록 (선택사항)
    // $nginx_error_log = '/var/log/nginx/error.log';
    // if (is_writable($nginx_error_log)) {
    //     file_put_contents($nginx_error_log, $formatted_message . PHP_EOL, FILE_APPEND | LOCK_EX);
    // }
}

/**
 * SQL Injection 탐지 및 Nginx 로깅
 */
function detectAndLogSQLInjection($input_data, $script_name = '') {
    global $injection_patterns;
    
    $client_ip = getNginxClientIP();
    $detected_patterns = [];
    $risk_level = 'LOW';
    
    // 각 입력 필드 검사
    foreach ($input_data as $field => $value) {
        if (is_string($value)) {
            $patterns = checkSQLInjectionPatterns($value, $injection_patterns);
            if (!empty($patterns)) {
                $detected_patterns[$field] = $patterns;
            }
        }
    }
    
    if (!empty($detected_patterns)) {
        $risk_level = calculateSQLInjectionRisk($detected_patterns);
        
        // Nginx 로그에 기록
        logSQLInjectionToNginx($risk_level, $detected_patterns, $script_name);
        
        // 높은 위험도일 경우 즉시 차단
        if ($risk_level === 'CRITICAL') {
            http_response_code(403);
            die('Malicious request detected and blocked');
        }
    }
    
    return [
        'detected' => !empty($detected_patterns),
        'patterns' => $detected_patterns,
        'risk_level' => $risk_level
    ];
}

/**
 * SQL Injection 패턴 매칭 검사
 */
function checkSQLInjectionPatterns($input, $patterns) {
    $detected = [];
    
    // URL 디코딩
    $decoded_input = urldecode($input);
    
    // HTML 엔티티 디코딩
    $html_decoded = html_entity_decode($decoded_input, ENT_QUOTES, 'UTF-8');
    
    // Base64 디코딩 시도
    if (preg_match('/^[A-Za-z0-9+\/]*={0,2}$/', $input) && strlen($input) % 4 == 0) {
        $base64_decoded = base64_decode($input, true);
        if ($base64_decoded !== false) {
            $html_decoded .= ' ' . $base64_decoded;
        }
    }
    
    $inputs_to_check = [$input, $decoded_input, $html_decoded];
    
    foreach ($inputs_to_check as $check_input) {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $check_input, $matches)) {
                $detected[] = [
                    'pattern' => $pattern,
                    'matched' => sanitizeForLog($matches[0]),
                    'severity' => 'HIGH'
                ];
            }
        }
    }
    
    return $detected;
}

/**
 * SQL Injection 위험도 계산
 */
function calculateSQLInjectionRisk($detected_patterns) {
    $score = 0;
    $critical_patterns = 0;
    
    foreach ($detected_patterns as $field => $patterns) {
        foreach ($patterns as $pattern) {
            $score += 10;
            $critical_patterns++;
        }
    }
    
    if ($critical_patterns >= 2 || $score >= 20) {
        return 'CRITICAL';
    } elseif ($critical_patterns >= 1 || $score >= 10) {
        return 'HIGH';
    } else {
        return 'MEDIUM';
    }
}

/**
 * Nginx 로그 형식으로 SQL Injection 시도 기록
 */
function logSQLInjectionToNginx($risk_level, $patterns, $script_name = '') {
    $client_ip = getNginxClientIP();
    $user_agent = sanitizeForLog($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
    $request_uri = sanitizeForLog($_SERVER['REQUEST_URI'] ?? '');
    $request_method = $_SERVER['REQUEST_METHOD'] ?? '';
    
    // 탐지된 패턴 요약
    $pattern_summary = [];
    foreach ($patterns as $field => $field_patterns) {
        $pattern_summary[] = $field . '(' . count($field_patterns) . ')';
    }
    
    // Nginx 친화적 로그 메시지 구성
    $log_data = [
        'event_type' => 'SQL_INJECTION_DETECTED',
        'risk_level' => $risk_level,
        'client_ip' => $client_ip,
        'method' => $request_method,
        'uri' => $request_uri,
        'script' => $script_name,
        'patterns_count' => count($patterns),
        'affected_fields' => implode(',', $pattern_summary),
        'user_agent_hash' => substr(hash('sha256', $user_agent), 0, 16),
        'session_id' => substr(hash('sha256', session_id()), 0, 12)
    ];
    
    // 로그 메시지 구성
    $message_parts = [];
    foreach ($log_data as $key => $value) {
        $message_parts[] = "{$key}={$value}";
    }
    
    $log_message = "SQL_INJECTION " . implode(' ', $message_parts);
    
    // Nginx 로그에 기록
    logToNginxErrorLog($log_message, 'warn');
}

/**
 * 인증 시도를 Nginx 로그에 기록
 */
function logAuthAttempt($event_type, $username = '', $success = false, $additional_data = []) {
    $safe_username = sanitizeForLog($username);
    $client_ip = getNginxClientIP();
    
    $log_data = [
        'event_type' => $event_type,
        'username_hash' => hash('sha256', $username),
        'result' => $success ? 'SUCCESS' : 'FAILED',
        'client_ip' => $client_ip,
        'session_id' => substr(hash('sha256', session_id()), 0, 12),
        'server_name' => $_SERVER['SERVER_NAME'] ?? 'localhost'
    ];
    
    // 추가 데이터 포함
    foreach ($additional_data as $key => $value) {
        if (is_scalar($value) && strlen($key) < 20) {
            $log_data[$key] = sanitizeForLog((string)$value);
        }
    }
    
    // 로그 메시지 구성
    $message_parts = [];
    foreach ($log_data as $key => $value) {
        $message_parts[] = "{$key}={$value}";
    }
    
    $log_message = "AUTH_EVENT " . implode(' ', $message_parts);
    
    // Nginx 로그에 기록
    $log_level = $success ? 'info' : 'warn';
    logToNginxErrorLog($log_message, $log_level);
}

/**
 * Log Injection 방지를 위한 입력값 정제
 */
function sanitizeForLog($input) {
    if (empty($input)) return '';
    
    $sanitized = preg_replace([
        '/[\r\n\t]/',
        '/[<>]/',
        '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/',
        '/["\[\]{}]/',
        '/\s+/',
    ], ['_', '_', '', '\\"', ' '], $input);
    
    return substr(trim($sanitized), 0, 100);
}

// ===== login.php 메인 로직 =====

require_once 'config/database.php';
require_once 'includes/functions.php';

// 이미 로그인된 경우 대시보드로 리다이렉트
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 🔍 SQL Injection 탐지 (POST 데이터 전체 검사)
    $sqli_result = detectAndLogSQLInjection($_POST, 'login.php');
    
    // 공격이 탐지된 경우 추가 처리
    if ($sqli_result['detected']) {
        if ($sqli_result['risk_level'] === 'CRITICAL' || $sqli_result['risk_level'] === 'HIGH') {
            http_response_code(403);
            exit('Security violation detected');
        }
    }
    
    $username = clean($_POST['username'] ?? '');
    $password = clean($_POST['password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrf_token)) {
        $error = '잘못된 요청입니다.';
        
        logAuthAttempt('CSRF_FAILED', $username, false, [
            'csrf_provided' => !empty($csrf_token)
        ]);
        
    } else if (empty($username) || empty($password)) {
        $error = '사용자명과 비밀번호를 모두 입력해주세요.';
        
        logAuthAttempt('INCOMPLETE_INPUT', $username, false);
        
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if ($user && verifyPassword($password, $user['password'])) {
                // 로그인 성공
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                
                unset($_SESSION['csrf_token']);
                generateCSRFToken();
                
                logAuthAttempt('LOGIN_SUCCESS', $username, true, [
                    'user_id' => $user['id']
                ]);
                
                setSuccessMessage('로그인되었습니다!');
                header("Location: dashboard.php");
                exit();
                
            } else {
                $error = '사용자명 또는 비밀번호가 잘못되었습니다.';
                
                logAuthAttempt('LOGIN_FAILED', $username, false, [
                    'user_exists' => $user !== false,
                    'pass_length' => strlen($password)
                ]);
            }
            
        } catch(PDOException $e) {
            $error = '로그인 처리 중 오류가 발생했습니다.';
            
            logAuthAttempt('SYSTEM_ERROR', $username, false, [
                'error_type' => 'PDOException'
            ]);
            
            error_log("Database error in login.php: " . $e->getMessage());
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
    <!-- Nginx 환경용 보안 헤더 -->
    <meta http-equiv="X-Frame-Options" content="DENY">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="X-XSS-Protection" content="1; mode=block">
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <div class="logo">Simple Blog</div>
                <ul class="nav-links">
                    <li><a href="index.php">홈</a></li>
                    <li><a href="login.php">로그인</a></li>
                    <li><a href="register.php">회원가입</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <main>
        <div class="container">
            <div class="form-container">
                <h2>로그인</h2>
                
                <?php if ($error): ?>
                    <div class="alert alert-error"><?php echo escape($error); ?></div>
                <?php endif; ?>
                
                <?php echo displayMessages(); ?>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    
                    <div class="form-group">
                        <label for="username">사용자명</label>
                        <input type="text" id="username" name="username" 
                               value="<?php echo escape($_POST['username'] ?? ''); ?>" 
                               required autocomplete="username" maxlength="50">
                    </div>
                    
                    <div class="form-group">
                        <label for="password">비밀번호</label>
                        <input type="password" id="password" name="password" 
                               required autocomplete="current-password" maxlength="255">
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn-full">로그인</button>
                    </div>
                </form>
                
                <div class="text-center mt-1">
                    <p>계정이 없으신가요? <a href="register.php" class="text-link">회원가입</a></p>
                </div>
            </div>
        </div>
    </main>
</body>
</html>

<?php
/*
=== Nginx 환경 설정 참고 ===

1. nginx.conf 또는 사이트 설정에서 error_log 설정:
   error_log /var/log/nginx/error.log warn;

2. PHP-FPM 설정에서 error_log 설정:
   php_admin_value[error_log] = /var/log/nginx/php_errors.log

3. 실제 로그 출력 예시:
   2025/06/24 15:30:45 [warn] 12345#0: SQL_INJECTION event_type=SQL_INJECTION_DETECTED risk_level=HIGH client_ip=192.168.1.100 method=POST uri=/login.php script=login.php patterns_count=1 affected_fields=password(1)

4. 로그 모니터링:
   sudo tail -f /var/log/nginx/error.log | grep "SQL_INJECTION\|AUTH_EVENT"
*/
?>