<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

$injection_patterns = [
    // Union 기반 공격
    '/\bunion\b.*\bselect\b/i',
    '/\bunion\b.*\ball\b.*\bselect\b/i',
    
    // Boolean 기반 공격
    '/\'.*or.*\'.*=.*\'/i',
    '/\".*or.*\".*=.*\"/i',
    '/\bor\b.*1\s*=\s*1/i',
    '/\band\b.*1\s*=\s*1/i',
    
    // Time 기반 공격
    '/\bsleep\s*\(/i',
    '/\bwaitfor\b.*\bdelay\b/i',
    '/\bbenchmark\s*\(/i',
    
    // Information Schema 공격
    '/\binformation_schema\b/i',
    '/\bsys\.databases\b/i',
    
    // 주석 기반 우회
    '/\/\*.*\*\//i',
    '/--.*$/m',
    '/\#.*$/m',
    
    // 특수 문자 조합
    '/\'.*;\s*drop\b/i',
    '/\'.*;\s*delete\b/i',
    '/\'.*;\s*update\b/i',
    '/\'.*;\s*insert\b/i',
    
    // 함수 기반 공격
    '/\bload_file\s*\(/i',
    '/\binto\s+outfile\b/i',
    '/\bchar\s*\(/i',
    '/\bconcat\s*\(/i',
    '/\bsubstring\s*\(/i',
    
    // Blind SQL Injection
    '/\bascii\s*\(\s*substring\s*\(/i',
    '/\blength\s*\(/i',
];


function detectAndLogSQLInjection($input_data, $script_name = '') {
    global $injection_patterns;
    
    $client_ip = getNginxRealIP();
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
        logSQLInjectionAttempt($risk_level, $detected_patterns, $script_name);
        
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

function logSQLInjectionAttempt($risk_level, $patterns, $script_name = '') {
    $client_ip = getNginxRealIP();
    $user_agent = sanitizeForLog($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown');
    $request_uri = sanitizeForLog($_SERVER['REQUEST_URI'] ?? '');
    $request_method = $_SERVER['REQUEST_METHOD'] ?? '';
    
    // 탐지된 패턴 요약
    $pattern_summary = [];
    foreach ($patterns as $field => $field_patterns) {
        $pattern_summary[] = $field . '(' . count($field_patterns) . ')';
    }
    
    // Error Log 형식으로 메시지 생성
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
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
    
    error_log($log_message);
}
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
function logAuthAttempt($event_type, $username = '', $success = false, $additional_data = []) {
    $client_ip = getNginxRealIP(); // 프로젝트 기존 함수 사용
    
    // 기본 로그 데이터 구성
    $log_data = [
        'timestamp' => date('Y-m-d H:i:s'),
        'event_type' => $event_type,
        'username_hash' => hash('sha256', $username),
        'result' => $success ? 'SUCCESS' : 'FAILED',
        'client_ip' => $client_ip,
        'session_id' => substr(hash('sha256', session_id()), 0, 12),
        'server_name' => $_SERVER['SERVER_NAME'] ?? 'localhost',
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
        'user_agent_hash' => substr(hash('sha256', $_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 16)
    ];
    
    // 추가 데이터 포함 (간단한 검증)
    foreach ($additional_data as $key => $value) {
        // 안전한 키인지 간단 체크
        if (is_scalar($value) && is_string($key) && strlen($key) < 20 && ctype_alnum(str_replace('_', '', $key))) {
            $safe_key = preg_replace('/[^a-zA-Z0-9_]/', '', $key);
            $log_data[$safe_key] = sanitizeForLog((string)$value);
        }
    }
    
    // 로그 메시지 구성
    $message_parts = [];
    foreach ($log_data as $key => $value) {
        $message_parts[] = "{$key}={$value}";
    }
    
    $log_message = "AUTH_EVENT " . implode(' ', $message_parts);
    
    // 로그 기록 (프로젝트 기존 방식)
    error_log($log_message);
}


function setNginxSecurityHeaders() {
    if (!headers_sent()) {
        header('X-Frame-Options: DENY');
        header('X-Content-Type-Options: nosniff');
        header('X-XSS-Protection: 1; mode=block');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        
        // HTTPS인 경우 추가 보안 헤더
        if (isSecureConnection()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
    }
}

/**
 * HTTPS 연결 확인 (Nginx Reverse Proxy 대응)
 */
function isSecureConnection() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        || (!empty($_SERVER['HTTP_X_FORWARDED_SSL']) && $_SERVER['HTTP_X_FORWARDED_SSL'] === 'on')
        || (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
}

setNginxSecurityHeaders();
// 이미 로그인된 경우 대시보드로 리다이렉트
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // ������ SQL Injection 탐지 (POST 데이터 전체 검사)
    $sqli_result = detectAndLogSQLInjection($_POST, 'login.php');
    
    // 공격이 탐지된 경우 추가 처리
    if ($sqli_result['detected']) {
        if ($sqli_result['risk_level'] === 'CRITICAL' || $sqli_result['risk_level'] === 'HIGH') {
            // 높은 위험도일 경우 즉시 종료
            http_response_code(403);
            exit('Security violation detected');
        }
        // 중간 위험도일 경우 경고 로그만 남기고 계속 진행
    }
    
    $username = clean($_POST['username'] ?? '');
    $password = clean($_POST['password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrf_token)) {
        $error = '잘못된 요청입니다.';
        // 인증 실패 로깅
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
                $error = '잘못된 사용자명 또는 비밀번호입니다.';

                logAuthAttempt('LOGIN_FAILED', $username, false, [
                    'user_exists' => $user !== false,
                    'pass_length' => strlen($password)
                ]);
            }
        } catch (PDOException $e) {
            $error = '로그인 처리 중 오류가 발생했습니다.';
            logAuthAttempt('SYSTEM_ERROR', $username, false, [
                'error_type' => 'PDOException'
            ]);

            error_log("Database error in login.php: " . $e->getMessage());
        }
    }
}// CSRF 토큰 생성
generateCSRFToken();

?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그인 - Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
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
                               required autocomplete="username">
                    </div>
                    
                    <div class="form-group">
                        <label for="password">비밀번호</label>
                        <input type="password" id="password" name="password" 
                               required autocomplete="current-password">
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