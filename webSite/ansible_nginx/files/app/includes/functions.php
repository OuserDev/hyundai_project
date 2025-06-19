<?php
require_once 'define.php';

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function requireLogin() {
    if (!isLoggedIn()) {
        header("Location: login.php");
        exit();
    }
}

function escape($string) {
    return htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
}

function clean($string) {
    return trim(stripslashes($string));
}

function hashPassword($password) {
    return password_hash($password, PASSWORD_DEFAULT);
}

function verifyPassword($password, $hash) {
    return password_verify($password, $hash);
}

function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verifyCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function setSuccessMessage($message) {
    $_SESSION['success_message'] = $message;
}

function setErrorMessage($message) {
    $_SESSION['error_message'] = $message;
}

function displayMessages() {
    $output = '';
    
    if (isset($_SESSION['success_message'])) {
        $output .= '<div class="alert alert-success">' . escape($_SESSION['success_message']) . '</div>';
        unset($_SESSION['success_message']);
    }
    
    if (isset($_SESSION['error_message'])) {
        $output .= '<div class="alert alert-error">' . escape($_SESSION['error_message']) . '</div>';
        unset($_SESSION['error_message']);
    }
    
    return $output;
}

function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePassword($password) {
    return strlen($password) >= 6;
}

function validateUsername($username) {
    return preg_match('/^[a-zA-Z0-9_]{3,20}$/', $username);
}

/////////////////////File Upload Funcs/////////////////////
function ensureUploadDirectories(){
    $directories = [UPLOAD_PATH, IMAGES_PATH, FILES_PATH];
    
    foreach ($directories as $dir) {
        error_log("dir value : $dir");
        if(!is_dir($dir)){
            if(!mkdir($dir, 0755, true)){
                throw new Exception("can not create upload directory");
            }
        }

        // Nginx용 index.html 파일 생성 (디렉토리 리스팅 방지)
        $index_file = $dir . 'index.html';
        if(!file_exists($index_file)){
            file_put_contents($index_file, "<!DOCTYPE html><html><head><title>403 Forbidden</title></head><body><h1>Directory access is forbidden.</h1></body></html>");
        }
    }
}

function generateSafeFilename($original_name){
    $extension = strtolower(pathinfo($original_name, PATHINFO_EXTENSION));
    $filename = uniqid() . '_' . time() . "." . $extension;
    return $filename;
}

function validateFileType($file, $type = 'image'){
    // 전역 변수 사용
    global $allowed_image_types, $allowed_attachment_types;

    $allowed_types = ($type === 'image') ? $allowed_image_types : $allowed_attachment_types;
    
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    if (!in_array($mime_type, $allowed_types)) {
        return false;
    }
    
    // 확장자 검증
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $allowed_extensions = [];
    
    if ($type === 'image') {
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    } else {
        $allowed_extensions = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'txt', 'csv'];
    }
    
    return in_array($extension, $allowed_extensions);
}

function uploadImage($file) {
    ensureUploadDirectories();
    
    // 기본 검증
    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new Exception('파일 업로드 중 오류가 발생했습니다.');
    }
    
    if ($file['size'] > MAX_IMAGE_SIZE) {
        throw new Exception('이미지 파일 크기는 5MB를 초과할 수 없습니다.');
    }
    
    if (!validateFileType($file, 'image')) {
        throw new Exception('지원하지 않는 이미지 형식입니다. (JPG, PNG, GIF, WEBP만 허용)');
    }
    
    // 파일명 생성 및 저장
    $stored_name = generateSafeFilename($file['name']);
    $file_path = IMAGES_PATH . $stored_name;
    
    if (!move_uploaded_file($file['tmp_name'], $file_path)) {
        throw new Exception('이미지 저장 중 오류가 발생했습니다.');
    }
    
    // 이미지 리사이즈 (선택사항)
    resizeImage($file_path, 1200, 800);
    
    return [
        'original_name' => $file['name'],
        'stored_name' => $stored_name,
        'file_path' => 'uploads/images/' . $stored_name,
        'file_size' => filesize($file_path),
        'mime_type' => mime_content_type($file_path)
    ];
} 

function uploadFiles($file) {
    debugFileUpload($file);
    
    try {
        ensureUploadDirectories();
    } catch (Exception $e) {
        error_log("Directory creation error: " . $e->getMessage());
        throw new Exception('업로드 디렉토리 생성 실패: ' . $e->getMessage());
    }
    
    // 기본 검증
    if ($file['error'] !== UPLOAD_ERR_OK) {
        $error_messages = [
            UPLOAD_ERR_INI_SIZE => 'PHP 설정(upload_max_filesize)에서 허용하는 크기를 초과했습니다.',
            UPLOAD_ERR_FORM_SIZE => 'HTML 폼에서 지정한 MAX_FILE_SIZE를 초과했습니다.',
            UPLOAD_ERR_PARTIAL => '파일이 부분적으로만 업로드되었습니다.',
            UPLOAD_ERR_NO_FILE => '파일이 업로드되지 않았습니다.',
            UPLOAD_ERR_NO_TMP_DIR => '임시 디렉토리가 없습니다.',
            UPLOAD_ERR_CANT_WRITE => '디스크에 쓸 수 없습니다.',
            UPLOAD_ERR_EXTENSION => 'PHP 확장에 의해 업로드가 중단되었습니다.'
        ];
        
        $error_msg = $error_messages[$file['error']] ?? '알 수 없는 업로드 오류가 발생했습니다.';
        error_log("Upload error detail: " . $error_msg);
        throw new Exception($error_msg);
    }
    
    // 수정: MAX_UPLOADFILE_SIZE 사용
    if ($file['size'] > MAX_UPLOADFILE_SIZE) {
        throw new Exception('첨부파일 크기는 ' . formatFileSize(MAX_UPLOADFILE_SIZE) . '를 초과할 수 없습니다.');
    }
    
    if (!validateFileType($file, 'attachment')) {
        throw new Exception('지원하지 않는 파일 형식입니다.');
    }
    
    // 파일명 생성 및 저장
    $stored_name = generateSafeFilename($file['name']);
    $file_path = FILES_PATH . $stored_name;
    
    if (!move_uploaded_file($file['tmp_name'], $file_path)) {
        throw new Exception('파일 저장 중 오류가 발생했습니다.');
    }
    
    return [
        'original_name' => $file['name'],
        'stored_name' => $stored_name,
        'file_path' => 'uploads/files/' . $stored_name, // 수정: attachments -> files
        'file_size' => filesize($file_path),
        'mime_type' => mime_content_type($file_path)
    ];
}

function resizeImage($file_path, $max_width = 1200, $max_height = 800) {
    $image_info = getimagesize($file_path);
    if (!$image_info) return false;
    
    $width = $image_info[0];
    $height = $image_info[1];
    $type = $image_info[2];
    
    // 리사이즈가 필요한지 확인
    if ($width <= $max_width && $height <= $max_height) {
        return true;
    }
    
    // 비율 계산
    $ratio = min($max_width / $width, $max_height / $height);
    $new_width = intval($width * $ratio);
    $new_height = intval($height * $ratio);
    
    // 원본 이미지 로드
    switch ($type) {
        case IMAGETYPE_JPEG:
            $source = imagecreatefromjpeg($file_path);
            break;
        case IMAGETYPE_PNG:
            $source = imagecreatefrompng($file_path);
            break;
        case IMAGETYPE_GIF:
            $source = imagecreatefromgif($file_path);
            break;
        default:
            return false;
    }
    
    if (!$source) return false;
    
    // 새 이미지 생성
    $new_image = imagecreatetruecolor($new_width, $new_height);
    
    // PNG 투명도 보존
    if ($type == IMAGETYPE_PNG) {
        imagealphablending($new_image, false);
        imagesavealpha($new_image, true);
        $transparent = imagecolorallocatealpha($new_image, 255, 255, 255, 127);
        imagefilledrectangle($new_image, 0, 0, $new_width, $new_height, $transparent);
    }
    
    // 리사이즈
    imagecopyresampled($new_image, $source, 0, 0, 0, 0, $new_width, $new_height, $width, $height);
    
    // 저장
    switch ($type) {
        case IMAGETYPE_JPEG:
            imagejpeg($new_image, $file_path, 85);
            break;
        case IMAGETYPE_PNG:
            imagepng($new_image, $file_path, 6);
            break;
        case IMAGETYPE_GIF:
            imagegif($new_image, $file_path);
            break;
    }
    
    imagedestroy($source);
    imagedestroy($new_image);
    
    return true;
}

function savePostImages($pdo, $post_id, $images) {
    foreach ($images as $image) {
        $stmt = $pdo->prepare("
            INSERT INTO images (post_id, filename, original_name, file_path, file_size, mime_type) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $post_id,
            $image['stored_name'],
            $image['original_name'],
            $image['file_path'],
            $image['file_size'],
            $image['mime_type']
        ]);
    }
}

function savePostFiles($pdo, $post_id, $attachments) {
    foreach ($attachments as $attachment) {
        $stmt = $pdo->prepare("
            INSERT INTO files (post_id, original_name, file_path, file_size, mime_type) 
            VALUES (?, ?, ?, ?, ?)
        ");
        $stmt->execute([
            $post_id,
            $attachment['original_name'],
            $attachment['file_path'],
            $attachment['file_size'],
            $attachment['mime_type']
        ]);
    }
}

function getPostImages($pdo, $post_id) {
    $stmt = $pdo->prepare("SELECT * FROM images WHERE post_id = ? ORDER BY id");
    $stmt->execute([$post_id]);
    return $stmt->fetchAll();
}

function getPostFiles($pdo, $post_id) {
    $stmt = $pdo->prepare("SELECT * FROM files WHERE post_id = ? ORDER BY id");
    $stmt->execute([$post_id]);
    return $stmt->fetchAll();
}

function formatFileSize($bytes) {
    if ($bytes >= 1073741824) {
        return number_format($bytes / 1073741824, 2) . ' GB';
    } elseif ($bytes >= 1048576) {
        return number_format($bytes / 1048576, 2) . ' MB';
    } elseif ($bytes >= 1024) {
        return number_format($bytes / 1024, 2) . ' KB';
    } else {
        return $bytes . ' bytes';
    }
}

function deleteFile($file_path) {
    $full_path = __DIR__ . '/../' . $file_path;
    if (file_exists($full_path)) {
        return unlink($full_path);
    }
    return true;
}

function deletePostFiles($pdo, $post_id) {
    // 이미지 삭제
    $stmt = $pdo->prepare("SELECT file_path FROM images WHERE post_id = ?");
    $stmt->execute([$post_id]);
    while ($row = $stmt->fetch()) {
        deleteFile($row['file_path']);
    }
    
    // 첨부파일 삭제
    $stmt = $pdo->prepare("SELECT file_path FROM files WHERE post_id = ?");
    $stmt->execute([$post_id]);
    while ($row = $stmt->fetch()) {
        deleteFile($row['file_path']);
    }
}

function debugFileUpload($file) {
    error_log("=== File Upload Debug ===");
    error_log("File name: " . ($file['name'] ?? 'NULL'));
    error_log("File size: " . ($file['size'] ?? 'NULL'));
    error_log("File type: " . ($file['type'] ?? 'NULL'));
    error_log("File error: " . ($file['error'] ?? 'NULL'));
    error_log("File tmp_name: " . ($file['tmp_name'] ?? 'NULL'));
    
    // 업로드 오류 코드 해석
    $upload_errors = [
        UPLOAD_ERR_OK => 'No error',
        UPLOAD_ERR_INI_SIZE => 'File too large (upload_max_filesize)',
        UPLOAD_ERR_FORM_SIZE => 'File too large (MAX_FILE_SIZE)',
        UPLOAD_ERR_PARTIAL => 'File partially uploaded',
        UPLOAD_ERR_NO_FILE => 'No file uploaded',
        UPLOAD_ERR_NO_TMP_DIR => 'No temporary directory',
        UPLOAD_ERR_CANT_WRITE => 'Cannot write to disk',
        UPLOAD_ERR_EXTENSION => 'Upload stopped by extension'
    ];
    
    $error_code = $file['error'] ?? -1;
    error_log("Upload error meaning: " . ($upload_errors[$error_code] ?? 'Unknown error'));
    
    // 디렉토리 상태 확인
    error_log("UPLOAD_PATH exists: " . (is_dir(UPLOAD_PATH) ? 'YES' : 'NO'));
    error_log("FILES_PATH exists: " . (is_dir(FILES_PATH) ? 'YES' : 'NO'));
    error_log("FILES_PATH writable: " . (is_writable(FILES_PATH) ? 'YES' : 'NO'));
    
    return true;
}

// Nginx용 추가 보안 함수들
function getNginxRealIP() {
    $headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CLIENT_IP',
        'REMOTE_ADDR'
    ];
    
    foreach ($headers as $header) {
        if (!empty($_SERVER[$header])) {
            $ips = explode(',', $_SERVER[$header]);
            return trim($ips[0]);
        }
    }
    
    return $_SERVER['REMOTE_ADDR'] ?? '';
}

function isSecureConnection() {
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
        || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https')
        || (!empty($_SERVER['SERVER_PORT']) && $_SERVER['SERVER_PORT'] == 443);
}

function setSecurityHeaders() {
    // CSRF 방지
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

// 세션 시작 시 보안 헤더 설정
if (session_status() == PHP_SESSION_NONE) {
    setSecurityHeaders();
}

?>