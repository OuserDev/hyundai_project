<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 파일 ID 확인
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    http_response_code(404);
    die('파일을 찾을 수 없습니다.');
}

$file_id = (int)$_GET['id'];

try {
    // 첨부파일 정보 가져오기
    $stmt = $pdo->prepare("SELECT * FROM files WHERE id = ?");
    $stmt->execute([$file_id]);
    $attachment = $stmt->fetch();
    
    if (!$attachment) {
        http_response_code(404);
        die('파일을 찾을 수 없습니다.');
    }
    
    // 실제 파일 경로 (Nginx용 조정)
    $file_path = __DIR__ . '/' . $attachment['file_path'];
    
    // 파일 존재 확인
    if (!file_exists($file_path)) {
        http_response_code(404);
        die('파일이 서버에 존재하지 않습니다.');
    }
    
    // 다운로드 횟수 증가 (테이블에 download_count 컬럼이 있는 경우)
    try {
        $stmt = $pdo->prepare("UPDATE files SET download_count = COALESCE(download_count, 0) + 1 WHERE id = ?");
        $stmt->execute([$file_id]);
    } catch(PDOException $e) {
        // download_count 컬럼이 없으면 무시
        error_log("Download count update failed: " . $e->getMessage());
    }
    
    // 파일 다운로드 헤더 설정
    $file_size = filesize($file_path);
    $original_name = $attachment['original_name'];
    
    // 브라우저별 파일명 인코딩 처리
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    
    if (preg_match('/MSIE|Edge|Trident/', $user_agent)) {
        // Internet Explorer / Edge
        $encoded_filename = urlencode($original_name);
        header("Content-Disposition: attachment; filename=\"{$encoded_filename}\"");
    } else {
        // Chrome, Firefox, Safari 등
        $encoded_filename = rawurlencode($original_name);
        if (strlen($encoded_filename) !== strlen($original_name)) {
            // 한글이 포함된 경우
            header("Content-Disposition: attachment; filename*=UTF-8''{$encoded_filename}");
        } else {
            // 영문인 경우
            header("Content-Disposition: attachment; filename=\"{$original_name}\"");
        }
    }
    
    // 기본 헤더 설정
    header("Content-Type: " . $attachment['mime_type']);
    header("Content-Length: " . $file_size);
    header("Cache-Control: private, must-revalidate");
    header("Pragma: public");
    header("Expires: 0");
    
    // Nginx X-Accel-Redirect 사용 (성능 향상)
    if (function_exists('apache_get_modules') === false) {
        // Nginx 환경에서는 X-Accel-Redirect 사용
        $nginx_path = str_replace(__DIR__ . '/', '/internal/', $file_path);
        header("X-Accel-Redirect: " . $nginx_path);
        header("X-Accel-Buffering: yes");
        header("X-Accel-Charset: utf-8");
    } else {
        // Apache 환경에서는 직접 파일 출력
        outputFile($file_path, $file_size);
    }
    
} catch(PDOException $e) {
    error_log("Database error in download.php: " . $e->getMessage());
    http_response_code(500);
    die('서버 오류가 발생했습니다.');
} catch(Exception $e) {
    error_log("General error in download.php: " . $e->getMessage());
    http_response_code(500);
    die('파일 처리 중 오류가 발생했습니다.');
}

function outputFile($file_path, $file_size) {
    // 출력 버퍼 정리
    if (ob_get_level()) {
        ob_end_clean();
    }
    
    // 큰 파일의 경우 청크 단위로 출력 (메모리 절약)
    if ($file_size > 10 * 1024 * 1024) { // 10MB 이상
        $handle = fopen($file_path, 'rb');
        if ($handle) {
            $chunk_size = 8192; // 8KB 청크
            while (!feof($handle)) {
                $chunk = fread($handle, $chunk_size);
                echo $chunk;
                flush();
                
                // 연결이 끊어진 경우 중단
                if (connection_aborted()) {
                    break;
                }
            }
            fclose($handle);
        }
    } else {
        // 작은 파일은 한 번에 출력
        readfile($file_path);
    }
}
?>