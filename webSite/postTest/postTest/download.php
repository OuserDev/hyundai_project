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
    $stmt = $pdo->prepare("SELECT * FROM post_files WHERE id = ?");
    $stmt->execute([$file_id]);
    $attachment = $stmt->fetch();
    
    if (!$attachment) {
        http_response_code(404);
        die('파일을 찾을 수 없습니다.');
    }
    
    // 실제 파일 경로
    $file_path = __DIR__ . '/' . $attachment['file_path'];
    
    // 파일 존재 확인
    if (!file_exists($file_path)) {
        http_response_code(404);
        die('파일이 서버에 존재하지 않습니다.');
    }
    
    // 다운로드 횟수 증가
    $stmt = $pdo->prepare("UPDATE post_files SET download_count = download_count + 1 WHERE id = ?");
    $stmt->execute([$file_id]);
    
    // 파일 다운로드 헤더 설정
    $file_size = filesize($file_path);
    $original_name = $attachment['original_name'];
    
    // 파일명 인코딩 (한글 파일명 지원)
    $encoded_filename = rawurlencode($original_name);
    if (strlen($encoded_filename) !== strlen($original_name)) {
        // 한글이 포함된 경우
        $encoded_filename = "UTF-8''" . $encoded_filename;
        header("Content-Disposition: attachment; filename*=" . $encoded_filename);
    } else {
        // 영문인 경우
        header("Content-Disposition: attachment; filename=\"" . $original_name . "\"");
    }
    
    header("Content-Type: " . $attachment['mime_type']);
    header("Content-Length: " . $file_size);
    header("Cache-Control: private, must-revalidate");
    header("Pragma: public");
    header("Expires: 0");
    
    // 파일 출력
    if ($file_size > 10 * 1024 * 1024) {
        // 10MB 이상의 큰 파일은 청크 단위로 출력
        $handle = fopen($file_path, 'rb');
        if ($handle) {
            while (!feof($handle)) {
                echo fread($handle, 8192);
                flush();
            }
            fclose($handle);
        }
    } else {
        // 작은 파일은 한 번에 출력
        readfile($file_path);
    }
    
} catch(PDOException $e) {
    http_response_code(500);
    die('서버 오류가 발생했습니다.');
} catch(Exception $e) {
    http_response_code(500);
    die('파일 처리 중 오류가 발생했습니다.');
}
?>