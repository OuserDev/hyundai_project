<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 로그인 확인
requireLogin();
ini_set('display_errors',1);
error_reporting(E_ALL);

$edit_mode = false;
$post_data = ['title' => '', 'content' => ''];
$post_images = [];
$post_files = [];
$errors = [];

// 수정 모드 확인
if (isset($_GET['edit']) && is_numeric($_GET['edit'])) {
    $edit_mode = true;
    $post_id = (int)$_GET['edit'];
    
    try {
        $stmt = $pdo->prepare("SELECT * FROM posts WHERE id = ? AND user_id = ?");
        $stmt->execute([$post_id, $_SESSION['user_id']]);
        $post_data = $stmt->fetch();
        
        if (!$post_data) {
            setErrorMessage('수정할 권한이 없거나 게시글을 찾을 수 없습니다.');
            header("Location: dashboard.php");
            exit();
        }
        $post_images = getPostImages($pdo, $post_id);
        $post_files = getPostFiles($pdo, $post_id);
    } catch(PDOException $e) {
        setErrorMessage('게시글을 불러오는 중 오류가 발생했습니다.');
        header("Location: dashboard.php");
        exit();
    }
}

// 파일 삭제 처리 (AJAX)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] == 'delete_file'){
    $file_type = $_POST['file_type'] ?? '';
    $file_id = (int)($_POST['file_id'] ?? 0);
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    header('Content-Type: application/json');
    
    if (!verifyCSRFToken($csrf_token)) {
        echo json_encode(['success' => false, 'message' => '잘못된 요청입니다.']);
        exit();
    }
    try {
        if ($file_type === 'image') {
            $stmt = $pdo->prepare("
                SELECT pi.*, p.user_id 
                FROM post_images pi 
                JOIN posts p ON pi.post_id = p.id 
                WHERE pi.id = ? AND p.user_id = ?
            ");
            $stmt->execute([$file_id, $_SESSION['user_id']]);
            $file = $stmt->fetch();
            
            if ($file) {
                deleteFile($file['file_path']);
                $stmt = $pdo->prepare("DELETE FROM post_images WHERE id = ?");
                $stmt->execute([$file_id]);
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'message' => '파일을 찾을 수 없습니다.']);
            }
        } elseif ($file_type === 'attachment') {
            $stmt = $pdo->prepare("
                SELECT pa.*, p.user_id 
                FROM post_files pa 
                JOIN posts p ON pa.post_id = p.id 
                WHERE pa.id = ? AND p.user_id = ?
            ");
            $stmt->execute([$file_id, $_SESSION['user_id']]);
            $file = $stmt->fetch();
            
            if ($file) {
                deleteFile($file['file_path']);
                $stmt = $pdo->prepare("DELETE FROM post_files WHERE id = ?");
                $stmt->execute([$file_id]);
                echo json_encode(['success' => true]);
            } else {
                echo json_encode(['success' => false, 'message' => '파일을 찾을 수 없습니다.']);
            }
        }
    } catch(Exception $e) {
        echo json_encode(['success' => false, 'message' => '파일 삭제 중 오류가 발생했습니다.']);
    }
    exit();
}

// 폼 제출 처리
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $title = clean($_POST['title'] ?? '');
    $content = clean($_POST['content'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrf_token)) {
        $errors[] = '잘못된 요청입니다.';
    } else {
        // 입력 검증
        if (empty($title)) {
            $errors[] = '제목을 입력해주세요.';
        } elseif (strlen($title) > 200) {
            $errors[] = '제목은 200자를 초과할 수 없습니다.';
        }
        
        if (empty($content)) {
            $errors[] = '내용을 입력해주세요.';
        }
        // 파일 업로드 처리
        $uploaded_images = [];
        $uploaded_attachments = [];

        // 이미지 업로드
        if (!empty($_FILES['images']['name'][0])) {
            foreach ($_FILES['images']['name'] as $key => $name) {
                if (!empty($name)) {
                    $file = [
                        'name' => $_FILES['images']['name'][$key],
                        'type' => $_FILES['images']['type'][$key],
                        'tmp_name' => $_FILES['images']['tmp_name'][$key],
                        'error' => $_FILES['images']['error'][$key],
                        'size' => $_FILES['images']['size'][$key]
                    ];
                    
                    try {
                        $uploaded_images[] = uploadImage($file);
                    } catch (Exception $e) {
                        $errors[] = '이미지 업로드 오류: ' . $e->getMessage();
                    }
                }
            }
        }
        
        // 첨부파일 업로드
        if (!empty($_FILES['attachments']['name'][0])) {
            foreach ($_FILES['attachments']['name'] as $key => $name) {
                if (!empty($name)) {
                    $file = [
                        'name' => $_FILES['attachments']['name'][$key],
                        'type' => $_FILES['attachments']['type'][$key],
                        'tmp_name' => $_FILES['attachments']['tmp_name'][$key],
                        'error' => $_FILES['attachments']['error'][$key],
                        'size' => $_FILES['attachments']['size'][$key]
                    ];
                    
                    try {
                        $uploaded_attachments[] = uploadFiles($file);
                    } catch (Exception $e) {
                        $errors[] = '첨부파일 업로드 오류: ' . $e->getMessage();
                    }
                }
            }
        }
// 게시글 저장/수정
        if (empty($errors)) {
            try {
                $pdo->beginTransaction();
                
                if ($edit_mode && isset($_POST['post_id'])) {
                    // 수정 모드
                    $post_id = (int)$_POST['post_id'];
                    $stmt = $pdo->prepare("
                        UPDATE posts 
                        SET title = ?, content = ? 
                        WHERE id = ? AND user_id = ?
                    ");
                    $stmt->execute([$title, $content, $post_id, $_SESSION['user_id']]);
                    
                    if ($stmt->rowCount() > 0) {
                        // 새 파일들 저장
                        if (!empty($uploaded_images)) {
                            savePostImages($pdo, $post_id, $uploaded_images);
                        }
                        if (!empty($uploaded_attachments)) {
                            savePostFiles($pdo, $post_id, $uploaded_attachments);
                        }
                        $pdo->commit();
                        setSuccessMessage('게시글이 수정되었습니다.');
                        header("Location: dashboard.php");
                        exit();
                    } else {
                        throw new Exception('수정할 권한이 없거나 게시글을 찾을 수 없습니다.');
                    }
                } else {
                    // 새 글 작성
                    $stmt = $pdo->prepare("
                        INSERT INTO posts (user_id, title, content) 
                        VALUES (?, ?, ?)
                    ");
                    $stmt->execute([$_SESSION['user_id'], $title, $content]);
                    $post_id = $pdo->lastInsertId();
                    
                    // 파일들 저장
                    if (!empty($uploaded_images)) {
                        savePostImages($pdo, $post_id, $uploaded_images);
                    }
                    if (!empty($uploaded_attachments)) {
                        savePostFiles($pdo, $post_id, $uploaded_attachments);
                    }
                    
                    $pdo->commit();
                    setSuccessMessage('게시글이 작성되었습니다.');
                    header("Location: dashboard.php");
                    exit();
                }
            } catch(Exception $e) {
                $pdo->rollback();
                $errors[] = '게시글 저장 중 오류가 발생했습니다: ' . $e->getMessage();
                
                // 업로드된 파일들 삭제
                foreach ($uploaded_images as $image) {
                    deleteFile($image['file_path']);
                }
                foreach ($uploaded_attachments as $attachment) {
                    deleteFile($attachment['file_path']);
                }
            }
        }
    }
    
    // 에러가 있는 경우 입력값 유지
    if (!empty($errors)) {
        $post_data['title'] = $title;
        $post_data['content'] = $content;
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $edit_mode ? '게시글 수정' : '새 글 작성'; ?> - Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .file-upload-area {
            border: 2px dashed #ddd;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 10px 0;
            transition: border-color 0.3s;
        }
        .file-upload-area:hover {
            border-color: #3498db;
        }
        .file-upload-area.dragover {
            border-color: #3498db;
            background-color: #f8f9fa;
        }
        .file-list {
            margin-top: 10px;
        }
        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px;
            border: 1px solid #eee;
            border-radius: 4px;
            margin: 5px 0;
            background: #f9f9f9;
        }
        .file-item img {
            max-width: 60px;
            max-height: 60px;
            border-radius: 4px;
        }
        .file-info {
            flex: 1;
            margin-left: 10px;
        }
        .file-name {
            font-weight: bold;
            color: #333;
        }
        .file-size {
            font-size: 0.9em;
            color: #666;
        }
        .delete-file-btn {
            background: #e74c3c;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.8em;
        }
        .delete-file-btn:hover {
            background: #c0392b;
        }
        .image-preview {
            max-width: 200px;
            max-height: 200px;
            border-radius: 8px;
            margin: 10px;
            border: 1px solid #ddd;
        }
    </style>
</head>
<body>
    <header>
        <div class="container">
            <nav>
                <div class="logo">Simple Blog</div>
                <ul class="nav-links">
                    <li><a href="index.php">홈</a></li>
                    <li><a href="dashboard.php">대시보드</a></li>
                    <li><a href="post.php">글쓰기</a></li>
                    <li><a href="logout.php">로그아웃</a></li>
                </ul>
            </nav>
        </div>
    </header>

    <main>
        <div class="container">
            <div class="form-container">
                <h2><?php echo $edit_mode ? '게시글 수정' : '새 글 작성'; ?></h2>
                
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-error">
                        <?php foreach ($errors as $error): ?>
                            <p><?php echo escape($error); ?></p>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <?php echo displayMessages(); ?>
                
                <form method="POST" action="" enctype="multipart/form-data" id="postForm">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <?php if ($edit_mode): ?>
                        <input type="hidden" name="post_id" value="<?php echo $post_data['id']; ?>">
                    <?php endif; ?>
                    
                    <div class="form-group">
                        <label for="title">제목</label>
                        <input type="text" id="title" name="title" 
                               value="<?php echo escape($post_data['title']); ?>" 
                               required maxlength="200"
                               placeholder="게시글 제목을 입력하세요">
                    </div>
                    
                    <div class="form-group">
                        <label for="content">내용</label>
                        <textarea id="content" name="content" 
                                  required rows="15"
                                  placeholder="게시글 내용을 입력하세요"><?php echo escape($post_data['content']); ?></textarea>
                    </div>
                    
                    <!-- 기존 이미지들 (수정 모드에서만 표시) -->
                    <?php if ($edit_mode && !empty($post_images)): ?>
                        <div class="form-group">
                            <label>기존 이미지</label>
                            <div class="file-list" id="existingImages">
                                <?php foreach ($post_images as $image): ?>
                                    <div class="file-item" data-file-id="<?php echo $image['id']; ?>" data-file-type="image">
                                        <img src="<?php echo escape($image['file_path']); ?>" alt="이미지 미리보기">
                                        <div class="file-info">
                                            <div class="file-name"><?php echo escape($image['original_name']); ?></div>
                                            <div class="file-size"><?php echo formatFileSize($image['file_size']); ?></div>
                                        </div>
                                        <button type="button" class="delete-file-btn" onclick="deleteExistingFile(<?php echo $image['id']; ?>, 'image', this)">삭제</button>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <!-- 새 이미지 업로드 -->
                    <div class="form-group">
                        <label for="images">이미지 첨부 (최대 5MB, JPG/PNG/GIF/WEBP)</label>
                        <div class="file-upload-area" id="imageUploadArea">
                            <p>이미지를 드래그하거나 클릭하여 선택하세요</p>
                            <input type="file" id="images" name="images[]" 
                                   multiple accept="image/*" style="display: none;">
                        </div>
                        <div class="file-list" id="imageList"></div>
                    </div>
                    
                    <!-- 기존 첨부파일들 (수정 모드에서만 표시) -->
                    <?php if ($edit_mode && !empty($post_files)): ?>
                        <div class="form-group">
                            <label>기존 첨부파일</label>
                            <div class="file-list" id="existingAttachments">
                                <?php foreach ($post_files as $attachment): ?>
                                    <div class="file-item" data-file-id="<?php echo $attachment['id']; ?>" data-file-type="attachment">
                                        <div class="file-info">
                                            <div class="file-name"><?php echo escape($attachment['original_name']); ?></div>
                                            <div class="file-size"><?php echo formatFileSize($attachment['file_size']); ?></div>
                                        </div>
                                        <button type="button" class="delete-file-btn" onclick="deleteExistingFile(<?php echo $attachment['id']; ?>, 'attachment', this)">삭제</button>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                        </div>
                    <?php endif; ?>
                    
                    <!-- 새 첨부파일 업로드 -->
                    <div class="form-group">
                        <label for="attachments">첨부파일 (최대 10MB, PDF/DOC/XLS/PPT/ZIP/TXT 등)</label>
                        <div class="file-upload-area" id="attachmentUploadArea">
                            <p>파일을 드래그하거나 클릭하여 선택하세요</p>
                            <input type="file" id="attachments" name="attachments[]" 
                                   multiple accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,.txt,.csv" style="display: none;">
                        </div>
                        <div class="file-list" id="attachmentList"></div>
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn-full">
                            <?php echo $edit_mode ? '수정하기' : '작성하기'; ?>
                        </button>
                    </div>
                </form>
                
                <div class="text-center mt-1">
                    <a href="dashboard.php" class="text-link">← 대시보드로 돌아가기</a>
                </div>
            </div>
        </div>
    </main>

    <script>
        // CSRF 토큰
        const csrfToken = '<?php echo generateCSRFToken(); ?>';
        
        // 파일 업로드 관련 함수들
        function setupFileUpload(uploadAreaId, inputId, listId, fileType) {
            const uploadArea = document.getElementById(uploadAreaId);
            const fileInput = document.getElementById(inputId);
            const fileList = document.getElementById(listId);
            
            // 클릭으로 파일 선택
            uploadArea.addEventListener('click', () => fileInput.click());
            
            // 드래그 앤 드롭
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.classList.add('dragover');
            });
            
            uploadArea.addEventListener('dragleave', () => {
                uploadArea.classList.remove('dragover');
            });
            
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.classList.remove('dragover');
                
                const files = e.dataTransfer.files;
                handleFiles(files, fileInput, listId, fileType);
            });
            
            // 파일 선택 시
            fileInput.addEventListener('change', (e) => {
                handleFiles(e.target.files, fileInput, listId, fileType);
            });
        }
        
        function handleFiles(files, fileInput, listId, fileType) {
            const fileList = document.getElementById(listId);
            
            Array.from(files).forEach((file, index) => {
                const fileItem = createFileItem(file, fileType);
                fileList.appendChild(fileItem);
            });
        }
        
        function createFileItem(file, fileType) {
            const item = document.createElement('div');
            item.className = 'file-item';
            
            let preview = '';
            if (fileType === 'image' && file.type.startsWith('image/')) {
                preview = `<img src="${URL.createObjectURL(file)}" class="image-preview" alt="미리보기">`;
            }
            
            item.innerHTML = `
                ${preview}
                <div class="file-info">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                </div>
                <button type="button" class="delete-file-btn" onclick="removeFileItem(this)">제거</button>
            `;
            
            return item;
        }
        
        function removeFileItem(button) {
            button.closest('.file-item').remove();
        }
        
        function formatFileSize(bytes) {
            if (bytes >= 1073741824) {
                return (bytes / 1073741824).toFixed(2) + ' GB';
            } else if (bytes >= 1048576) {
                return (bytes / 1048576).toFixed(2) + ' MB';
            } else if (bytes >= 1024) {
                return (bytes / 1024).toFixed(2) + ' KB';
            } else {
                return bytes + ' bytes';
            }
        }
        
        // 기존 파일 삭제
        function deleteExistingFile(fileId, fileType, button) {
            if (!confirm('정말 삭제하시겠습니까?')) {
                return;
            }
            
            const formData = new FormData();
            formData.append('action', 'delete_file');
            formData.append('file_type', fileType);
            formData.append('file_id', fileId);
            formData.append('csrf_token', csrfToken);
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    button.closest('.file-item').remove();
                } else {
                    alert('파일 삭제 중 오류가 발생했습니다: ' + (data.message || ''));
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('파일 삭제 중 오류가 발생했습니다.');
            });
        }
        
        // 초기화
        document.addEventListener('DOMContentLoaded', function() {
            setupFileUpload('imageUploadArea', 'images', 'imageList', 'image');
            setupFileUpload('attachmentUploadArea', 'attachments', 'attachmentList', 'attachment');
            
            // 작성 중인 내용 임시 저장 (새로고침 방지)
            window.addEventListener('beforeunload', function(e) {
                const title = document.getElementById('title').value;
                const content = document.getElementById('content').value;
                
                if (title.trim() || content.trim()) {
                    e.preventDefault();
                    e.returnValue = '';
                }
            });
            
            // 실시간 글자수 카운터
            const titleInput = document.getElementById('title');
            const titleCounter = document.createElement('small');
            titleCounter.style.color = '#666';
            titleCounter.style.float = 'right';
            titleInput.parentNode.appendChild(titleCounter);
            
            function updateTitleCounter() {
                const length = titleInput.value.length;
                titleCounter.textContent = `${length}/200`;
                if (length > 180) {
                    titleCounter.style.color = '#e74c3c';
                } else {
                    titleCounter.style.color = '#666';
                }
            }
            
            titleInput.addEventListener('input', updateTitleCounter);
            updateTitleCounter();
        });
    </script>
</body>
</html>