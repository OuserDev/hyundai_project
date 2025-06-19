<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 최근 게시글 가져오기
try {
    $stmt = $pdo->prepare("
        SELECT p.*, u.username 
        FROM posts p 
        JOIN users u ON p.user_id = u.id 
        ORDER BY p.created_at DESC 
        LIMIT 10
    ");
    $stmt->execute();
    $posts = $stmt->fetchAll();
} catch(PDOException $e) {
    $posts = [];
    setErrorMessage("게시글을 불러오는 중 오류가 발생했습니다.");
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .post-images {
            margin: 15px 0;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .post-image {
            max-width: 200px;
            max-height: 150px;
            border-radius: 8px;
            border: 1px solid #ddd;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .post-image:hover {
            transform: scale(1.05);
        }
        .post-attachments {
            margin: 15px 0;
        }
        .attachment-item {
            display: inline-flex;
            align-items: center;
            background: #f8f9fa;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 8px 12px;
            margin: 5px 5px 5px 0;
            text-decoration: none;
            color: #333;
            font-size: 0.9em;
            transition: background-color 0.2s;
        }
        .attachment-item:hover {
            background: #e9ecef;
            text-decoration: none;
        }
        .attachment-icon {
            margin-right: 8px;
            font-size: 1.1em;
        }
        .attachment-size {
            margin-left: 8px;
            color: #666;
            font-size: 0.8em;
        }
        .image-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.8);
            cursor: pointer;
        }
        .modal-content {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            max-width: 90%;
            max-height: 90%;
        }
        .modal-content img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }
        .close-modal {
            position: absolute;
            top: 15px;
            right: 35px;
            color: white;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
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
                    <?php if (isLoggedIn()): ?>
                        <li><a href="dashboard.php">대시보드</a></li>
                        <li><a href="post.php">글쓰기</a></li>
                        <li><a href="logout.php">로그아웃</a></li>
                    <?php else: ?>
                        <li><a href="login.php">로그인</a></li>
                        <li><a href="register.php">회원가입</a></li>
                    <?php endif; ?>
                </ul>
            </nav>
        </div>
    </header>

    <main>
        <div class="container">
            <?php echo displayMessages(); ?>
            
            <div class="dashboard-header">
                <h1>최근 게시글</h1>
                <?php if (isLoggedIn()): ?>
                    <a href="post.php" class="text-link">새 글 작성</a>
                <?php endif; ?>
            </div>

            <div class="posts-container">
                <?php if (empty($posts)): ?>
                    <div class="post-item text-center">
                        <p>아직 게시글이 없습니다.</p>
                        <?php if (isLoggedIn()): ?>
                            <p><a href="post.php" class="text-link">첫 번째 글을 작성해보세요!</a></p>
                        <?php else: ?>
                            <p><a href="register.php" class="text-link">회원가입</a> 후 글을 작성해보세요!</p>
                        <?php endif; ?>
                    </div>
                <?php else: ?>
                    <?php foreach ($posts as $post): ?>
                        <?php
                        // 게시글의 이미지와 첨부파일 가져오기
                        $post_images = getPostImages($pdo, $post['id']);
                        $post_files = getPostFiles($pdo, $post['id']);
                        ?>
                        <div class="post-item">
                            <h3 class="post-title">
                                <a href="?post_id=<?php echo $post['id']; ?>">
                                    <?php echo escape($post['title']); ?>
                                </a>
                            </h3>
                            <div class="post-meta">
                                작성자: <?php echo escape($post['username']); ?> | 
                                작성일: <?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?>
                            </div>
                            
                            <!-- 이미지 미리보기 -->
                            <?php if (!empty($post_images)): ?>
                                <div class="post-images">
                                    <?php foreach (array_slice($post_images, 0, 3) as $image): ?>
                                        <img src="<?php echo escape($image['file_path']); ?>" 
                                             alt="게시글 이미지" 
                                             class="post-image"
                                             onclick="openImageModal('<?php echo escape($image['file_path']); ?>')">
                                    <?php endforeach; ?>
                                    <?php if (count($post_images) > 3): ?>
                                        <div style="align-self: center; color: #666; font-size: 0.9em;">
                                            +<?php echo count($post_images) - 3; ?>개 더보기
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                            
                            <div class="post-content">
                                <?php 
                                $content = escape($post['content']);
                                echo strlen($content) > 200 ? substr($content, 0, 200) . '...' : $content;
                                ?>
                            </div>
                            
                            <!-- 첨부파일 표시 -->
                            <?php if (!empty($post_files)): ?>
                                <div class="post-attachments">
                                    <strong>첨부파일:</strong>
                                    <?php foreach ($post_files as $attachment): ?>
                                        <a href="download.php?id=<?php echo $attachment['id']; ?>" 
                                           class="attachment-item"
                                           target="_blank">
                                            <span class="attachment-icon">📎</span>
                                            <?php echo escape($attachment['original_name']); ?>
                                            <span class="attachment-size">(<?php echo formatFileSize($attachment['file_size']); ?>)</span>
                                        </a>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>

            <?php 
            // 개별 게시글 보기
            if (isset($_GET['post_id']) && is_numeric($_GET['post_id'])):
                try {
                    $stmt = $pdo->prepare("
                        SELECT p.*, u.username 
                        FROM posts p 
                        JOIN users u ON p.user_id = u.id 
                        WHERE p.id = ?
                    ");
                    $stmt->execute([$_GET['post_id']]);
                    $post = $stmt->fetch();
                    
                    if ($post):
                        $post_images = getPostImages($pdo, $post['id']);
                        $post_files = getPostFiles($pdo, $post['id']);
            ?>
                <div class="form-container mt-2">
                    <h2><?php echo escape($post['title']); ?></h2>
                    <div class="post-meta mb-1">
                        작성자: <?php echo escape($post['username']); ?> | 
                        작성일: <?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?>
                    </div>
                    
                    <!-- 게시글 이미지들 -->
                    <?php if (!empty($post_images)): ?>
                        <div class="post-images">
                            <?php foreach ($post_images as $image): ?>
                                <img src="<?php echo escape($image['file_path']); ?>" 
                                     alt="게시글 이미지" 
                                     class="post-image"
                                     onclick="openImageModal('<?php echo escape($image['file_path']); ?>')">
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <div class="post-content">
                        <?php echo nl2br(escape($post['content'])); ?>
                    </div>
                    
                    <!-- 첨부파일들 -->
                    <?php if (!empty($post_files)): ?>
                        <div class="post-attachments mt-2">
                            <h4>첨부파일</h4>
                            <?php foreach ($post_files as $attachment): ?>
                                <a href="download.php?id=<?php echo $attachment['id']; ?>" 
                                   class="attachment-item"
                                   target="_blank">
                                    <span class="attachment-icon">📎</span>
                                    <?php echo escape($attachment['original_name']); ?>
                                    <span class="attachment-size">(<?php echo formatFileSize($attachment['file_size']); ?>)</span>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                    
                    <div class="mt-2 text-center">
                        <a href="index.php" class="text-link">← 목록으로 돌아가기</a>
                    </div>
                </div>
            <?php 
                    else:
                        setErrorMessage("게시글을 찾을 수 없습니다.");
                    endif;
                } catch(PDOException $e) {
                    setErrorMessage("게시글을 불러오는 중 오류가 발생했습니다.");
                }
            endif;
            ?>
        </div>
    </main>

    <!-- 이미지 모달 -->
    <div id="imageModal" class="image-modal" onclick="closeImageModal()">
        <span class="close-modal">&times;</span>
        <div class="modal-content">
            <img id="modalImage" src="" alt="확대 이미지">
        </div>
    </div>

    <script>
        function openImageModal(imageSrc) {
            const modal = document.getElementById('imageModal');
            const modalImg = document.getElementById('modalImage');
            modal.style.display = 'block';
            modalImg.src = imageSrc;
        }
        
        function closeImageModal() {
            document.getElementById('imageModal').style.display = 'none';
        }
        
        // ESC 키로 모달 닫기
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape') {
                closeImageModal();
            }
        });
    </script>
</body>
</html>