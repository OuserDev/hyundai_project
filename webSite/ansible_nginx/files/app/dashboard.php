<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 로그인 확인
requireLogin();

// 사용자 통계 가져오기
try {
    // 내가 작성한 게시글 수
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM posts WHERE user_id = ?");
    $stmt->execute([$_SESSION['user_id']]);
    $my_posts_count = $stmt->fetchColumn();
    
    // 전체 게시글 수
    $stmt = $pdo->query("SELECT COUNT(*) FROM posts");
    $total_posts_count = $stmt->fetchColumn();
    
    // 전체 사용자 수
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    $total_users_count = $stmt->fetchColumn();
    
    // 내 최근 게시글들
    $stmt = $pdo->prepare("
        SELECT id, title, content, created_at 
        FROM posts 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 5
    ");
    $stmt->execute([$_SESSION['user_id']]);
    $my_recent_posts = $stmt->fetchAll();
    
} catch(PDOException $e) {
    $my_posts_count = 0;
    $total_posts_count = 0;
    $total_users_count = 0;
    $my_recent_posts = [];
    setErrorMessage("데이터를 불러오는 중 오류가 발생했습니다.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_post'])) {
    $post_id = (int)$_POST['post_id'];
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    if (!verifyCSRFToken($csrf_token)) {
        setErrorMessage('잘못된 요청입니다.');
    } else {
        try {
            // 본인의 게시글인지 확인
            $stmt = $pdo->prepare("SELECT id FROM posts WHERE id = ? AND user_id = ?");
            $stmt->execute([$post_id, $_SESSION['user_id']]);
            
            if ($stmt->fetch()) {
                $pdo->beginTransaction();
                
                // 게시글 관련 파일들 삭제
                deletePostFiles($pdo, $post_id);
                
                // 게시글 삭제 (CASCADE로 관련 파일 레코드도 자동 삭제됨)
                $stmt = $pdo->prepare("DELETE FROM posts WHERE id = ? AND user_id = ?");
                $stmt->execute([$post_id, $_SESSION['user_id']]);
                
                $pdo->commit();
                setSuccessMessage('게시글이 삭제되었습니다.');
            } else {
                setErrorMessage('삭제할 권한이 없습니다.');
            }
        } catch(Exception $e) {
            $pdo->rollback();
            setErrorMessage('게시글 삭제 중 오류가 발생했습니다.');
        }
        
        header("Location: dashboard.php");
        exit();
    }
}
?>
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>대시보드 - Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
    <style>
        .post-files {
            margin-top: 10px;
            font-size: 0.9em;
        }
        .file-count {
            display: inline-block;
            background: #f8f9fa;
            color: #495057;
            padding: 2px 8px;
            border-radius: 12px;
            margin-right: 10px;
            font-size: 0.8em;
        }
        .file-count.images {
            background: #e3f2fd;
            color: #1976d2;
        }
        .file-count.attachments {
            background: #f3e5f5;
            color: #7b1fa2;
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
            <?php echo displayMessages(); ?>
            
            <div class="dashboard-header">
                <h1><?php echo escape($_SESSION['username']); ?>님의 대시보드</h1>
                <a href="post.php" class="text-link">새 글 작성</a>
            </div>

            <!-- 통계 카드들 -->
            <div class="dashboard-stats">
                <div class="stat-card">
                    <div class="stat-number"><?php echo $my_posts_count; ?></div>
                    <div class="stat-label">내 게시글</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $total_posts_count; ?></div>
                    <div class="stat-label">전체 게시글</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number"><?php echo $total_users_count; ?></div>
                    <div class="stat-label">전체 사용자</div>
                </div>
            </div>

            <!-- 내 최근 게시글 -->
            <div class="posts-container">
                <div class="dashboard-header">
                    <h2>내 최근 게시글</h2>
                </div>
                
                <?php if (empty($my_recent_posts)): ?>
                    <div class="post-item text-center">
                        <p>아직 작성한 게시글이 없습니다.</p>
                        <p><a href="post.php" class="text-link">첫 번째 글을 작성해보세요!</a></p>
                    </div>
                <?php else: ?>
                    <?php foreach ($my_recent_posts as $post): ?>
                        <?php
                        // 각 게시글의 파일 정보 가져오기
                        $post_images = getPostImages($pdo, $post['id']);
                        $post_attachments = getPostFiles($pdo, $post['id']);
                        ?>
                        <div class="post-item">
                            <h3 class="post-title">
                                <a href="index.php?post_id=<?php echo $post['id']; ?>">
                                    <?php echo escape($post['title']); ?>
                                </a>
                            </h3>
                            <div class="post-meta">
                                작성일: <?php echo date('Y-m-d H:i', strtotime($post['created_at'])); ?>
                            </div>
                            
                            <!-- 파일 개수 표시 -->
                            <?php if (!empty($post_images) || !empty($post_attachments)): ?>
                                <div class="post-files">
                                    <?php if (!empty($post_images)): ?>
                                        <span class="file-count images">
                                            📷 이미지 <?php echo count($post_images); ?>개
                                        </span>
                                    <?php endif; ?>
                                    <?php if (!empty($post_attachments)): ?>
                                        <span class="file-count attachments">
                                            📎 첨부파일 <?php echo count($post_attachments); ?>개
                                        </span>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                            
                            <div class="post-content">
                                <?php 
                                $content = escape($post['content']);
                                echo strlen($content) > 150 ? substr($content, 0, 150) . '...' : $content;
                                ?>
                            </div>
                            <div class="mt-1">
                                <a href="post.php?edit=<?php echo $post['id']; ?>" class="text-link">수정</a>
                                |
                                <form method="POST" style="display: inline;" 
                                      onsubmit="return confirm('게시글과 관련된 모든 파일이 함께 삭제됩니다. 정말 삭제하시겠습니까?');">
                                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                                    <input type="hidden" name="post_id" value="<?php echo $post['id']; ?>">
                                    <button type="submit" name="delete_post" 
                                            style="background: none; border: none; color: #e74c3c; cursor: pointer; text-decoration: underline;">
                                        삭제
                                    </button>
                                </form>
                            </div>
                        </div>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </main>
</body>
</html>