<?php
require_once 'includes/functions.php';

// CSRF 토큰 검증 (GET 방식이므로 간단한 확인만)
if (isset($_GET['confirm']) && $_GET['confirm'] === 'yes') {
    // 세션 완전히 삭제
    session_start();
    
    // 세션 변수 모두 삭제
    $_SESSION = array();
    
    // 세션 쿠키 삭제
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000,
            $params["path"], $params["domain"],
            $params["secure"], $params["httponly"]
        );
    }
    
    // 세션 파기
    session_destroy();
    
    // 로그인 페이지로 리다이렉트
    header("Location: login.php");
    exit();
}

// 로그아웃 확인이 없는 경우 확인 페이지 표시
session_start();
if (!isLoggedIn()) {
    header("Location: login.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>로그아웃 - Simple Blog</title>
    <link rel="stylesheet" href="css/style.css">
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
                <h2>로그아웃</h2>
                
                <div class="text-center">
                    <p class="mb-2">정말 로그아웃하시겠습니까?</p>
                    
                    <div style="display: flex; gap: 1rem; justify-content: center;">
                        <a href="logout.php?confirm=yes" 
                           style="background: #e74c3c; color: white; padding: 0.75rem 2rem; text-decoration: none; border-radius: 4px;">
                            예, 로그아웃
                        </a>
                        <a href="dashboard.php" 
                           style="background: #95a5a6; color: white; padding: 0.75rem 2rem; text-decoration: none; border-radius: 4px;">
                            취소
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </main>
</body>
</html>