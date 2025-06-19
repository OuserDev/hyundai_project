<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 이미 로그인된 경우 대시보드로 리다이렉트
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = clean($_POST['username'] ?? '');
    $password = clean($_POST['password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrf_token)) {
        $error = '잘못된 요청입니다.';
    } else if (empty($username) || empty($password)) {
        $error = '사용자명과 비밀번호를 모두 입력해주세요.';
    } else {
        try {
            $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ?");
            $stmt->execute([$username]);
            $user = $stmt->fetch();
            
            if ($user && verifyPassword($password, $user['password'])) {
                // 로그인 성공
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                
                // 새로운 CSRF 토큰 생성
                unset($_SESSION['csrf_token']);
                generateCSRFToken();
                
                setSuccessMessage('로그인되었습니다!');
                header("Location: dashboard.php");
                exit();
            } else {
                $error = '사용자명 또는 비밀번호가 잘못되었습니다.';
            }
        } catch(PDOException $e) {
            $error = '로그인 처리 중 오류가 발생했습니다.';
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