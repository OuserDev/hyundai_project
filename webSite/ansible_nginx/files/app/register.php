<?php
require_once 'config/database.php';
require_once 'includes/functions.php';

// 이미 로그인된 경우 대시보드로 리다이렉트
if (isLoggedIn()) {
    header("Location: dashboard.php");
    exit();
}

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = clean($_POST['username'] ?? '');
    $email = clean($_POST['email'] ?? '');
    $password = clean($_POST['password'] ?? '');
    $confirm_password = clean($_POST['confirm_password'] ?? '');
    $csrf_token = $_POST['csrf_token'] ?? '';
    
    // CSRF 토큰 검증
    if (!verifyCSRFToken($csrf_token)) {
        $errors[] = '잘못된 요청입니다.';
    } else {
        // 입력 검증
        if (empty($username)) {
            $errors[] = '사용자명을 입력해주세요.';
        } elseif (!validateUsername($username)) {
            $errors[] = '사용자명은 3-20자의 영문, 숫자, 언더스코어만 사용 가능합니다.';
        }
        
        if (empty($email)) {
            $errors[] = '이메일을 입력해주세요.';
        } elseif (!validateEmail($email)) {
            $errors[] = '올바른 이메일 형식을 입력해주세요.';
        }
        
        if (empty($password)) {
            $errors[] = '비밀번호를 입력해주세요.';
        } elseif (!validatePassword($password)) {
            $errors[] = '비밀번호는 최소 6자 이상이어야 합니다.';
        }
        
        if ($password !== $confirm_password) {
            $errors[] = '비밀번호가 일치하지 않습니다.';
        }
        
        // 중복 검사
        if (empty($errors)) {
            try {
                // 사용자명 중복 검사
                $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
                $stmt->execute([$username]);
                if ($stmt->fetch()) {
                    $errors[] = '이미 사용 중인 사용자명입니다.';
                }
                
                // 이메일 중복 검사
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                if ($stmt->fetch()) {
                    $errors[] = '이미 사용 중인 이메일입니다.';
                }
            } catch(PDOException $e) {
                $errors[] = '중복 검사 중 오류가 발생했습니다.';
            }
        }
        
        // 회원가입 처리
        if (empty($errors)) {
            try {
                $hashed_password = hashPassword($password);
                $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
                $stmt->execute([$username, $email, $hashed_password]);
                
                setSuccessMessage('회원가입이 완료되었습니다. 로그인해주세요.');
                header("Location: login.php");
                exit();
            } catch(PDOException $e) {
                $errors[] = '회원가입 처리 중 오류가 발생했습니다.';
            }
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>회원가입 - Simple Blog</title>
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
                <h2>회원가입</h2>
                
                <?php if (!empty($errors)): ?>
                    <div class="alert alert-error">
                        <?php foreach ($errors as $error): ?>
                            <p><?php echo escape($error); ?></p>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
                
                <?php echo displayMessages(); ?>
                
                <form method="POST" action="">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    
                    <div class="form-group">
                        <label for="username">사용자명</label>
                        <input type="text" id="username" name="username" 
                               value="<?php echo escape($_POST['username'] ?? ''); ?>" 
                               required autocomplete="username"
                               placeholder="3-20자의 영문, 숫자, 언더스코어">
                    </div>
                    
                    <div class="form-group">
                        <label for="email">이메일</label>
                        <input type="email" id="email" name="email" 
                               value="<?php echo escape($_POST['email'] ?? ''); ?>" 
                               required autocomplete="email">
                    </div>
                    
                    <div class="form-group">
                        <label for="password">비밀번호</label>
                        <input type="password" id="password" name="password" 
                               required autocomplete="new-password"
                               placeholder="최소 6자 이상">
                    </div>
                    
                    <div class="form-group">
                        <label for="confirm_password">비밀번호 확인</label>
                        <input type="password" id="confirm_password" name="confirm_password" 
                               required autocomplete="new-password">
                    </div>
                    
                    <div class="form-group">
                        <button type="submit" class="btn-full">회원가입</button>
                    </div>
                </form>
                
                <div class="text-center mt-1">
                    <p>이미 계정이 있으신가요? <a href="login.php" class="text-link">로그인</a></p>
                </div>
            </div>
        </div>
    </main>
</body>
</html>