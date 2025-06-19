-- 블로그 데이터베이스 스키마 (기존 구조 기반)

-- 외래 키 체크 비활성화 (테이블 생성 중)
SET FOREIGN_KEY_CHECKS = 0;

-- 사용자 테이블
CREATE TABLE IF NOT EXISTS `users` (
    `id` int NOT NULL AUTO_INCREMENT,
    `username` varchar(50) NOT NULL,
    `email` varchar(100) NOT NULL,
    `password` varchar(255) NOT NULL,
    `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `username` (`username`),
    UNIQUE KEY `email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 게시글 테이블
CREATE TABLE IF NOT EXISTS `posts` (
    `id` int NOT NULL AUTO_INCREMENT,
    `user_id` int DEFAULT NULL,
    `title` varchar(200) NOT NULL,
    `content` text NOT NULL,
    `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 이미지 테이블
CREATE TABLE IF NOT EXISTS `images` (
    `id` int NOT NULL AUTO_INCREMENT,
    `post_id` int NOT NULL,
    `filename` varchar(255) NOT NULL,
    `original_name` varchar(255) NOT NULL,
    `file_path` varchar(500) NOT NULL,
    `file_size` int NOT NULL,
    `mime_type` varchar(100) NOT NULL,
    `create_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `post_id` (`post_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 파일 테이블
CREATE TABLE IF NOT EXISTS `files` (
    `id` int NOT NULL AUTO_INCREMENT,
    `post_id` int NOT NULL,
    `original_name` varchar(255) NOT NULL,
    `file_path` varchar(500) NOT NULL,
    `file_size` int NOT NULL,
    `mime_type` varchar(100) NOT NULL,
    `create_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `post_id` (`post_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

-- 외래 키 제약 조건 추가 (모든 테이블 생성 후)
ALTER TABLE `posts` 
ADD CONSTRAINT `posts_ibfk_1` 
FOREIGN KEY (`user_id`) REFERENCES `users` (`id`);

ALTER TABLE `images` 
ADD CONSTRAINT `images_ibfk_1` 
FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE;

ALTER TABLE `files` 
ADD CONSTRAINT `files_ibfk_1` 
FOREIGN KEY (`post_id`) REFERENCES `posts` (`id`) ON DELETE CASCADE;

-- 외래 키 체크 다시 활성화
SET FOREIGN_KEY_CHECKS = 1;