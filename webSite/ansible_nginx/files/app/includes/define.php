<?php
    define('MAX_IMAGE_SIZE', 5 * 1024 * 1024);          //5MB
    define('MAX_UPLOADFILE_SIZE', 10 * 1024 * 1024);    //10MB
    define('UPLOAD_PATH', __DIR__ . '/../uploads/');
    define('IMAGES_PATH', UPLOAD_PATH . 'images/');
    define('FILES_PATH', UPLOAD_PATH . 'files/');

    $allowed_image_types = [
        'image/jpeg', 
        'image/jpg', 
        'image/png', 
        'image/gif', 
        'image/webp'
    ];
    $allowed_attachment_types = [
        'application/pdf', 'application/msword', 
    // 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    // 'application/vnd.ms-excel',
    // 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    // 'application/vnd.ms-powerpoint',
    // 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    // 'application/zip', 'application/x-zip-compressed',
    // 'text/plain', 'text/csv'
    ];
    
?>