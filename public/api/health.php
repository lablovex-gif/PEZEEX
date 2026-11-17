<?php
/**
 * Diagnostic & Health Check Endpoint for Pezeex
 * Works on Hostinger, cPanel, LiteSpeed, Apache, Nginx
 * Visit in browser: https://yourdomain.com/api/health.php
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
header('Cross-Origin-Resource-Policy: same-origin');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Cache-Control: no-store');

if ($_SERVER['REQUEST_METHOD'] !== 'GET' && $_SERVER['REQUEST_METHOD'] !== 'HEAD') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

echo json_encode([
    'status' => 'ok',
    'timestamp' => gmdate('c')
], JSON_UNESCAPED_SLASHES);

