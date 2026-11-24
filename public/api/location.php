<?php
/**
 * Lightweight request-header country detection endpoint (privacy-safe, returns 2-letter ISO code or null)
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

$headers = [
    'HTTP_CF_IPCOUNTRY',
    'HTTP_X_VERCEL_IP_COUNTRY',
    'HTTP_X_APPENGINE_COUNTRY',
    'HTTP_X_COUNTRY_CODE',
    'HTTP_FLY_CLIENT_COUNTRY'
];

$country = null;
foreach ($headers as $h) {
    if (!empty($_SERVER[$h])) {
        $code = strtoupper(trim($_SERVER[$h]));
        if (preg_match('/^[A-Z]{2}$/', $code) && !in_array($code, ['XX', 'T1', 'ZZ'], true)) {
            $country = strtolower($code);
            break;
        }
    }
}

echo json_encode(['country' => $country]);
