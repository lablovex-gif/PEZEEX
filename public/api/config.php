<?php
/**
 * Pezeex - Production AI Configuration
 */
if (PHP_SAPI !== 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === realpath(__FILE__)) {
    http_response_code(403);
    exit;
}

return [
    'GEMINI_API_KEY' => '',
    'APP_URL' => 'https://pezeex.com'
];
