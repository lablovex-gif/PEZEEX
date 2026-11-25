<?php
/**
 * Pezeex - Alternative AI Configuration
 * 
 * If your shared hosting (e.g. Hostinger Business) does not pass system environment variables to PHP,
 * you can simply rename this file to "config.php" in the same folder (api/config.php)
 * and enter your API key below.
 * 
 * It supports ANY AI provider (Gemini, OpenAI, Groq, DeepSeek, Anthropic, OpenRouter, etc.)
 */
if (PHP_SAPI !== 'cli' && realpath($_SERVER['SCRIPT_FILENAME'] ?? '') === realpath(__FILE__)) {
    http_response_code(403);
    exit;
}

return [
    // Single key OR array of dozens/hundreds of keys (automatically rotated on every search):
    'DAHL_API_KEYS' => [
        // 'dahl_key_1',
        // 'dahl_key_2',
    ],
    // Or single/comma-separated key:
    'AI_API_KEY' => 'YOUR_API_KEY_HERE',

    // Optional: Specify custom model or custom base URL if needed
    'AI_BASE_URL' => 'https://inference.dahl.global/v1',
    'AI_MODEL' => 'MiniMaxAI/MiniMax-M2.7',

    // Takeads Server-to-Server Monetize API (Platform Public Key from Platform settings -> Platform API)
    'TAKEADS_PUBLIC_KEY' => '',
    'TAKEADS_SUB_ID' => 'pezeex',
];
