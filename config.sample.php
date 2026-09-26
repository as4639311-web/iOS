<?php
/**
 * config.sample.php — انسخه باسم config.php على الخادم واملأ القيم.
 * config.php مُدرج في .gitignore: لا تضع كلمات المرور في Git.
 */
ini_set("display_errors", "0");
ini_set("log_errors", "1");
error_reporting(E_ALL);

define("DB_HOST", "fdbXXXX.awardspace.net");
define("DB_NAME", "your_db_name");
define("DB_USER", "your_db_user");
define("DB_PASS", "CHANGE_ME");

// المنطقة الزمنية للنظام (المواعيد، «اليوم»، «خلال 7 أيام») — الافتراضي Asia/Dubai
define("APP_TIMEZONE", "Asia/Dubai");

function db(): PDO {
    static $pdo = null;
    if ($pdo !== null) return $pdo;
    try {
        $pdo = new PDO(
            "mysql:host=" . DB_HOST . ";dbname=" . DB_NAME . ";charset=utf8mb4",
            DB_USER,
            DB_PASS,
            [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => true,
            ]
        );
        return $pdo;
    } catch (PDOException $e) {
        error_log("DB connection failed: " . $e->getMessage());
        http_response_code(500);
        die("<!DOCTYPE html><html lang='ar' dir='rtl'><body style='font-family:sans-serif;padding:40px;text-align:center;background:#070b14;color:#e2e8f0'>\n            <h2 style='color:#22d3ee'>تعذّر الاتصال بقاعدة البيانات</h2>\n            <p>تحقق من بيانات الاتصال في config.php.</p>\n            </body></html>");
    }
}
