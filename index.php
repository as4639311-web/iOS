<?php
/**
 * index.php — FMS/EMS: تطبيق واحد متكامل. ملفان فقط يشغّلان النظام
 * بالكامل: config.php (اتصال القاعدة) وهذا الملف (كل شيء آخر: منطق،
 * HTML، CSS، JS — مدمج بالكامل، لا ملفات إضافية).
 */

require_once __DIR__ . "/config.php";

/* =====================================================================
   إعدادات جلسة آمنة — يجب ضبطها قبل session_start() مباشرة، وإلا فلا أثر لها
   ===================================================================== */
$isHttps = (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off")
    || (($_SERVER["HTTP_X_FORWARDED_PROTO"] ?? "") === "https"); // خلف بروكسي عكسي محتمل على بعض الاستضافات
session_set_cookie_params([
    "lifetime" => 0,
    "path" => "/",
    "secure" => $isHttps,       // يُفعَّل تلقائياً فقط عند HTTPS فعلي — لا يمنع العمل على HTTP أثناء الاختبار
    "httponly" => true,          // يمنع الوصول للكوكي عبر JavaScript — حماية أساسية ضد XSS يسرق الجلسة
    "samesite" => "Strict",      // يمنع إرسال كوكي الجلسة من طلبات مصدرها موقع آخر (تعزيز إضافي فوق CSRF Token الموجود أصلاً)
]);
session_start();

/* المنطقة الزمنية: توحيد PHP وMySQL على نفس التوقيت — ضروري لمنطق "اليوم"
   و"خلال 7 أيام" في المواعيد. يمكن تغييرها بتعريف APP_TIMEZONE في config.php */
date_default_timezone_set(defined("APP_TIMEZONE") ? APP_TIMEZONE : "Asia/Dubai");

/* معالج أخطاء أخير: أي استثناء غير ملتقَط يُسجَّل في سجل الخادم ويظهر
   للمستخدم كرسالة ودّية (لا صفحة بيضاء ولا تسريب تفاصيل SQL). */
set_exception_handler(function (Throwable $e) {
    error_log("FMS uncaught: " . $e->getMessage() . " @ " . $e->getFile() . ":" . $e->getLine());
    if (!headers_sent() && ($_SERVER["REQUEST_METHOD"] ?? "GET") === "POST" && session_status() === PHP_SESSION_ACTIVE) {
        flash(friendlyError($e), "danger");
        redirect("index.php" . (isset($_GET["page"]) ? "?page=" . urlencode((string)$_GET["page"]) : ""));
    }
    if (!headers_sent()) http_response_code(500);
    echo "<div style='font-family:system-ui;padding:40px;text-align:center;background:#070b14;color:#e2e8f0'>حدث خطأ غير متوقع. <a style='color:#22d3ee' href='index.php'>العودة للرئيسية</a></div>";
});

$pdo = db();
try { $pdo->exec("SET time_zone = '" . date("P") . "'"); } catch (Throwable $e) { error_log("SET time_zone failed: " . $e->getMessage()); }
ensureSchema($pdo);

/* =====================================================================
   إنشاء الجداول تلقائياً عند أول تشغيل — لا حاجة لاستيراد يدوي عبر
   phpMyAdmin. يتحقق أولاً من وجود جدول "users"؛ إن لم يكن موجوداً،
   يُنشئ كل الجداول ثم يزرع بيانات تجريبية أولية (بلا مستخدمين — حساب
   المدير الأول يُنشأ لاحقاً من داخل التطبيق نفسه بكلمة مرور حقيقية).
   آمن للتكرار: كل الجمل تستخدم IF NOT EXISTS، فتشغيلها على قاعدة
   جاهزة مسبقاً لا يفعل شيئاً ولا يمسح أي بيانات موجودة.
   ===================================================================== */
function ensureSchema(PDO $pdo): void {
    $isFirstRun = !$pdo->query("SHOW TABLES LIKE 'users'")->fetch();
    // ملاحظة تصميم مهمة: أزلنا "return" المبكر الذي كان هنا سابقاً — الآن
    // تُنفَّذ كل جمل CREATE TABLE IF NOT EXISTS في كل طلب (كلفتها زهيدة
    // على MySQL)، بحيث تُنشأ أي جداول جديدة نضيفها مستقبلاً (كجدولي
    // المزادات هنا) تلقائياً حتى على نظام يعمل فعلاً ببيانات حقيقية،
    // دون الحاجة لأي ترحيل (Migration) يدوي. بيانات الزرع التجريبية
    // فقط تبقى مقيَّدة بأول تشغيل عبر $isFirstRun أسفل الدالة.

    $pdo->exec("SET FOREIGN_KEY_CHECKS = 0");

    $tables = [
        "CREATE TABLE IF NOT EXISTS users (
            id VARCHAR(36) PRIMARY KEY, username VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL, full_name VARCHAR(190) NOT NULL,
            role ENUM('EXECUTIVE_MANAGEMENT','FLEET_MANAGER','WORKSHOP_MANAGER','STOREKEEPER','TECHNICIAN') NOT NULL,
            is_active TINYINT(1) NOT NULL DEFAULT 1, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS assets (
            id VARCHAR(36) PRIMARY KEY, asset_code VARCHAR(60) NOT NULL UNIQUE,
            serial_number VARCHAR(120) NOT NULL UNIQUE, vin VARCHAR(120) UNIQUE,
            brand VARCHAR(120) NOT NULL, model VARCHAR(120) NOT NULL, manufacturing_year INT NOT NULL,
            fuel_type ENUM('DIESEL','PETROL','ELECTRIC','HYBRID','CNG') NOT NULL, category VARCHAR(120) NOT NULL,
            initial_capex DECIMAL(14,2) NOT NULL, book_value DECIMAL(14,2) NOT NULL, current_market_value DECIMAL(14,2) NOT NULL,
            status ENUM('ACTIVE','UNDER_MAINTENANCE','IDLE','FOR_SALE','SOLD','SCRAPPED') NOT NULL DEFAULT 'ACTIVE',
            location VARCHAR(190), odometer_km DECIMAL(12,2) NOT NULL DEFAULT 0, engine_hours DECIMAL(12,2) NOT NULL DEFAULT 0,
            cumulative_maintenance_cost DECIMAL(14,2) NOT NULL DEFAULT 0, cumulative_operational_cost DECIMAL(14,2) NOT NULL DEFAULT 0,
            is_disposal_flagged TINYINT(1) NOT NULL DEFAULT 0,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            deleted_at DATETIME NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS maintenance_schedules (
            id VARCHAR(36) PRIMARY KEY, asset_id VARCHAR(36) NOT NULL, task_name VARCHAR(190) NOT NULL,
            trigger_type ENUM('KM','ENGINE_HOURS','TIME_MONTHS') NOT NULL, interval_value DECIMAL(10,2) NOT NULL,
            last_service_hours DECIMAL(12,2) NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS work_orders (
            id VARCHAR(36) PRIMARY KEY, wo_number VARCHAR(60) NOT NULL UNIQUE, asset_id VARCHAR(36) NOT NULL,
            type ENUM('PREVENTIVE','CORRECTIVE','ACCIDENT') NOT NULL,
            failure_type ENUM('MECHANICAL','ELECTRICAL','HYDRAULIC','BODY','OTHER') NULL,
            status ENUM('DRAFT','APPROVED_OPEN','IN_PROGRESS','PENDING_PARTS','QUALITY_INSPECTION','CLOSED') NOT NULL DEFAULT 'DRAFT',
            description TEXT NOT NULL, technician_id VARCHAR(36) NULL,
            actual_labor_hours DECIMAL(8,2) NULL, technician_hourly_rate DECIMAL(10,2) NULL,
            labor_cost DECIMAL(12,2) NOT NULL DEFAULT 0, parts_cost DECIMAL(12,2) NOT NULL DEFAULT 0, total_cost DECIMAL(12,2) NOT NULL DEFAULT 0,
            inspection_passed TINYINT(1) NULL, workshop_manager_approved_by VARCHAR(36) NULL,
            opened_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP, closed_at DATETIME NULL,
            FOREIGN KEY (asset_id) REFERENCES assets(id), FOREIGN KEY (technician_id) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS warehouses (id VARCHAR(36) PRIMARY KEY, name VARCHAR(190) NOT NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS spare_parts (
            id VARCHAR(36) PRIMARY KEY, sku VARCHAR(80) NOT NULL UNIQUE, description VARCHAR(255) NOT NULL,
            quantity INT NOT NULL DEFAULT 0, reorder_level INT NOT NULL DEFAULT 0, unit_cost DECIMAL(12,2) NOT NULL,
            warehouse_id VARCHAR(36) NOT NULL, FOREIGN KEY (warehouse_id) REFERENCES warehouses(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS wo_parts_consumption (
            id VARCHAR(36) PRIMARY KEY, work_order_id VARCHAR(36) NOT NULL, spare_part_id VARCHAR(36) NOT NULL,
            quantity INT NOT NULL, unit_cost_snapshot DECIMAL(12,2) NOT NULL, total_cost DECIMAL(12,2) NOT NULL,
            consumed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (work_order_id) REFERENCES work_orders(id) ON DELETE CASCADE,
            FOREIGN KEY (spare_part_id) REFERENCES spare_parts(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS stock_alerts (
            id VARCHAR(36) PRIMARY KEY, spare_part_id VARCHAR(36) NOT NULL, message VARCHAR(255) NOT NULL,
            status ENUM('OPEN','RESOLVED') NOT NULL DEFAULT 'OPEN', created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (spare_part_id) REFERENCES spare_parts(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS tco_analysis_logs (
            id VARCHAR(36) PRIMARY KEY, asset_id VARCHAR(36) NOT NULL, capex DECIMAL(14,2) NOT NULL,
            cumulative_maintenance_cost DECIMAL(14,2) NOT NULL, cumulative_operational_cost DECIMAL(14,2) NOT NULL,
            current_market_recovery_value DECIMAL(14,2) NOT NULL, tco DECIMAL(14,2) NOT NULL,
            maintenance_to_value_ratio DECIMAL(6,4) NOT NULL, is_unfeasible TINYINT(1) NOT NULL DEFAULT 0,
            calculated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS audit_logs (
            id VARCHAR(36) PRIMARY KEY, user_id VARCHAR(36) NULL, action VARCHAR(60) NOT NULL,
            entity VARCHAR(80) NOT NULL, entity_id VARCHAR(80) NOT NULL, details VARCHAR(255) NULL,
            timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS auctions (
            id VARCHAR(36) PRIMARY KEY, asset_id VARCHAR(36) NOT NULL, title VARCHAR(190) NOT NULL,
            starting_price DECIMAL(14,2) NOT NULL, bid_step DECIMAL(12,2) NOT NULL DEFAULT 500,
            deposit_percent DECIMAL(5,2) NOT NULL DEFAULT 10,
            anti_snipe_window_minutes INT NOT NULL DEFAULT 5, anti_snipe_extend_minutes INT NOT NULL DEFAULT 5,
            start_at DATETIME NOT NULL, end_at DATETIME NOT NULL,
            status ENUM('SCHEDULED','LIVE','ENDED','CANCELLED') NOT NULL DEFAULT 'SCHEDULED',
            created_by VARCHAR(36) NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (asset_id) REFERENCES assets(id), FOREIGN KEY (created_by) REFERENCES users(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS bids (
            id VARCHAR(36) PRIMARY KEY, auction_id VARCHAR(36) NOT NULL,
            bidder_name VARCHAR(190) NOT NULL, amount DECIMAL(14,2) NOT NULL,
            placed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (auction_id) REFERENCES auctions(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

                "CREATE TABLE IF NOT EXISTS asset_documents (
            id VARCHAR(36) PRIMARY KEY,
            asset_id VARCHAR(36) NOT NULL,
            doc_type ENUM('INSURANCE','LICENSE','INSPECTION','REGISTRATION','WARRANTY','OTHER') NOT NULL DEFAULT 'OTHER',
            title VARCHAR(190) NOT NULL,
            doc_number VARCHAR(120) NULL,
            issued_at DATE NULL,
            expires_at DATE NULL,
            notes TEXT NULL,
            created_by VARCHAR(36) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_asset (asset_id),
            INDEX idx_expires (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS stock_movements (
            id VARCHAR(36) PRIMARY KEY,
            part_id VARCHAR(36) NOT NULL,
            movement_type ENUM('RECEIVE','ISSUE','ADJUST_IN','ADJUST_OUT') NOT NULL,
            quantity DECIMAL(12,2) NOT NULL,
            unit_cost DECIMAL(14,2) NOT NULL DEFAULT 0,
            reference_type VARCHAR(40) NULL,
            reference_id VARCHAR(36) NULL,
            notes VARCHAR(255) NULL,
            created_by VARCHAR(36) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_part (part_id),
            INDEX idx_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS login_attempts (
            id BIGINT AUTO_INCREMENT PRIMARY KEY, ip_address VARCHAR(64) NOT NULL,
            username VARCHAR(100) NOT NULL, attempted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip_time (ip_address, attempted_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        // ── v4: مواعيد الصيانة ──
        "CREATE TABLE IF NOT EXISTS maintenance_appointments (
            id VARCHAR(36) PRIMARY KEY,
            appt_number VARCHAR(40) NOT NULL UNIQUE,
            asset_id VARCHAR(36) NOT NULL,
            requested_by VARCHAR(36) NULL,
            scheduled_at DATETIME NOT NULL,
            scheduled_date DATE NOT NULL,
            preferred_slot ENUM('MORNING','NOON','EVENING') NOT NULL,
            is_exact_time TINYINT(1) NOT NULL DEFAULT 0,
            service_type ENUM('PREVENTIVE','CORRECTIVE','INSPECTION','OTHER') NOT NULL DEFAULT 'PREVENTIVE',
            description TEXT NULL,
            status ENUM('PENDING','CONFIRMED','IN_PROGRESS','COMPLETED','CANCELLED','NO_SHOW') NOT NULL DEFAULT 'PENDING',
            assigned_technician VARCHAR(36) NULL,
            linked_work_order_id VARCHAR(36) NULL,
            workshop_notes TEXT NULL,
            cancel_reason VARCHAR(255) NULL,
            odometer_at_service DECIMAL(12,2) NULL,
            asset_prev_status VARCHAR(30) NULL,
            confirmed_by VARCHAR(36) NULL,
            confirmed_at DATETIME NULL,
            started_at DATETIME NULL,
            completed_at DATETIME NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_appt_asset_day (asset_id, scheduled_date, preferred_slot),
            INDEX idx_appt_status_date (status, scheduled_date),
            INDEX idx_appt_tech_day (assigned_technician, scheduled_date),
            INDEX idx_appt_date (scheduled_at),
            FOREIGN KEY (asset_id) REFERENCES assets(id),
            FOREIGN KEY (requested_by) REFERENCES users(id),
            FOREIGN KEY (assigned_technician) REFERENCES users(id),
            FOREIGN KEY (linked_work_order_id) REFERENCES work_orders(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        // ── v4: "تذكرني" — ضروري على آيفون: التطبيق المثبَّت يفقد كوكي الجلسة عند إغلاقه
        "CREATE TABLE IF NOT EXISTS auth_tokens (
            id BIGINT AUTO_INCREMENT PRIMARY KEY,
            selector CHAR(24) NOT NULL UNIQUE,
            validator_hash CHAR(64) NOT NULL,
            user_id VARCHAR(36) NOT NULL,
            user_agent VARCHAR(190) NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_tok_user (user_id),
            INDEX idx_tok_exp (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",

        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INT PRIMARY KEY,
            applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
    ];

    foreach ($tables as $sql) {
        $pdo->exec($sql);
    }
    $pdo->exec("SET FOREIGN_KEY_CHECKS = 1");

    // فهارس على الأعمدة الأكثر استخداماً في WHERE/ORDER BY/JOIN — تُضاف هنا
    // صراحة (لا ضمن CREATE TABLE فقط) لأنها تحتاج العمل حتى على جداول
    // *موجودة بالفعل* من نسخة سابقة للتطبيق، لا الجداول الجديدة فقط.
    // ensureIndex() تتحقق أولاً فلا تُكرَّر العملية ولا تفشل إن كانت موجودة.
    ensureIndex($pdo, "assets", "idx_status", "status");
    ensureIndex($pdo, "assets", "idx_created_at", "created_at");
    ensureIndex($pdo, "work_orders", "idx_asset_id", "asset_id");
    ensureIndex($pdo, "work_orders", "idx_status", "status");
    ensureIndex($pdo, "work_orders", "idx_opened_at", "opened_at");
    ensureIndex($pdo, "auctions", "idx_status_end", "status, end_at");
    ensureIndex($pdo, "audit_logs", "idx_timestamp", "timestamp");
    ensureIndex($pdo, "spare_parts", "idx_quantity_reorder", "quantity, reorder_level");

    // تعديلات الأعمدة (ALTER) — مُقيَّدة برقم إصدار، فتُنفَّذ مرة واحدة فقط لا في كل طلب
    runMigrations($pdo);

    if (!$isFirstRun) return; // النظام يعمل فعلاً ببيانات حقيقية — لا نزرع شيئاً فوقها

    // بيانات تجريبية أولية غير حساسة (بلا مستخدمين) — تُزرَع مرة واحدة فقط هنا
    $wh = uid();
    $pdo->prepare("INSERT INTO warehouses (id, name) VALUES (?, 'المستودع الرئيسي')")->execute([$wh]);

    $assetsSeed = [
        ["a-" . uid(), "AST-2026-0001", "CAT-D6-0001", "1CAT2024D6X00001", "Caterpillar", "D6 Bulldozer", 2021, "DIESEL", "جرافة", 850000, 620000, 540000, "ACTIVE", "الموقع الرئيسي", 0, 8200, 12000, 8000],
        ["a-" . uid(), "AST-2026-0002", "VOLVO-EC220-0002", "2VOLVOEC220X00002", "Volvo", "EC220 Excavator", 2019, "DIESEL", "حفارة", 620000, 310000, 180000, "ACTIVE", "الموقع الرئيسي", 0, 14500, 115000, 15000],
        ["a-" . uid(), "AST-2026-0003", "TOYOTA-HILUX-0003", "3TOYHILUXX00003", "Toyota", "Hilux 4x4", 2023, "DIESEL", "مركبة نقل خفيف", 145000, 128000, 120000, "ACTIVE", "الموقع الرئيسي", 42000, 0, 4000, 6000],
    ];
    $assetStmt = $pdo->prepare("INSERT INTO assets (id, asset_code, serial_number, vin, brand, model, manufacturing_year, fuel_type, category, initial_capex, book_value, current_market_value, status, location, odometer_km, engine_hours, cumulative_maintenance_cost, cumulative_operational_cost) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)");
    foreach ($assetsSeed as $row) $assetStmt->execute($row);

    $partsSeed = [
        ["OIL-15W40", "زيت محرك 15W40", 120, 30, 45.5],
        ["FILTER-OIL-CAT", "فلتر زيت - كاتربيلر", 8, 10, 120],
        ["TIRE-29.5", "إطار 29.5 للمعدات الثقيلة", 16, 6, 3800],
    ];
    $partStmt = $pdo->prepare("INSERT INTO spare_parts (id, sku, description, quantity, reorder_level, unit_cost, warehouse_id) VALUES (?,?,?,?,?,?,?)");
    foreach ($partsSeed as $row) $partStmt->execute([uid(), $row[0], $row[1], $row[2], $row[3], $row[4], $wh]);
}

/** يضيف فهرساً فقط إن لم يكن موجوداً بالفعل — آمن للتشغيل المتكرر على
 * جدول قائم منذ نسخة سابقة من التطبيق، بلا خطر تكرار أو فشل. */
function ensureIndex(PDO $pdo, string $table, string $indexName, string $columns): void {
    $check = $pdo->prepare("
        SELECT COUNT(*) c FROM information_schema.statistics
        WHERE table_schema = DATABASE() AND table_name = ? AND index_name = ?
    ");
    $check->execute([$table, $indexName]);
    if ((int)$check->fetch()["c"] > 0) return;
    try {
        $pdo->exec("CREATE INDEX $indexName ON $table ($columns)");
    } catch (Throwable $e) {
        error_log("ensureIndex failed for $table.$indexName: " . $e->getMessage());
    }
}

/** يضيف عموداً فقط إن لم يكن موجوداً — آمن تماماً على بيانات قائمة (لا حذف ولا تعديل لأي عمود). */
function ensureColumn(PDO $pdo, string $table, string $column, string $definition): void {
    $check = $pdo->prepare("SELECT COUNT(*) c FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?");
    $check->execute([$table, $column]);
    if ((int)$check->fetch()["c"] > 0) return;
    try {
        $pdo->exec("ALTER TABLE `$table` ADD COLUMN `$column` $definition");
    } catch (Throwable $e) {
        // 1060 = Duplicate column: طلب آخر متزامن أضافه للتو — ليس خطأً
        if (strpos($e->getMessage(), "1060") === false) error_log("ensureColumn failed for $table.$column: " . $e->getMessage());
    }
}

/**
 * runMigrations() — ترحيلات إضافية فقط (Additive) مُرقَّمة بإصدار. تكلفتها
 * بعد التطبيق الأول: استعلام واحد على مفتاح أساسي. لإضافة ترحيل مستقبلي:
 * ارفع SCHEMA_VERSION وأضف كتلة if ($v < N) جديدة.
 */
define("SCHEMA_VERSION", 4);
function runMigrations(PDO $pdo): void {
    $v = (int)$pdo->query("SELECT COALESCE(MAX(version), 0) v FROM schema_migrations")->fetch()["v"];
    if ($v >= SCHEMA_VERSION) return;

    if ($v < 4) {
        // المتطلب 1: إثراء بيانات الآليات. ملاحظة: رقم الهيكل موجود أصلاً
        // بعمود vin (رقم الهيكل = VIN) — لم نكرّره بعمود جديد لتفادي تضارب البيانات.
        ensureColumn($pdo, "assets", "plate_number", "VARCHAR(40) NULL AFTER vin");
        ensureColumn($pdo, "assets", "ownership_type", "ENUM('OWNED','LEASED','RENTED') NOT NULL DEFAULT 'OWNED'");
        ensureColumn($pdo, "assets", "department", "VARCHAR(120) NULL");
        ensureColumn($pdo, "assets", "cost_center", "VARCHAR(60) NULL");
        ensureColumn($pdo, "assets", "assigned_driver", "VARCHAR(190) NULL");
        ensureColumn($pdo, "assets", "service_interval_days", "INT NULL");
        ensureColumn($pdo, "assets", "service_interval_km", "INT NULL");
        ensureColumn($pdo, "assets", "last_service_date", "DATE NULL");
        ensureColumn($pdo, "assets", "next_service_due_date", "DATE NULL");
        ensureColumn($pdo, "assets", "next_service_due_km", "DECIMAL(12,2) NULL");
        ensureColumn($pdo, "assets", "notes", "TEXT NULL");
        ensureColumn($pdo, "assets", "photo_path", "VARCHAR(255) NULL");
        ensureIndex($pdo, "assets", "idx_plate", "plate_number");
        ensureIndex($pdo, "assets", "idx_next_service", "next_service_due_date");
        $pdo->exec("INSERT IGNORE INTO schema_migrations (version) VALUES (4)");
    }
}

/* =====================================================================
   أدوات مساعدة عامة
   ===================================================================== */
function uid(): string { return bin2hex(random_bytes(16)); }
function e($s): string { return htmlspecialchars((string)$s, ENT_QUOTES, "UTF-8"); }
function money($n): string { return number_format((float)$n, 0); }
function redirect(string $url): void { header("Location: $url"); exit; }
function flash(string $msg, string $type = "success"): void { $_SESSION["flash"] = $msg; $_SESSION["flash_type"] = $type; }
function csrfToken(): string { if (empty($_SESSION["csrf"])) $_SESSION["csrf"] = bin2hex(random_bytes(24)); return $_SESSION["csrf"]; }
function csrfCheck(): void {
    $t = $_POST["csrf"] ?? ""; if (!is_string($t) || empty($_SESSION["csrf"]) || !hash_equals($_SESSION["csrf"], $t)) { flash("انتهت صلاحية الجلسة، أعد المحاولة.", "danger"); redirect("index.php"); }
}
function logAudit($pdo, ?string $userId, string $action, string $entity, string $entityId, string $details = ""): void {
    // details عمود VARCHAR(255): نقصّه بأمان (UTF-8) بدل أن يفشل الإدراج في وضع SQL الصارم
    $pdo->prepare("INSERT INTO audit_logs (id, user_id, action, entity, entity_id, details) VALUES (?,?,?,?,?,?)")
        ->execute([uid(), $userId, strCut($action, 60), strCut($entity, 80), strCut($entityId, 80), strCut($details, 250)]);
}

/* ── قراءة مدخلات POST بأمان: أنواع مضمونة، أطوال محدودة، لا مصفوفات مدسوسة ── */
function strCut(string $s, int $max): string {
    return function_exists("mb_substr") ? mb_substr($s, 0, $max, "UTF-8") : substr($s, 0, $max);
}
function postVal(string $k): string { $v = $_POST[$k] ?? ""; return is_scalar($v) ? (string)$v : ""; }
function inStr(string $k, int $max = 190): string { return strCut(trim(preg_replace('/\s+/u', " ", postVal($k)) ?? ""), $max); }
function inText(string $k, int $max = 5000): string { return strCut(trim(postVal($k)), $max); }
function inEnum(string $k, array $allowed, ?string $default = null): ?string { $v = postVal($k); return in_array($v, $allowed, true) ? $v : $default; }
function inDate(string $k): ?string {
    $v = trim(postVal($k)); if ($v === "") return null;
    $d = DateTime::createFromFormat("!Y-m-d", $v);
    return ($d && $d->format("Y-m-d") === $v) ? $v : null;
}
function inIntOrNull(string $k, int $min, int $max): ?int {
    $v = trim(postVal($k)); if ($v === "" || !is_numeric($v)) return null;
    $i = (int)round((float)$v); return ($i < $min || $i > $max) ? null : $i;
}
function inNumOrNull(string $k, float $min = 0, float $max = 1e12): ?float {
    $v = trim(postVal($k)); if ($v === "" || !is_numeric($v)) return null;
    $f = (float)$v; return ($f < $min || $f > $max) ? null : round($f, 2);
}
/** يحفظ مدخلات النموذج عند الخطأ ليُعاد ملؤه بدل أن يفقد المستخدم ما كتبه */
function keepOldInput(): void { $o = $_POST; unset($o["csrf"], $o["action"]); $_SESSION["old"] = $o; }
function takeOldInput(): array { $o = $_SESSION["old"] ?? []; unset($_SESSION["old"]); return is_array($o) ? $o : []; }

/** رسالة آمنة للمستخدم: أخطاء منطق العمل تظهر كما هي، وأخطاء القاعدة تُسجَّل ولا تُكشف */
function friendlyError(Throwable $e): string {
    if ($e instanceof PDOException) {
        error_log("FMS DB error: " . $e->getMessage());
        return ((string)$e->getCode() === "23000") ? "القيمة مدخلة سابقاً (رقم تسلسلي أو رقم هيكل مكرر) أو مرتبطة بسجل آخر." : "تعذّر حفظ البيانات. أعد المحاولة.";
    }
    return $e->getMessage();
}
function can(string $perm, string $role, array $ACTION_ROLES): bool { return in_array($role, $ACTION_ROLES[$perm] ?? [], true); }
function isHttpsRequest(): bool {
    return (!empty($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] !== "off") || (($_SERVER["HTTP_X_FORWARDED_PROTO"] ?? "") === "https");
}
function roleLabel(string $role): string {
    $m = ["EXECUTIVE_MANAGEMENT" => "الإدارة العليا", "FLEET_MANAGER" => "مدير الأسطول", "WORKSHOP_MANAGER" => "مدير الورشة", "STOREKEEPER" => "أمين المخزن", "TECHNICIAN" => "فني الصيانة"];
    return $m[$role] ?? $role;
}
function arDate(string $ymd, bool $withWeekday = true): string {
    $ts = strtotime($ymd); if (!$ts) return $ymd;
    $days = ["الأحد", "الاثنين", "الثلاثاء", "الأربعاء", "الخميس", "الجمعة", "السبت"];
    $months = ["يناير", "فبراير", "مارس", "أبريل", "مايو", "يونيو", "يوليو", "أغسطس", "سبتمبر", "أكتوبر", "نوفمبر", "ديسمبر"];
    return ($withWeekday ? $days[(int)date("w", $ts)] . " " : "") . (int)date("j", $ts) . " " . $months[(int)date("n", $ts) - 1] . " " . date("Y", $ts);
}

/* =====================================================================
   بيانات الآليات الموسّعة (المتطلب 1)
   ===================================================================== */
function ownershipLabels(): array { return ["OWNED" => "ملك الشركة", "LEASED" => "تأجير تمويلي / طويل الأجل", "RENTED" => "إيجار مؤقت"]; }
function assetStatusLabels(): array { return ["ACTIVE" => "نشطة", "UNDER_MAINTENANCE" => "تحت الصيانة", "IDLE" => "متوقفة", "FOR_SALE" => "معروضة للبيع", "SOLD" => "مباعة", "SCRAPPED" => "مستبعدة"]; }
function fuelLabels(): array { return ["DIESEL" => "ديزل", "PETROL" => "بنزين", "ELECTRIC" => "كهربائي", "HYBRID" => "هجين", "CNG" => "غاز"]; }

/** يقرأ الحقول الجديدة من النموذج ويتحقق منها — مشترك بين الإنشاء والتعديل */
function assetExtraFromPost(): array {
    $plate = inStr("plate_number", 40);
    $plate = function_exists("mb_strtoupper") ? mb_strtoupper($plate, "UTF-8") : strtoupper($plate);
    return [
        "plate_number" => $plate !== "" ? $plate : null,
        "ownership_type" => inEnum("ownership_type", array_keys(ownershipLabels()), "OWNED"),
        "department" => inStr("department", 120) ?: null,
        "cost_center" => inStr("cost_center", 60) ?: null,
        "assigned_driver" => inStr("assigned_driver", 190) ?: null,
        "service_interval_days" => inIntOrNull("service_interval_days", 1, 3650),
        "service_interval_km" => inIntOrNull("service_interval_km", 1, 1000000),
        "next_service_due_date" => inDate("next_service_due_date"),
        "next_service_due_km" => inNumOrNull("next_service_due_km", 0),
        "notes" => inText("notes", 5000) ?: null,
    ];
}
/** منع تكرار رقم اللوحة بين الأصول غير المحذوفة (فحص من الخادم) */
function plateTaken(PDO $pdo, ?string $plate, ?string $exceptId = null): bool {
    if (!$plate) return false;
    $st = $pdo->prepare("SELECT id FROM assets WHERE plate_number = ? AND deleted_at IS NULL" . ($exceptId ? " AND id <> ?" : "") . " LIMIT 1");
    $st->execute($exceptId ? [$plate, $exceptId] : [$plate]);
    return (bool)$st->fetch();
}
/** حالة استحقاق الصيانة: overdue | soon | ok | none */
function serviceDueState(array $a): string {
    $today = date("Y-m-d");
    $d = $a["next_service_due_date"] ?? null; $km = $a["next_service_due_km"] ?? null; $odo = (float)($a["odometer_km"] ?? 0);
    if (($d && $d < $today) || ($km !== null && $km !== "" && $odo >= (float)$km)) return "overdue";
    if (($d && $d <= date("Y-m-d", strtotime("+14 days"))) || ($km !== null && $km !== "" && (float)$km - $odo <= 500)) return "soon";
    return ($d || ($km !== null && $km !== "")) ? "ok" : "none";
}
function serviceDuePill(array $a): string {
    $st = serviceDueState($a);
    if ($st === "overdue") return "<span class='pill pill-danger'>صيانة متأخرة</span>";
    if ($st === "soon") return "<span class='pill pill-warn'>صيانة قريبة</span>";
    if ($st === "ok") return "<span class='pill pill-success'>" . e($a["next_service_due_date"] ?: (money($a["next_service_due_km"]) . " كم")) . "</span>";
    return "<span class='pill pill-neutral'>غير محددة</span>";
}

/* ── صورة الآلية: رفع آمن إلى مجلد محمي بالكامل من الوصول المباشر، وتُقدَّم
   فقط عبر index.php لمستخدم مسجَّل الدخول (serveAssetPhoto) ── */
define("ASSET_PHOTO_DIR", "uploads/assets");
define("ASSET_PHOTO_MAX_BYTES", 5 * 1024 * 1024);
function ensureUploadGuard(string $dir): void {
    $root = __DIR__ . "/uploads";
    if (!is_file("$root/.htaccess")) {
        @file_put_contents("$root/.htaccess", "# لا وصول مباشر — الملفات تُقدَّم عبر index.php بعد التحقق من الدخول\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Order allow,deny\n  Deny from all\n</IfModule>\n");
    }
    if (!is_file("$dir/index.html")) @file_put_contents("$dir/index.html", "");
}
function handleAssetPhotoUpload(string $field = "photo"): ?string {
    if (empty($_FILES[$field]) || !is_array($_FILES[$field])) return null;
    $f = $_FILES[$field];
    if (is_array($f["error"])) throw new RuntimeException("طلب رفع غير صالح");
    if ($f["error"] === UPLOAD_ERR_NO_FILE) return null;
    if ($f["error"] === UPLOAD_ERR_INI_SIZE || $f["error"] === UPLOAD_ERR_FORM_SIZE) throw new RuntimeException("حجم الصورة أكبر من الحد المسموح على الخادم");
    if ($f["error"] !== UPLOAD_ERR_OK || !is_uploaded_file($f["tmp_name"])) throw new RuntimeException("فشل رفع الصورة");
    if ($f["size"] > ASSET_PHOTO_MAX_BYTES) throw new RuntimeException("الحد الأقصى لحجم الصورة 5 ميغابايت");
    $info = @getimagesize($f["tmp_name"]); // يفحص المحتوى الفعلي لا الامتداد المُرسَل
    $ext = [IMAGETYPE_JPEG => "jpg", IMAGETYPE_PNG => "png", IMAGETYPE_WEBP => "webp"];
    if (!$info || !isset($ext[$info[2]]) || $info[0] < 1 || $info[0] > 12000 || $info[1] > 12000) throw new RuntimeException("الصيغ المدعومة: JPG أو PNG أو WEBP");
    $dir = __DIR__ . "/" . ASSET_PHOTO_DIR;
    if (!is_dir($dir) && !@mkdir($dir, 0755, true)) throw new RuntimeException("تعذّر إنشاء مجلد الصور — تحقق من صلاحيات الكتابة على الاستضافة");
    ensureUploadGuard($dir);
    $name = uid() . "." . $ext[$info[2]]; // اسم عشوائي يولّده الخادم — لا يُستخدم اسم الملف الأصلي إطلاقاً
    if (!@move_uploaded_file($f["tmp_name"], "$dir/$name")) throw new RuntimeException("تعذّر حفظ الصورة على الخادم");
    @chmod("$dir/$name", 0644);
    return ASSET_PHOTO_DIR . "/" . $name;
}
function assetPhotoFile(?string $path): ?string {
    $base = basename((string)$path);
    if (!preg_match('/^[a-f0-9]{32}\.(jpg|png|webp)$/', $base)) return null;
    $full = __DIR__ . "/" . ASSET_PHOTO_DIR . "/" . $base;
    return is_file($full) ? $full : null;
}
function deleteAssetPhoto(?string $path): void { if ($f = assetPhotoFile($path)) @unlink($f); }
function serveAssetPhoto(PDO $pdo, string $assetId): void {
    $st = $pdo->prepare("SELECT photo_path FROM assets WHERE id = ?"); $st->execute([$assetId]);
    $file = assetPhotoFile(($st->fetch() ?: [])["photo_path"] ?? null);
    if (!$file) { http_response_code(404); exit; }
    $types = ["jpg" => "image/jpeg", "png" => "image/png", "webp" => "image/webp"];
    header("Content-Type: " . $types[pathinfo($file, PATHINFO_EXTENSION)]);
    header("Content-Length: " . filesize($file));
    header("Cache-Control: private, max-age=86400");
    header("X-Content-Type-Options: nosniff");
    readfile($file);
    exit;
}

/* =====================================================================
   مواعيد الصيانة (المتطلب 2) — قواعد العمل كلها هنا في الخادم
   ===================================================================== */
define("APPT_ACTIVE", ["PENDING", "CONFIRMED", "IN_PROGRESS"]);
define("APPT_BLOCKED_ASSET_STATUSES", ["SOLD", "SCRAPPED"]);
define("WEEK_START", 1); // 1 = الاثنين (أسبوع العمل في الإمارات)، 6 = السبت، 0 = الأحد

function apptSlots(): array { return ["MORNING" => "صباحاً", "NOON" => "ظهراً", "EVENING" => "مساءً"]; }
function apptSlotRange(string $slot): array { return ["MORNING" => ["06:00", "12:00"], "NOON" => ["12:00", "17:00"], "EVENING" => ["17:00", "23:59"]][$slot] ?? ["00:00", "23:59"]; }
function apptSlotDefaultTime(string $slot): string { return ["MORNING" => "08:00", "NOON" => "13:00", "EVENING" => "17:30"][$slot] ?? "08:00"; }
function apptSlotFromTime(string $hhmm): string { $h = (int)substr($hhmm, 0, 2); return $h < 12 ? "MORNING" : ($h < 17 ? "NOON" : "EVENING"); }
function apptTypes(): array { return ["PREVENTIVE" => "صيانة وقائية", "CORRECTIVE" => "إصلاح عطل", "INSPECTION" => "فحص", "OTHER" => "أخرى"]; }
function apptStatuses(): array {
    return ["PENDING" => ["warn", "بانتظار التأكيد"], "CONFIRMED" => ["accent", "مؤكَّد"], "IN_PROGRESS" => ["live", "في الورشة"],
            "COMPLETED" => ["success", "مكتمل"], "CANCELLED" => ["neutral", "ملغى"], "NO_SHOW" => ["danger", "لم تحضر الآلية"]];
}
function apptStatusPill(string $s): string { [$c, $l] = apptStatuses()[$s] ?? ["neutral", $s]; return "<span class='pill pill-$c'>" . e($l) . "</span>"; }
/** آلة الحالات: أي انتقال خارج هذه الخريطة يُرفض من الخادم */
function apptTransitions(): array {
    return ["PENDING" => ["CONFIRMED", "CANCELLED"], "CONFIRMED" => ["IN_PROGRESS", "CANCELLED", "NO_SHOW"],
            "IN_PROGRESS" => ["COMPLETED"], "COMPLETED" => [], "CANCELLED" => [], "NO_SHOW" => []];
}
function apptWhenLabel(array $ap): string {
    return arDate($ap["scheduled_date"]) . " · " . ((int)$ap["is_exact_time"] ? date("H:i", strtotime($ap["scheduled_at"])) : (apptSlots()[$ap["preferred_slot"]] ?? ""));
}

/** يقرأ ويتحقق من (التاريخ + الفترة/الوقت) — يعيد [بيانات, رسالة خطأ] */
function apptParseWhen(): array {
    $date = inDate("scheduled_date");
    $slotIn = inEnum("slot", ["MORNING", "NOON", "EVENING", "CUSTOM"], null);
    if (!$date) return [null, "اختر تاريخاً صحيحاً للموعد"];
    if (!$slotIn) return [null, "اختر فترة الموعد"];
    $today = date("Y-m-d");
    if ($date < $today) return [null, "لا يمكن حجز موعد في تاريخ ماضٍ"];
    if ($date > date("Y-m-d", strtotime("+365 days"))) return [null, "أقصى مدى للحجز سنة واحدة"];
    if ($slotIn === "CUSTOM") {
        $time = trim(postVal("time"));
        if (!preg_match('/^([01]\d|2[0-3]):[0-5]\d$/', $time)) return [null, "أدخل وقتاً صحيحاً (مثال 09:30)"];
        $slot = apptSlotFromTime($time); $exact = 1;
        if ($date === $today && $time <= date("H:i")) return [null, "هذا الوقت مضى اليوم — اختر وقتاً لاحقاً"];
    } else {
        $slot = $slotIn; $time = apptSlotDefaultTime($slot); $exact = 0;
        if ($date === $today && date("H:i") >= apptSlotRange($slot)[1]) return [null, "فترة «" . apptSlots()[$slot] . "» انتهت اليوم — اختر فترة أو يوماً آخر"];
    }
    return [["date" => $date, "slot" => $slot, "at" => "$date $time:00", "exact" => $exact], null];
}
/** قفل صف الأصل داخل المعاملة: يمنع حجزين متزامنين لنفس الآلية من تجاوز فحص التعارض معاً */
function lockAsset(PDO $pdo, string $assetId): ?array {
    $st = $pdo->prepare("SELECT * FROM assets WHERE id = ? FOR UPDATE"); $st->execute([$assetId]);
    return $st->fetch() ?: null;
}
function assertAssetBookable(?array $asset): void {
    if (!$asset || $asset["deleted_at"]) throw new RuntimeException("الآلية غير موجودة أو محذوفة — لا يمكن حجز موعد لها");
    if (in_array($asset["status"], APPT_BLOCKED_ASSET_STATUSES, true)) throw new RuntimeException("لا يمكن حجز موعد لآلية بحالة «" . (assetStatusLabels()[$asset["status"]] ?? $asset["status"]) . "»");
}
function apptConflict(PDO $pdo, string $assetId, string $date, string $slot, ?string $exceptId = null): ?array {
    $st = $pdo->prepare("SELECT appt_number FROM maintenance_appointments WHERE asset_id = ? AND scheduled_date = ? AND preferred_slot = ? AND status IN ('PENDING','CONFIRMED','IN_PROGRESS')" . ($exceptId ? " AND id <> ?" : "") . " LIMIT 1");
    $st->execute($exceptId ? [$assetId, $date, $slot, $exceptId] : [$assetId, $date, $slot]);
    return $st->fetch() ?: null;
}
function techConflict(PDO $pdo, string $techId, string $date, string $slot, ?string $exceptId = null): ?array {
    $st = $pdo->prepare("SELECT appt_number FROM maintenance_appointments WHERE assigned_technician = ? AND scheduled_date = ? AND preferred_slot = ? AND status IN ('CONFIRMED','IN_PROGRESS')" . ($exceptId ? " AND id <> ?" : "") . " LIMIT 1");
    $st->execute($exceptId ? [$techId, $date, $slot, $exceptId] : [$techId, $date, $slot]);
    return $st->fetch() ?: null;
}
function validTechnician(PDO $pdo, string $techId): bool {
    $st = $pdo->prepare("SELECT id FROM users WHERE id = ? AND role = 'TECHNICIAN' AND is_active = 1"); $st->execute([$techId]);
    return (bool)$st->fetch();
}
/** تغيير حالة الموعد: يتحقق من آلة الحالات ويسجّل في audit_logs دائماً */
function apptMove(PDO $pdo, array $ap, string $target, array $extra, string $userId, string $note = ""): void {
    if (!in_array($target, apptTransitions()[$ap["status"]] ?? [], true)) {
        throw new RuntimeException("انتقال غير مسموح: من «" . apptStatuses()[$ap["status"]][1] . "» إلى «" . (apptStatuses()[$target][1] ?? $target) . "»");
    }
    $sets = ["status = ?"]; $params = [$target];
    foreach ($extra as $col => $val) { $sets[] = "`$col` = ?"; $params[] = $val; }
    $params[] = $ap["id"];
    $pdo->prepare("UPDATE maintenance_appointments SET " . implode(", ", $sets) . " WHERE id = ?")->execute($params);
    logAudit($pdo, $userId, "STATUS_CHANGE", "Appointment", $ap["id"], "{$ap['appt_number']}: {$ap['status']} -> $target" . ($note !== "" ? " · $note" : ""));
}
/** ينشئ أمر شغل «مسودة» مربوطاً بالموعد (نفس جدول وترقيم أوامر الشغل الحالية) */
function createWoFromAppointment(PDO $pdo, array $ap, ?string $techId, string $userId): string {
    $woType = ["PREVENTIVE" => "PREVENTIVE", "INSPECTION" => "PREVENTIVE", "CORRECTIVE" => "CORRECTIVE", "OTHER" => "CORRECTIVE"][$ap["service_type"]] ?? "CORRECTIVE";
    $id = uid(); $num = "WO-" . date("Y") . "-" . random_int(100000, 999999);
    $desc = "موعد صيانة " . $ap["appt_number"] . " — " . (apptTypes()[$ap["service_type"]] ?? "") . " (" . $ap["scheduled_date"] . ")" . (trim((string)$ap["description"]) !== "" ? "\n" . $ap["description"] : "");
    $pdo->prepare("INSERT INTO work_orders (id, wo_number, asset_id, type, description, technician_id) VALUES (?,?,?,?,?,?)")
        ->execute([$id, $num, $ap["asset_id"], $woType, $desc, $techId ?: null]);
    $pdo->prepare("UPDATE maintenance_appointments SET linked_work_order_id = ? WHERE id = ?")->execute([$id, $ap["id"]]);
    logAudit($pdo, $userId, "CREATE", "WorkOrder", $id, "$num من الموعد " . $ap["appt_number"]);
    return $num;
}

/* =====================================================================
   "تذكرني" — رمز (selector:validator) مع تخزين بصمة SHA-256 فقط، وتدوير
   الرمز عند كل استخدام. ضروري لتجربة آيفون: تطبيق الشاشة الرئيسية يفقد
   كوكي الجلسة كلما أُغلق، فيُطلب الدخول في كل مرة بدون هذه الآلية.
   ===================================================================== */
define("REMEMBER_COOKIE", "fms_remember");
define("REMEMBER_DAYS", 30);
function setRememberCookie(string $value, int $expires): void {
    setcookie(REMEMBER_COOKIE, $value, ["expires" => $expires, "path" => "/", "secure" => isHttpsRequest(), "httponly" => true, "samesite" => "Lax"]);
}
function issueRememberToken(PDO $pdo, string $userId): void {
    $selector = bin2hex(random_bytes(12)); $validator = bin2hex(random_bytes(32));
    $exp = time() + REMEMBER_DAYS * 86400;
    $pdo->prepare("INSERT INTO auth_tokens (selector, validator_hash, user_id, user_agent, expires_at) VALUES (?,?,?,?,?)")
        ->execute([$selector, hash("sha256", $validator), $userId, strCut((string)($_SERVER["HTTP_USER_AGENT"] ?? ""), 190), date("Y-m-d H:i:s", $exp)]);
    setRememberCookie("$selector:$validator", $exp);
}
function clearRememberToken(PDO $pdo): void {
    $c = (string)($_COOKIE[REMEMBER_COOKIE] ?? "");
    if (strpos($c, ":") !== false) $pdo->prepare("DELETE FROM auth_tokens WHERE selector = ?")->execute([explode(":", $c, 2)[0]]);
    setRememberCookie("", time() - 3600);
}
function tryRememberLogin(PDO $pdo): void {
    $c = (string)($_COOKIE[REMEMBER_COOKIE] ?? "");
    if (!preg_match('/^([a-f0-9]{24}):([a-f0-9]{64})$/', $c, $m)) return;
    $st = $pdo->prepare("SELECT * FROM auth_tokens WHERE selector = ? AND expires_at > NOW()"); $st->execute([$m[1]]);
    $tok = $st->fetch();
    if (!$tok) { setRememberCookie("", time() - 3600); return; }
    if (!hash_equals($tok["validator_hash"], hash("sha256", $m[2]))) {
        // selector صحيح ومُحقِّق خاطئ = احتمال سرقة رمز: نُبطل كل رموز هذا المستخدم
        $pdo->prepare("DELETE FROM auth_tokens WHERE user_id = ?")->execute([$tok["user_id"]]);
        setRememberCookie("", time() - 3600); return;
    }
    $pdo->prepare("DELETE FROM auth_tokens WHERE id = ?")->execute([$tok["id"]]);
    $u = $pdo->prepare("SELECT * FROM users WHERE id = ? AND is_active = 1"); $u->execute([$tok["user_id"]]); $u = $u->fetch();
    if (!$u) { setRememberCookie("", time() - 3600); return; }
    session_regenerate_id(true);
    $_SESSION["user"] = ["id" => $u["id"], "username" => $u["username"], "full_name" => $u["full_name"], "role" => $u["role"]];
    issueRememberToken($pdo, $u["id"]); // تدوير
    $pdo->prepare("DELETE FROM auth_tokens WHERE user_id = ? AND expires_at < NOW()")->execute([$u["id"]]);
    logAudit($pdo, $u["id"], "LOGIN", "User", $u["id"], "remember-me");
}

/**
 * paginate() — Pagination حقيقية على مستوى SQL، لا تحميل الجدول كاملاً.
 * $countSql/$dataSql يجب أن يستخدما نفس شرط WHERE ونفس $params بالضبط.
 * $pageSize و$page يُحوَّلان لأعداد صحيحة صراحة قبل إدراجهما في نص LIMIT/OFFSET
 * (لا استيفاء لأي قيمة قادمة من المستخدم مباشرة) — آمن تماماً من SQL Injection.
 */
function paginate(PDO $pdo, string $countSql, string $dataSql, array $params = [], int $pageSize = 20): array {
    $page = max(1, (int)($_GET["p"] ?? 1));
    $countStmt = $pdo->prepare($countSql);
    $countStmt->execute($params);
    $total = (int)$countStmt->fetch()["c"];
    $totalPages = max(1, (int)ceil($total / $pageSize));
    $page = min($page, $totalPages);
    $offset = ($page - 1) * $pageSize;

    $stmt = $pdo->prepare($dataSql . " LIMIT " . (int)$pageSize . " OFFSET " . (int)$offset);
    $stmt->execute($params);
    return ["items" => $stmt->fetchAll(), "total" => $total, "page" => $page, "totalPages" => $totalPages, "pageSize" => $pageSize];
}

/** يرسم شريط أرقام صفحات بسيطاً، محافظاً على أي معاملات GET أخرى في الرابط (page=assets مثلاً). */
function paginationLinks(array $result): string {
    if ($result["totalPages"] <= 1) return "";
    $baseParams = $_GET;
    unset($baseParams["p"]);
    $html = "<div class='pagination'>";
    for ($i = 1; $i <= $result["totalPages"]; $i++) {
        $params = $baseParams; $params["p"] = $i;
        $qs = http_build_query($params);
        $html .= "<a class='page-link" . ($i === $result["page"] ? " is-active" : "") . "' href='index.php?$qs'>$i</a>";
    }
    $html .= "</div>";
    return $html;
}

/* =====================================================================
   نظام التصميم — CSS واحد مُضمَّن، يُستخدَم في كل الشاشات
   ===================================================================== */
function icon(string $name): string {
    $paths = [
        "dashboard" => '<rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/>',
        "assets" => '<path d="M3 13h4l2-6h6l2 6h4"/><rect x="5" y="13" width="14" height="6" rx="1"/><circle cx="8.5" cy="19.5" r="1.5"/><circle cx="15.5" cy="19.5" r="1.5"/>',
        "workorders" => '<rect x="4" y="4" width="16" height="16" rx="2"/><path d="M8 9h8M8 13h5"/>',
        "inventory" => '<path d="M3 7l9-4 9 4-9 4-9-4Z"/><path d="M3 7v10l9 4 9-4V7"/><path d="M12 11v10"/>',
        "tco" => '<path d="M3 3v18h18"/><path d="m7 14 4-4 3 3 5-6"/>',
        "auctions" => '<path d="M14 4l6 6-9 9-6-6z"/><path d="m3 21 3-3"/><path d="M12 7l5 5"/>',
        "users" => '<circle cx="9" cy="8" r="3.5"/><path d="M2 20c0-3.5 3-6 7-6s7 2.5 7 6"/><circle cx="17" cy="8" r="2.5"/><path d="M16.5 14.2c2.5.5 4.5 2.6 4.5 5.8"/>',
        "audit" => '<path d="M9 3h6l3 3v15H6V6z"/><path d="M9 3v4h6"/><path d="M9 13h6M9 17h4"/>',
        "help" => '<circle cx="12" cy="12" r="9"/><path d="M9.5 9a2.5 2.5 0 0 1 5 0c0 1.5-2 2-2 3.5"/><circle cx="12" cy="17" r=".6" fill="currentColor"/>',
        "logout" => '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>',
        "plus" => '<path d="M12 5v14M5 12h14"/>',
        "edit" => '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
        "trash" => '<path d="M4 7h16"/><path d="M6 7V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v2"/><path d="m7 7 1 13h8l1-13"/>',
        "check" => '<path d="m5 12 5 5 9-10"/>',
        "arrow" => '<path d="M19 12H5"/><path d="m11 18-6-6 6-6"/>',
        "back" => '<path d="M19 12H5"/><path d="m11 18-6-6 6-6"/>',
        "gavel" => '<path d="M14 4l6 6-9 9-6-6z"/><path d="m3 21 3-3"/><path d="M12 7l5 5"/>',
        "install" => '<path d="M12 3v13"/><path d="m7 12 5 5 5-5"/><path d="M5 21h14"/>',
        "documents" => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M9 15h6M9 11h6"/>',
        "print" => '<path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><path d="M6 14h12v8H6z"/>',
        "appointments" => '<rect x="3" y="5" width="18" height="16" rx="2.5"/><path d="M3 10h18M8 3v4M16 3v4"/><path d="m9 15 2 2 4-4"/>',
        "calendar-plus" => '<rect x="3" y="5" width="18" height="16" rx="2.5"/><path d="M3 10h18M8 3v4M16 3v4M12 13v5M9.5 15.5h5"/>',
        "wrench" => '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4z"/>',
        "clock" => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        "more" => '<circle cx="5" cy="12" r="1.6" fill="currentColor"/><circle cx="12" cy="12" r="1.6" fill="currentColor"/><circle cx="19" cy="12" r="1.6" fill="currentColor"/>',
        "chev-back" => '<path d="m9 18 6-6-6-6"/>',
        "chev-fwd" => '<path d="m15 18-6-6 6-6"/>',
        "share-ios" => '<path d="M12 3v12"/><path d="m8 7 4-4 4 4"/><path d="M7 11H6a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-1"/>',
        "add-square" => '<rect x="3" y="3" width="18" height="18" rx="4"/><path d="M12 8v8M8 12h8"/>',
        "install-app" => '<rect x="6" y="2" width="12" height="20" rx="3"/><path d="M12 7v7m-3-3 3 3 3-3M10 18h4"/>',
    ];
    $p = $paths[$name] ?? "";
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" class="ic" aria-hidden="true" focusable="false">' . $p . '</svg>';
}

function pwaHeadTags(): string {
    // شاشات الإقلاع في iOS: بدونها يظهر وميض أبيض عند فتح التطبيق من الشاشة الرئيسية
    $splash = "";
    foreach ([[440,956,3],[402,874,3],[420,912,3],[430,932,3],[393,852,3],[428,926,3],[390,844,3],[375,812,3],[414,896,3],[414,896,2],[375,667,2],[744,1133,2],[820,1180,2],[834,1194,2],[1024,1366,2]] as [$w, $h, $r]) {
        $splash .= "\n    <link rel=\"apple-touch-startup-image\" media=\"(device-width: {$w}px) and (device-height: {$h}px) and (-webkit-device-pixel-ratio: $r) and (orientation: portrait)\" href=\"./icons/splash/splash-" . ($w * $r) . "x" . ($h * $r) . ".png\">";
    }
    return '<link rel="manifest" href="./manifest.json">
    <meta name="theme-color" content="#070b14">
    <meta name="color-scheme" content="dark">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
    <meta name="apple-mobile-web-app-title" content="إدارة الأسطول">
    <meta name="format-detection" content="telephone=no">
    <link rel="apple-touch-icon" href="./icons/apple-touch-icon.png">
    <link rel="apple-touch-icon" sizes="152x152" href="./icons/apple-touch-icon-152.png">
    <link rel="apple-touch-icon" sizes="167x167" href="./icons/apple-touch-icon-167.png">
    <link rel="apple-touch-icon" sizes="180x180" href="./icons/apple-touch-icon.png">
    <link rel="icon" href="./icons/icon-192.png">' . $splash . '
    <script>(function(){var d=document.documentElement,s=window.matchMedia("(display-mode: standalone)").matches||navigator.standalone===true;if(s)d.classList.add("is-standalone");var ua=navigator.userAgent;if(/iphone|ipad|ipod/i.test(ua)||(/Macintosh/.test(ua)&&navigator.maxTouchPoints>1))d.classList.add("is-ios");})();</script>';
}

/** ورقة تعليمات التثبيت (Bottom Sheet) — تُضمَّن في كل الصفحات بما فيها تسجيل الدخول */
function installSheetHtml(): string {
    return '<div class="sheet-backdrop" id="install-sheet" hidden>
      <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="install-title">
        <div class="sheet-grabber" aria-hidden="true"></div>
        <div class="sheet-head"><img src="./icons/icon-180.png" alt="" width="56" height="56"><div><b id="install-title">أضف «إدارة الأسطول» إلى الشاشة الرئيسية</b><span>يفتح كتطبيق مستقل بملء الشاشة</span></div></div>
        <div data-install-ios>
          <ol class="install-steps">
            <li><span class="step-n">1</span><div>اضغط زر <b>المشاركة</b> ' . icon("share-ios") . ' في سفاري <small>(في iOS 26: داخل زر ⋯ أسفل الشاشة)</small></div></li>
            <li><span class="step-n">2</span><div>اختر <b>«إضافة إلى الشاشة الرئيسية»</b> ' . icon("add-square") . '</div></li>
            <li><span class="step-n">3</span><div>اضغط <b>«إضافة»</b> — ثم افتح التطبيق من أيقونته</div></li>
          </ol>
          <p class="sheet-note" data-install-inapp hidden>أنت داخل متصفح تطبيق آخر (واتساب/إنستغرام...) — افتح الرابط في <b>سفاري</b> أولاً ثم اتبع الخطوات.</p>
          <div class="sheet-pointer" aria-hidden="true">' . icon("arrow") . '</div>
        </div>
        <div data-install-other hidden>
          <ol class="install-steps">
            <li><span class="step-n">1</span><div>افتح قائمة المتصفح <b>⋮</b></div></li>
            <li><span class="step-n">2</span><div>اختر <b>«تثبيت التطبيق»</b> أو <b>«إضافة إلى الشاشة الرئيسية»</b></div></li>
          </ol>
        </div>
        <button class="btn btn-primary btn-block" type="button" data-sheet-close>فهمت</button>
      </div>
    </div>';
}

/**
 * chatbaseWidgetScript() — ودجت الدعم الفني (Chatbase). يُحمَّل بعد
 * اكتمال تحميل الصفحة (window.addEventListener("load", ...)) كي لا
 * يُبطئ أول ظهور لبيانات النظام. أُصلِح هنا خطأ حقيقي كان في الكود
 * الأصلي المُرسَل: قيمة script.domain كانت رابط Markdown
 * "[www.chatbase.co](https://www.chatbase.co)" بدل النص الصحيح
 * "www.chatbase.co" — على الأرجح انتقل هكذا أثناء نسخه من مكان يحوّل
 * الروابط تلقائياً. لو تُرِك كما وصل، لن يتعرّف Chatbase على النطاق.
 */
function chatbaseWidgetScript(): string {
    return '<script>
    (function(){
      if(!window.chatbase||window.chatbase("getState")!=="initialized"){
        window.chatbase=(...arguments)=>{if(!window.chatbase.q){window.chatbase.q=[]}window.chatbase.q.push(arguments)};
        window.chatbase=new Proxy(window.chatbase,{get(target,prop){if(prop==="q"){return target.q}return(...args)=>target(prop,...args)}})
      }
      const onLoad=function(){
        const script=document.createElement("script");
        script.src="https://www.chatbase.co/embed.min.js";
        script.id="Abl3pvvT_mfxiiDOp1S6Z";
        script.domain="www.chatbase.co";
        document.body.appendChild(script)
      };
      if(document.readyState==="complete"){onLoad()}else{window.addEventListener("load",onLoad)}
    })();
    </script>';
}

/**
 * pwaRegisterScript() — تسجيل عامل الخدمة + منطق التثبيت + مدير الأوراق السفلية.
 * أندرويد: يبقى beforeinstallprompt كما هو (مربع التثبيت الأصلي).
 * آيفون: سفاري لا يدعم ذلك الحدث (قيد من أبل)، فنعرض ورقة تعليمات أنيقة بدل alert().
 */
function pwaRegisterScript(): string {
    return <<<'JS'
<script>
if ("serviceWorker" in navigator) { navigator.serviceWorker.register("./sw.js").catch(function(){}); }
var deferredPrompt = null;
function fmsIsStandalone(){ return window.matchMedia("(display-mode: standalone)").matches || window.navigator.standalone === true; }
function fmsIsIOS(){ var ua = navigator.userAgent; return /iphone|ipad|ipod/i.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1); }
function fmsIsInApp(){ return /FBAN|FBAV|Instagram|Line\/|Snapchat|TikTok|MicroMessenger|WhatsApp/i.test(navigator.userAgent); }
function fmsShowInstallUi(show){
  var fab = document.getElementById("pwa-install-btn");
  var hiddenUntil = 0; try { hiddenUntil = +localStorage.getItem("fms_fab_hidden_until") || 0; } catch(e){}
  if (fab) fab.style.display = (show && Date.now() > hiddenUntil) ? "flex" : "none";
  document.querySelectorAll("[data-install-open]").forEach(function(b){ if (show) b.removeAttribute("hidden"); });
}
window.addEventListener("beforeinstallprompt", function (e) { e.preventDefault(); deferredPrompt = e; fmsShowInstallUi(true); });
window.addEventListener("appinstalled", function () { deferredPrompt = null; fmsShowInstallUi(false); fmsCloseSheet(document.getElementById("install-sheet")); });

/* ── الأوراق السفلية (Bottom Sheets) بأسلوب iOS: فتح/إغلاق/سحب للأسفل ── */
function fmsOpenSheet(el){
  if (!el) return;
  el.hidden = false; document.body.classList.add("sheet-open");
  requestAnimationFrame(function(){ requestAnimationFrame(function(){ el.classList.add("is-open"); }); });
  var f = el.querySelector("button, a"); if (f) setTimeout(function(){ f.focus({preventScroll:true}); }, 320);
}
function fmsCloseSheet(el){
  if (!el || el.hidden) return;
  el.classList.remove("is-open"); var s = el.querySelector(".sheet"); if (s) s.style.transform = "";
  setTimeout(function(){ el.hidden = true; if (!document.querySelector(".sheet-backdrop.is-open")) document.body.classList.remove("sheet-open"); }, 280);
}
function fmsInstallApp(){
  if (deferredPrompt) { deferredPrompt.prompt(); deferredPrompt.userChoice.finally(function(){ deferredPrompt = null; }); return; }
  var sheet = document.getElementById("install-sheet"); if (!sheet) return;
  var ios = fmsIsIOS();
  sheet.querySelector("[data-install-ios]").hidden = !ios;
  sheet.querySelector("[data-install-other]").hidden = ios;
  sheet.querySelector("[data-install-inapp]").hidden = !(ios && fmsIsInApp());
  fmsOpenSheet(sheet);
}
document.addEventListener("click", function(e){
  var t = e.target;
  if (t.closest("[data-install-open]")) { e.preventDefault(); fmsCloseSheet(document.getElementById("more-sheet")); setTimeout(fmsInstallApp, 50); return; }
  if (t.closest("[data-fab-dismiss]")) { try { localStorage.setItem("fms_fab_hidden_until", Date.now() + 14 * 864e5); } catch(err){} document.getElementById("pwa-install-btn").style.display = "none"; return; }
  if (t.closest("[data-open-more]")) { e.preventDefault(); fmsOpenSheet(document.getElementById("more-sheet")); return; }
  if (t.closest("[data-sheet-close]") || t.classList.contains("sheet-backdrop")) { fmsCloseSheet(t.closest(".sheet-backdrop")); }
});
document.addEventListener("keydown", function(e){ if (e.key === "Escape") document.querySelectorAll(".sheet-backdrop.is-open").forEach(fmsCloseSheet); });
/* سحب الورقة للأسفل لإغلاقها */
document.addEventListener("touchstart", function(e){
  var sheet = e.target.closest && e.target.closest(".sheet"); if (!sheet || sheet.scrollTop > 0) return;
  var y0 = e.touches[0].clientY, dy = 0;
  function mv(ev){ dy = Math.max(0, ev.touches[0].clientY - y0); sheet.style.transition = "none"; sheet.style.transform = "translateY(" + dy + "px)"; }
  function up(){ sheet.style.transition = ""; document.removeEventListener("touchmove", mv); document.removeEventListener("touchend", up);
    if (dy > 90) fmsCloseSheet(sheet.closest(".sheet-backdrop")); else sheet.style.transform = ""; }
  document.addEventListener("touchmove", mv, {passive:true}); document.addEventListener("touchend", up);
}, {passive:true});

document.addEventListener("DOMContentLoaded", function () {
  if (fmsIsStandalone()) {
    document.documentElement.classList.add("is-standalone");
    document.querySelectorAll("[data-installed-note]").forEach(function(n){ n.hidden = false; });
    return;
  }
  if (fmsIsIOS()) fmsShowInstallUi(true);
});
</script>
JS;
}

/** سلوكيات الواجهة داخل التطبيق (بعد تسجيل الدخول) — JavaScript خفيف بلا مكتبات */
function appUiScript(): string {
    return <<<'JS'
<script>
(function(){
  var html = document.documentElement;
  /* تأكيد العمليات الحساسة (data-confirm) */
  document.querySelectorAll("form[data-confirm]").forEach(function (el) {
    el.addEventListener("submit", function (ev) { if (!confirm(el.getAttribute("data-confirm"))) ev.preventDefault(); });
  });
  /* منع الإرسال المزدوج: يُعطَّل الزر بعد لحظة (كي تُرسَل قيمته أولاً) مع مؤشر تحميل */
  document.addEventListener("submit", function (ev) {
    if (ev.defaultPrevented) return;
    var f = ev.target;
    if (f.dataset.submitting) { ev.preventDefault(); return; }
    f.dataset.submitting = "1";
    var btn = ev.submitter || f.querySelector("button[type=submit]");
    setTimeout(function(){ f.querySelectorAll("button[type=submit]").forEach(function(b){ b.disabled = true; }); if (btn) btn.classList.add("is-loading"); }, 0);
    if (f.method.toLowerCase() === "post") html.classList.add("is-navigating");
  });
  /* عند العودة بزر الرجوع (bfcache) نعيد تفعيل الأزرار */
  window.addEventListener("pageshow", function(){
    html.classList.remove("is-navigating");
    document.querySelectorAll("form[data-submitting]").forEach(function(f){ delete f.dataset.submitting; f.querySelectorAll("button[type=submit]").forEach(function(b){ b.disabled = false; b.classList.remove("is-loading"); }); });
  });
  /* شريط تقدّم رفيع عند التنقل بين الصفحات */
  document.addEventListener("click", function(e){
    var a = e.target.closest && e.target.closest("a[href]");
    if (!a || a.target || e.metaKey || e.ctrlKey || e.shiftKey || a.getAttribute("href").charAt(0) === "#" || a.hasAttribute("data-open-more") || a.hasAttribute("data-install-open")) return;
    if (a.origin === location.origin) html.classList.add("is-navigating");
  });
  /* روابط تفتح <details> (مثل زر «تعديل») */
  document.querySelectorAll("[data-open-details]").forEach(function(a){
    a.addEventListener("click", function(){ var d = document.getElementById(a.getAttribute("data-open-details")); if (d) d.open = true; });
  });
  /* الشريط العلوي: يظهر العنوان الصغير بعد تمرير العنوان الكبير (Large Title) */
  var bar = document.querySelector(".ios-topbar");
  if (bar) { var onS = function(){ bar.classList.toggle("is-scrolled", window.scrollY > 36); }; window.addEventListener("scroll", onS, {passive:true}); onS(); }

  /* السحب للتحديث — فقط في وضع التطبيق المثبَّت (لا يوجد زر تحديث هناك) */
  var ptr = document.getElementById("ptr");
  if (ptr && (window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true)) {
    var y0 = null, d = 0;
    window.addEventListener("touchstart", function(e){
      if (window.scrollY > 0 || document.body.classList.contains("sheet-open") || e.target.closest(".panel .body, .chips, .week-grid, input, textarea, select")) { y0 = null; return; }
      y0 = e.touches[0].clientY; d = 0;
    }, {passive:true});
    window.addEventListener("touchmove", function(e){
      if (y0 === null) return; d = e.touches[0].clientY - y0; if (d <= 0) return;
      var p = Math.min(d, 110);
      ptr.style.opacity = Math.min(1, p / 70); ptr.style.transform = "translateY(" + (p * .7 - 50) + "px)";
      ptr.classList.toggle("is-ready", d > 85);
    }, {passive:true});
    window.addEventListener("touchend", function(){
      if (y0 === null) return; y0 = null;
      if (d > 85) { ptr.classList.add("is-loading"); ptr.style.transform = "translateY(22px)"; location.reload(); }
      else { ptr.style.opacity = 0; ptr.style.transform = ""; ptr.classList.remove("is-ready"); }
    });
  }

  /* تصغير الصورة في المتصفح قبل الرفع — يوفّر بيانات الجوال ويتجاوز حد الرفع في الاستضافة المشتركة */
  document.querySelectorAll("input[type=file][data-resize]").forEach(function(inp){
    inp.addEventListener("change", function(){
      var file = inp.files && inp.files[0]; var max = +inp.getAttribute("data-resize") || 1600;
      if (!file || !/^image\//.test(file.type) || typeof DataTransfer === "undefined") return;
      var img = new Image(), url = URL.createObjectURL(file);
      img.onload = function(){
        URL.revokeObjectURL(url);
        var sc = Math.min(1, max / Math.max(img.naturalWidth, img.naturalHeight));
        if (sc === 1 && file.size < 900 * 1024) return;
        var c = document.createElement("canvas"); c.width = Math.round(img.naturalWidth * sc); c.height = Math.round(img.naturalHeight * sc);
        c.getContext("2d").drawImage(img, 0, 0, c.width, c.height);
        c.toBlob(function(b){ if (!b) return; try { var dt = new DataTransfer(); dt.items.add(new File([b], (file.name || "photo").replace(/\.\w+$/, "") + ".jpg", {type: "image/jpeg"})); inp.files = dt.files; } catch(e){} }, "image/jpeg", .85);
      };
      img.src = url;
    });
  });

  /* نموذج المواعيد: إظهار حقل الوقت + تنبيه فوري بالتعارض (القرار النهائي من الخادم) */
  document.querySelectorAll("form").forEach(function(form){
    var radios = form.querySelectorAll("[data-appt-slot]"); if (!radios.length) return;
    var timeF = form.querySelector("[data-time-field]"), dateI = form.querySelector("[data-appt-date]"), assetS = form.querySelector("[data-appt-asset]"), warn = form.querySelector("[data-appt-warning]");
    var names = {MORNING: "الصباحية", NOON: "الظهر", EVENING: "المسائية"};
    function slotOf(){ var r = form.querySelector("[data-appt-slot]:checked"); if (!r) return null; if (r.value !== "CUSTOM") return r.value; var t = (form.querySelector("[name=time]") || {}).value || ""; var h = parseInt(t, 10); return isNaN(h) ? null : (h < 12 ? "MORNING" : (h < 17 ? "NOON" : "EVENING")); }
    function upd(){
      var r = form.querySelector("[data-appt-slot]:checked"); if (timeF) timeF.hidden = !(r && r.value === "CUSTOM");
      if (!warn || !assetS || !window.FMS_BUSY) return;
      var busy = (window.FMS_BUSY[assetS.value] || {})[dateI.value] || {};
      radios.forEach(function(x){ x.closest("label").classList.toggle("is-busy", !!busy[x.value]); });
      var s = slotOf(), hit = s && busy[s];
      warn.hidden = !hit; if (hit) warn.textContent = "تنبيه: للآلية موعد آخر (" + hit + ") في الفترة " + names[s] + " من هذا اليوم — اختر فترة أو يوماً آخر.";
    }
    form.addEventListener("change", upd); form.addEventListener("input", upd); upd();
  });
})();
</script>
JS;
}

function pageStyles(): string {
    return <<<'CSS'
    :root{
      --bg:#070b14;
      --bg-elevated:#0c1220;
      --surface:rgba(15,23,42,.72);
      --surface-solid:#0f172a;
      --surface-alt:rgba(30,41,59,.55);
      --border:rgba(56,189,248,.12);
      --border-strong:rgba(56,189,248,.28);
      --ink-950:#020617;
      --ink-900:#0f172a;
      --text-primary:#e2e8f0;
      --text-secondary:#94a3b8;
      --text-tertiary:#64748b;
      --accent:#22d3ee;
      --accent-hover:#67e8f9;
      --accent-bg:rgba(34,211,238,.12);
      --purple:#a855f7;
      --success:#34d399;
      --success-bg:rgba(52,211,153,.12);
      --warning:#fbbf24;
      --warning-bg:rgba(251,191,36,.12);
      --danger:#f87171;
      --danger-bg:rgba(248,113,113,.12);
      --neutral:#64748b;
      --neutral-bg:rgba(100,116,139,.15);
      --radius-s:10px;
      --radius-m:16px;
      --sidebar-w:250px;
    }
    *{box-sizing:border-box;margin:0;padding:0}
    html{scroll-behavior:smooth}
    body{
      background:var(--bg);
      color:var(--text-primary);
      font-family:system-ui,-apple-system,'Segoe UI',Tahoma,sans-serif;
      font-size:14px;line-height:1.65;min-height:100vh;
      background-image:
        radial-gradient(ellipse 80% 50% at 50% -20%, rgba(34,211,238,.08), transparent),
        linear-gradient(rgba(34,211,238,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34,211,238,.03) 1px, transparent 1px);
      background-size:100% 100%, 48px 48px, 48px 48px;
      background-attachment:fixed;
    }
    a{color:inherit;text-decoration:none}
    table{border-collapse:collapse;width:100%}
    input,select,textarea,button{font:inherit;color:inherit}
    ::selection{background:rgba(34,211,238,.3);color:#fff}

    .app{display:flex;min-height:100vh}
    .sidebar{
      width:var(--sidebar-w);
      background:linear-gradient(180deg,#060a12 0%,#0a1020 100%);
      border-left:1px solid var(--border);
      color:#e2e8f0;display:flex;flex-direction:column;
      position:sticky;top:0;height:100vh;
      box-shadow:-8px 0 32px rgba(0,0,0,.4);
    }
    .brand{
      padding:22px 20px;font-weight:700;font-size:1.1rem;
      border-bottom:1px solid var(--border);
      display:flex;align-items:center;gap:10px;
    }
    .brand::before{
      content:"";width:10px;height:10px;border-radius:50%;
      background:var(--accent);box-shadow:0 0 12px var(--accent);flex:none;
    }
    .brand span{display:block;font-size:.7rem;color:var(--text-tertiary);font-weight:400;margin-top:3px}
    .sidebar nav{flex:1;padding:14px 12px;display:flex;flex-direction:column;gap:4px;overflow-y:auto}
    .nav-item{
      padding:11px 14px;border-radius:12px;color:var(--text-secondary);font-size:.86rem;
      display:flex;align-items:center;gap:12px;transition:all .2s ease;
    }
    .nav-item svg{width:18px;height:18px;flex:none;opacity:.75}
    .nav-item:hover{background:rgba(34,211,238,.08);color:#fff}
    .nav-item:hover svg{opacity:1}
    .nav-item.is-active{
      background:linear-gradient(135deg,rgba(34,211,238,.18),rgba(168,85,247,.12));
      color:var(--accent);font-weight:600;
      box-shadow:inset 0 0 0 1px rgba(34,211,238,.25);
    }
    .nav-item.is-active svg{opacity:1;filter:drop-shadow(0 0 4px rgba(34,211,238,.6))}
    .sidebar-footer{padding:16px 18px;border-top:1px solid var(--border)}
    .role-name{font-size:.84rem;font-weight:600;color:#e2e8f0}
    .role-name span{display:block;font-size:.7rem;color:var(--text-tertiary);font-weight:400;margin-top:3px}
    .logout-link{display:inline-block;margin-top:12px;font-size:.78rem;color:var(--accent);opacity:.85}
    .logout-link:hover{opacity:1}
    .main{flex:1;padding:28px 32px;max-width:1280px}

    h1{font-size:1.45rem;margin-bottom:6px;font-weight:700;color:#f1f5f9}
    h2{font-size:1.1rem;margin:18px 0 10px;font-weight:600;color:#e2e8f0}
    .sub{color:var(--text-secondary);font-size:.88rem;margin-bottom:22px}
    .page-sub{color:var(--text-secondary);font-size:.88rem;margin-bottom:22px}

    .card,.panel{
      background:var(--surface);backdrop-filter:blur(16px);
      border:1px solid var(--border);border-radius:var(--radius-m);
      box-shadow:0 4px 24px rgba(0,0,0,.25);
    }
    .panel{padding:0;overflow:hidden}
    .panel h2{padding:16px 20px 0;margin:0;font-size:1rem}
    .panel .body{padding:12px 0}
    .card{padding:20px}
    .card + .card,.panel + .panel{margin-top:16px}

    .kpi-strip{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:24px}
    .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:14px;margin-bottom:24px}
    .kpi{
      background:linear-gradient(145deg,rgba(15,23,42,.9),rgba(12,18,32,.95));
      border:1px solid var(--border);border-radius:var(--radius-m);
      padding:18px 16px;position:relative;overflow:hidden;
      box-shadow:0 4px 20px rgba(0,0,0,.3);
    }
    .kpi::before{
      content:"";position:absolute;top:0;left:0;right:0;height:2px;
      background:linear-gradient(90deg,transparent,var(--accent),transparent);opacity:.7;
    }
    .kpi .l,.kpi .label{font-size:.72rem;color:var(--text-tertiary);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
    .kpi .v,.kpi .value{font-size:1.7rem;font-weight:700;color:var(--accent);text-shadow:0 0 18px rgba(34,211,238,.3);font-variant-numeric:tabular-nums}
    .kpi .v.warn{color:var(--warning);text-shadow:0 0 18px rgba(251,191,36,.3)}
    .kpi .v.bad{color:var(--danger);text-shadow:0 0 18px rgba(248,113,113,.3)}
    .kpi .hint{font-size:.72rem;color:var(--text-tertiary);margin-top:6px}

    .table-wrap{overflow-x:auto;border-radius:var(--radius-m);border:1px solid var(--border);background:var(--surface)}
    table.data,table.dt{width:100%}
    table.data th,table.dt th{
      background:rgba(15,23,42,.95);color:var(--text-secondary);
      font-size:.74rem;font-weight:600;text-align:right;padding:12px 14px;
      border-bottom:1px solid var(--border);white-space:nowrap;
    }
    table.data td,table.dt td{
      padding:12px 14px;border-bottom:1px solid rgba(56,189,248,.06);font-size:.86rem;
    }
    table.data tr:hover td,table.dt tr:hover td{background:rgba(34,211,238,.04)}
    table.data tr:last-child td,table.dt tr:last-child td{border-bottom:none}

    .badge,.pill{display:inline-flex;align-items:center;gap:5px;padding:3px 10px;border-radius:999px;font-size:.7rem;font-weight:600}
    .badge-live{background:rgba(34,211,238,.15);color:var(--accent);border:1px solid rgba(34,211,238,.3)}
    .badge-success,.pill-success{background:var(--success-bg);color:var(--success)}
    .badge-warning,.pill-warn{background:var(--warning-bg);color:var(--warning)}
    .badge-danger,.pill-danger{background:var(--danger-bg);color:var(--danger)}
    .badge-neutral,.pill-neutral{background:var(--neutral-bg);color:var(--text-secondary)}
    .badge-accent,.pill-accent{background:var(--accent-bg);color:var(--accent)}

    .btn{
      display:inline-flex;align-items:center;gap:7px;padding:9px 16px;border-radius:12px;
      font-size:.82rem;font-weight:600;border:1px solid transparent;cursor:pointer;transition:all .2s ease;
    }
    .btn-primary{
      background:linear-gradient(135deg,#22d3ee,#06b6d4);color:#0c1220;border:none;
      box-shadow:0 0 20px rgba(34,211,238,.35);
    }
    .btn-primary:hover{box-shadow:0 0 28px rgba(34,211,238,.5);transform:translateY(-1px)}
    .btn-ghost{background:transparent;color:var(--text-secondary);border:1px solid var(--border-strong)}
    .btn-ghost:hover{background:rgba(34,211,238,.08);color:var(--accent);border-color:rgba(34,211,238,.35)}
    .btn-danger{background:var(--danger-bg);color:var(--danger);border:1px solid rgba(248,113,113,.25)}
    .btn-sm{padding:6px 11px;font-size:.74rem;border-radius:9px}
    .btn-block{width:100%;justify-content:center}
    form.inline{display:inline-block}

    .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .form-grid label,.field label{display:block;font-size:.78rem;color:var(--text-secondary);margin-bottom:6px}
    .form-grid input,.form-grid select,.form-grid textarea,
    .field input,.field select,.field textarea{
      width:100%;padding:11px 14px;border:1px solid var(--border-strong);border-radius:12px;
      background:rgba(15,23,42,.8);color:var(--text-primary);
    }
    .form-grid input:focus,.form-grid select:focus,.form-grid textarea:focus,
    .field input:focus,.field select:focus,.field textarea:focus{
      outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(34,211,238,.15);
    }
    .field{margin-bottom:14px}
    .mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.85em}

    .tabs{display:flex;gap:4px;border-bottom:1px solid var(--border);margin-bottom:18px;flex-wrap:wrap}
    .tabs a{padding:10px 14px;font-size:.84rem;color:var(--text-secondary);border-bottom:2px solid transparent;border-radius:8px 8px 0 0}
    .tabs a:hover{color:var(--text-primary);background:rgba(34,211,238,.05)}
    .tabs a.is-active{color:var(--accent);border-color:var(--accent);font-weight:600}

    .alert{padding:13px 16px;border-radius:12px;font-size:.86rem;margin-bottom:16px;border:1px solid transparent}
    .alert-success{background:var(--success-bg);color:var(--success);border-color:rgba(52,211,153,.25)}
    .alert-danger{background:var(--danger-bg);color:var(--danger);border-color:rgba(248,113,113,.25)}
    .alert-warning{background:var(--warning-bg);color:var(--warning);border-color:rgba(251,191,36,.25)}
    .alert-info{background:var(--accent-bg);color:var(--accent);border-color:rgba(34,211,238,.25)}

    .empty{padding:40px 20px;text-align:center;color:var(--text-tertiary);font-size:.88rem}
    .pagination{display:flex;gap:6px;justify-content:center;padding:18px;flex-wrap:wrap}
    .pagination .page-link{
      padding:8px 14px;border-radius:10px;background:var(--surface-alt);border:1px solid var(--border);
      font-size:.82rem;font-family:ui-monospace,monospace;color:var(--text-secondary);
    }
    .pagination .page-link:hover{border-color:var(--accent);color:var(--accent)}
    .pagination .page-link.is-active{
      background:linear-gradient(135deg,rgba(34,211,238,.2),rgba(6,182,212,.15));
      color:var(--accent);border-color:rgba(34,211,238,.4);
    }
    .actions-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
    .toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:16px}

    .auth-body{
      background:var(--bg);
      background-image:
        radial-gradient(ellipse 70% 50% at 50% 0%, rgba(34,211,238,.12), transparent 60%),
        linear-gradient(rgba(34,211,238,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(34,211,238,.03) 1px, transparent 1px);
      background-size:100% 100%, 40px 40px, 40px 40px;
      min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    }
    .auth-card{
      background:linear-gradient(160deg,rgba(15,23,42,.95),rgba(12,18,32,.98));
      border:1px solid var(--border-strong);border-radius:20px;padding:36px 38px;max-width:400px;width:100%;
      box-shadow:0 0 60px rgba(34,211,238,.08),0 25px 50px -12px rgba(0,0,0,.6);
    }
    .auth-eyebrow{color:var(--accent);font-size:.76rem;font-weight:700;margin-bottom:8px;letter-spacing:1px}
    .auth-card h1{margin-bottom:6px;color:#f1f5f9}
    .auth-sub{color:var(--text-secondary);font-size:.84rem;margin-bottom:20px;line-height:1.65}
    .auth-card label{display:block;font-size:.78rem;color:var(--text-secondary);margin:14px 0 6px}
    .auth-card input{
      width:100%;padding:12px 14px;border:1px solid var(--border-strong);border-radius:12px;
      background:rgba(15,23,42,.8);color:var(--text-primary);
    }
    .auth-card input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(34,211,238,.15)}
    .auth-card button{
      margin-top:20px;width:100%;padding:13px;
      background:linear-gradient(135deg,#22d3ee,#06b6d4);color:#0c1220;border:none;border-radius:12px;
      font-weight:700;font-size:.9rem;cursor:pointer;box-shadow:0 0 24px rgba(34,211,238,.35);
    }
    .auth-card button:hover{box-shadow:0 0 32px rgba(34,211,238,.5)}

    .pwa-install-fab{
      position:fixed;bottom:24px;left:24px;z-index:40;
      background:linear-gradient(135deg,#a855f7,#ec4899);color:#fff;border:none;border-radius:999px;
      padding:12px 20px;font-size:.82rem;font-weight:600;box-shadow:0 0 28px rgba(168,85,247,.45);
      cursor:pointer;display:flex;align-items:center;gap:8px;
    }
    .pwa-install-fab:active{transform:scale(.96)}

    .mobile-nav{display:none}
    @media(max-width:900px){
      .sidebar{display:none}
      .form-grid{grid-template-columns:1fr}
      .kpi{min-width:120px}
      .main{padding:18px 14px 90px}
      .pwa-install-fab{bottom:calc(72px + env(safe-area-inset-bottom));left:16px}
      .mobile-nav{
        display:flex;position:fixed;bottom:0;inset-inline:0;z-index:30;
        background:linear-gradient(180deg,#060a12,#0a1020);border-top:1px solid var(--border);
        padding:6px 4px calc(6px + env(safe-area-inset-bottom));overflow-x:auto;gap:2px;
      }
      .mobile-nav a{
        flex:1;min-width:62px;display:flex;flex-direction:column;align-items:center;gap:3px;
        padding:8px 4px;color:var(--text-tertiary);font-size:.64rem;border-radius:10px;
      }
      .mobile-nav a svg{width:19px;height:19px}
      .mobile-nav a.is-active{color:var(--accent);background:rgba(34,211,238,.12)}
    }

    /* ═════════════════════════════════════════════════════════════
       إضافات v4 — نفس متغيرات التصميم الهولوغرافي (لا ألوان جديدة)
       ═════════════════════════════════════════════════════════════ */
    .ic{width:1em;height:1em;vertical-align:-2px;flex:none}
    :root{color-scheme:dark;--tabbar-h:58px;--topbar-h:48px;--ease-ios:cubic-bezier(.32,.72,0,1)}
    html{-webkit-text-size-adjust:100%;-webkit-tap-highlight-color:transparent}
    body{overflow-wrap:anywhere}
    .app-col{flex:1;min-width:0;display:flex;flex-direction:column}
    .main{width:100%}
    .panel .body{overflow-x:auto;-webkit-overflow-scrolling:touch}
    .panel .body:not([style]){padding:14px 20px}
    .panel .body table.dt{min-width:560px}
    .panel h2 small,.form-section small{font-weight:400;color:var(--text-tertiary);font-size:.72rem}
    .link{color:var(--accent)}
    .link:hover{text-decoration:underline}
    .danger-text{color:var(--danger)}
    .hint,.form-hint{font-size:.76rem;color:var(--text-tertiary);margin-top:6px;line-height:1.6}
    .btn:disabled{opacity:.55;cursor:not-allowed;transform:none}
    .btn.is-loading{position:relative;color:transparent !important}
    .btn.is-loading::after{content:"";position:absolute;inset:0;margin:auto;width:16px;height:16px;border-radius:50%;
      border:2px solid rgba(12,18,32,.35);border-top-color:#0c1220;animation:fms-spin .7s linear infinite}
    .btn-ghost.is-loading::after,.btn-danger.is-loading::after{border-color:rgba(148,163,184,.3);border-top-color:var(--accent)}
    .btn-lg{padding:14px 24px;font-size:.95rem;border-radius:14px}
    .btn svg{width:17px;height:17px;flex:none}
    .btn-sm svg{width:14px;height:14px}
    @keyframes fms-spin{to{transform:rotate(360deg)}}
    .pill-live{background:var(--accent-bg);color:var(--accent);box-shadow:inset 0 0 0 1px rgba(34,211,238,.35)}
    .pill-live::before{content:"";width:6px;height:6px;border-radius:50%;background:var(--accent);box-shadow:0 0 8px var(--accent);animation:fms-pulse 1.6s ease-in-out infinite}
    @keyframes fms-pulse{50%{opacity:.35}}
    .inline-input{padding:7px 10px;border:1px solid var(--border-strong);border-radius:10px;background:rgba(15,23,42,.8);color:var(--text-primary)}

    /* رأس الصفحة */
    .page-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;flex-wrap:wrap;margin-bottom:6px}
    .page-head .sub{margin-bottom:16px}
    .back-link{margin-bottom:14px}
    .back-link svg{width:14px;height:14px}

    /* النماذج */
    .form-section{grid-column:1/-1;margin-top:10px;padding-top:14px;border-top:1px solid var(--border);
      font-size:.8rem;font-weight:700;color:var(--accent);letter-spacing:.3px;display:flex;flex-direction:column;gap:2px}
    .form-grid > .form-section:first-child{margin-top:0;padding-top:0;border-top:0}
    .span-2,.form-grid .span-2{grid-column:1/-1}
    .check-row{display:flex !important;align-items:center;gap:10px;cursor:pointer;margin:12px 0 !important;font-size:.84rem;color:var(--text-primary) !important}
    .check-row input[type=checkbox],.auth-card .check-row input[type=checkbox]{width:20px !important;height:20px;flex:none;padding:0 !important;accent-color:var(--accent);margin:0}
    .form-grid select,.field select{appearance:none;-webkit-appearance:none;padding-left:36px;
      background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2394a3b8' stroke-width='2.5'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
      background-repeat:no-repeat;background-position:left 14px center}
    .form-grid textarea,.field textarea{min-height:90px;resize:vertical}
    input[type=date],input[type=time],input[type=datetime-local]{min-height:44px;-webkit-appearance:none;appearance:none;text-align:right}
    input[type=date]::-webkit-date-and-time-value,input[type=time]::-webkit-date-and-time-value{text-align:right}
    input::-webkit-calendar-picker-indicator{filter:invert(.75)}
    input[type=file]{padding:9px !important;font-size:.8rem}
    input[type=file]::file-selector-button{margin-inline-end:10px;border:0;border-radius:9px;padding:7px 12px;background:var(--accent-bg);color:var(--accent);font-weight:600;cursor:pointer}

    /* أقسام قابلة للطي */
    .panel-collapse > summary,details.action-card > summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:10px;font-weight:600;user-select:none;-webkit-user-select:none}
    .panel-collapse > summary::-webkit-details-marker,details.action-card > summary::-webkit-details-marker{display:none}
    .panel-collapse > summary{padding:16px 20px;color:var(--accent);min-height:52px}
    .panel-collapse > summary svg,details.action-card > summary svg{width:18px;height:18px}
    .panel-collapse > summary::after,details.action-card > summary::after{content:"";margin-inline-start:auto;width:8px;height:8px;
      border-inline-start:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(-45deg);transition:transform .25s var(--ease-ios);opacity:.7}
    .panel-collapse[open] > summary::after,details.action-card[open] > summary::after{transform:rotate(135deg)}
    .panel-collapse[open] > summary{border-bottom:1px solid var(--border)}
    .panel-collapse{margin-bottom:16px}

    /* البحث والرقائق */
    .search-bar input[type=search]{flex:1;min-width:200px;padding:11px 16px;border-radius:12px;border:1px solid var(--border-strong);background:rgba(15,23,42,.8)}
    .search-bar input[type=search]:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(34,211,238,.15)}
    .chips{display:flex;gap:8px;overflow-x:auto;padding:2px 0 12px;margin-bottom:6px;scrollbar-width:none;-webkit-overflow-scrolling:touch}
    .chips::-webkit-scrollbar{display:none}
    .chip{flex:none;display:inline-flex;align-items:center;gap:6px;padding:8px 15px;border-radius:999px;font-size:.8rem;cursor:pointer;
      background:var(--surface-alt);border:1px solid var(--border);color:var(--text-secondary);white-space:nowrap;transition:all .2s ease}
    .chip input{position:absolute;opacity:0;pointer-events:none}
    .chip:hover{color:var(--text-primary);border-color:var(--border-strong)}
    .chip.is-active{background:var(--accent-bg);border-color:rgba(34,211,238,.45);color:var(--accent);font-weight:600}

    /* التحكم المقسَّم (Segmented Control) */
    .segmented{display:flex;gap:2px;padding:3px;border-radius:12px;background:rgba(2,6,23,.6);border:1px solid var(--border)}
    .segmented > a,.segmented > label{flex:1;display:flex;align-items:center;justify-content:center;gap:6px;text-align:center;
      padding:8px 10px;border-radius:9px;font-size:.8rem;color:var(--text-secondary);cursor:pointer;position:relative;transition:background .2s,color .2s;margin:0 !important}
    .segmented > label input{position:absolute;opacity:0;pointer-events:none}
    .segmented > a.is-active,.segmented > label:has(input:checked){background:linear-gradient(135deg,rgba(34,211,238,.22),rgba(168,85,247,.14));color:var(--accent);font-weight:600;box-shadow:0 1px 6px rgba(0,0,0,.35)}
    .segmented > label.is-busy::after{content:"";position:absolute;top:5px;left:6px;width:6px;height:6px;border-radius:50%;background:var(--warning)}
    .segmented-nav{margin-bottom:16px;max-width:460px}
    .kpi-link{display:block;transition:transform .15s ease,border-color .2s}
    .kpi-link:hover{border-color:var(--border-strong)}
    .kpi-link:active{transform:scale(.97)}
    .kpi-compact .kpi{padding:14px}
    .kpi-compact .kpi .v{font-size:1.45rem}
    .alert-link{display:flex;align-items:center;gap:10px}
    .alert-link svg{width:18px;height:18px;flex:none}
    .alert-link::after{content:"‹";margin-inline-start:auto;font-size:1.2rem;opacity:.7}

    /* بيانات الآلية */
    .plate{display:inline-block;padding:1px 8px;border-radius:6px;background:#f1f5f9;color:#0f172a;font-weight:700;font-size:.74rem;
      font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.5px;border:1px solid #cbd5e1;direction:ltr;unicode-bidi:isolate}
    .kv{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:2px 18px}
    .kv > div{display:flex;flex-direction:column;gap:2px;padding:10px 0;border-bottom:1px solid rgba(56,189,248,.07)}
    .kv > div span{font-size:.72rem;color:var(--text-tertiary)}
    .kv > div b{font-weight:600;font-size:.88rem;color:var(--text-primary)}
    .kv > div b small{color:var(--text-tertiary);font-weight:400}
    .note-box{margin:14px 0 4px;padding:12px 14px;border-radius:12px;background:var(--surface-alt);border:1px solid var(--border);font-size:.85rem;line-height:1.8}
    .note-danger{background:var(--danger-bg);border-color:rgba(248,113,113,.25);color:var(--danger)}
    .asset-hero{display:flex;gap:20px;align-items:center;margin-bottom:20px;padding:18px;border-radius:var(--radius-m);
      background:linear-gradient(135deg,rgba(34,211,238,.08),rgba(168,85,247,.06));border:1px solid var(--border)}
    .asset-photo{width:150px;height:150px;border-radius:18px;object-fit:cover;flex:none;border:1px solid var(--border-strong);background:var(--surface-solid)}
    .asset-photo-empty{display:flex;align-items:center;justify-content:center;color:var(--text-tertiary)}
    .asset-photo-empty svg{width:56px;height:56px;opacity:.5}
    .asset-hero-body{flex:1;min-width:0}
    .asset-hero-body .sub{margin-bottom:10px}

    /* قائمة المواعيد (أسلوب قوائم iOS) */
    .appt-list{display:flex;flex-direction:column}
    .appt-item{display:flex;align-items:center;gap:14px;padding:12px 20px;border-bottom:1px solid rgba(56,189,248,.07);transition:background .15s;min-height:64px}
    .appt-item:last-child{border-bottom:0}
    .appt-item:hover,.appt-item:active{background:rgba(34,211,238,.05)}
    .appt-date{flex:none;width:54px;text-align:center;border-radius:12px;padding:5px 0;background:var(--surface-alt);border:1px solid var(--border);line-height:1.25}
    .appt-date span{display:block;font-size:.62rem;color:var(--text-tertiary)}
    .appt-date b{display:block;font-size:1.25rem;color:var(--text-primary);font-variant-numeric:tabular-nums}
    .appt-item.is-today .appt-date{background:var(--accent-bg);border-color:rgba(34,211,238,.45)}
    .appt-item.is-today .appt-date b{color:var(--accent)}
    .appt-item.is-late .appt-date{border-color:rgba(248,113,113,.4)}
    .appt-body{flex:1;min-width:0}
    .appt-title{font-weight:600;font-size:.88rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
    .appt-meta{font-size:.74rem;color:var(--text-secondary);display:flex;align-items:center;gap:4px;flex-wrap:wrap;margin-top:2px}
    .appt-meta svg{width:13px;height:13px;opacity:.8}
    .appt-side{flex:none;display:flex;flex-direction:column;align-items:flex-end;gap:4px}
    .appt-num{font-size:.66rem;color:var(--text-tertiary)}
    .panel .body:has(> .appt-list){padding:4px 0}

    /* عرض الأسبوع */
    .week-nav{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}
    .week-nav b{font-size:.88rem}
    .week-grid{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px}
    .week-day{min-height:140px;border-radius:14px;background:var(--surface);border:1px solid var(--border);padding:8px;display:flex;flex-direction:column;gap:6px}
    .week-day.is-today{border-color:rgba(34,211,238,.5);box-shadow:0 0 0 1px rgba(34,211,238,.25),0 0 22px rgba(34,211,238,.1)}
    .week-day-head{font-size:.72rem;color:var(--text-secondary);font-weight:600;padding-bottom:6px;border-bottom:1px solid var(--border)}
    .week-day.is-today .week-day-head{color:var(--accent)}
    .week-empty{color:var(--text-tertiary);text-align:center;font-size:.8rem;margin:auto}
    .week-ev{display:block;padding:6px 8px;border-radius:9px;font-size:.72rem;line-height:1.45;border-inline-start:3px solid var(--neutral);background:var(--neutral-bg)}
    .week-ev span{display:block;color:var(--text-tertiary);font-size:.66rem}
    .week-ev.ev-warn{border-color:var(--warning);background:var(--warning-bg)}
    .week-ev.ev-accent,.week-ev.ev-live{border-color:var(--accent);background:var(--accent-bg)}
    .week-ev.ev-success{border-color:var(--success);background:var(--success-bg)}
    .week-ev.ev-danger{border-color:var(--danger);background:var(--danger-bg)}
    .week-ev.ev-neutral{opacity:.7;text-decoration:line-through}

    /* مسار الحالة (Stepper) */
    .stepper{list-style:none;display:flex;gap:4px;margin:4px 0 20px;counter-reset:st}
    .stepper li{flex:1;position:relative;text-align:center;font-size:.72rem;color:var(--text-tertiary);padding-top:26px}
    .stepper li span{position:absolute;top:0;inset-inline-start:50%;transform:translateX(50%);width:18px;height:18px;border-radius:50%;
      background:var(--surface-solid);border:2px solid var(--border-strong);z-index:1}
    .stepper li::before{content:"";position:absolute;top:8px;inset-inline-start:-50%;width:100%;height:2px;background:var(--border-strong)}
    .stepper li:first-child::before{display:none}
    .stepper li.done{color:var(--text-secondary)}
    .stepper li.done span{background:var(--accent);border-color:var(--accent)}
    .stepper li.done::before,.stepper li.current::before{background:var(--accent)}
    .stepper li.current{color:var(--accent);font-weight:700}
    .stepper li.current span{border-color:var(--accent);box-shadow:0 0 0 4px rgba(34,211,238,.18),0 0 12px var(--accent)}
    .stepper li.stopped{color:var(--danger);font-weight:700}
    .stepper li.stopped span{background:var(--danger);border-color:var(--danger)}

    /* بطاقات الإجراءات */
    .action-card{display:block;padding:16px;border-radius:var(--radius-m);background:var(--surface);border:1px solid var(--border);margin-bottom:12px}
    .action-card h3{font-size:.9rem;display:flex;align-items:center;gap:8px;margin-bottom:12px;color:var(--text-primary)}
    .action-card h3 svg{width:18px;height:18px;color:var(--accent)}
    details.action-card > form{margin-top:14px}
    details.action-card > summary{min-height:24px}

    /* الخط الزمني */
    .timeline{list-style:none;position:relative;padding-inline-start:18px}
    .timeline::before{content:"";position:absolute;inset-inline-start:4px;top:6px;bottom:6px;width:2px;background:var(--border)}
    .timeline li{position:relative;padding:0 0 14px;font-size:.84rem}
    .timeline li::before{content:"";position:absolute;inset-inline-start:-18px;top:7px;width:10px;height:10px;border-radius:50%;background:var(--surface-solid);border:2px solid var(--accent)}
    .timeline li span{color:var(--text-secondary)}
    .timeline li small{display:block;color:var(--text-tertiary);font-size:.72rem;margin-top:2px}

    /* التثبيت */
    .install-hero{text-align:center;padding:28px 16px 30px;margin-bottom:18px;border-radius:22px;
      background:radial-gradient(ellipse 70% 80% at 50% 0%,rgba(34,211,238,.14),transparent 70%),var(--surface);border:1px solid var(--border)}
    .install-hero img{border-radius:22px;box-shadow:0 10px 30px rgba(0,0,0,.5),0 0 40px rgba(34,211,238,.2);margin-bottom:14px}
    .install-hero .sub{max-width:460px;margin-inline:auto}
    .install-state{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:999px;background:var(--success-bg);color:var(--success);font-size:.84rem;margin-bottom:14px}
    .install-state svg{width:16px;height:16px}
    .install-steps{list-style:none;display:flex;flex-direction:column;gap:12px}
    .install-steps li{display:flex;gap:12px;align-items:flex-start;font-size:.88rem;line-height:1.7}
    .install-steps li svg{width:20px;height:20px;vertical-align:-5px;color:var(--accent);display:inline-block}
    .install-steps small{color:var(--text-tertiary)}
    .step-n{flex:none;width:26px;height:26px;border-radius:50%;display:flex;align-items:center;justify-content:center;
      background:var(--accent-bg);color:var(--accent);font-weight:700;font-size:.8rem;border:1px solid rgba(34,211,238,.35)}
    html.is-standalone .install-hero .btn{display:none}

    /* الأوراق السفلية (Bottom Sheets) */
    body.sheet-open{overflow:hidden}
    .sheet-backdrop{position:fixed;inset:0;z-index:100;background:rgba(2,6,23,0);display:flex;align-items:flex-end;justify-content:center;
      transition:background .28s ease;-webkit-backdrop-filter:blur(0);backdrop-filter:blur(0)}
    .sheet-backdrop[hidden]{display:none}
    .sheet-backdrop.is-open{background:rgba(2,6,23,.6);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px)}
    .sheet{width:100%;max-width:520px;max-height:88vh;overflow-y:auto;overscroll-behavior:contain;
      background:linear-gradient(180deg,#101a2e,#0a1020);border:1px solid var(--border-strong);border-bottom:0;border-radius:22px 22px 0 0;
      padding:8px 20px calc(20px + env(safe-area-inset-bottom));box-shadow:0 -20px 60px rgba(0,0,0,.6);
      transform:translateY(105%);transition:transform .32s var(--ease-ios)}
    .sheet-backdrop.is-open .sheet{transform:translateY(0)}
    .sheet-grabber{width:38px;height:5px;border-radius:3px;background:rgba(148,163,184,.45);margin:4px auto 14px}
    .sheet-head{display:flex;gap:14px;align-items:center;margin-bottom:18px}
    .sheet-head img{border-radius:13px;flex:none;box-shadow:0 4px 14px rgba(0,0,0,.4)}
    .sheet-head b{display:block;font-size:.96rem}
    .sheet-head span{display:block;font-size:.78rem;color:var(--text-secondary)}
    .sheet .install-steps{margin-bottom:16px}
    .sheet-note{font-size:.8rem;padding:10px 12px;border-radius:10px;background:var(--warning-bg);color:var(--warning);margin-bottom:14px}
    .sheet-pointer{display:none;justify-content:center;color:var(--accent);margin:-4px 0 10px}
    .sheet-pointer svg{width:22px;height:22px;transform:rotate(90deg);animation:fms-bob 1.2s ease-in-out infinite}
    html.is-ios .sheet-pointer{display:flex}
    @keyframes fms-bob{50%{translate:0 5px}}
    .sheet .btn-block{min-height:48px;font-size:.92rem}
    @media(min-width:901px){
      .sheet-backdrop{align-items:center}
      .sheet{border-radius:22px;border-bottom:1px solid var(--border-strong);transform:translateY(24px) scale(.97);opacity:0;transition:transform .28s var(--ease-ios),opacity .2s}
      .sheet-backdrop.is-open .sheet{transform:none;opacity:1}
      .sheet-grabber,.sheet-pointer,html.is-ios .sheet-pointer{display:none}
    }

    /* ورقة «المزيد» — قائمة مجمّعة بأسلوب الإعدادات في iOS */
    .more-user{display:flex;align-items:center;gap:12px;padding:6px 2px 16px}
    .avatar{width:46px;height:46px;border-radius:50%;flex:none;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.05rem;
      background:linear-gradient(135deg,rgba(34,211,238,.3),rgba(168,85,247,.3));color:#fff;border:1px solid var(--border-strong)}
    .more-user b{display:block}
    .more-user div span{display:block;font-size:.76rem;color:var(--text-secondary)}
    .ios-list{border-radius:14px;overflow:hidden;background:rgba(30,41,59,.45);border:1px solid var(--border);margin-bottom:14px}
    .ios-list a,.ios-list button{display:flex;align-items:center;gap:12px;width:100%;min-height:50px;padding:0 14px;background:none;border:0;
      border-bottom:1px solid rgba(56,189,248,.08);font-size:.9rem;text-align:start;cursor:pointer;color:var(--text-primary)}
    .ios-list > :last-child{border-bottom:0}
    .ios-list a:active,.ios-list button:active{background:rgba(34,211,238,.08)}
    .ios-list svg{width:20px;height:20px;color:var(--accent);flex:none}
    .ios-list a::after{content:"‹";margin-inline-start:auto;color:var(--text-tertiary);font-size:1.25rem;line-height:1}
    .ios-list a.is-active{color:var(--accent);font-weight:600}
    .ios-list .danger{color:var(--danger)}
    .ios-list .danger svg{color:var(--danger)}
    .ios-list .danger::after{display:none}

    /* شريط التقدّم + السحب للتحديث */
    .nav-progress{position:fixed;top:0;inset-inline:0;height:3px;z-index:200;pointer-events:none;
      background:linear-gradient(90deg,var(--purple),var(--accent));transform:scaleX(0);transform-origin:right;opacity:0}
    html.is-navigating .nav-progress{opacity:1;animation:fms-progress 8s cubic-bezier(.1,.8,.2,1) forwards}
    @keyframes fms-progress{0%{transform:scaleX(0)}10%{transform:scaleX(.4)}100%{transform:scaleX(.92)}}
    .ptr{position:fixed;top:calc(env(safe-area-inset-top) + 6px);left:50%;margin-left:-18px;z-index:60;width:36px;height:36px;border-radius:50%;
      display:flex;align-items:center;justify-content:center;background:var(--surface-solid);border:1px solid var(--border-strong);
      box-shadow:0 6px 18px rgba(0,0,0,.45);opacity:0;transform:translateY(-50px);transition:opacity .15s;pointer-events:none}
    .ptr i{width:16px;height:16px;border-radius:50%;border:2px solid rgba(34,211,238,.25);border-top-color:var(--accent)}
    .ptr.is-ready i{border-color:var(--accent)}
    .ptr.is-loading i{animation:fms-spin .7s linear infinite;border-color:rgba(34,211,238,.25);border-top-color:var(--accent)}

    /* الشريط العلوي + شريط التبويبات (تظهر على الجوال فقط) */
    .ios-topbar,.ios-tabbar{display:none}
    .fab-x{display:none}

    /* الانتقالات بين الصفحات (Safari 18.2+/Chrome 126+) — بدون مكتبات */
    @view-transition{navigation:auto}
    ::view-transition-old(root){animation:fms-vt-out .18s ease both}
    ::view-transition-new(root){animation:fms-vt-in .26s var(--ease-ios) both}
    @keyframes fms-vt-out{to{opacity:0}}
    @keyframes fms-vt-in{from{opacity:0;transform:translateY(8px)}}
    .main > *{animation:fms-rise .32s var(--ease-ios) both}
    @keyframes fms-rise{from{opacity:0;transform:translateY(6px)}}
    @supports (view-transition-name:none){.main > *{animation:none}}

    /* شاشة الدخول */
    .auth-body{min-height:100vh;min-height:100dvh;padding:calc(24px + env(safe-area-inset-top)) calc(18px + env(safe-area-inset-right)) calc(24px + env(safe-area-inset-bottom)) calc(18px + env(safe-area-inset-left))}
    .auth-logo{display:block;border-radius:16px;margin-bottom:16px;box-shadow:0 8px 24px rgba(0,0,0,.5),0 0 30px rgba(34,211,238,.18)}
    .auth-card button.auth-install{background:transparent;color:var(--accent);box-shadow:none;border:1px dashed rgba(34,211,238,.4);
      margin-top:12px;display:flex;align-items:center;justify-content:center;gap:8px;font-weight:600}
    .auth-card button.auth-install[hidden]{display:none}
    .auth-card button.auth-install svg{width:18px;height:18px}
    .auth-card .alert{margin-top:6px}

    /* الدليل */
    .help-section{padding:16px 18px;border-radius:var(--radius-m);background:var(--surface);border:1px solid var(--border);margin-bottom:12px}
    .help-section h3{font-size:.95rem;color:var(--accent);margin-bottom:6px}
    .help-section p{color:var(--text-secondary);font-size:.86rem;line-height:1.9}

    /* زر التثبيت العائم */
    .pwa-install-fab{padding:0;overflow:hidden}
    .pwa-install-fab button{background:none;border:0;color:inherit;cursor:pointer;display:flex;align-items:center;gap:8px;font-weight:600;font-size:.82rem}
    .pwa-install-fab .fab-main{padding:12px 6px 12px 18px}
    .pwa-install-fab .fab-main svg{width:18px;height:18px}
    .pwa-install-fab .fab-x{display:flex;padding:12px 14px 12px 10px;opacity:.75;font-size:1rem;border-inline-start:1px solid rgba(255,255,255,.25)}

    /* في وضع التطبيق المثبَّت: لا واجهات تثبيت، ولا ارتداد للصفحة */
    html.is-standalone{overscroll-behavior-y:none}
    html.is-standalone body{overscroll-behavior-y:none}
    html.is-standalone .pwa-install-fab,html.is-standalone [data-install-row],html.is-standalone .auth-install{display:none !important}

    /* ═══════════ الجوال: تجربة تطبيق آيفون ═══════════ */
    @media(max-width:900px){
      .mobile-nav{display:none !important}
      body{background-attachment:scroll}
      .main{padding:10px calc(14px + env(safe-area-inset-right)) calc(var(--tabbar-h) + env(safe-area-inset-bottom) + 24px) calc(14px + env(safe-area-inset-left))}
      h1{font-size:1.75rem;letter-spacing:-.3px;line-height:1.3}
      .page-head{flex-direction:column;align-items:stretch;gap:0}
      .page-head > .btn{align-self:flex-start;margin-bottom:14px}
      .back-link{display:none}

      .ios-topbar{display:flex;position:sticky;top:0;z-index:50;align-items:center;gap:6px;
        padding:env(safe-area-inset-top) calc(8px + env(safe-area-inset-right)) 0 calc(8px + env(safe-area-inset-left));
        min-height:calc(var(--topbar-h) + env(safe-area-inset-top));
        background:rgba(7,11,20,.55);-webkit-backdrop-filter:saturate(180%) blur(20px);backdrop-filter:saturate(180%) blur(20px);
        border-bottom:.5px solid transparent;transition:border-color .2s,background .2s}
      .ios-topbar.is-scrolled{border-bottom-color:var(--border-strong);background:rgba(7,11,20,.82)}
      .ios-topbar .tb-title{flex:1;text-align:center;font-weight:600;font-size:.95rem;opacity:0;transform:translateY(4px);transition:opacity .2s,transform .2s;
        white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding:0 4px}
      .ios-topbar.is-scrolled .tb-title{opacity:1;transform:none}
      .ios-topbar .tb-side{width:96px;display:flex;align-items:center}
      .ios-topbar .tb-side:last-child{justify-content:flex-end}
      .tb-back{display:flex;align-items:center;gap:2px;color:var(--accent);font-size:.95rem;min-height:44px;padding:0 4px}
      .tb-back svg{width:22px;height:22px}
      .tb-brand{display:flex;align-items:center;gap:8px;font-weight:700;font-size:.85rem;color:var(--text-secondary)}
      .tb-brand img{border-radius:7px}
      .tb-btn{display:flex;align-items:center;justify-content:center;min-width:44px;min-height:44px;color:var(--accent);border-radius:12px}
      .tb-btn svg{width:22px;height:22px}

      .ios-tabbar{display:flex;position:fixed;bottom:0;inset-inline:0;z-index:40;
        padding:0 env(safe-area-inset-right) env(safe-area-inset-bottom) env(safe-area-inset-left);
        background:rgba(7,11,20,.78);-webkit-backdrop-filter:saturate(180%) blur(22px);backdrop-filter:saturate(180%) blur(22px);
        border-top:.5px solid var(--border-strong)}
      .ios-tabbar a{flex:1;min-width:0;height:var(--tabbar-h);display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;
        color:var(--text-tertiary);font-size:.64rem;font-weight:500;position:relative;transition:color .2s}
      .ios-tabbar a span{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;padding:0 2px}
      .ios-tabbar a svg{width:24px;height:24px;transition:transform .2s var(--ease-ios)}
      .ios-tabbar a:active svg{transform:scale(.86)}
      .ios-tabbar a.is-active{color:var(--accent)}
      .ios-tabbar a.is-active svg{filter:drop-shadow(0 0 6px rgba(34,211,238,.55))}
      .ios-tabbar a.is-active::before{content:"";position:absolute;top:0;width:28px;height:2px;border-radius:0 0 2px 2px;background:var(--accent);box-shadow:0 0 10px var(--accent)}
      .tab-badge{position:absolute;top:6px;left:calc(50% - 22px);min-width:18px;height:18px;padding:0 5px;border-radius:9px;
        background:var(--danger);color:#fff;font-size:.62rem;font-weight:700;display:flex;align-items:center;justify-content:center;
        box-shadow:0 0 0 2px var(--bg);font-variant-numeric:tabular-nums}

      .pwa-install-fab{bottom:calc(var(--tabbar-h) + env(safe-area-inset-bottom) + 14px);left:calc(14px + env(safe-area-inset-left))}
      .asset-hero{flex-direction:column;align-items:stretch;text-align:start;padding:14px}
      .asset-photo{width:100%;height:210px}
      .asset-hero .actions-row .btn{flex:1;justify-content:center;min-height:46px}
      .btn-block-mobile{width:100%;justify-content:center;min-height:48px}
      .panel .body:not([style]){padding:12px 16px}
      .panel .body:has(> .appt-list){padding:4px 0}
      .appt-item{padding:12px 14px}
      .appt-side .pill{font-size:.64rem}
      .kv{grid-template-columns:1fr 1fr}
      .week-grid{grid-template-columns:1fr;gap:6px}
      .week-day{min-height:0;flex-direction:row;flex-wrap:wrap;align-items:center}
      .week-day-head{border:0;padding:0;width:100%}
      .week-ev{flex:1 1 100%}
      .week-empty{margin:0;text-align:start}
      .stepper li{font-size:.62rem}
      .search-bar{flex-wrap:nowrap;overflow-x:auto}
      .search-bar input[type=search]{min-width:0}
      .segmented-nav{max-width:none}
      .kpi-strip,.kpis{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
      .kpi .v,.kpi .value{font-size:1.4rem}
      .toolbar{gap:8px}
      #chatbase-bubble-button,#chatbase-bubble-window{bottom:calc(var(--tabbar-h) + env(safe-area-inset-bottom) + 12px) !important}
      #chatbase-bubble-button{right:calc(12px + env(safe-area-inset-right)) !important;transform:scale(.85);transform-origin:bottom right}
    }

    /* لمس دقيق: أهداف لمس 44px + خط 16px يمنع التكبير التلقائي في iOS عند التركيز على الحقول */
    @media(pointer:coarse){
      .btn{min-height:44px}
      .btn-sm{min-height:36px;padding:8px 12px}
      .chip{min-height:38px}
      .segmented > a,.segmented > label{min-height:40px}
      .nav-item,.pagination .page-link{min-height:44px;display:flex;align-items:center}
      .form-grid input,.form-grid select,.form-grid textarea,.field input,.field select,.field textarea,
      .auth-card input,.search-bar input,.inline-input,input,select,textarea{font-size:16px}
      .check-row input[type=checkbox]{width:22px !important;height:22px}
      a,button,label,summary{touch-action:manipulation}
      .ios-tabbar,.ios-topbar,.sheet-grabber,.btn,.chip{-webkit-user-select:none;user-select:none;-webkit-touch-callout:none}
    }
    @media(prefers-reduced-motion:reduce){
      *,*::before,*::after{animation-duration:.01ms !important;animation-iteration-count:1 !important;transition-duration:.01ms !important;scroll-behavior:auto !important}
      @view-transition{navigation:none}
    }
    @media print{
      .ios-topbar,.ios-tabbar,.nav-progress,.ptr,.pwa-install-fab,.sheet-backdrop,#chatbase-bubble-button{display:none !important}
    }

CSS;
}


/* =====================================================================
   إعداد أول تشغيل: إنشاء أول حساب مدير (يظهر فقط إن كان جدول users فارغاً)
   ===================================================================== */
$userCount = (int)$pdo->query("SELECT COUNT(*) c FROM users")->fetch()["c"];

if ($userCount === 0) {
    $setupError = "";
    if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["setup_submit"])) {
        csrfCheck();
        $username = trim($_POST["username"] ?? "");
        $password = $_POST["password"] ?? "";
        $fullName = trim($_POST["full_name"] ?? "");
        if (strlen($username) < 3 || strlen($password) < 6 || $fullName === "") {
            $setupError = "تأكد من: اسم مستخدم 3 أحرف فأكثر، كلمة مرور 6 أحرف فأكثر، والاسم الكامل.";
        } else {
            $hash = password_hash($password, PASSWORD_DEFAULT);
            $pdo->prepare("INSERT INTO users (id, username, password_hash, full_name, role) VALUES (?,?,?,?, 'EXECUTIVE_MANAGEMENT')")
                ->execute([uid(), $username, $hash, $fullName]);
            flash("تم إنشاء حساب المدير بنجاح. سجّل الدخول الآن.");
            redirect("index.php");
        }
    }
    echo "<!DOCTYPE html><html lang='ar' dir='rtl'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'><title>إعداد أول استخدام — FMS/EMS</title>" . pwaHeadTags() . "<style>" . pageStyles() . "</style></head><body class='auth-body'>";
    echo "<form class='auth-card' method='post'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
    echo "<div class='auth-eyebrow'>الإعداد الأول</div><h1>أنشئ حساب المدير الأول</h1>";
    echo "<p class='auth-sub'>هذا الحساب سيملك صلاحية الإدارة العليا الكاملة. يمكنك إضافة بقية المستخدمين لاحقاً من داخل النظام.</p>";
    if ($setupError) echo "<div class='alert alert-danger'>" . e($setupError) . "</div>";
    echo "<label>اسم المستخدم</label><input type='text' name='username' required minlength='3' autocapitalize='none' autocorrect='off' autocomplete='username' value='" . e($_POST["username"] ?? "") . "'>";
    echo "<label>الاسم الكامل</label><input type='text' name='full_name' required value='" . e($_POST["full_name"] ?? "") . "'>";
    echo "<label>كلمة المرور</label><input type='password' name='password' required minlength='6' autocomplete='new-password'>";
    echo "<button class='btn btn-primary btn-block' type='submit' name='setup_submit' value='1'>إنشاء الحساب والمتابعة</button>";
    echo "</form>" . installSheetHtml() . pwaRegisterScript() . chatbaseWidgetScript() . "</body></html>";
    exit;
}

/* =====================================================================
   تسجيل الخروج / الدخول
   ===================================================================== */
if (isset($_GET["logout"])) {
    // الخروج يتطلب رمز CSRF في الرابط — يمنع موقعاً خارجياً من إخراج المستخدم بصورة أو رابط مدسوس
    if (isset($_SESSION["user"]) && hash_equals(csrfToken(), (string)($_GET["t"] ?? ""))) {
        clearRememberToken($pdo);
        logAudit($pdo, $_SESSION["user"]["id"], "LOGOUT", "User", $_SESSION["user"]["id"]);
        $_SESSION = [];
        session_destroy();
    }
    redirect("index.php");
}

if (!isset($_SESSION["user"])) tryRememberLogin($pdo);

if (!isset($_SESSION["user"])) {
    $loginError = "";
    $clientIp = $_SERVER["REMOTE_ADDR"] ?? "0.0.0.0";
    // حماية بسيطة من هجوم القوة الغاشمة (Brute Force): 5 محاولات فاشلة
    // كحد أقصى لكل عنوان IP خلال 15 دقيقة — يُحسَب من جدول login_attempts
    // نفسه مباشرة، بلا أي جدول أو ملف إضافي.
    $failStmt = $pdo->prepare("SELECT COUNT(*) c FROM login_attempts WHERE ip_address = ? AND attempted_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)");
    $failStmt->execute([$clientIp]);
    $recentFails = (int)$failStmt->fetch()["c"];
    $isRateLimited = $recentFails >= 5;

    if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["login_submit"])) {
        if (!hash_equals(csrfToken(), postVal("csrf"))) {
            $loginError = "انتهت صلاحية الصفحة — أعد المحاولة.";
        } elseif ($isRateLimited) {
            $loginError = "محاولات دخول فاشلة كثيرة من جهازك. انتظر 15 دقيقة ثم أعد المحاولة.";
        } else {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND is_active = 1");
        $stmt->execute([trim($_POST["username"] ?? "")]);
        $u = $stmt->fetch();
        $hashToCheck = $u["password_hash"] ?? '$2y$10$usqIrspZmdT.63KKB4A6y.7hoLW1CGPCEEW8YQzkzL9RUdCgxJDTG';
        $ok = password_verify($_POST["password"] ?? "", $hashToCheck);
        if ($u && $ok) {
            session_regenerate_id(true); // يمنع Session Fixation: أي معرّف جلسة معروف مسبقاً (قبل الدخول) يصبح لاغياً هنا فوراً
            $_SESSION["user"] = ["id" => $u["id"], "username" => $u["username"], "full_name" => $u["full_name"], "role" => $u["role"]];
            logAudit($pdo, $u["id"], "LOGIN", "User", $u["id"]);
            if (!empty($_POST["remember"])) issueRememberToken($pdo, $u["id"]);
            redirect("index.php");
        } else {
            $pdo->prepare("INSERT INTO login_attempts (ip_address, username) VALUES (?, ?)")->execute([$clientIp, trim($_POST["username"] ?? "")]);
            $loginError = "اسم المستخدم أو كلمة المرور غير صحيحة.";
        }
        }
    }
    echo "<!DOCTYPE html><html lang='ar' dir='rtl'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1, viewport-fit=cover'><title>تسجيل الدخول — FMS/EMS</title>" . pwaHeadTags() . "<style>" . pageStyles() . "</style></head><body class='auth-body'>";
    echo "<form class='auth-card' method='post'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
    echo "<img class='auth-logo' src='./icons/icon-180.png' alt='' width='64' height='64'>";
    echo "<div class='auth-eyebrow'>FMS / EMS</div><h1>تسجيل الدخول</h1><p class='auth-sub'>نظام إدارة الآليات والمعدات والصيانة والبيع</p>";
    if ($loginError) echo "<div class='alert alert-danger'>" . e($loginError) . "</div>";
    if ($m = $_SESSION["flash"] ?? null) { $t = $_SESSION["flash_type"] ?? "success"; unset($_SESSION["flash"]); echo "<div class='alert alert-$t'>" . e($m) . "</div>"; }
    // autocomplete صحيح = يعمل الملء التلقائي من «كلمات السر» في آيفون (Face ID)
    echo "<label>اسم المستخدم</label><input type='text' name='username' required autocapitalize='none' autocorrect='off' spellcheck='false' autocomplete='username' value='" . e(postVal("username")) . "'>";
    echo "<label>كلمة المرور</label><input type='password' name='password' required autocomplete='current-password'>";
    echo "<label class='check-row'><input type='checkbox' name='remember' value='1' checked> <span>تذكرني على هذا الجهاز (" . REMEMBER_DAYS . " يوماً)</span></label>";
    echo "<button class='btn btn-primary btn-block' type='submit' name='login_submit' value='1'>دخول</button>";
    echo "<button type='button' class='auth-install' data-install-open hidden>" . icon("install") . " ثبّت التطبيق على الشاشة الرئيسية</button>";
    echo "</form>" . installSheetHtml() . pwaRegisterScript() . chatbaseWidgetScript() . "</body></html>";
    exit;
}

$user = $_SESSION["user"];
$role = $user["role"];

/* =====================================================================
   الصلاحيات — RBAC حقيقي يُفرَض هنا في الخادم قبل أي تعديل على القاعدة
   ===================================================================== */
$NAV_BY_ROLE = [
    "EXECUTIVE_MANAGEMENT" => ["dashboard", "assets", "appointments", "workorders", "inventory", "documents", "tco", "auctions", "users", "audit", "help"],
    "FLEET_MANAGER"        => ["dashboard", "assets", "appointments", "workorders", "inventory", "documents", "tco", "auctions", "audit", "help"],
    "WORKSHOP_MANAGER"     => ["dashboard", "appointments", "assets", "workorders", "inventory", "documents", "help"],
    "STOREKEEPER"          => ["dashboard", "inventory", "appointments", "help"], // المواعيد: عرض فقط
    "TECHNICIAN"           => ["dashboard", "workorders", "appointments", "help"],
];
$ACTION_ROLES = [
    "create_asset" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "update_asset" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "delete_asset" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "create_wo"    => ["FLEET_MANAGER", "WORKSHOP_MANAGER"],
    "transition_wo"=> ["WORKSHOP_MANAGER", "TECHNICIAN", "FLEET_MANAGER"],
    "submit_inspection" => ["WORKSHOP_MANAGER", "TECHNICIAN"],
    "approve_wo"   => ["WORKSHOP_MANAGER"],
    "record_labor" => ["WORKSHOP_MANAGER", "TECHNICIAN"],
    "create_part"  => ["STOREKEEPER", "FLEET_MANAGER"],
    "issue_part"   => ["STOREKEEPER"],
    "compute_tco"  => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "create_user"  => ["EXECUTIVE_MANAGEMENT"],
    "create_auction" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "place_bid"    => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT", "WORKSHOP_MANAGER", "STOREKEEPER", "TECHNICIAN"],
    "cancel_auction" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "create_document" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT", "WORKSHOP_MANAGER"],
    "delete_document" => ["FLEET_MANAGER", "EXECUTIVE_MANAGEMENT"],
    "receive_stock"   => ["STOREKEEPER", "FLEET_MANAGER"],
    "adjust_stock"    => ["STOREKEEPER", "FLEET_MANAGER"],
    // ── مواعيد الصيانة ──
    "request_appointment" => ["FLEET_MANAGER", "WORKSHOP_MANAGER", "TECHNICIAN", "EXECUTIVE_MANAGEMENT"], // + سحب طلبه المعلّق
    "manage_appointment"  => ["WORKSHOP_MANAGER", "EXECUTIVE_MANAGEMENT"], // تأكيد/إلغاء/تعيين فني/إعادة جدولة/لم يحضر
    "work_appointment"    => ["WORKSHOP_MANAGER", "EXECUTIVE_MANAGEMENT", "TECHNICIAN"], // بدء/إكمال — الفني فقط إن كان هو المعيَّن
];
function requirePerm(string $action, string $role, array $ACTION_ROLES): void {
    if (!in_array($role, $ACTION_ROLES[$action] ?? [], true)) {
        flash("دورك ($role) لا يملك صلاحية تنفيذ هذا الإجراء.", "danger");
        redirect("index.php");
    }
}

// صور الآليات: تُقدَّم فقط لمستخدم مسجَّل الدخول (المجلد نفسه مغلق أمام الوصول المباشر)
if (($_GET["media"] ?? "") === "asset_photo") serveAssetPhoto($pdo, (string)($_GET["id"] ?? ""));

/* =====================================================================
   محرك TCO — نفس المعادلة والعتبة 60% من الوثيقة الأصلية
   ===================================================================== */
define("TCO_THRESHOLD", 0.60);
function computeAndSaveTco(string $assetId, PDO $pdo): array {
    $asset = $pdo->prepare("SELECT * FROM assets WHERE id = ?");
    $asset->execute([$assetId]);
    $a = $asset->fetch();
    if (!$a) throw new RuntimeException("الأصل غير موجود");

    $maintAgg = $pdo->prepare("SELECT COALESCE(SUM(total_cost),0) t FROM work_orders WHERE asset_id = ? AND status = 'CLOSED'");
    $maintAgg->execute([$assetId]);
    $maintCost = (float)$maintAgg->fetch()["t"];
    $operCost = (float)$a["cumulative_operational_cost"];
    $marketValue = (float)$a["current_market_value"];

    if ($marketValue <= 0) throw new RuntimeException("القيمة السوقية يجب أن تكون أكبر من صفر لحساب TCO");

    $tco = (float)$a["initial_capex"] + $maintCost + $operCost - $marketValue;
    $ratio = $maintCost / $marketValue;
    $unfeasible = $ratio >= TCO_THRESHOLD;

    $pdo->prepare("INSERT INTO tco_analysis_logs (id, asset_id, capex, cumulative_maintenance_cost, cumulative_operational_cost, current_market_recovery_value, tco, maintenance_to_value_ratio, is_unfeasible) VALUES (?,?,?,?,?,?,?,?,?)")
        ->execute([uid(), $assetId, $a["initial_capex"], $maintCost, $operCost, $marketValue, $tco, $ratio, $unfeasible ? 1 : 0]);

    $pdo->prepare("UPDATE assets SET cumulative_maintenance_cost = ?, is_disposal_flagged = ? WHERE id = ?")
        ->execute([$maintCost, $unfeasible ? 1 : 0, $assetId]);

    return ["tco" => $tco, "ratio" => $ratio, "unfeasible" => $unfeasible];
}

/* =====================================================================
   معالجة كل إجراءات POST (كل التعديلات على قاعدة البيانات تمر من هنا)
   ===================================================================== */
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST["action"])) {
    csrfCheck();
    $action = $_POST["action"];

    if ($action === "create_asset") {
        requirePerm($action, $role, $ACTION_ROLES);
        $serial = inStr("serial_number", 120);
        $vin = inStr("vin", 120);
        $extra = assetExtraFromPost();
        $fuel = inEnum("fuel_type", array_keys(fuelLabels()), null);
        $year = inIntOrNull("manufacturing_year", 1950, (int)date("Y") + 1);
        $capex = inNumOrNull("initial_capex", 0.01);
        $market = inNumOrNull("current_market_value", 0);
        $err = "";
        if ($serial === "" || inStr("brand") === "" || inStr("model") === "" || inStr("category", 120) === "") $err = "أكمل الحقول الإلزامية (*)";
        elseif (!$fuel || !$year || $capex === null || $market === null) $err = "تحقق من نوع الوقود وسنة الصنع والقيم المالية";
        else {
            $dup = $pdo->prepare("SELECT id FROM assets WHERE serial_number = ? OR (vin <> '' AND vin = ?)");
            $dup->execute([$serial, $vin]);
            if ($dup->fetch()) $err = "الرقم التسلسلي أو رقم الهيكل مدخل سابقاً";
            elseif (plateTaken($pdo, $extra["plate_number"])) $err = "رقم اللوحة مسجّل لآلية أخرى";
        }
        if ($err) { keepOldInput(); flash($err, "danger"); redirect("index.php?page=assets&new=1"); }

        $id = uid();
        $code = "AST-" . date("Y") . "-" . strtoupper(substr(uid(), 0, 6));
        $pdo->prepare("INSERT INTO assets (id, asset_code, serial_number, vin, brand, model, manufacturing_year, fuel_type, category, initial_capex, book_value, current_market_value, location, odometer_km, engine_hours,
                plate_number, ownership_type, department, cost_center, assigned_driver, service_interval_days, service_interval_km, next_service_due_date, next_service_due_km, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?,?,?)")
            ->execute([$id, $code, $serial, $vin ?: null, inStr("brand"), inStr("model"), $year, $fuel, inStr("category", 120), $capex, $capex, $market, inStr("location"),
                inNumOrNull("odometer_km", 0) ?? 0, inNumOrNull("engine_hours", 0) ?? 0,
                $extra["plate_number"], $extra["ownership_type"], $extra["department"], $extra["cost_center"], $extra["assigned_driver"],
                $extra["service_interval_days"], $extra["service_interval_km"], $extra["next_service_due_date"], $extra["next_service_due_km"], $extra["notes"]]);
        logAudit($pdo, $user["id"], "CREATE", "Asset", $id, $code);
        $msg = "تم إنشاء الأصل $code بنجاح"; $type = "success";
        try {
            if ($photo = handleAssetPhotoUpload()) $pdo->prepare("UPDATE assets SET photo_path = ? WHERE id = ?")->execute([$photo, $id]);
        } catch (RuntimeException $ex) { $msg .= " — لكن لم تُحفظ الصورة: " . $ex->getMessage(); $type = "warning"; }
        flash($msg, $type);
        redirect("index.php?page=asset_detail&id=" . urlencode($id));
    }

    if ($action === "update_asset") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = inStr("id", 36);
        $cur = $pdo->prepare("SELECT * FROM assets WHERE id = ? AND deleted_at IS NULL"); $cur->execute([$id]); $cur = $cur->fetch();
        if (!$cur) { flash("الأصل غير موجود", "danger"); redirect("index.php?page=assets"); }
        $back = "index.php?page=asset_detail&id=" . urlencode($id);
        $status = inEnum("status", array_keys(assetStatusLabels()), null);
        $vin = inStr("vin", 120);
        $extra = assetExtraFromPost();
        $err = "";
        if (!$status) $err = "حالة غير صالحة";
        elseif ($vin !== "" && $vin !== (string)$cur["vin"]) {
            $dup = $pdo->prepare("SELECT id FROM assets WHERE vin = ? AND id <> ?"); $dup->execute([$vin, $id]);
            if ($dup->fetch()) $err = "رقم الهيكل مسجّل لأصل آخر";
        }
        if (!$err && plateTaken($pdo, $extra["plate_number"], $id)) $err = "رقم اللوحة مسجّل لآلية أخرى";
        if ($err) { flash($err, "danger"); redirect($back . "&edit=1"); }

        $pdo->prepare("UPDATE assets SET status=?, current_market_value=?, location=?, vin=?, odometer_km=?, engine_hours=?,
                plate_number=?, ownership_type=?, department=?, cost_center=?, assigned_driver=?, service_interval_days=?, service_interval_km=?,
                next_service_due_date=?, next_service_due_km=?, notes=? WHERE id=?")
            ->execute([$status, inNumOrNull("current_market_value", 0) ?? $cur["current_market_value"], inStr("location"), $vin ?: null,
                inNumOrNull("odometer_km", 0) ?? $cur["odometer_km"], inNumOrNull("engine_hours", 0) ?? $cur["engine_hours"],
                $extra["plate_number"], $extra["ownership_type"], $extra["department"], $extra["cost_center"], $extra["assigned_driver"],
                $extra["service_interval_days"], $extra["service_interval_km"], $extra["next_service_due_date"], $extra["next_service_due_km"], $extra["notes"], $id]);
        $changes = $cur["status"] !== $status ? "status {$cur['status']} -> $status" : "";
        $msg = "تم تحديث بيانات الأصل"; $type = "success";
        try {
            if (!empty($_POST["remove_photo"]) && $cur["photo_path"]) {
                deleteAssetPhoto($cur["photo_path"]);
                $pdo->prepare("UPDATE assets SET photo_path = NULL WHERE id = ?")->execute([$id]);
                $changes .= " photo removed";
            }
            if ($photo = handleAssetPhotoUpload()) {
                deleteAssetPhoto($cur["photo_path"]);
                $pdo->prepare("UPDATE assets SET photo_path = ? WHERE id = ?")->execute([$photo, $id]);
                $changes .= " photo updated";
            }
        } catch (RuntimeException $ex) { $msg .= " — لكن لم تُحفظ الصورة: " . $ex->getMessage(); $type = "warning"; }
        logAudit($pdo, $user["id"], "UPDATE", "Asset", $id, trim($changes));
        flash($msg, $type);
        redirect($back);
    }

    if ($action === "delete_asset") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = $_POST["id"];
        $pdo->prepare("UPDATE assets SET deleted_at = NOW() WHERE id = ?")->execute([$id]);
        logAudit($pdo, $user["id"], "DELETE", "Asset", $id);
        flash("تم حذف الأصل");
        redirect("index.php?page=assets");
    }

    if ($action === "create_wo") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = uid();
        $num = "WO-" . date("Y") . "-" . random_int(100000, 999999);
        $pdo->prepare("INSERT INTO work_orders (id, wo_number, asset_id, type, failure_type, description) VALUES (?,?,?,?,?,?)")
            ->execute([$id, $num, $_POST["asset_id"], $_POST["type"], $_POST["failure_type"] ?: null, trim($_POST["description"])]);
        logAudit($pdo, $user["id"], "CREATE", "WorkOrder", $id, $num);
        flash("تم إنشاء أمر الشغل $num");
        redirect("index.php?page=workorders");
    }

    if ($action === "transition_wo") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = $_POST["id"];
        $target = $_POST["target"];
        $allowed = [
            "DRAFT" => ["APPROVED_OPEN"], "APPROVED_OPEN" => ["IN_PROGRESS"],
            "IN_PROGRESS" => ["PENDING_PARTS", "QUALITY_INSPECTION"], "PENDING_PARTS" => ["IN_PROGRESS"],
            "QUALITY_INSPECTION" => ["CLOSED", "IN_PROGRESS"], "CLOSED" => [],
        ];
        $woStmt = $pdo->prepare("SELECT * FROM work_orders WHERE id = ?"); $woStmt->execute([$id]); $wo = $woStmt->fetch();
        if (!$wo) { flash("أمر الشغل غير موجود", "danger"); redirect("index.php?page=workorders"); }
        if (!in_array($target, $allowed[$wo["status"]] ?? [], true)) {
            flash("انتقال غير مسموح من {$wo['status']} إلى $target", "danger");
            redirect("index.php?page=workorders");
        }
        if ($target === "CLOSED" && (!$wo["inspection_passed"] || !$wo["workshop_manager_approved_by"])) {
            flash("لا يمكن الإغلاق قبل اجتياز الفحص الفني واعتماد مدير الورشة", "danger");
            redirect("index.php?page=workorders");
        }
        $closedAt = $target === "CLOSED" ? date("Y-m-d H:i:s") : null;
        $pdo->prepare("UPDATE work_orders SET status=?, closed_at=COALESCE(?, closed_at) WHERE id=?")->execute([$target, $closedAt, $id]);
        logAudit($pdo, $user["id"], "STATUS_CHANGE", "WorkOrder", $id, "{$wo['status']} -> $target");
        if ($target === "CLOSED") {
            try { computeAndSaveTco($wo["asset_id"], $pdo); } catch (Throwable $ex) { /* لا نمنع الإغلاق إن فشل حساب TCO لاحقاً */ }
        }
        flash("تم نقل أمر الشغل إلى الحالة التالية");
        redirect("index.php?page=workorders");
    }

    if ($action === "submit_inspection") {
        requirePerm($action, $role, $ACTION_ROLES);
        $pdo->prepare("UPDATE work_orders SET inspection_passed = ? WHERE id = ?")->execute([$_POST["passed"] === "1" ? 1 : 0, $_POST["id"]]);
        logAudit($pdo, $user["id"], "UPDATE", "WorkOrder", $_POST["id"], "inspection=" . $_POST["passed"]);
        flash("تم تسجيل نتيجة الفحص الفني");
        redirect("index.php?page=workorders");
    }

    if ($action === "approve_wo") {
        requirePerm($action, $role, $ACTION_ROLES);
        $pdo->prepare("UPDATE work_orders SET workshop_manager_approved_by = ? WHERE id = ?")->execute([$user["id"], $_POST["id"]]);
        logAudit($pdo, $user["id"], "APPROVE", "WorkOrder", $_POST["id"]);
        flash("تم اعتماد مدير الورشة");
        redirect("index.php?page=workorders");
    }

    if ($action === "record_labor") {
        requirePerm($action, $role, $ACTION_ROLES);
        $hours = (float)$_POST["hours"]; $rate = (float)$_POST["rate"];
        $labor = round($hours * $rate, 2);
        $woStmt = $pdo->prepare("SELECT parts_cost FROM work_orders WHERE id = ?"); $woStmt->execute([$_POST["id"]]);
        $partsCost = (float)$woStmt->fetch()["parts_cost"];
        $pdo->prepare("UPDATE work_orders SET actual_labor_hours=?, technician_hourly_rate=?, labor_cost=?, total_cost=? WHERE id=?")
            ->execute([$hours, $rate, $labor, $labor + $partsCost, $_POST["id"]]);
        logAudit($pdo, $user["id"], "UPDATE", "WorkOrder", $_POST["id"], "labor_cost=$labor");
        flash("تم تسجيل ساعات العمل والتكلفة");
        redirect("index.php?page=workorders");
    }

    if ($action === "create_part") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = uid();
        $pdo->prepare("INSERT INTO spare_parts (id, sku, description, quantity, reorder_level, unit_cost, warehouse_id) VALUES (?,?,?,?,?,?, (SELECT id FROM (SELECT id FROM warehouses LIMIT 1) w))")
            ->execute([$id, trim($_POST["sku"]), trim($_POST["description"]), (int)$_POST["quantity"], (int)$_POST["reorder_level"], (float)$_POST["unit_cost"]]);
        logAudit($pdo, $user["id"], "CREATE", "SparePart", $id);
        flash("تمت إضافة الصنف للمخزون");
        redirect("index.php?page=inventory");
    }

    if ($action === "issue_part") {
        requirePerm($action, $role, $ACTION_ROLES);
        $pdo->beginTransaction();
        try {
            $woStmt = $pdo->prepare("SELECT * FROM work_orders WHERE id = ? FOR UPDATE"); $woStmt->execute([$_POST["work_order_id"]]); $wo = $woStmt->fetch();
            if (!$wo || $wo["status"] !== "IN_PROGRESS") throw new RuntimeException("لا يجوز الصرف إلا لأمر شغل بحالة قيد التنفيذ");
            $partStmt = $pdo->prepare("SELECT * FROM spare_parts WHERE id = ? FOR UPDATE"); $partStmt->execute([$_POST["spare_part_id"]]); $part = $partStmt->fetch();
            $qty = (int)$_POST["quantity"];
            if (!$part || $part["quantity"] < $qty) throw new RuntimeException("الكمية المتاحة غير كافية");

            $total = $part["unit_cost"] * $qty;
            $pdo->prepare("INSERT INTO wo_parts_consumption (id, work_order_id, spare_part_id, quantity, unit_cost_snapshot, total_cost) VALUES (?,?,?,?,?,?)")
                ->execute([uid(), $wo["id"], $part["id"], $qty, $part["unit_cost"], $total]);
            $newQty = $part["quantity"] - $qty;
            $pdo->prepare("UPDATE spare_parts SET quantity = ? WHERE id = ?")->execute([$newQty, $part["id"]]);
            $pdo->prepare("UPDATE work_orders SET parts_cost = parts_cost + ?, total_cost = total_cost + ? WHERE id = ?")->execute([$total, $total, $wo["id"]]);
            if ($newQty <= $part["reorder_level"]) {
                $pdo->prepare("INSERT INTO stock_alerts (id, spare_part_id, message) VALUES (?,?,?)")
                    ->execute([uid(), $part["id"], "المخزون ($newQty) وصل لحد إعادة الطلب لصنف: " . $part["description"]]);
            }
            $pdo->prepare("INSERT INTO stock_movements (id, part_id, movement_type, quantity, unit_cost, reference_type, reference_id, notes, created_by) VALUES (?,?,?,?,?,?,?,?,?)")
                ->execute([uid(), $part["id"], "ISSUE", $qty, $part["unit_cost"], "WorkOrder", $wo["id"], "صرف لأمر " . $wo["wo_number"], $user["id"]]);
            logAudit($pdo, $user["id"], "UPDATE", "SparePart", $part["id"], "issued $qty to WO {$wo['wo_number']}");
            $pdo->commit();
            flash("تم صرف القطعة وتحديث تكلفة أمر الشغل");
        } catch (Throwable $ex) {
            $pdo->rollBack();
            flash($ex->getMessage(), "danger");
        }
        redirect("index.php?page=inventory");
    }

    if ($action === "compute_tco") {
        requirePerm($action, $role, $ACTION_ROLES);
        try {
            $r = computeAndSaveTco($_POST["asset_id"], $pdo);
            flash("TCO = " . money($r["tco"]) . " — نسبة الصيانة/القيمة: " . round($r["ratio"] * 100, 1) . "٪" . ($r["unfeasible"] ? " تحذير: غير مجدٍ اقتصادياً" : ""));
        } catch (Throwable $ex) {
            flash($ex->getMessage(), "danger");
        }
        redirect("index.php?page=tco");
    }

    if ($action === "create_user") {
        requirePerm($action, $role, $ACTION_ROLES);
        $hash = password_hash($_POST["password"], PASSWORD_DEFAULT);
        $id = uid();
        $pdo->prepare("INSERT INTO users (id, username, password_hash, full_name, role) VALUES (?,?,?,?,?)")
            ->execute([$id, trim($_POST["username"]), $hash, trim($_POST["full_name"]), $_POST["role"]]);
        logAudit($pdo, $user["id"], "CREATE", "User", $id);
        flash("تم إنشاء المستخدم بنجاح");
        redirect("index.php?page=users");
    }

    if ($action === "create_auction") {
        requirePerm($action, $role, $ACTION_ROLES);
        $startAt = $_POST["start_at"] ?: date("Y-m-d H:i:s");
        $endAt = $_POST["end_at"];
        if (strtotime($endAt) <= strtotime($startAt)) {
            flash("موعد انتهاء المزاد يجب أن يكون بعد موعد البدء", "danger");
            redirect("index.php?page=auctions");
        }
        $id = uid();
        $pdo->prepare("INSERT INTO auctions (id, asset_id, title, starting_price, bid_step, deposit_percent, start_at, end_at, status, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)")
            ->execute([$id, $_POST["asset_id"], trim($_POST["title"]), (float)$_POST["starting_price"], (float)($_POST["bid_step"] ?: 500), (float)($_POST["deposit_percent"] ?: 10), $startAt, $endAt, strtotime($startAt) <= time() ? "LIVE" : "SCHEDULED", $user["id"]]);
        // القسم 6.4/16: لا يمكن طرح أصل للمزاد وهو ما يزال بحالة نشطة تشغيلياً — نحوّله تلقائياً لحالة "معروضة للبيع"
        $pdo->prepare("UPDATE assets SET status = 'FOR_SALE' WHERE id = ?")->execute([$_POST["asset_id"]]);
        logAudit($pdo, $user["id"], "CREATE", "Auction", $id, trim($_POST["title"]));
        flash("تم إنشاء المزاد بنجاح");
        redirect("index.php?page=auctions");
    }

    if ($action === "place_bid") {
        requirePerm($action, $role, $ACTION_ROLES);
        $auctionId = $_POST["auction_id"];
        $amount = (float)$_POST["amount"];
        $bidderName = trim($_POST["bidder_name"] ?: $user["full_name"]);

        $pdo->beginTransaction();
        try {
            $aStmt = $pdo->prepare("SELECT * FROM auctions WHERE id = ? FOR UPDATE");
            $aStmt->execute([$auctionId]);
            $auction = $aStmt->fetch();
            if (!$auction) throw new RuntimeException("المزاد غير موجود");
            if (strtotime($auction["end_at"]) <= time() || $auction["status"] === "ENDED" || $auction["status"] === "CANCELLED") {
                throw new RuntimeException("انتهى هذا المزاد أو أُلغي — لا يمكن المزايدة عليه");
            }
            $topStmt = $pdo->prepare("SELECT MAX(amount) m FROM bids WHERE auction_id = ?");
            $topStmt->execute([$auctionId]);
            $currentTop = (float)($topStmt->fetch()["m"] ?? 0);
            $minRequired = max((float)$auction["starting_price"], $currentTop + (float)$auction["bid_step"]);
            if ($amount < $minRequired) {
                throw new RuntimeException("المبلغ يجب ألا يقل عن " . money($minRequired));
            }

            $pdo->prepare("INSERT INTO bids (id, auction_id, bidder_name, amount) VALUES (?,?,?,?)")
                ->execute([uid(), $auctionId, $bidderName, $amount]);

            // قاعدة Anti-Sniping (القسم 6.5): مزايدة خلال آخر N دقائق تُمدِّد
            // المزاد تلقائياً N دقيقة من لحظة المزايدة نفسها، لا من الموعد الأصلي
            $remainingSeconds = strtotime($auction["end_at"]) - time();
            $windowSeconds = (int)$auction["anti_snipe_window_minutes"] * 60;
            $extended = false;
            if ($remainingSeconds <= $windowSeconds) {
                $newEnd = date("Y-m-d H:i:s", time() + (int)$auction["anti_snipe_extend_minutes"] * 60);
                $pdo->prepare("UPDATE auctions SET end_at = ?, status = 'LIVE' WHERE id = ?")->execute([$newEnd, $auctionId]);
                $extended = true;
            } else {
                $pdo->prepare("UPDATE auctions SET status = 'LIVE' WHERE id = ? AND status = 'SCHEDULED'")->execute([$auctionId]);
            }

            logAudit($pdo, $user["id"], "CREATE", "Bid", $auctionId, "$bidderName: " . money($amount));
            $pdo->commit();
            flash($extended ? "تم قبول مزايدتك — تم تمديد المزاد تلقائياً (Anti-Sniping)" : "تم قبول مزايدتك بنجاح");
        } catch (Throwable $ex) {
            $pdo->rollBack();
            flash($ex->getMessage(), "danger");
        }
        redirect("index.php?page=auction_detail&id=" . urlencode($auctionId));
    }

    if ($action === "cancel_auction") {
        requirePerm($action, $role, $ACTION_ROLES);
        $pdo->prepare("UPDATE auctions SET status = 'CANCELLED' WHERE id = ?")->execute([$_POST["id"]]);
        logAudit($pdo, $user["id"], "UPDATE", "Auction", $_POST["id"], "cancelled");
        flash("تم إلغاء المزاد");
        redirect("index.php?page=auctions");
    }

    // ── وثائق الأصول ──
    if ($action === "create_document") {
        requirePerm($action, $role, $ACTION_ROLES);
        $assetId = $_POST["asset_id"] ?? "";
        $title = trim($_POST["title"] ?? "");
        if ($assetId === "" || $title === "") {
            flash("الأصل والعنوان مطلوبان", "danger");
            redirect("index.php?page=documents");
        }
        $id = uid();
        $pdo->prepare("INSERT INTO asset_documents (id, asset_id, doc_type, title, doc_number, issued_at, expires_at, notes, created_by) VALUES (?,?,?,?,?,?,?,?,?)")
            ->execute([
                $id, $assetId, $_POST["doc_type"] ?? "OTHER", $title,
                trim($_POST["doc_number"] ?? "") ?: null,
                ($_POST["issued_at"] ?? "") ?: null,
                ($_POST["expires_at"] ?? "") ?: null,
                trim($_POST["notes"] ?? "") ?: null,
                $user["id"]
            ]);
        logAudit($pdo, $user["id"], "CREATE", "Document", $id, $title);
        flash("تم إضافة الوثيقة بنجاح");
        redirect("index.php?page=documents");
    }

    if ($action === "delete_document") {
        requirePerm($action, $role, $ACTION_ROLES);
        $id = $_POST["id"] ?? "";
        $pdo->prepare("DELETE FROM asset_documents WHERE id = ?")->execute([$id]);
        logAudit($pdo, $user["id"], "DELETE", "Document", $id);
        flash("تم حذف الوثيقة");
        redirect("index.php?page=documents");
    }

    // ── حركات المخزون ──
    if ($action === "receive_stock") {
        requirePerm($action, $role, $ACTION_ROLES);
        $partId = $_POST["part_id"] ?? "";
        $qty = (float)($_POST["quantity"] ?? 0);
        $cost = (float)($_POST["unit_cost"] ?? 0);
        if ($qty <= 0 || $partId === "") {
            flash("الكمية والصنف مطلوبان", "danger");
            redirect("index.php?page=inventory");
        }
        $pdo->beginTransaction();
        try {
            $pdo->prepare("UPDATE spare_parts SET quantity = quantity + ? WHERE id = ?")->execute([$qty, $partId]);
            if ($cost > 0) {
                $pdo->prepare("UPDATE spare_parts SET unit_cost = ? WHERE id = ?")->execute([$cost, $partId]);
            }
            $mid = uid();
            $pdo->prepare("INSERT INTO stock_movements (id, part_id, movement_type, quantity, unit_cost, notes, created_by) VALUES (?,?,?,?,?,?,?)")
                ->execute([$mid, $partId, "RECEIVE", $qty, $cost, trim($_POST["notes"] ?? "") ?: null, $user["id"]]);
            $pdo->commit();
            logAudit($pdo, $user["id"], "CREATE", "StockMovement", $mid, "RECEIVE +$qty");
            flash("تم إدخال الكمية للمخزون");
        } catch (Throwable $e) {
            $pdo->rollBack();
            flash("فشل إدخال المخزون: " . $e->getMessage(), "danger");
        }
        redirect("index.php?page=inventory");
    }

    if ($action === "adjust_stock") {
        requirePerm($action, $role, $ACTION_ROLES);
        $partId = $_POST["part_id"] ?? "";
        $qty = (float)($_POST["quantity"] ?? 0);
        $dir = $_POST["direction"] ?? "ADJUST_IN";
        if ($qty <= 0 || $partId === "") {
            flash("الكمية والصنف مطلوبان", "danger");
            redirect("index.php?page=inventory");
        }
        $type = $dir === "ADJUST_OUT" ? "ADJUST_OUT" : "ADJUST_IN";
        $pdo->beginTransaction();
        try {
            if ($type === "ADJUST_OUT") {
                $cur = $pdo->prepare("SELECT quantity FROM spare_parts WHERE id = ? FOR UPDATE");
                $cur->execute([$partId]);
                $row = $cur->fetch();
                if (!$row || (float)$row["quantity"] < $qty) {
                    $pdo->rollBack();
                    flash("الكمية المتوفرة غير كافية للتسوية بالخصم", "danger");
                    redirect("index.php?page=inventory");
                }
                $pdo->prepare("UPDATE spare_parts SET quantity = quantity - ? WHERE id = ?")->execute([$qty, $partId]);
            } else {
                $pdo->prepare("UPDATE spare_parts SET quantity = quantity + ? WHERE id = ?")->execute([$qty, $partId]);
            }
            $mid = uid();
            $pdo->prepare("INSERT INTO stock_movements (id, part_id, movement_type, quantity, unit_cost, notes, created_by) VALUES (?,?,?,?,0,?,?)")
                ->execute([$mid, $partId, $type, $qty, trim($_POST["notes"] ?? "") ?: null, $user["id"]]);
            $pdo->commit();
            logAudit($pdo, $user["id"], "CREATE", "StockMovement", $mid, "$type $qty");
            flash("تمت تسوية المخزون");
        } catch (Throwable $e) {
            $pdo->rollBack();
            flash("فشلت التسوية: " . $e->getMessage(), "danger");
        }
        redirect("index.php?page=inventory");
    }

    /* ══════════════════ مواعيد الصيانة ══════════════════ */
    if ($action === "request_appointment") {
        requirePerm("request_appointment", $role, $ACTION_ROLES);
        $assetId = inStr("asset_id", 36);
        $back = "index.php?page=appointments&view=book" . ($assetId !== "" ? "&asset=" . urlencode($assetId) : "");
        [$when, $err] = apptParseWhen();
        $type = inEnum("service_type", array_keys(apptTypes()), null);
        $desc = inText("description", 2000);
        if (!$err && !$type) $err = "اختر نوع الخدمة";
        if (!$err && $type === "CORRECTIVE" && $desc === "") $err = "صف العطل باختصار لطلب الإصلاح";
        if ($err) { keepOldInput(); flash($err, "danger"); redirect($back); }
        $pdo->beginTransaction();
        try {
            $asset = lockAsset($pdo, $assetId);
            assertAssetBookable($asset);
            if ($c = apptConflict($pdo, $assetId, $when["date"], $when["slot"])) {
                throw new RuntimeException("يوجد موعد آخر لنفس الآلية في نفس اليوم والفترة ({$c['appt_number']}) — اختر فترة أو يوماً آخر");
            }
            $id = uid(); $num = "APT-" . date("ymd") . "-" . strtoupper(substr(uid(), 0, 5));
            $pdo->prepare("INSERT INTO maintenance_appointments (id, appt_number, asset_id, requested_by, scheduled_at, scheduled_date, preferred_slot, is_exact_time, service_type, description) VALUES (?,?,?,?,?,?,?,?,?,?)")
                ->execute([$id, $num, $assetId, $user["id"], $when["at"], $when["date"], $when["slot"], $when["exact"], $type, $desc !== "" ? $desc : null]);
            logAudit($pdo, $user["id"], "CREATE", "Appointment", $id, "$num · {$asset['asset_code']} · {$when['date']} {$when['slot']} · $type");
            $pdo->commit();
        } catch (Throwable $ex) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            keepOldInput(); flash(friendlyError($ex), "danger"); redirect($back);
        }
        flash("تم إرسال طلب الموعد $num — بانتظار تأكيد الورشة");
        redirect("index.php?page=appointment_detail&id=" . urlencode($id));
    }

    $APPT_ACTION_PERM = [
        "confirm_appointment" => "manage_appointment", "cancel_appointment" => "manage_appointment",
        "no_show_appointment" => "manage_appointment", "reschedule_appointment" => "manage_appointment",
        "assign_appointment_tech" => "manage_appointment", "create_appointment_wo" => "manage_appointment",
        "start_appointment" => "work_appointment", "complete_appointment" => "work_appointment",
        "withdraw_appointment" => "request_appointment",
    ];
    if (isset($APPT_ACTION_PERM[$action])) {
        requirePerm($APPT_ACTION_PERM[$action], $role, $ACTION_ROLES);
        $apptId = inStr("id", 36);
        $back = "index.php?page=appointment_detail&id=" . urlencode($apptId);
        $today = date("Y-m-d");
        $msg = "";
        $pdo->beginTransaction();
        try {
            $st = $pdo->prepare("SELECT * FROM maintenance_appointments WHERE id = ? FOR UPDATE"); $st->execute([$apptId]);
            $ap = $st->fetch();
            if (!$ap) throw new RuntimeException("الموعد غير موجود");
            $asset = lockAsset($pdo, $ap["asset_id"]);
            if (!$asset) throw new RuntimeException("الآلية المرتبطة بالموعد غير موجودة");
            // الفني لا يبدأ/يُكمل إلا الموعد المعيَّن له هو
            if ($role === "TECHNICIAN" && in_array($action, ["start_appointment", "complete_appointment"], true) && $ap["assigned_technician"] !== $user["id"]) {
                throw new RuntimeException("هذا الموعد غير مُعيَّن لك — لا يمكنك تغيير حالته");
            }

            if ($action === "confirm_appointment") {
                assertAssetBookable($asset); // قد تكون بيعت بعد الطلب
                if ($ap["scheduled_date"] < $today) throw new RuntimeException("تاريخ الموعد مضى — أعد جدولته قبل التأكيد");
                $tech = inStr("assigned_technician", 36) ?: null;
                if ($tech && !validTechnician($pdo, $tech)) throw new RuntimeException("الفني المختار غير صالح");
                if ($tech && ($c = techConflict($pdo, $tech, $ap["scheduled_date"], $ap["preferred_slot"], $ap["id"]))) throw new RuntimeException("الفني مرتبط بموعد آخر في نفس الفترة ({$c['appt_number']})");
                $notes = inText("workshop_notes", 2000);
                apptMove($pdo, $ap, "CONFIRMED", ["assigned_technician" => $tech, "confirmed_by" => $user["id"], "confirmed_at" => date("Y-m-d H:i:s"), "workshop_notes" => $notes !== "" ? $notes : $ap["workshop_notes"]], $user["id"]);
                $msg = "تم تأكيد الموعد " . $ap["appt_number"];
                if (!empty($_POST["create_wo"]) && !$ap["linked_work_order_id"]) $msg .= " وإنشاء أمر الشغل " . createWoFromAppointment($pdo, $ap, $tech, $user["id"]) . " (مسودة)";
            }

            elseif ($action === "cancel_appointment") {
                $reason = inStr("cancel_reason", 250);
                if ((function_exists("mb_strlen") ? mb_strlen($reason, "UTF-8") : strlen($reason)) < 3) throw new RuntimeException("اكتب سبب الإلغاء (3 أحرف على الأقل)");
                apptMove($pdo, $ap, "CANCELLED", ["cancel_reason" => $reason], $user["id"], $reason);
                $msg = "تم إلغاء الموعد" . ($ap["linked_work_order_id"] ? " — تنبيه: أمر الشغل المرتبط لم يُمَس، راجعه من صفحة أوامر الشغل" : "");
            }

            elseif ($action === "withdraw_appointment") {
                if ($ap["requested_by"] !== $user["id"]) throw new RuntimeException("يمكنك سحب طلباتك أنت فقط");
                if ($ap["status"] !== "PENDING") throw new RuntimeException("لا يمكن سحب الطلب بعد تأكيده — تواصل مع الورشة");
                apptMove($pdo, $ap, "CANCELLED", ["cancel_reason" => "سحبه مقدّم الطلب"], $user["id"], "withdrawn by requester");
                $msg = "تم سحب طلب الموعد";
            }

            elseif ($action === "no_show_appointment") {
                if ($ap["scheduled_date"] > $today) throw new RuntimeException("لا يمكن تسجيل «لم تحضر» قبل يوم الموعد");
                apptMove($pdo, $ap, "NO_SHOW", [], $user["id"]);
                $msg = "تم تسجيل عدم حضور الآلية";
            }

            elseif ($action === "start_appointment") {
                assertAssetBookable($asset);
                if ($ap["scheduled_date"] > $today) throw new RuntimeException("لا يمكن بدء الموعد قبل يومه — أعد جدولته إن حضرت الآلية مبكراً");
                $prev = null;
                if (in_array($asset["status"], ["ACTIVE", "IDLE"], true)) {
                    $prev = $asset["status"];
                    $pdo->prepare("UPDATE assets SET status = 'UNDER_MAINTENANCE' WHERE id = ?")->execute([$asset["id"]]);
                    logAudit($pdo, $user["id"], "UPDATE", "Asset", $asset["id"], "status $prev -> UNDER_MAINTENANCE (appointment {$ap['appt_number']})");
                }
                apptMove($pdo, $ap, "IN_PROGRESS", ["started_at" => date("Y-m-d H:i:s"), "asset_prev_status" => $prev], $user["id"]);
                $msg = "بدأ العمل على الموعد — الآلية الآن «تحت الصيانة»";
            }

            elseif ($action === "complete_appointment") {
                $odo = inNumOrNull("odometer_km", 0);
                $hours = inNumOrNull("engine_hours", 0);
                $nextDate = inDate("next_service_due_date");
                $nextKm = inNumOrNull("next_service_due_km", 0);
                $notes = inText("workshop_notes", 2000);
                if ($odo !== null && $odo < (float)$asset["odometer_km"]) throw new RuntimeException("قراءة العداد أقل من المسجَّلة سابقاً (" . money($asset["odometer_km"]) . " كم)");
                if ($hours !== null && $hours < (float)$asset["engine_hours"]) throw new RuntimeException("ساعات المحرك أقل من المسجَّلة سابقاً");
                if ($nextDate !== null && $nextDate <= $today) throw new RuntimeException("تاريخ الصيانة القادمة يجب أن يكون بعد اليوم");
                $odoNow = $odo ?? (float)$asset["odometer_km"];
                if ($nextKm !== null && $nextKm <= $odoNow) throw new RuntimeException("كيلومترات الصيانة القادمة يجب أن تتجاوز قراءة العداد الحالية");

                // تحديث next_service_due: القيمة اليدوية أولاً، ثم فترة الصيانة الدورية
                // (للصيانة الوقائية فقط — إصلاح عطل لا يُعيد ضبط جدول الوقاية)
                $isPrev = $ap["service_type"] === "PREVENTIVE";
                $curDate = $asset["next_service_due_date"]; $curKm = $asset["next_service_due_km"];
                if ($nextDate === null) {
                    if ($isPrev && $asset["service_interval_days"]) $nextDate = date("Y-m-d", strtotime("+" . (int)$asset["service_interval_days"] . " days"));
                    elseif ($isPrev) $nextDate = ($curDate && $curDate > $today) ? $curDate : null; // المستحق تحقق بهذه الصيانة
                    else $nextDate = $curDate;
                }
                if ($nextKm === null) {
                    if ($isPrev && $asset["service_interval_km"]) $nextKm = $odoNow + (int)$asset["service_interval_km"];
                    elseif ($isPrev) $nextKm = ($curKm !== null && (float)$curKm > $odoNow) ? $curKm : null;
                    else $nextKm = $curKm;
                }
                $newStatus = ($asset["status"] === "UNDER_MAINTENANCE" && $ap["asset_prev_status"]) ? $ap["asset_prev_status"] : $asset["status"];
                $pdo->prepare("UPDATE assets SET odometer_km = ?, engine_hours = ?, next_service_due_date = ?, next_service_due_km = ?, last_service_date = ?, status = ? WHERE id = ?")
                    ->execute([$odoNow, $hours ?? $asset["engine_hours"], $nextDate, $nextKm, $isPrev ? $today : $asset["last_service_date"], $newStatus, $asset["id"]]);
                logAudit($pdo, $user["id"], "UPDATE", "Asset", $asset["id"], "service done ({$ap['appt_number']}) next=" . ($nextDate ?? "-") . "/" . ($nextKm !== null ? money($nextKm) . "km" : "-") . ($newStatus !== $asset["status"] ? " status -> $newStatus" : ""));
                apptMove($pdo, $ap, "COMPLETED", ["completed_at" => date("Y-m-d H:i:s"), "odometer_at_service" => $odo,
                    "workshop_notes" => trim(((string)$ap["workshop_notes"]) . ($notes !== "" ? "\n" . $notes : "")) ?: null], $user["id"]);
                $msg = "اكتمل الموعد — الصيانة القادمة: " . ($nextDate ? arDate($nextDate, false) : "غير محددة") . ($nextKm !== null ? " / " . money($nextKm) . " كم" : "");
                if ($ap["linked_work_order_id"]) {
                    $wo = $pdo->prepare("SELECT wo_number, status FROM work_orders WHERE id = ?"); $wo->execute([$ap["linked_work_order_id"]]); $wo = $wo->fetch();
                    if ($wo && $wo["status"] !== "CLOSED") $msg .= " · تذكير: أمر الشغل {$wo['wo_number']} ما زال مفتوحاً";
                }
            }

            elseif ($action === "reschedule_appointment") {
                if (!in_array($ap["status"], ["PENDING", "CONFIRMED"], true)) throw new RuntimeException("إعادة الجدولة متاحة للمواعيد المعلّقة أو المؤكدة فقط");
                assertAssetBookable($asset);
                [$when, $err] = apptParseWhen();
                if ($err) throw new RuntimeException($err);
                if ($c = apptConflict($pdo, $ap["asset_id"], $when["date"], $when["slot"], $ap["id"])) throw new RuntimeException("يوجد موعد آخر لنفس الآلية في تلك الفترة ({$c['appt_number']})");
                if ($ap["assigned_technician"] && $ap["status"] === "CONFIRMED" && ($c = techConflict($pdo, $ap["assigned_technician"], $when["date"], $when["slot"], $ap["id"]))) {
                    throw new RuntimeException("الفني المعيَّن مشغول في تلك الفترة ({$c['appt_number']}) — غيّر الفني أولاً");
                }
                $pdo->prepare("UPDATE maintenance_appointments SET scheduled_at = ?, scheduled_date = ?, preferred_slot = ?, is_exact_time = ? WHERE id = ?")
                    ->execute([$when["at"], $when["date"], $when["slot"], $when["exact"], $ap["id"]]);
                logAudit($pdo, $user["id"], "RESCHEDULE", "Appointment", $ap["id"], "{$ap['appt_number']}: {$ap['scheduled_at']} -> {$when['at']}");
                $msg = "تمت إعادة جدولة الموعد إلى " . arDate($when["date"]);
            }

            elseif ($action === "assign_appointment_tech") {
                if (!in_array($ap["status"], APPT_ACTIVE, true)) throw new RuntimeException("لا يمكن تعيين فني لموعد منتهٍ");
                $tech = inStr("assigned_technician", 36) ?: null;
                if ($tech && !validTechnician($pdo, $tech)) throw new RuntimeException("الفني المختار غير صالح");
                if ($tech && $ap["status"] !== "PENDING" && ($c = techConflict($pdo, $tech, $ap["scheduled_date"], $ap["preferred_slot"], $ap["id"]))) throw new RuntimeException("الفني مرتبط بموعد آخر في نفس الفترة ({$c['appt_number']})");
                $pdo->prepare("UPDATE maintenance_appointments SET assigned_technician = ? WHERE id = ?")->execute([$tech, $ap["id"]]);
                if ($ap["linked_work_order_id"]) $pdo->prepare("UPDATE work_orders SET technician_id = ? WHERE id = ? AND status <> 'CLOSED'")->execute([$tech, $ap["linked_work_order_id"]]);
                logAudit($pdo, $user["id"], "ASSIGN", "Appointment", $ap["id"], "{$ap['appt_number']}: technician " . ($tech ?? "none"));
                $msg = $tech ? "تم تعيين الفني" : "تمت إزالة الفني المعيَّن";
            }

            elseif ($action === "create_appointment_wo") {
                if (!in_array($ap["status"], ["CONFIRMED", "IN_PROGRESS"], true)) throw new RuntimeException("يُنشأ أمر الشغل لموعد مؤكد أو جارٍ فقط");
                if ($ap["linked_work_order_id"]) throw new RuntimeException("الموعد مرتبط بأمر شغل بالفعل");
                $msg = "تم إنشاء أمر الشغل " . createWoFromAppointment($pdo, $ap, $ap["assigned_technician"], $user["id"]) . " (مسودة)";
            }

            $pdo->commit();
            flash($msg ?: "تم");
        } catch (Throwable $ex) {
            if ($pdo->inTransaction()) $pdo->rollBack();
            flash(friendlyError($ex), "danger");
        }
        redirect($back);
    }

    // أي إجراء غير معروف: عودة آمنة (نُقل إلى هنا — كان سابقاً قبل إجراءات
    // الوثائق والمخزون فيمنع تنفيذها كلياً)
    redirect("index.php");
}

/* =====================================================================
   دوال عرض الصفحات — كل دالة تُخرِج HTML الخاص بصفحة واحدة
   ===================================================================== */

function renderDashboard(PDO $pdo, string $role): void {
    // تجميع من SQL مباشرة بدل تحميل كل الأصول في الذاكرة
    $k = $pdo->query("SELECT COUNT(*) total, COALESCE(SUM(status='ACTIVE'),0) active, COALESCE(SUM(is_disposal_flagged=1),0) flagged, COALESCE(SUM(current_market_value),0) fleet_value FROM assets WHERE deleted_at IS NULL")->fetch();
    $total = (int)$k["total"]; $active = (int)$k["active"]; $flagged = (int)$k["flagged"]; $fleetValue = (float)$k["fleet_value"];
    $recent = $pdo->query("SELECT * FROM assets WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 8")->fetchAll();
    $openWo = (int)$pdo->query("SELECT COUNT(*) c FROM work_orders WHERE status <> 'CLOSED'")->fetch()["c"];
    $lowStock = (int)$pdo->query("SELECT COUNT(*) c FROM spare_parts WHERE quantity <= reorder_level")->fetch()["c"];
    $docExpired = 0; $docSoon = 0;
    try {
        $docExpired = (int)$pdo->query("SELECT COUNT(*) c FROM asset_documents WHERE expires_at IS NOT NULL AND expires_at < CURDATE()")->fetch()["c"];
        $docSoon = (int)$pdo->query("SELECT COUNT(*) c FROM asset_documents WHERE expires_at IS NOT NULL AND expires_at >= CURDATE() AND expires_at <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)")->fetch()["c"];
    } catch (Throwable $e) { /* الجدول قد لا يكون موجوداً بعد على نسخة قديمة */ }

    // ── مواعيد الصيانة: خلال 7 أيام + المعلّقة + الآليات المستحقة ──
    $today = date("Y-m-d"); $in7 = date("Y-m-d", strtotime("+7 days"));
    $st = $pdo->prepare("SELECT COUNT(*) c, COALESCE(SUM(status='PENDING'),0) pending FROM maintenance_appointments WHERE status IN ('PENDING','CONFIRMED') AND scheduled_date BETWEEN ? AND ?");
    $st->execute([$today, $in7]); $ap7 = $st->fetch();
    $apptWeek = (int)$ap7["c"]; $apptPending = (int)$ap7["pending"];
    $st = $pdo->prepare("SELECT COUNT(*) c FROM assets WHERE deleted_at IS NULL AND status NOT IN ('SOLD','SCRAPPED') AND ((next_service_due_date IS NOT NULL AND next_service_due_date < ?) OR (next_service_due_km IS NOT NULL AND odometer_km >= next_service_due_km))");
    $st->execute([$today]); $serviceOverdue = (int)$st->fetch()["c"];
    $st = $pdo->prepare("SELECT m.*, a.asset_code, a.brand, a.model, a.plate_number FROM maintenance_appointments m JOIN assets a ON a.id = m.asset_id WHERE m.status IN ('PENDING','CONFIRMED','IN_PROGRESS') AND m.scheduled_date BETWEEN ? AND ? ORDER BY m.scheduled_at ASC LIMIT 5");
    $st->execute([$today, $in7]); $upcoming = $st->fetchAll();

    echo "<h1>مرحباً</h1><p class='sub'>نظرة عامة محدَّثة لحظياً من قاعدة البيانات الحقيقية.</p>";
    echo "<div class='kpi-strip'>";
    echo "<div class='kpi'><div class='l'>إجمالي الآليات</div><div class='v'>$total</div></div>";
    echo "<div class='kpi'><div class='l'>الآليات العاملة</div><div class='v'>$active</div></div>";
    echo "<a class='kpi kpi-link' href='index.php?page=appointments&f=upcoming'><div class='l'>مواعيد صيانة خلال 7 أيام</div><div class='v " . ($apptPending ? "warn" : "") . "'>$apptWeek</div>" . ($apptPending ? "<div class='hint'>$apptPending بانتظار التأكيد</div>" : "") . "</a>";
    echo "<div class='kpi'><div class='l'>أوامر شغل مفتوحة</div><div class='v " . ($openWo ? "warn" : "") . "'>$openWo</div></div>";
    echo "<div class='kpi'><div class='l'>آليات تجاوزت عتبة TCO</div><div class='v " . ($flagged ? "bad" : "") . "'>$flagged</div></div>";
    echo "<div class='kpi'><div class='l'>أصناف تحت حد إعادة الطلب</div><div class='v " . ($lowStock ? "warn" : "") . "'>$lowStock</div></div>";
    echo "<div class='kpi'><div class='l'>قيمة الأسطول السوقية</div><div class='v'>" . money($fleetValue) . "</div></div>";
    echo "<div class='kpi'><div class='l'>وثائق منتهية / قريبة</div><div class='v " . (($docExpired || $docSoon) ? "warn" : "") . "'>" . ($docExpired + $docSoon) . "</div></div>";
    echo "</div>";

    if ($apptWeek) echo "<a class='alert alert-info alert-link' href='index.php?page=appointments&f=upcoming'>" . icon("appointments") . " لديكم $apptWeek موعد صيانة خلال الأيام السبعة القادمة" . ($apptPending ? " — منها $apptPending بانتظار تأكيد الورشة" : "") . ".</a>";
    if ($serviceOverdue) echo "<a class='alert alert-warning alert-link' href='index.php?page=assets&due=1'>" . icon("wrench") . " $serviceOverdue آلية تجاوزت موعد أو كيلومترات الصيانة الدورية.</a>";
    if ($flagged) echo "<div class='alert alert-danger'>$flagged آلية تجاوزت عتبة عدم الجدوى الاقتصادية (TCO) وتحتاج مراجعة — صفحة \"التكلفة الكلية\".</div>";
    if ($docExpired) echo "<div class='alert alert-danger'>$docExpired وثيقة منتهية الصلاحية — راجع صفحة \"الوثائق\".</div>";
    if ($docSoon) echo "<div class='alert alert-warning'>$docSoon وثيقة ستنتهي خلال 30 يوماً.</div>";

    if ($upcoming) {
        echo "<div class='panel'><h2>المواعيد القادمة</h2><div class='body'>" . apptListHtml($upcoming) . "</div></div>";
    }

    echo "<div class='panel'><h2>أحدث الأصول</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الرمز</th><th>الآلية</th><th>الفئة</th><th>الحالة</th><th>القيمة السوقية</th></tr>";
    foreach ($recent as $a) {
        echo "<tr><td class='mono'>" . e($a["asset_code"]) . "</td><td>" . e($a["brand"] . " " . $a["model"]) . "</td><td>" . e($a["category"]) . "</td><td>" . statusPill($a["status"]) . "</td><td class='mono'>" . money($a["current_market_value"]) . "</td></tr>";
    }
    if (!$recent) echo "<tr><td colspan='5'><div class='empty'>لا توجد أصول بعد</div></td></tr>";
    echo "</table></div></div>";
}

function statusPill(string $status): string {
    $map = [
        "ACTIVE" => ["success", "نشطة"], "UNDER_MAINTENANCE" => ["warn", "تحت الصيانة"], "IDLE" => ["neutral", "متوقفة"],
        "FOR_SALE" => ["accent", "معروضة للبيع"], "SOLD" => ["neutral", "مباعة"], "SCRAPPED" => ["danger", "مستبعدة"],
        "DRAFT" => ["neutral", "مسودة"], "APPROVED_OPEN" => ["accent", "معتمد"], "IN_PROGRESS" => ["warn", "قيد التنفيذ"],
        "PENDING_PARTS" => ["danger", "بانتظار القطع"], "QUALITY_INSPECTION" => ["accent", "فحص الجودة"], "CLOSED" => ["success", "مغلق"],
    ];
    [$cls, $label] = $map[$status] ?? ["neutral", $status];
    return "<span class='pill pill-$cls'>" . e($label) . "</span>";
}

/** حقول الآلية الموسَّعة — مشتركة بين نموذج الإنشاء والتعديل */
function assetFormFields(array $a, bool $isCreate): string {
    $v = function (string $k) use ($a) { return e($a[$k] ?? ""); };
    $sel = function (string $name, array $opts, $cur) { $h = "<select name='$name'>"; foreach ($opts as $k => $l) $h .= "<option value='" . e($k) . "'" . ((string)$cur === (string)$k ? " selected" : "") . ">" . e($l) . "</option>"; return $h . "</select>"; };
    $h = "<div class='form-grid'>";
    if ($isCreate) {
        $h .= "<div class='form-section'>الهوية</div>";
        $h .= "<div class='field'><label>الرقم التسلسلي *</label><input name='serial_number' required maxlength='120' value='" . $v("serial_number") . "'></div>";
        $h .= "<div class='field'><label>الماركة *</label><input name='brand' required value='" . $v("brand") . "'></div>";
        $h .= "<div class='field'><label>الموديل *</label><input name='model' required value='" . $v("model") . "'></div>";
        $h .= "<div class='field'><label>سنة الصنع *</label><input type='number' inputmode='numeric' name='manufacturing_year' required min='1950' max='" . (date("Y") + 1) . "' value='" . $v("manufacturing_year") . "'></div>";
        $h .= "<div class='field'><label>نوع الوقود *</label>" . $sel("fuel_type", fuelLabels(), $a["fuel_type"] ?? "DIESEL") . "</div>";
        $h .= "<div class='field'><label>الفئة *</label><input name='category' required placeholder='جرافة، حفارة، رافعة...' value='" . $v("category") . "'></div>";
    } else {
        $h .= "<div class='form-section'>الحالة والتشغيل</div>";
        $h .= "<div class='field'><label>الحالة</label>" . $sel("status", assetStatusLabels(), $a["status"]) . "</div>";
        $h .= "<div class='field'><label>القيمة السوقية الحالية</label><input type='number' inputmode='decimal' step='0.01' min='0' name='current_market_value' value='" . $v("current_market_value") . "'></div>";
    }
    $h .= "<div class='field'><label>رقم اللوحة</label><input name='plate_number' maxlength='40' placeholder='مثال: RAK 12345' value='" . $v("plate_number") . "'></div>";
    $h .= "<div class='field'><label>رقم الهيكل (VIN / Chassis)</label><input name='vin' maxlength='120' autocapitalize='characters' value='" . $v("vin") . "'></div>";
    $h .= "<div class='form-section'>الملكية والمسؤولية</div>";
    $h .= "<div class='field'><label>نوع الملكية</label>" . $sel("ownership_type", ownershipLabels(), $a["ownership_type"] ?? "OWNED") . "</div>";
    $h .= "<div class='field'><label>القسم</label><input name='department' maxlength='120' value='" . $v("department") . "'></div>";
    $h .= "<div class='field'><label>مركز التكلفة</label><input name='cost_center' maxlength='60' placeholder='CC-100' value='" . $v("cost_center") . "'></div>";
    $h .= "<div class='field'><label>السائق / المشغّل المسؤول</label><input name='assigned_driver' maxlength='190' value='" . $v("assigned_driver") . "'></div>";
    $h .= "<div class='field'><label>الموقع</label><input name='location' value='" . $v("location") . "'></div>";
    $h .= "<div class='field'><label>قراءة العداد (كم)</label><input type='number' inputmode='decimal' step='0.1' min='0' name='odometer_km' value='" . $v("odometer_km") . "'></div>";
    $h .= "<div class='field'><label>ساعات المحرك</label><input type='number' inputmode='decimal' step='0.1' min='0' name='engine_hours' value='" . $v("engine_hours") . "'></div>";
    if ($isCreate) {
        $h .= "<div class='form-section'>القيم المالية</div>";
        $h .= "<div class='field'><label>التكلفة الرأسمالية (CAPEX) *</label><input type='number' inputmode='decimal' step='0.01' name='initial_capex' required min='0.01' value='" . $v("initial_capex") . "'></div>";
        $h .= "<div class='field'><label>القيمة السوقية الحالية *</label><input type='number' inputmode='decimal' step='0.01' name='current_market_value' required min='0' value='" . $v("current_market_value") . "'></div>";
    }
    $h .= "<div class='form-section'>الصيانة الدورية <small>الفترات تُستخدم لحساب الموعد القادم تلقائياً بعد كل صيانة وقائية</small></div>";
    $h .= "<div class='field'><label>تاريخ الصيانة القادمة</label><input type='date' name='next_service_due_date' value='" . $v("next_service_due_date") . "'></div>";
    $h .= "<div class='field'><label>الصيانة القادمة عند (كم)</label><input type='number' inputmode='decimal' step='1' min='0' name='next_service_due_km' value='" . $v("next_service_due_km") . "'></div>";
    $h .= "<div class='field'><label>الفترة الدورية (أيام)</label><input type='number' inputmode='numeric' min='1' max='3650' name='service_interval_days' placeholder='مثال: 90' value='" . $v("service_interval_days") . "'></div>";
    $h .= "<div class='field'><label>الفترة الدورية (كم)</label><input type='number' inputmode='numeric' min='1' name='service_interval_km' placeholder='مثال: 5000' value='" . $v("service_interval_km") . "'></div>";
    $h .= "<div class='form-section'>ملاحظات وصورة</div>";
    $h .= "<div class='field span-2'><label>ملاحظات</label><textarea name='notes' rows='3' maxlength='5000'>" . $v("notes") . "</textarea></div>";
    $h .= "<div class='field span-2'><label>صورة الآلية (JPG / PNG / WEBP — تُصغَّر تلقائياً قبل الرفع)</label><input type='file' name='photo' accept='image/jpeg,image/png,image/webp' data-resize='1600'>";
    if (!$isCreate && !empty($a["photo_path"])) $h .= "<label class='check-row'><input type='checkbox' name='remove_photo' value='1'> <span>حذف الصورة الحالية</span></label>";
    $h .= "</div></div>";
    return $h;
}

function renderAssets(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $q = trim((string)($_GET["q"] ?? "")); $q = strCut($q, 80);
    $dueOnly = !empty($_GET["due"]);
    $where = "deleted_at IS NULL"; $params = [];
    if ($q !== "") {
        $like = "%" . addcslashes($q, "%_\\") . "%";
        $where .= " AND (asset_code LIKE ? OR serial_number LIKE ? OR vin LIKE ? OR plate_number LIKE ? OR brand LIKE ? OR model LIKE ? OR assigned_driver LIKE ? OR department LIKE ?)";
        $params = array_fill(0, 8, $like);
    }
    if ($dueOnly) { $where .= " AND status NOT IN ('SOLD','SCRAPPED') AND ((next_service_due_date IS NOT NULL AND next_service_due_date <= ?) OR (next_service_due_km IS NOT NULL AND odometer_km >= next_service_due_km - 500))"; $params[] = date("Y-m-d", strtotime("+14 days")); }
    $result = paginate($pdo, "SELECT COUNT(*) c FROM assets WHERE $where", "SELECT * FROM assets WHERE $where ORDER BY created_at DESC", $params);
    $assets = $result["items"];
    $canCreate = can("create_asset", $role, $ACTION_ROLES);
    $old = takeOldInput();

    echo "<h1>سجل الأصول</h1><p class='sub'>الهوية الرقمية الكاملة لكل آلية.</p>";

    if ($canCreate) {
        echo "<details class='panel panel-collapse'" . (!empty($_GET["new"]) ? " open" : "") . "><summary>" . icon('plus') . " إضافة أصل جديد</summary><div class='body'>";
        echo "<form method='post' enctype='multipart/form-data'><input type='hidden' name='action' value='create_asset'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo assetFormFields($old, true);
        echo "<button class='btn btn-primary' type='submit'>" . icon('plus') . " إنشاء الأصل</button></form></div></details>";
    }

    echo "<form class='toolbar search-bar' method='get'><input type='hidden' name='page' value='assets'>";
    echo "<input type='search' name='q' value='" . e($q) . "' placeholder='بحث: رمز، لوحة، هيكل، ماركة، سائق...' enterkeyhint='search'>";
    echo "<label class='chip" . ($dueOnly ? " is-active" : "") . "'><input type='checkbox' name='due' value='1'" . ($dueOnly ? " checked" : "") . " onchange='this.form.submit()'> مستحقة الصيانة</label>";
    echo "<button class='btn btn-ghost' type='submit'>بحث</button></form>";

    echo "<div class='panel'><h2>" . ($q !== "" || $dueOnly ? "نتائج البحث" : "كل الأصول") . " (" . $result["total"] . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الرمز</th><th>الآلية</th><th>الفئة</th><th>الحالة</th><th>الصيانة القادمة</th><th>القيمة السوقية</th><th></th></tr>";
    foreach ($assets as $a) {
        echo "<tr><td class='mono'>" . e($a["asset_code"]) . "</td><td>" . e($a["brand"] . " " . $a["model"]);
        if ($a["plate_number"]) echo "<br><span class='plate'>" . e($a["plate_number"]) . "</span>";
        echo "</td><td>" . e($a["category"]) . "</td><td>" . statusPill($a["status"]);
        if ($a["is_disposal_flagged"]) echo " <span class='pill pill-danger'>مرشّحة للبيع</span>";
        echo "</td><td>" . serviceDuePill($a) . "</td><td class='mono'>" . money($a["current_market_value"]) . "</td><td><a class='btn btn-ghost btn-sm' href='index.php?page=asset_detail&id=" . e($a["id"]) . "'>التفاصيل</a></td></tr>";
    }
    if (!$assets) echo "<tr><td colspan='7'><div class='empty'>" . ($q !== "" || $dueOnly ? "لا نتائج مطابقة" : "لا توجد أصول بعد — أضف أول أصل أعلاه") . "</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}

function renderAssetDetail(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $id = (string)($_GET["id"] ?? "");
    $stmt = $pdo->prepare("SELECT * FROM assets WHERE id = ? AND deleted_at IS NULL"); $stmt->execute([$id]); $a = $stmt->fetch();
    if (!$a) { echo "<div class='alert alert-danger'>الأصل غير موجود.</div><a class='btn btn-ghost' href='index.php?page=assets'>رجوع</a>"; return; }

    $wos = $pdo->prepare("SELECT * FROM work_orders WHERE asset_id = ? ORDER BY opened_at DESC"); $wos->execute([$id]); $wos = $wos->fetchAll();
    $tcoLogs = $pdo->prepare("SELECT * FROM tco_analysis_logs WHERE asset_id = ? ORDER BY calculated_at DESC LIMIT 5"); $tcoLogs->execute([$id]); $tcoLogs = $tcoLogs->fetchAll();
    $appts = $pdo->prepare("SELECT m.*, a.asset_code, a.brand, a.model, a.plate_number FROM maintenance_appointments m JOIN assets a ON a.id = m.asset_id WHERE m.asset_id = ? ORDER BY (m.status IN ('PENDING','CONFIRMED','IN_PROGRESS')) DESC, m.scheduled_at DESC LIMIT 6");
    $appts->execute([$id]); $appts = $appts->fetchAll();
    $canEdit = can("update_asset", $role, $ACTION_ROLES);
    $canDelete = can("delete_asset", $role, $ACTION_ROLES);
    $bookable = !in_array($a["status"], APPT_BLOCKED_ASSET_STATUSES, true);
    $canBook = can("request_appointment", $role, $ACTION_ROLES) && $bookable;

    echo "<a class='btn btn-ghost btn-sm back-link' href='index.php?page=assets'>" . icon("chev-back") . " رجوع للسجل</a>";
    echo "<div class='asset-hero'>";
    if ($a["photo_path"]) echo "<img class='asset-photo' src='index.php?media=asset_photo&id=" . e($a["id"]) . "&v=" . e(substr(md5((string)$a["photo_path"]), 0, 8)) . "' alt='صورة الآلية' loading='lazy'>";
    else echo "<div class='asset-photo asset-photo-empty'>" . icon("assets") . "</div>";
    echo "<div class='asset-hero-body'><h1>" . e($a["brand"] . " " . $a["model"]) . "</h1>";
    echo "<p class='sub mono'>" . e($a["asset_code"]) . " · " . e($a["serial_number"]) . ($a["plate_number"] ? " · <span class='plate'>" . e($a["plate_number"]) . "</span>" : "") . "</p>";
    echo "<div class='actions-row'>" . statusPill($a["status"]) . " " . serviceDuePill($a) . "</div>";
    echo "<div class='actions-row' style='margin-top:14px'>";
    if ($canBook) echo "<a class='btn btn-primary' href='index.php?page=appointments&view=book&asset=" . e($a["id"]) . "'>" . icon("calendar-plus") . " احجز صيانة</a>";
    elseif (!$bookable) echo "<span class='pill pill-neutral'>لا يمكن حجز صيانة لآلية " . e(assetStatusLabels()[$a["status"]]) . "</span>";
    if ($canEdit) echo "<a class='btn btn-ghost' href='#edit' data-open-details='edit'>" . icon("edit") . " تعديل</a>";
    echo "</div></div></div>";

    $kv = function (string $label, string $valHtml) { return "<div><span>" . e($label) . "</span><b>" . ($valHtml !== "" ? $valHtml : "—") . "</b></div>"; };
    echo "<div class='form-grid'>";
    echo "<div class='panel'><h2>البيانات</h2><div class='body'><div class='kv'>";
    echo $kv("الفئة", e($a["category"])) . $kv("سنة الصنع", e($a["manufacturing_year"])) . $kv("الوقود", e(fuelLabels()[$a["fuel_type"]] ?? $a["fuel_type"]));
    echo $kv("رقم اللوحة", e($a["plate_number"] ?? "")) . $kv("رقم الهيكل (VIN)", "<span class='mono'>" . e($a["vin"] ?? "") . "</span>");
    echo $kv("الملكية", e(ownershipLabels()[$a["ownership_type"] ?? "OWNED"] ?? "")) . $kv("القسم", e($a["department"] ?? "")) . $kv("مركز التكلفة", e($a["cost_center"] ?? ""));
    echo $kv("السائق المسؤول", e($a["assigned_driver"] ?? "")) . $kv("الموقع", e($a["location"] ?? ""));
    echo $kv("العداد", money($a["odometer_km"]) . " كم") . $kv("ساعات المحرك", money($a["engine_hours"]));
    echo $kv("القيمة الدفترية", money($a["book_value"])) . $kv("القيمة السوقية", money($a["current_market_value"]));
    echo "</div></div></div>";

    $remainKm = ($a["next_service_due_km"] !== null && $a["next_service_due_km"] !== "") ? (float)$a["next_service_due_km"] - (float)$a["odometer_km"] : null;
    echo "<div class='panel'><h2>الصيانة الدورية</h2><div class='body'><div class='kv'>";
    echo $kv("آخر صيانة وقائية", $a["last_service_date"] ? e(arDate($a["last_service_date"], false)) : "");
    echo $kv("الصيانة القادمة (تاريخ)", $a["next_service_due_date"] ? e(arDate($a["next_service_due_date"])) : "");
    echo $kv("الصيانة القادمة (كم)", $remainKm !== null ? money($a["next_service_due_km"]) . " <small>(" . ($remainKm > 0 ? "متبقٍ " . money($remainKm) : "تجاوز بـ " . money(-$remainKm)) . " كم)</small>" : "");
    echo $kv("الفترة الدورية", trim(($a["service_interval_days"] ? (int)$a["service_interval_days"] . " يوم" : "") . ($a["service_interval_days"] && $a["service_interval_km"] ? " / " : "") . ($a["service_interval_km"] ? money($a["service_interval_km"]) . " كم" : "")));
    echo "</div>";
    if ($a["notes"]) echo "<div class='note-box'>" . nl2br(e($a["notes"])) . "</div>";
    echo "</div></div>";
    echo "</div>";

    echo "<div class='panel'><h2>مواعيد الصيانة" . ($canBook ? " <a class='btn btn-ghost btn-sm' style='float:left' href='index.php?page=appointments&view=book&asset=" . e($a["id"]) . "'>" . icon("plus") . " موعد جديد</a>" : "") . "</h2><div class='body'>";
    echo $appts ? apptListHtml($appts, false) : "<div class='empty'>لا توجد مواعيد لهذه الآلية</div>";
    echo "</div></div>";

    if ($canEdit) {
        echo "<details class='panel panel-collapse' id='edit'" . (!empty($_GET["edit"]) ? " open" : "") . "><summary>" . icon("edit") . " تعديل بيانات الآلية</summary><div class='body'>";
        echo "<form method='post' enctype='multipart/form-data'><input type='hidden' name='action' value='update_asset'><input type='hidden' name='id' value='" . e($id) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo assetFormFields($a, false);
        echo "<button class='btn btn-primary' type='submit'>" . icon('check') . " حفظ التعديل</button></form>";
        if ($canDelete) {
            echo "<form method='post' data-confirm='سيُحذَف هذا الأصل. متابعة؟' style='margin-top:14px'><input type='hidden' name='action' value='delete_asset'><input type='hidden' name='id' value='" . e($id) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-danger btn-sm' type='submit'>" . icon("trash") . " حذف الأصل</button></form>";
        }
        echo "</div></details>";
    }

    echo "<div class='panel'><h2>أوامر الشغل (" . count($wos) . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الرقم</th><th>النوع</th><th>الحالة</th><th>التكلفة</th></tr>";
    foreach ($wos as $w) echo "<tr><td class='mono'>" . e($w["wo_number"]) . "</td><td>" . e($w["type"]) . "</td><td>" . statusPill($w["status"]) . "</td><td class='mono'>" . money($w["total_cost"]) . "</td></tr>";
    if (!$wos) echo "<tr><td colspan='4'><div class='empty'>لا توجد أوامر شغل لهذا الأصل</div></td></tr>";
    echo "</table></div></div>";

    echo "<div class='panel'><h2>سجل التكلفة الكلية (TCO)</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>التاريخ</th><th>TCO</th><th>نسبة الصيانة/القيمة</th><th>الحالة</th></tr>";
    foreach ($tcoLogs as $t) echo "<tr><td>" . e(date("Y-m-d H:i", strtotime($t["calculated_at"]))) . "</td><td class='mono'>" . money($t["tco"]) . "</td><td class='mono'>" . round($t["maintenance_to_value_ratio"] * 100, 1) . "٪</td><td>" . ($t["is_unfeasible"] ? "<span class='pill pill-danger'>غير مجدٍ</span>" : "<span class='pill pill-success'>مجدٍ</span>") . "</td></tr>";
    if (!$tcoLogs) echo "<tr><td colspan='4'><div class='empty'>لم يُحسَب TCO لهذا الأصل بعد — من صفحة \"التكلفة الكلية\"</div></td></tr>";
    echo "</table></div></div>";
}

function renderWorkOrders(PDO $pdo, string $role, array $ACTION_ROLES, string $userId): void {
    $assets = $pdo->query("SELECT id, asset_code, brand, model FROM assets WHERE deleted_at IS NULL")->fetchAll();
    $result = paginate(
        $pdo,
        "SELECT COUNT(*) c FROM work_orders",
        "SELECT w.*, a.asset_code, a.brand, a.model FROM work_orders w JOIN assets a ON a.id = w.asset_id ORDER BY w.opened_at DESC"
    );
    $wos = $result["items"];
    $canCreate = in_array($role, $ACTION_ROLES["create_wo"], true);
    $canTransition = in_array($role, $ACTION_ROLES["transition_wo"], true);
    $canInspect = in_array($role, $ACTION_ROLES["submit_inspection"], true);
    $canApprove = in_array($role, $ACTION_ROLES["approve_wo"], true);
    $canLabor = in_array($role, $ACTION_ROLES["record_labor"], true);

    echo "<h1>أوامر الشغل</h1><p class='sub'>مسودة &larr; معتمد &larr; قيد التنفيذ &larr; بانتظار القطع &larr; فحص الجودة &larr; مغلق.</p>";

    if ($canCreate) {
        echo "<div class='panel'><h2>إنشاء أمر شغل</h2><div class='body'>";
        echo "<form method='post'><input type='hidden' name='action' value='create_wo'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo "<div class='form-grid'>";
        echo "<div class='field'><label>الأصل *</label><select name='asset_id' required>";
        foreach ($assets as $a) echo "<option value='" . e($a["id"]) . "'>" . e($a["asset_code"] . " — " . $a["brand"] . " " . $a["model"]) . "</option>";
        echo "</select></div>";
        echo "<div class='field'><label>النوع *</label><select name='type' required><option value='PREVENTIVE'>وقائية</option><option value='CORRECTIVE'>تصحيحية</option><option value='ACCIDENT'>حادث</option></select></div>";
        echo "<div class='field'><label>نوع العطل</label><select name='failure_type'><option value=''>—</option><option value='MECHANICAL'>ميكانيكي</option><option value='ELECTRICAL'>كهربائي</option><option value='HYDRAULIC'>هيدروليكي</option><option value='BODY'>هيكل</option><option value='OTHER'>آخر</option></select></div>";
        echo "<div class='field' style='grid-column:1/-1'><label>الوصف *</label><textarea name='description' required rows='2'></textarea></div>";
        echo "</div><button class='btn btn-primary' type='submit'>" . icon('plus') . " إنشاء</button></form></div></div>";
    }

    echo "<div class='panel'><h2>كل أوامر الشغل (" . $result["total"] . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الرقم</th><th>الأصل</th><th>الحالة</th><th>التكلفة</th><th>إجراءات</th></tr>";
    $nextMap = ["DRAFT" => ["APPROVED_OPEN" => "اعتماد وفتح"], "APPROVED_OPEN" => ["IN_PROGRESS" => "بدء التنفيذ"], "IN_PROGRESS" => ["QUALITY_INSPECTION" => "إرسال للفحص", "PENDING_PARTS" => "تحويل لبانتظار القطع"], "PENDING_PARTS" => ["IN_PROGRESS" => "استئناف التنفيذ"], "QUALITY_INSPECTION" => ["CLOSED" => "إغلاق"]];
    foreach ($wos as $w) {
        echo "<tr><td class='mono'>" . e($w["wo_number"]) . "</td><td>" . e($w["asset_code"]) . "</td><td>" . statusPill($w["status"]) . "</td><td class='mono'>" . money($w["total_cost"]) . "</td><td><div class='actions-row'>";

        if ($canTransition) {
            foreach ($nextMap[$w["status"]] ?? [] as $target => $label) {
                if ($target === "CLOSED" && !($w["inspection_passed"] && $w["workshop_manager_approved_by"])) continue;
                echo "<form class='inline' method='post'><input type='hidden' name='action' value='transition_wo'><input type='hidden' name='id' value='" . e($w["id"]) . "'><input type='hidden' name='target' value='$target'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-ghost btn-sm' type='submit'>" . e($label) . "</button></form>";
            }
        }
        if ($w["status"] === "QUALITY_INSPECTION" && $canInspect && !$w["inspection_passed"]) {
            echo "<form class='inline' method='post'><input type='hidden' name='action' value='submit_inspection'><input type='hidden' name='id' value='" . e($w["id"]) . "'><input type='hidden' name='passed' value='1'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-ghost btn-sm' type='submit'>فحص: ناجح ✓</button></form>";
        }
        if ($w["status"] === "QUALITY_INSPECTION" && $canApprove && !$w["workshop_manager_approved_by"]) {
            echo "<form class='inline' method='post'><input type='hidden' name='action' value='approve_wo'><input type='hidden' name='id' value='" . e($w["id"]) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-ghost btn-sm' type='submit'>اعتماد مدير الورشة</button></form>";
        }
        echo " <a class='btn btn-ghost btn-sm' href='index.php?page=wo_print&id=" . e($w["id"]) . "'>" . icon("print") . " تقرير</a>";
        echo "</div></td></tr>";

        if ($w["status"] === "IN_PROGRESS" && $canLabor && !$w["actual_labor_hours"]) {
            echo "<tr><td colspan='5' style='background:var(--surface-alt)'><form method='post' class='actions-row'><input type='hidden' name='action' value='record_labor'><input type='hidden' name='id' value='" . e($w["id"]) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
            echo "<span style='font-size:.78rem;color:var(--text-secondary)'>تسجيل ساعات العمل:</span>";
            echo "<input type='number' inputmode='decimal' step='0.5' name='hours' placeholder='الساعات' required class='inline-input' style='width:100px'>";
            echo "<input type='number' inputmode='decimal' step='0.01' name='rate' placeholder='أجر الساعة' required class='inline-input' style='width:120px'>";
            echo "<button class='btn btn-ghost btn-sm' type='submit'>حفظ</button></form></td></tr>";
        }
    }
    if (!$wos) echo "<tr><td colspan='5'><div class='empty'>لا توجد أوامر شغل بعد</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}

function renderInventory(PDO $pdo, string $role, array $ACTION_ROLES): void {
    // استعلام منفصل بلا حدّ لكل الأصناف — يُستخدَم في القائمة المنسدلة لنموذج
    // الصرف، حيث يجب أن تظهر كل قطعة متاحة بصرف النظر عن رقم صفحة العرض أدناه
    $allParts = $pdo->query("SELECT id, description, quantity FROM spare_parts ORDER BY description")->fetchAll();
    $result = paginate($pdo, "SELECT COUNT(*) c FROM spare_parts", "SELECT * FROM spare_parts ORDER BY description");
    $parts = $result["items"];
    $inProgressWos = $pdo->query("SELECT w.id, w.wo_number, a.asset_code FROM work_orders w JOIN assets a ON a.id=w.asset_id WHERE w.status='IN_PROGRESS'")->fetchAll();
    $canCreate = in_array($role, $ACTION_ROLES["create_part"], true);
    $canIssue = in_array($role, $ACTION_ROLES["issue_part"], true);
    $canReceive = in_array($role, $ACTION_ROLES["receive_stock"], true); // كانا غير معرَّفين سابقاً فلا تظهر اللوحتان أبداً
    $canAdjust = in_array($role, $ACTION_ROLES["adjust_stock"], true);

    echo "<h1>المخزون وقطع الغيار</h1><p class='sub'>الصرف مرتبط إلزامياً بأمر شغل بحالة \"قيد التنفيذ\" فقط.</p>";

    if ($canCreate) {
        echo "<div class='panel'><h2>إضافة صنف</h2><div class='body'><form method='post'><input type='hidden' name='action' value='create_part'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo "<div class='form-grid'>";
        echo "<div class='field'><label>SKU *</label><input name='sku' required></div>";
        echo "<div class='field'><label>الوصف *</label><input name='description' required></div>";
        echo "<div class='field'><label>الكمية *</label><input type='number' name='quantity' required min='0'></div>";
        echo "<div class='field'><label>حد إعادة الطلب *</label><input type='number' name='reorder_level' required min='0'></div>";
        echo "<div class='field'><label>تكلفة الوحدة *</label><input type='number' step='0.01' name='unit_cost' required min='0'></div>";
        echo "</div><button class='btn btn-primary' type='submit'>" . icon('plus') . " إضافة</button></form></div></div>";
    }

    if ($canIssue) {
        echo "<div class='panel'><h2>صرف قطعة لأمر شغل</h2><div class='body'>";
        if (!$inProgressWos) {
            echo "<div class='empty'>لا توجد أوامر شغل بحالة \"قيد التنفيذ\" حالياً لصرف قطع لها</div>";
        } else {
            echo "<form method='post'><input type='hidden' name='action' value='issue_part'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><div class='form-grid'>";
            echo "<div class='field'><label>أمر الشغل *</label><select name='work_order_id' required>";
            foreach ($inProgressWos as $w) echo "<option value='" . e($w["id"]) . "'>" . e($w["wo_number"] . " — " . $w["asset_code"]) . "</option>";
            echo "</select></div>";
            echo "<div class='field'><label>القطعة *</label><select name='spare_part_id' required>";
            foreach ($allParts as $p) echo "<option value='" . e($p["id"]) . "'>" . e($p["description"] . " (متاح: " . $p["quantity"] . ")") . "</option>";
            echo "</select></div>";
            echo "<div class='field'><label>الكمية *</label><input type='number' name='quantity' required min='1'></div>";
            echo "</div><button class='btn btn-primary' type='submit'>" . icon('check') . " صرف</button></form>";
        }
        echo "</div></div>";
    }


    if ($canReceive) {
        echo "<div class='panel'><h2>إدخال للمخزون (استلام)</h2><div class='body'><form method='post'><input type='hidden' name='action' value='receive_stock'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><div class='form-grid'>";
        echo "<div class='field'><label>الصنف *</label><select name='part_id' required><option value=''>— اختر —</option>";
        foreach ($allParts as $p) echo "<option value='" . e($p["id"]) . "'>" . e($p["description"]) . " (متوفر: " . e($p["quantity"]) . ")</option>";
        echo "</select></div>";
        echo "<div class='field'><label>الكمية *</label><input type='number' step='0.01' name='quantity' required min='0.01'></div>";
        echo "<div class='field'><label>تكلفة الوحدة (اختياري)</label><input type='number' step='0.01' name='unit_cost' min='0'></div>";
        echo "<div class='field'><label>ملاحظات</label><input name='notes' placeholder='فاتورة / مورد'></div>";
        echo "</div><button class='btn btn-primary' type='submit'>تأكيد الإدخال</button></form></div></div>";
    }

    if ($canAdjust) {
        echo "<div class='panel'><h2>تسوية مخزون</h2><div class='body'><form method='post'><input type='hidden' name='action' value='adjust_stock'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><div class='form-grid'>";
        echo "<div class='field'><label>الصنف *</label><select name='part_id' required><option value=''>— اختر —</option>";
        foreach ($allParts as $p) echo "<option value='" . e($p["id"]) . "'>" . e($p["description"]) . " (متوفر: " . e($p["quantity"]) . ")</option>";
        echo "</select></div>";
        echo "<div class='field'><label>الاتجاه *</label><select name='direction'><option value='ADJUST_IN'>زيادة (جرد زائد)</option><option value='ADJUST_OUT'>نقص (جرد ناقص / تالف)</option></select></div>";
        echo "<div class='field'><label>الكمية *</label><input type='number' step='0.01' name='quantity' required min='0.01'></div>";
        echo "<div class='field'><label>سبب التسوية</label><input name='notes' placeholder='جرد / تالف / تصحيح'></div>";
        echo "</div><button class='btn btn-primary' type='submit'>تنفيذ التسوية</button></form></div></div>";
    }

    // آخر الحركات
    $movements = $pdo->query("SELECT m.*, p.description, p.sku FROM stock_movements m JOIN spare_parts p ON p.id = m.part_id ORDER BY m.created_at DESC LIMIT 15")->fetchAll();
    $movLabels = ["RECEIVE"=>"إدخال","ISSUE"=>"صرف","ADJUST_IN"=>"تسوية +","ADJUST_OUT"=>"تسوية −"];
    if ($movements) {
        echo "<div class='panel'><h2>آخر حركات المخزون</h2><div class='body' style='padding:0'><table class='dt'>";
        echo "<tr><th>التاريخ</th><th>النوع</th><th>الصنف</th><th>الكمية</th><th>ملاحظات</th></tr>";
        foreach ($movements as $m) {
            echo "<tr><td class='mono'>" . e($m["created_at"]) . "</td><td>" . e($movLabels[$m["movement_type"]] ?? $m["movement_type"]) . "</td>";
            echo "<td>" . e($m["description"]) . " <span class='mono' style='color:var(--text-tertiary)'>" . e($m["sku"]) . "</span></td>";
            echo "<td class='mono'>" . e($m["quantity"]) . "</td><td>" . e($m["notes"] ?? "—") . "</td></tr>";
        }
        echo "</table></div></div>";
    }

    echo "<div class='panel'><h2>المخزون الحالي (" . $result["total"] . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>SKU</th><th>الوصف</th><th>الكمية</th><th>حد إعادة الطلب</th><th>تكلفة الوحدة</th><th>الحالة</th></tr>";
    foreach ($parts as $p) {
        $low = $p["quantity"] <= $p["reorder_level"];
        echo "<tr><td class='mono'>" . e($p["sku"]) . "</td><td>" . e($p["description"]) . "</td><td class='mono'>" . e($p["quantity"]) . "</td><td class='mono'>" . e($p["reorder_level"]) . "</td><td class='mono'>" . money($p["unit_cost"]) . "</td><td>" . ($low ? "<span class='pill pill-danger'>أعد الطلب</span>" : "<span class='pill pill-success'>متوفر</span>") . "</td></tr>";
    }
    if (!$parts) echo "<tr><td colspan='6'><div class='empty'>لا توجد أصناف بعد</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}

function renderTco(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $assets = $pdo->query("SELECT * FROM assets WHERE deleted_at IS NULL ORDER BY is_disposal_flagged DESC, brand")->fetchAll();
    $canCompute = in_array($role, $ACTION_ROLES["compute_tco"], true);

    echo "<h1>التكلفة الكلية للملكية (TCO) وقرار البيع</h1><p class='sub'>TCO = CAPEX + تكاليف الصيانة المتراكمة + التكاليف التشغيلية − القيمة السوقية الحالية. عتبة عدم الجدوى: نسبة الصيانة/القيمة ≥ 60٪.</p>";

    echo "<div class='panel'><h2>كل الأصول</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الأصل</th><th>تكاليف الصيانة المتراكمة</th><th>القيمة السوقية</th><th>نسبة الصيانة/القيمة</th><th>الحالة</th><th></th></tr>";
    foreach ($assets as $a) {
        $ratio = $a["current_market_value"] > 0 ? $a["cumulative_maintenance_cost"] / $a["current_market_value"] : 0;
        echo "<tr><td>" . e($a["brand"] . " " . $a["model"]) . " <span class='mono' style='color:var(--text-tertiary)'>(" . e($a["asset_code"]) . ")</span></td>";
        echo "<td class='mono'>" . money($a["cumulative_maintenance_cost"]) . "</td><td class='mono'>" . money($a["current_market_value"]) . "</td>";
        echo "<td class='mono' style='color:" . ($ratio >= 0.6 ? "var(--danger)" : "inherit") . "'>" . round($ratio * 100, 1) . "٪</td>";
        echo "<td>" . ($a["is_disposal_flagged"] ? "<span class='pill pill-danger'>غير مجدٍ اقتصادياً</span>" : "<span class='pill pill-success'>مجدٍ</span>") . "</td>";
        echo "<td>";
        if ($canCompute) echo "<form class='inline' method='post'><input type='hidden' name='action' value='compute_tco'><input type='hidden' name='asset_id' value='" . e($a["id"]) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-ghost btn-sm' type='submit'>احسب الآن</button></form>";
        echo "</td></tr>";
    }
    if (!$assets) echo "<tr><td colspan='6'><div class='empty'>لا توجد أصول بعد</div></td></tr>";
    echo "</table></div></div>";
}

function auctionStatusPill(array $auction): string {
    $isEnded = strtotime($auction["end_at"]) <= time();
    if ($auction["status"] === "CANCELLED") return "<span class='pill pill-neutral'>ملغى</span>";
    if ($isEnded) return "<span class='pill pill-neutral'>منتهٍ</span>";
    if ($auction["status"] === "SCHEDULED" && strtotime($auction["start_at"]) > time()) return "<span class='pill pill-accent'>مجدوَل</span>";
    return "<span class='pill pill-danger'>مباشر الآن</span>";
}

function renderAuctions(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $result = paginate(
        $pdo,
        "SELECT COUNT(*) c FROM auctions",
        "SELECT a.*, ast.asset_code, ast.brand, ast.model,
        (SELECT MAX(amount) FROM bids WHERE auction_id = a.id) AS top_bid,
        (SELECT COUNT(*) FROM bids WHERE auction_id = a.id) AS bid_count
        FROM auctions a JOIN assets ast ON ast.id = a.asset_id
        ORDER BY (a.status = 'CANCELLED'), a.end_at DESC"
    );
    $auctions = $result["items"];
    $sellableAssets = $pdo->query("SELECT id, asset_code, brand, model FROM assets WHERE deleted_at IS NULL AND status IN ('ACTIVE','FOR_SALE')")->fetchAll();
    $canCreate = in_array($role, $ACTION_ROLES["create_auction"], true);

    echo "<h1>" . icon("gavel") . " المزادات</h1><p class='sub'>مزايدة لحظية مع تمديد تلقائي (Anti-Sniping) عند أي مزايدة خلال آخر دقائق المزاد.</p>";

    if ($canCreate) {
        echo "<div class='panel'><h2>" . icon("plus") . " إنشاء مزاد جديد</h2><div class='body'>";
        if (!$sellableAssets) {
            echo "<div class='empty'>لا توجد أصول متاحة للطرح حالياً (يجب أن تكون بحالة نشطة أو معروضة للبيع)</div>";
        } else {
            echo "<form method='post'><input type='hidden' name='action' value='create_auction'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
            echo "<div class='form-grid'>";
            echo "<div class='field'><label>الأصل *</label><select name='asset_id' required>";
            foreach ($sellableAssets as $a) echo "<option value='" . e($a["id"]) . "'>" . e($a["asset_code"] . " — " . $a["brand"] . " " . $a["model"]) . "</option>";
            echo "</select></div>";
            echo "<div class='field'><label>عنوان المزاد *</label><input name='title' required placeholder='مزاد التخلص من المعدات - دفعة...'></div>";
            echo "<div class='field'><label>السعر الافتتاحي *</label><input type='number' step='0.01' name='starting_price' required min='0.01'></div>";
            echo "<div class='field'><label>خطوة المزايدة الدنيا</label><input type='number' step='0.01' name='bid_step' value='500'></div>";
            echo "<div class='field'><label>نسبة الضمان المالي (٪)</label><input type='number' step='0.5' name='deposit_percent' value='10'></div>";
            echo "<div class='field'><label>موعد البدء</label><input type='datetime-local' name='start_at'></div>";
            echo "<div class='field'><label>موعد الانتهاء *</label><input type='datetime-local' name='end_at' required></div>";
            echo "</div><button class='btn btn-primary' type='submit'>" . icon("gavel") . " إنشاء المزاد</button></form>";
        }
        echo "</div></div>";
    }

    echo "<div class='panel'><h2>كل المزادات (" . $result["total"] . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>العنوان</th><th>الأصل</th><th>السعر الافتتاحي</th><th>أعلى مزايدة</th><th>الحالة</th><th></th></tr>";
    foreach ($auctions as $a) {
        echo "<tr><td>" . e($a["title"]) . "</td><td class='mono'>" . e($a["asset_code"]) . "</td><td class='mono'>" . money($a["starting_price"]) . "</td>";
        echo "<td class='mono'>" . ($a["top_bid"] ? money($a["top_bid"]) . " (" . (int)$a["bid_count"] . " مزايدة)" : "—") . "</td>";
        echo "<td>" . auctionStatusPill($a) . "</td>";
        echo "<td><a class='btn btn-ghost btn-sm' href='index.php?page=auction_detail&id=" . e($a["id"]) . "'>عرض</a></td></tr>";
    }
    if (!$auctions) echo "<tr><td colspan='6'><div class='empty'>لا توجد مزادات بعد</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}

function renderAuctionDetail(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $id = $_GET["id"] ?? "";
    $stmt = $pdo->prepare("SELECT a.*, ast.asset_code, ast.brand, ast.model, ast.category FROM auctions a JOIN assets ast ON ast.id = a.asset_id WHERE a.id = ?");
    $stmt->execute([$id]);
    $auction = $stmt->fetch();
    if (!$auction) { echo "<div class='alert alert-danger'>المزاد غير موجود.</div><a class='btn btn-ghost' href='index.php?page=auctions'>رجوع</a>"; return; }

    $bids = $pdo->prepare("SELECT * FROM bids WHERE auction_id = ? ORDER BY amount DESC, placed_at DESC");
    $bids->execute([$id]);
    $bids = $bids->fetchAll();
    $topBid = $bids[0]["amount"] ?? 0;
    $minRequired = max((float)$auction["starting_price"], (float)$topBid + (float)$auction["bid_step"]);
    $isEnded = strtotime($auction["end_at"]) <= time() || $auction["status"] === "CANCELLED";
    $canBid = in_array($role, $ACTION_ROLES["place_bid"], true) && !$isEnded;
    $canCancel = in_array($role, $ACTION_ROLES["cancel_auction"], true) && !$isEnded;

    echo "<a class='btn btn-ghost btn-sm' href='index.php?page=auctions' style='margin-bottom:14px'>" . icon("back") . " رجوع للمزادات</a>";
    echo "<h1>" . e($auction["title"]) . "</h1><p class='sub mono'>" . e($auction["asset_code"] . " — " . $auction["brand"] . " " . $auction["model"]) . "</p>";

    echo "<div class='form-grid'>";
    echo "<div class='panel'><h2>حالة المزاد</h2><div class='body'>";
    echo "<p style='margin-bottom:10px'>" . auctionStatusPill($auction) . "</p>";
    echo "<p><b>ينتهي في:</b> <span id='auction-end-time' data-end='" . e(date("c", strtotime($auction["end_at"]))) . "'>" . e(date("Y-m-d H:i", strtotime($auction["end_at"]))) . "</span></p>";
    echo "<p id='auction-countdown' class='mono' style='font-size:1.4rem;font-weight:700;margin-top:6px'></p>";
    echo "<p style='margin-top:10px'><b>السعر الافتتاحي:</b> " . money($auction["starting_price"]) . "</p>";
    echo "<p><b>خطوة المزايدة الدنيا:</b> " . money($auction["bid_step"]) . "</p>";
    echo "<p><b>الضمان المالي المطلوب:</b> " . round($auction["deposit_percent"], 1) . "٪ (" . money($auction["starting_price"] * $auction["deposit_percent"] / 100) . ")</p>";
    echo "<p style='margin-top:10px;font-size:1.3rem;font-weight:700' class='mono'>أعلى مزايدة: " . money($topBid) . "</p>";
    if ($canCancel) echo "<form method='post' data-confirm='سيُلغى هذا المزاد. متابعة؟' style='margin-top:14px'><input type='hidden' name='action' value='cancel_auction'><input type='hidden' name='id' value='" . e($id) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-danger btn-sm' type='submit'>إلغاء المزاد</button></form>";
    echo "</div></div>";

    echo "<div class='panel'><h2>" . ($canBid ? "ضع مزايدتك" : "المزايدة") . "</h2><div class='body'>";
    if ($isEnded) {
        echo "<div class='empty'>" . ($bids ? "انتهى المزاد — الفائز: <b>" . e($bids[0]["bidder_name"]) . "</b> بمبلغ " . money($topBid) : "انتهى المزاد بلا أي مزايدات") . "</div>";
    } elseif ($canBid) {
        echo "<form method='post'><input type='hidden' name='action' value='place_bid'><input type='hidden' name='auction_id' value='" . e($id) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo "<div class='field'><label>اسم المزايد</label><input name='bidder_name' placeholder='(اختياري — يُستخدَم اسمك الحالي إن تُرك فارغاً)'></div>";
        echo "<div class='field'><label>مبلغ المزايدة (الحد الأدنى " . money($minRequired) . ") *</label><input type='number' step='0.01' name='amount' required min='" . e($minRequired) . "'></div>";
        echo "<button class='btn btn-primary btn-block' type='submit'>" . icon("gavel") . " زايِد الآن</button></form>";
        echo "<p style='font-size:.76rem;color:var(--text-tertiary);margin-top:10px'>⚠️ ملاحظة: لا توجد بعد بوابة مصادقة منفصلة لمشترين خارجيين ولا تحصيل فعلي للضمان المالي — المزايدة هنا متاحة حالياً لمستخدمي النظام الداخليين فقط، كخطوة أولى قبل بناء بوابة مشترين مستقلة.</p>";
    } else {
        echo "<div class='empty'>ليست لديك صلاحية المزايدة.</div>";
    }
    echo "</div></div>";
    echo "</div>";

    echo "<div class='panel'><h2>سجل المزايدات (" . count($bids) . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>المزايد</th><th>المبلغ</th><th>الوقت</th></tr>";
    foreach ($bids as $i => $b) echo "<tr><td>" . e($b["bidder_name"]) . ($i === 0 && !$isEnded ? " <span class='pill pill-success'>الأعلى حالياً</span>" : "") . "</td><td class='mono'>" . money($b["amount"]) . "</td><td>" . e(date("Y-m-d H:i:s", strtotime($b["placed_at"]))) . "</td></tr>";
    if (!$bids) echo "<tr><td colspan='3'><div class='empty'>لا توجد مزايدات بعد — كن أول من يزايد</div></td></tr>";
    echo "</table></div></div>";

    if (!$isEnded) {
        echo "<script>
        (function(){
          var el = document.getElementById('auction-countdown');
          var endEl = document.getElementById('auction-end-time');
          var end = new Date(endEl.getAttribute('data-end')).getTime();
          function tick(){
            var diff = end - Date.now();
            if (diff <= 0) { el.textContent = 'انتهى المزاد — أعد تحميل الصفحة'; el.style.color = 'var(--text-tertiary)'; return; }
            var h = Math.floor(diff/3600000), m = Math.floor((diff%3600000)/60000), s = Math.floor((diff%60000)/1000);
            el.textContent = (h>0? h+':':'') + String(m).padStart(2,'0') + ':' + String(s).padStart(2,'0') + ' متبقٍ';
            el.style.color = diff <= 300000 ? 'var(--danger)' : 'var(--accent)';
            setTimeout(tick, 1000);
          }
          tick();
        })();
        </script>";
    }
}

function renderUsers(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $users = $pdo->query("SELECT * FROM users ORDER BY created_at DESC")->fetchAll();
    $canCreate = in_array($role, $ACTION_ROLES["create_user"], true);

    echo "<h1>المستخدمون</h1><p class='sub'>حسابات الدخول إلى النظام وأدوارها.</p>";

    if ($canCreate) {
        echo "<div class='panel'><h2>إضافة مستخدم</h2><div class='body'><form method='post'><input type='hidden' name='action' value='create_user'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo "<div class='form-grid'>";
        echo "<div class='field'><label>اسم المستخدم *</label><input name='username' required minlength='3'></div>";
        echo "<div class='field'><label>الاسم الكامل *</label><input name='full_name' required></div>";
        echo "<div class='field'><label>كلمة المرور *</label><input type='password' name='password' required minlength='6'></div>";
        echo "<div class='field'><label>الدور *</label><select name='role' required>";
        foreach (["EXECUTIVE_MANAGEMENT" => "الإدارة العليا", "FLEET_MANAGER" => "مدير الأسطول", "WORKSHOP_MANAGER" => "مدير الورشة", "STOREKEEPER" => "أمين المخزن", "TECHNICIAN" => "فني الصيانة"] as $k => $l) echo "<option value='$k'>" . e($l) . "</option>";
        echo "</select></div></div><button class='btn btn-primary' type='submit'>" . icon('plus') . " إنشاء</button></form></div></div>";
    }

    echo "<div class='panel'><h2>كل المستخدمين (" . count($users) . ")</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>اسم المستخدم</th><th>الاسم الكامل</th><th>الدور</th><th>الحالة</th></tr>";
    foreach ($users as $u) echo "<tr><td class='mono'>" . e($u["username"]) . "</td><td>" . e($u["full_name"]) . "</td><td>" . e($u["role"]) . "</td><td>" . ($u["is_active"] ? "<span class='pill pill-success'>نشط</span>" : "<span class='pill pill-neutral'>موقوف</span>") . "</td></tr>";
    echo "</table></div></div>";
}

function renderAudit(PDO $pdo): void {
    $result = paginate(
        $pdo,
        "SELECT COUNT(*) c FROM audit_logs",
        "SELECT l.*, u.full_name FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id ORDER BY l.timestamp DESC",
        [], 30
    );
    $logs = $result["items"];
    echo "<h1>سجل التدقيق</h1><p class='sub'>سجل غير قابل للتعديل أو الحذف — كل إجراء حساس مسجَّل بختم زمني. (" . $result["total"] . " سجلاً إجمالاً)</p>";
    echo "<div class='panel'><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>المستخدم</th><th>الإجراء</th><th>الكيان</th><th>التفاصيل</th><th>التاريخ</th></tr>";
    foreach ($logs as $l) echo "<tr><td>" . e($l["full_name"] ?? "—") . "</td><td>" . e($l["action"]) . "</td><td>" . e($l["entity"]) . "</td><td>" . e($l["details"]) . "</td><td>" . e(date("Y-m-d H:i", strtotime($l["timestamp"]))) . "</td></tr>";
    if (!$logs) echo "<tr><td colspan='5'><div class='empty'>لا توجد سجلات بعد</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}


function renderDocuments(PDO $pdo, string $role, array $ACTION_ROLES): void {
    $canCreate = in_array($role, $ACTION_ROLES["create_document"], true);
    $canDelete = in_array($role, $ACTION_ROLES["delete_document"], true);
    $assets = $pdo->query("SELECT id, asset_code, brand, model FROM assets WHERE deleted_at IS NULL ORDER BY asset_code")->fetchAll();

    $today = date("Y-m-d");
    $in30 = date("Y-m-d", strtotime("+30 days"));

    $result = paginate(
        $pdo,
        "SELECT COUNT(*) c FROM asset_documents",
        "SELECT d.*, a.asset_code, a.brand, a.model FROM asset_documents d JOIN assets a ON a.id = d.asset_id ORDER BY COALESCE(d.expires_at, '9999-12-31') ASC, d.created_at DESC"
    );
    $docs = $result["items"];

    $expired = (int)$pdo->query("SELECT COUNT(*) c FROM asset_documents WHERE expires_at IS NOT NULL AND expires_at < CURDATE()")->fetch()["c"];
    $soon = (int)$pdo->query("SELECT COUNT(*) c FROM asset_documents WHERE expires_at IS NOT NULL AND expires_at >= CURDATE() AND expires_at <= DATE_ADD(CURDATE(), INTERVAL 30 DAY)")->fetch()["c"];

    $typeLabels = [
        "INSURANCE" => "تأمين", "LICENSE" => "رخصة", "INSPECTION" => "فحص دوري",
        "REGISTRATION" => "تسجيل", "WARRANTY" => "ضمان", "OTHER" => "أخرى"
    ];

    echo "<h1>وثائق الأصول</h1><p class='sub'>تأمين، رخص، فحوصات — مع تنبيهات قبل الانتهاء.</p>";

    echo "<div class='kpi-strip'>";
    echo "<div class='kpi'><div class='l'>إجمالي الوثائق</div><div class='v'>" . (int)$result["total"] . "</div></div>";
    echo "<div class='kpi'><div class='l'>تنتهي خلال 30 يوماً</div><div class='v " . ($soon ? "warn" : "") . "'>$soon</div></div>";
    echo "<div class='kpi'><div class='l'>منتهية الصلاحية</div><div class='v " . ($expired ? "bad" : "") . "'>$expired</div></div>";
    echo "</div>";

    if ($expired) echo "<div class='alert alert-danger'>$expired وثيقة منتهية الصلاحية — راجعها فوراً.</div>";
    if ($soon) echo "<div class='alert alert-warning'>$soon وثيقة ستنتهي خلال 30 يوماً.</div>";

    if ($canCreate) {
        echo "<div class='panel'><h2>إضافة وثيقة</h2><div class='body' style='padding:16px 20px'><form method='post'><input type='hidden' name='action' value='create_document'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
        echo "<div class='form-grid'>";
        echo "<div class='field'><label>الأصل *</label><select name='asset_id' required><option value=''>— اختر —</option>";
        foreach ($assets as $a) echo "<option value='" . e($a["id"]) . "'>" . e($a["asset_code"] . " — " . $a["brand"] . " " . $a["model"]) . "</option>";
        echo "</select></div>";
        echo "<div class='field'><label>نوع الوثيقة *</label><select name='doc_type'>";
        foreach ($typeLabels as $k => $v) echo "<option value='$k'>" . e($v) . "</option>";
        echo "</select></div>";
        echo "<div class='field'><label>العنوان *</label><input name='title' required placeholder='مثال: وثيقة تأمين شاملة 2026'></div>";
        echo "<div class='field'><label>رقم الوثيقة</label><input name='doc_number'></div>";
        echo "<div class='field'><label>تاريخ الإصدار</label><input type='date' name='issued_at'></div>";
        echo "<div class='field'><label>تاريخ الانتهاء</label><input type='date' name='expires_at'></div>";
        echo "</div>";
        echo "<div class='field'><label>ملاحظات</label><textarea name='notes' rows='2'></textarea></div>";
        echo "<button class='btn btn-primary' type='submit'>حفظ الوثيقة</button></form></div></div>";
    }

    echo "<div class='panel' style='margin-top:16px'><h2>قائمة الوثائق</h2><div class='body' style='padding:0'><table class='dt'>";
    echo "<tr><th>الأصل</th><th>النوع</th><th>العنوان</th><th>الرقم</th><th>الإصدار</th><th>الانتهاء</th><th>الحالة</th><th></th></tr>";
    foreach ($docs as $d) {
        $exp = $d["expires_at"];
        if ($exp && $exp < $today) {
            $st = "<span class='pill pill-danger'>منتهية</span>";
        } elseif ($exp && $exp <= $in30) {
            $st = "<span class='pill pill-warn'>قريبة الانتهاء</span>";
        } elseif ($exp) {
            $st = "<span class='pill pill-success'>سارية</span>";
        } else {
            $st = "<span class='pill pill-neutral'>بدون تاريخ</span>";
        }
        echo "<tr>";
        echo "<td>" . e($d["asset_code"]) . "<br><span style='font-size:.75rem;color:var(--text-tertiary)'>" . e($d["brand"] . " " . $d["model"]) . "</span></td>";
        echo "<td>" . e($typeLabels[$d["doc_type"]] ?? $d["doc_type"]) . "</td>";
        echo "<td>" . e($d["title"]) . "</td>";
        echo "<td class='mono'>" . e($d["doc_number"] ?? "—") . "</td>";
        echo "<td class='mono'>" . e($d["issued_at"] ?? "—") . "</td>";
        echo "<td class='mono'>" . e($exp ?? "—") . "</td>";
        echo "<td>$st</td><td>";
        if ($canDelete) {
            echo "<form class='inline' method='post' data-confirm='حذف هذه الوثيقة؟'><input type='hidden' name='action' value='delete_document'><input type='hidden' name='id' value='" . e($d["id"]) . "'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><button class='btn btn-danger btn-sm' type='submit'>حذف</button></form>";
        }
        echo "</td></tr>";
    }
    if (!$docs) echo "<tr><td colspan='8'><div class='empty'>لا توجد وثائق بعد</div></td></tr>";
    echo "</table></div>" . paginationLinks($result) . "</div>";
}

function renderWoPrint(PDO $pdo, string $role): void {
    $id = $_GET["id"] ?? "";
    $st = $pdo->prepare("SELECT w.*, a.asset_code, a.brand, a.model, a.serial_number, a.category FROM work_orders w JOIN assets a ON a.id = w.asset_id WHERE w.id = ?");
    $st->execute([$id]);
    $w = $st->fetch();
    if (!$w) {
        echo "<div class='alert alert-danger'>أمر الشغل غير موجود</div>";
        return;
    }
    $parts = $pdo->prepare("SELECT c.*, p.description, p.sku FROM wo_parts_consumption c JOIN spare_parts p ON p.id = c.spare_part_id WHERE c.work_order_id = ?");
    $parts->execute([$id]);
    $parts = $parts->fetchAll();

    $statusMap = [
        "DRAFT" => "مسودة", "APPROVED_OPEN" => "معتمد", "IN_PROGRESS" => "قيد التنفيذ",
        "PENDING_PARTS" => "بانتظار القطع", "QUALITY_INSPECTION" => "فحص الجودة", "CLOSED" => "مغلق"
    ];

    // Print-friendly layout (still dark-theme compatible; user can print)
    echo "<div style='max-width:800px;margin:0 auto'>";
    echo "<div class='actions-row' style='margin-bottom:20px'>";
    echo "<button class='btn btn-primary' onclick='window.print()'>" . icon("print") . " طباعة / PDF</button>";
    echo "<a class='btn btn-ghost' href='index.php?page=workorders'>رجوع</a>";
    echo "</div>";

    echo "<div class='panel' style='padding:28px' id='print-area'>";
    echo "<div style='display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:24px;border-bottom:1px solid var(--border);padding-bottom:16px'>";
    echo "<div><div style='font-size:1.3rem;font-weight:700;color:var(--accent)'>FMS · EMS</div><div style='font-size:.8rem;color:var(--text-tertiary)'>نظام إدارة الأسطول والمعدات</div></div>";
    echo "<div style='text-align:left'><div style='font-size:1.1rem;font-weight:700'>تقرير أمر شغل</div><div class='mono' style='color:var(--accent)'>" . e($w["wo_number"]) . "</div></div>";
    echo "</div>";

    echo "<div class='form-grid' style='margin-bottom:20px'>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>الحالة</span><div style='font-weight:600'>" . e($statusMap[$w["status"]] ?? $w["status"]) . "</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>النوع</span><div style='font-weight:600'>" . e($w["type"]) . "</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>الأصل</span><div style='font-weight:600'>" . e($w["brand"] . " " . $w["model"]) . " (" . e($w["asset_code"]) . ")</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>الرقم التسلسلي</span><div class='mono'>" . e($w["serial_number"]) . "</div></div>";
    echo "</div>";

    echo "<div style='margin-bottom:16px'><span style='color:var(--text-tertiary);font-size:.78rem'>الوصف</span><div style='margin-top:4px'>" . nl2br(e($w["description"] ?? "—")) . "</div></div>";

    echo "<div class='form-grid' style='margin-bottom:20px'>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>ساعات العمل</span><div class='mono' style='font-size:1.2rem'>" . e($w["actual_labor_hours"] ?? "—") . "</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>تكلفة الأجور</span><div class='mono' style='font-size:1.2rem'>" . money($w["labor_cost"] ?? 0) . "</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>تكلفة القطع</span><div class='mono' style='font-size:1.2rem'>" . money($w["parts_cost"] ?? 0) . "</div></div>";
    echo "<div><span style='color:var(--text-tertiary);font-size:.78rem'>الإجمالي</span><div class='mono' style='font-size:1.2rem;color:var(--accent)'>" . money(($w["labor_cost"] ?? 0) + ($w["parts_cost"] ?? 0)) . "</div></div>";
    echo "</div>";

    if ($parts) {
        echo "<h2 style='font-size:1rem;margin-bottom:10px'>قطع الغيار المصروفة</h2>";
        echo "<table class='dt'><tr><th>SKU</th><th>الوصف</th><th>الكمية</th><th>التكلفة</th></tr>";
        foreach ($parts as $p) {
            echo "<tr><td class='mono'>" . e($p["sku"]) . "</td><td>" . e($p["description"]) . "</td><td class='mono'>" . e($p["quantity"]) . "</td><td class='mono'>" . money($p["total_cost"] ?? 0) . "</td></tr>";
        }
        echo "</table>";
    }

    echo "<div style='margin-top:28px;padding-top:16px;border-top:1px solid var(--border);font-size:.75rem;color:var(--text-tertiary);display:flex;justify-content:space-between'>";
    echo "<span>تاريخ الطباعة: " . date("Y-m-d H:i") . "</span>";
    echo "<span>فحص: " . ($w["inspection_passed"] ? "ناجح" : "—") . " · اعتماد المدير: " . ($w["workshop_manager_approved_by"] ? "نعم" : "—") . "</span>";
    echo "</div>";
    echo "</div></div>";

    echo "<style>@media print { .sidebar,.mobile-nav,.ios-tabbar,.ios-topbar,.nav-progress,.pwa-install-fab,.actions-row,.alert { display:none !important; } .main { padding:0 !important; max-width:100% !important; } body { background:#fff !important; color:#111 !important; } .panel { box-shadow:none !important; border:1px solid #ccc !important; background:#fff !important; } .mono,h1,h2,td,th,div { color:#111 !important; text-shadow:none !important; } }</style>";
}


/** قائمة مواعيد بأسلوب iOS (بطاقة تاريخ + تفاصيل) — مشتركة بين الصفحات */
function apptListHtml(array $rows, bool $showAsset = true): string {
    $days = ["أحد", "اثنين", "ثلاثاء", "أربعاء", "خميس", "جمعة", "سبت"];
    $today = date("Y-m-d");
    $h = "<div class='appt-list'>";
    foreach ($rows as $r) {
        $ts = strtotime($r["scheduled_date"]);
        $late = in_array($r["status"], ["PENDING", "CONFIRMED"], true) && $r["scheduled_date"] < $today;
        $h .= "<a class='appt-item" . ($r["scheduled_date"] === $today ? " is-today" : "") . ($late ? " is-late" : "") . "' href='index.php?page=appointment_detail&id=" . e($r["id"]) . "'>";
        $h .= "<div class='appt-date'><span>" . $days[(int)date("w", $ts)] . "</span><b>" . (int)date("j", $ts) . "</b><span>" . date("m/y", $ts) . "</span></div>";
        $h .= "<div class='appt-body'><div class='appt-title'>";
        $h .= $showAsset ? e($r["asset_code"] . " — " . $r["brand"] . " " . $r["model"]) : e(apptTypes()[$r["service_type"]] ?? $r["service_type"]);
        $h .= "</div><div class='appt-meta'>" . icon("clock") . " " . ((int)$r["is_exact_time"] ? date("H:i", strtotime($r["scheduled_at"])) : e(apptSlots()[$r["preferred_slot"]] ?? ""));
        if ($showAsset) $h .= " · " . e(apptTypes()[$r["service_type"]] ?? "");
        if (!empty($r["plate_number"]) && $showAsset) $h .= " · <span class='plate'>" . e($r["plate_number"]) . "</span>";
        if (!empty($r["tech_name"])) $h .= " · " . icon("wrench") . " " . e($r["tech_name"]);
        $h .= "</div></div><div class='appt-side'>" . apptStatusPill($r["status"]) . ($late ? "<span class='pill pill-danger'>متأخر</span>" : "") . "<span class='appt-num mono'>" . e($r["appt_number"]) . "</span></div></a>";
    }
    return $h . "</div>";
}

/** نموذج التاريخ + الفترة (مشترك: الحجز وإعادة الجدولة) */
function apptWhenFields(array $old, string $idp): string {
    $slot = $old["slot"] ?? "MORNING";
    $h = "<div class='field'><label>التاريخ *</label><input type='date' name='scheduled_date' required min='" . date("Y-m-d") . "' max='" . date("Y-m-d", strtotime("+365 days")) . "' value='" . e($old["scheduled_date"] ?? "") . "' data-appt-date></div>";
    $h .= "<div class='field'><label>الفترة *</label><div class='segmented' role='radiogroup'>";
    foreach (apptSlots() + ["CUSTOM" => "وقت محدد"] as $k => $l) {
        $h .= "<label><input type='radio' name='slot' value='$k'" . ($slot === $k ? " checked" : "") . " data-appt-slot> <span>" . e($l) . "</span></label>";
    }
    $h .= "</div></div>";
    $h .= "<div class='field' data-time-field" . ($slot === "CUSTOM" ? "" : " hidden") . "><label>الوقت</label><input type='time' name='time' step='900' value='" . e($old["time"] ?? "09:00") . "'></div>";
    return $h;
}

function renderAppointments(PDO $pdo, string $role, array $ACTION_ROLES, string $userId): void {
    $canRequest = can("request_appointment", $role, $ACTION_ROLES);
    $view = (string)($_GET["view"] ?? "list");
    if ($view === "book" && !$canRequest) $view = "list";
    $today = date("Y-m-d");

    $st = $pdo->prepare("SELECT COALESCE(SUM(scheduled_date = ? AND status IN ('PENDING','CONFIRMED','IN_PROGRESS')),0) today_c,
        COALESCE(SUM(scheduled_date BETWEEN ? AND ? AND status IN ('PENDING','CONFIRMED')),0) week_c,
        COALESCE(SUM(status = 'PENDING' AND scheduled_date >= ?),0) pending_c,
        COALESCE(SUM(scheduled_date < ? AND status IN ('PENDING','CONFIRMED')),0) late_c
        FROM maintenance_appointments");
    $st->execute([$today, $today, date("Y-m-d", strtotime("+7 days")), $today, $today]); $k = $st->fetch();

    echo "<div class='page-head'><div><h1>مواعيد الصيانة</h1><p class='sub'>حجز مواعيد الورشة للآليات — التعارض والصلاحيات تُفحص من الخادم.</p></div>";
    if ($canRequest && $view !== "book") echo "<a class='btn btn-primary' href='index.php?page=appointments&view=book'>" . icon("calendar-plus") . " حجز موعد</a>";
    echo "</div>";

    echo "<div class='kpi-strip kpi-compact'>";
    echo "<a class='kpi kpi-link' href='index.php?page=appointments&f=today'><div class='l'>اليوم</div><div class='v'>" . (int)$k["today_c"] . "</div></a>";
    echo "<a class='kpi kpi-link' href='index.php?page=appointments&f=upcoming'><div class='l'>خلال 7 أيام</div><div class='v'>" . (int)$k["week_c"] . "</div></a>";
    echo "<a class='kpi kpi-link' href='index.php?page=appointments&f=pending'><div class='l'>بانتظار التأكيد</div><div class='v " . ($k["pending_c"] ? "warn" : "") . "'>" . (int)$k["pending_c"] . "</div></a>";
    echo "<a class='kpi kpi-link' href='index.php?page=appointments&f=overdue'><div class='l'>متأخرة</div><div class='v " . ($k["late_c"] ? "bad" : "") . "'>" . (int)$k["late_c"] . "</div></a>";
    echo "</div>";

    echo "<nav class='segmented segmented-nav'>";
    echo "<a href='index.php?page=appointments' class='" . ($view === "list" ? "is-active" : "") . "'>القائمة</a>";
    echo "<a href='index.php?page=appointments&view=week' class='" . ($view === "week" ? "is-active" : "") . "'>التقويم الأسبوعي</a>";
    if ($canRequest) echo "<a href='index.php?page=appointments&view=book' class='" . ($view === "book" ? "is-active" : "") . "'>+ حجز</a>";
    echo "</nav>";

    if ($view === "book") { renderAppointmentBookForm($pdo); return; }
    if ($view === "week") { renderAppointmentWeek($pdo); return; }

    $filters = ["upcoming" => "القادمة", "today" => "اليوم", "pending" => "بانتظار التأكيد", "overdue" => "متأخرة", "mine" => "مواعيدي", "done" => "المنتهية", "cancelled" => "الملغاة", "all" => "الكل"];
    $f = (string)($_GET["f"] ?? "upcoming"); if (!isset($filters[$f])) $f = "upcoming";
    $conds = [
        "upcoming" => ["m.scheduled_date >= ? AND m.status IN ('PENDING','CONFIRMED','IN_PROGRESS')", [$today], "m.scheduled_at ASC"],
        "today" => ["m.scheduled_date = ?", [$today], "m.scheduled_at ASC"],
        "pending" => ["m.status = 'PENDING' AND m.scheduled_date >= ?", [$today], "m.scheduled_at ASC"],
        "overdue" => ["m.scheduled_date < ? AND m.status IN ('PENDING','CONFIRMED')", [$today], "m.scheduled_at ASC"],
        "mine" => ["(m.assigned_technician = ? OR m.requested_by = ?)", [$userId, $userId], "m.scheduled_at DESC"],
        "done" => ["m.status = 'COMPLETED'", [], "m.scheduled_at DESC"],
        "cancelled" => ["m.status IN ('CANCELLED','NO_SHOW')", [], "m.scheduled_at DESC"],
        "all" => ["1=1", [], "m.scheduled_at DESC"],
    ];
    [$where, $params, $order] = $conds[$f];
    echo "<div class='chips'>";
    foreach ($filters as $key => $label) echo "<a class='chip" . ($f === $key ? " is-active" : "") . "' href='index.php?page=appointments&f=$key'>" . e($label) . "</a>";
    echo "</div>";

    $result = paginate($pdo, "SELECT COUNT(*) c FROM maintenance_appointments m WHERE $where",
        "SELECT m.*, a.asset_code, a.brand, a.model, a.plate_number, t.full_name tech_name FROM maintenance_appointments m JOIN assets a ON a.id = m.asset_id LEFT JOIN users t ON t.id = m.assigned_technician WHERE $where ORDER BY $order", $params);
    echo "<div class='panel'><h2>" . e($filters[$f]) . " (" . $result["total"] . ")</h2><div class='body'>";
    echo $result["items"] ? apptListHtml($result["items"]) : "<div class='empty'>لا توجد مواعيد في هذا التصنيف" . ($canRequest ? " — <a class='link' href='index.php?page=appointments&view=book'>احجز موعداً</a>" : "") . "</div>";
    echo "</div>" . paginationLinks($result) . "</div>";
}

function renderAppointmentBookForm(PDO $pdo): void {
    $old = takeOldInput();
    $preAsset = (string)($old["asset_id"] ?? ($_GET["asset"] ?? ""));
    $assets = $pdo->query("SELECT id, asset_code, brand, model, plate_number, status FROM assets WHERE deleted_at IS NULL AND status NOT IN ('SOLD','SCRAPPED') ORDER BY asset_code")->fetchAll();
    $ids = array_column($assets, "id");
    if ($preAsset !== "" && !in_array($preAsset, $ids, true)) {
        echo "<div class='alert alert-warning'>الآلية المحددة غير متاحة للحجز (محذوفة أو مباعة أو مستبعدة) — اختر آلية أخرى.</div>";
        $preAsset = "";
    }
    // المواعيد النشطة للأسابيع القادمة: تنبيه فوري في الواجهة قبل الإرسال (القرار النهائي من الخادم)
    $st = $pdo->prepare("SELECT asset_id, scheduled_date, preferred_slot, appt_number FROM maintenance_appointments WHERE status IN ('PENDING','CONFIRMED','IN_PROGRESS') AND scheduled_date BETWEEN ? AND ?");
    $st->execute([date("Y-m-d"), date("Y-m-d", strtotime("+120 days"))]);
    $busy = [];
    foreach ($st->fetchAll() as $r) $busy[$r["asset_id"]][$r["scheduled_date"]][$r["preferred_slot"]] = $r["appt_number"];

    echo "<div class='panel' id='book'><h2>" . icon("calendar-plus") . " طلب موعد صيانة</h2><div class='body'>";
    if (!$assets) { echo "<div class='empty'>لا توجد آليات قابلة للحجز.</div></div></div>"; return; }
    echo "<form method='post' data-appt-form><input type='hidden' name='action' value='request_appointment'><input type='hidden' name='csrf' value='" . e(csrfToken()) . "'>";
    echo "<div class='form-grid'>";
    echo "<div class='field span-2'><label>الآلية *</label><select name='asset_id' required data-appt-asset><option value=''>— اختر الآلية —</option>";
    foreach ($assets as $a) echo "<option value='" . e($a["id"]) . "'" . ($preAsset === $a["id"] ? " selected" : "") . ">" . e($a["asset_code"] . " — " . $a["brand"] . " " . $a["model"] . ($a["plate_number"] ? " · " . $a["plate_number"] : "") . ($a["status"] === "UNDER_MAINTENANCE" ? " (تحت الصيانة)" : "")) . "</option>";
    echo "</select></div>";
    echo apptWhenFields($old, "b");
    echo "<div class='field'><label>نوع الخدمة *</label><select name='service_type' required>";
    foreach (apptTypes() as $kk => $l) echo "<option value='$kk'" . (($old["service_type"] ?? "PREVENTIVE") === $kk ? " selected" : "") . ">" . e($l) . "</option>";
    echo "</select></div>";
    echo "<div class='field span-2'><label>الوصف / الأعراض</label><textarea name='description' rows='3' maxlength='2000' placeholder='مثال: تغيير زيت وفلاتر عند 250 ساعة، أو: صوت غير طبيعي في ناقل الحركة'>" . e($old["description"] ?? "") . "</textarea></div>";
    echo "</div>";
    echo "<div class='alert alert-warning' data-appt-warning hidden></div>";
    echo "<button class='btn btn-primary btn-block-mobile' type='submit'>" . icon("check") . " إرسال طلب الموعد</button>";
    echo "<p class='form-hint'>يصل الطلب بحالة «بانتظار التأكيد» — مدير الورشة يؤكده ويعيّن الفني، ويمكن إنشاء أمر شغل مسودة تلقائياً عند التأكيد.</p>";
    echo "</form></div></div>";
    echo "<script>window.FMS_BUSY=" . json_encode((object)$busy, JSON_HEX_TAG | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE) . ";</script>";
}

function renderAppointmentWeek(PDO $pdo): void {
    $ref = (string)($_GET["w"] ?? date("Y-m-d"));
    $refTs = strtotime($ref) ?: time();
    $dow = (int)date("w", $refTs);
    $start = strtotime("-" . (($dow - WEEK_START + 7) % 7) . " days", strtotime(date("Y-m-d", $refTs)));
    $startD = date("Y-m-d", $start); $endD = date("Y-m-d", strtotime("+6 days", $start));
    $st = $pdo->prepare("SELECT m.*, a.asset_code, a.brand, a.model, t.full_name tech_name FROM maintenance_appointments m JOIN assets a ON a.id = m.asset_id LEFT JOIN users t ON t.id = m.assigned_technician WHERE m.scheduled_date BETWEEN ? AND ? ORDER BY m.scheduled_at ASC LIMIT 500");
    $st->execute([$startD, $endD]);
    $byDay = [];
    foreach ($st->fetchAll() as $r) $byDay[$r["scheduled_date"]][] = $r;

    echo "<div class='week-nav'>";
    echo "<a class='btn btn-ghost btn-sm' href='index.php?page=appointments&view=week&w=" . date("Y-m-d", strtotime("-7 days", $start)) . "'>" . icon("chev-back") . " السابق</a>";
    echo "<b>" . e(arDate($startD, false)) . " — " . e(arDate($endD, false)) . "</b>";
    echo "<a class='btn btn-ghost btn-sm' href='index.php?page=appointments&view=week&w=" . date("Y-m-d", strtotime("+7 days", $start)) . "'>التالي " . icon("chev-fwd") . "</a>";
    echo "</div><div class='week-grid'>";
    $today = date("Y-m-d");
    for ($i = 0; $i < 7; $i++) {
        $d = date("Y-m-d", strtotime("+$i days", $start));
        echo "<div class='week-day" . ($d === $today ? " is-today" : "") . "'><div class='week-day-head'>" . e(arDate($d, true)) . "</div>";
        if (empty($byDay[$d])) echo "<div class='week-empty'>—</div>";
        foreach ($byDay[$d] ?? [] as $r) {
            [$cls] = apptStatuses()[$r["status"]] ?? ["neutral"];
            echo "<a class='week-ev ev-$cls' href='index.php?page=appointment_detail&id=" . e($r["id"]) . "'>";
            echo "<b>" . ((int)$r["is_exact_time"] ? date("H:i", strtotime($r["scheduled_at"])) : e(apptSlots()[$r["preferred_slot"]])) . "</b> " . e($r["asset_code"]);
            echo "<span>" . e(apptTypes()[$r["service_type"]] ?? "") . ($r["tech_name"] ? " · " . e($r["tech_name"]) : "") . "</span></a>";
        }
        echo "</div>";
    }
    echo "</div>";
    if ($startD > $today || $endD < $today) echo "<p style='text-align:center;margin-top:12px'><a class='link' href='index.php?page=appointments&view=week'>العودة لهذا الأسبوع</a></p>";
}

function renderAppointmentDetail(PDO $pdo, string $role, array $ACTION_ROLES, string $userId): void {
    $id = (string)($_GET["id"] ?? "");
    $st = $pdo->prepare("SELECT m.*, a.asset_code, a.brand, a.model, a.plate_number, a.status asset_status, a.odometer_km, a.next_service_due_date, a.next_service_due_km, a.deleted_at asset_deleted,
        r.full_name req_name, t.full_name tech_name, c.full_name conf_name, w.wo_number, w.status wo_status
        FROM maintenance_appointments m JOIN assets a ON a.id = m.asset_id
        LEFT JOIN users r ON r.id = m.requested_by LEFT JOIN users t ON t.id = m.assigned_technician LEFT JOIN users c ON c.id = m.confirmed_by
        LEFT JOIN work_orders w ON w.id = m.linked_work_order_id WHERE m.id = ?");
    $st->execute([$id]); $ap = $st->fetch();
    if (!$ap) { echo "<div class='alert alert-danger'>الموعد غير موجود.</div><a class='btn btn-ghost' href='index.php?page=appointments'>رجوع</a>"; return; }

    $today = date("Y-m-d");
    $s = $ap["status"];
    $canManage = can("manage_appointment", $role, $ACTION_ROLES);
    $canWork = can("work_appointment", $role, $ACTION_ROLES) && ($role !== "TECHNICIAN" || $ap["assigned_technician"] === $userId);
    $canWithdraw = can("request_appointment", $role, $ACTION_ROLES) && $ap["requested_by"] === $userId && $s === "PENDING";
    $csrf = "<input type='hidden' name='csrf' value='" . e(csrfToken()) . "'><input type='hidden' name='id' value='" . e($ap["id"]) . "'>";
    $techs = ($canManage && in_array($s, APPT_ACTIVE, true)) ? $pdo->query("SELECT id, full_name FROM users WHERE role = 'TECHNICIAN' AND is_active = 1 ORDER BY full_name")->fetchAll() : [];
    $techSelect = function (?string $cur) use ($techs) {
        $h = "<select name='assigned_technician'><option value=''>— بدون تعيين —</option>";
        foreach ($techs as $t) $h .= "<option value='" . e($t["id"]) . "'" . ($cur === $t["id"] ? " selected" : "") . ">" . e($t["full_name"]) . "</option>";
        return $h . "</select>";
    };

    echo "<a class='btn btn-ghost btn-sm back-link' href='index.php?page=appointments'>" . icon("chev-back") . " كل المواعيد</a>";
    echo "<div class='page-head'><div><h1>موعد <span class='mono'>" . e($ap["appt_number"]) . "</span></h1><p class='sub'>" . e(apptWhenLabel($ap)) . "</p></div><div>" . apptStatusPill($s) . "</div></div>";
    if (in_array($s, ["PENDING", "CONFIRMED"], true) && $ap["scheduled_date"] < $today) echo "<div class='alert alert-danger'>تاريخ هذا الموعد مضى ولم يُنجَز — أعد جدولته أو سجّل «لم تحضر» أو ألغِه.</div>";

    // مسار الحالة
    $steps = ["PENDING" => "طلب", "CONFIRMED" => "تأكيد", "IN_PROGRESS" => "في الورشة", "COMPLETED" => "مكتمل"];
    $order = array_keys($steps); $pos = array_search($s, $order, true);
    echo "<ol class='stepper'>";
    foreach ($steps as $key => $label) {
        $i = array_search($key, $order, true);
        $cls = ($pos !== false && $i < $pos) ? "done" : (($pos !== false && $i === $pos) ? "current" : "");
        echo "<li class='$cls'><span></span>" . e($label) . "</li>";
    }
    if ($pos === false) echo "<li class='stopped'><span></span>" . e(apptStatuses()[$s][1]) . "</li>";
    echo "</ol>";

    $kv = function (string $l, string $v) { return "<div><span>" . e($l) . "</span><b>" . ($v !== "" ? $v : "—") . "</b></div>"; };
    $assetLink = in_array($role, ["EXECUTIVE_MANAGEMENT", "FLEET_MANAGER", "WORKSHOP_MANAGER"], true)
        ? "<a class='link' href='index.php?page=asset_detail&id=" . e($ap["asset_id"]) . "'>" . e($ap["asset_code"] . " — " . $ap["brand"] . " " . $ap["model"]) . "</a>"
        : e($ap["asset_code"] . " — " . $ap["brand"] . " " . $ap["model"]);
    $woLink = $ap["wo_number"] ? (in_array($role, ["EXECUTIVE_MANAGEMENT", "FLEET_MANAGER", "WORKSHOP_MANAGER", "TECHNICIAN"], true)
        ? "<a class='link mono' href='index.php?page=wo_print&id=" . e($ap["linked_work_order_id"]) . "'>" . e($ap["wo_number"]) . "</a> " . statusPill($ap["wo_status"]) : e($ap["wo_number"])) : "";

    echo "<div class='form-grid'>";
    echo "<div class='panel'><h2>تفاصيل الموعد</h2><div class='body'><div class='kv'>";
    echo $kv("الآلية", $assetLink) . $kv("رقم اللوحة", e($ap["plate_number"] ?? "")) . $kv("نوع الخدمة", e(apptTypes()[$ap["service_type"]] ?? ""));
    echo $kv("الموعد", e(apptWhenLabel($ap))) . $kv("مقدّم الطلب", e($ap["req_name"] ?? "")) . $kv("تاريخ الطلب", e(date("Y-m-d H:i", strtotime($ap["created_at"]))));
    echo $kv("الفني المعيَّن", e($ap["tech_name"] ?? "")) . $kv("أكّده", e($ap["conf_name"] ?? "")) . $kv("أمر الشغل", $woLink);
    echo "</div>";
    if ($ap["description"]) echo "<div class='note-box'><b>الوصف:</b><br>" . nl2br(e($ap["description"])) . "</div>";
    if ($ap["workshop_notes"]) echo "<div class='note-box'><b>ملاحظات الورشة:</b><br>" . nl2br(e($ap["workshop_notes"])) . "</div>";
    if ($ap["cancel_reason"]) echo "<div class='note-box note-danger'><b>سبب الإلغاء:</b> " . e($ap["cancel_reason"]) . "</div>";
    echo "</div></div>";

    // ── الإجراءات المتاحة حسب الحالة والصلاحية (نفس القواعد مفروضة في الخادم) ──
    echo "<div class='panel'><h2>الإجراءات</h2><div class='body'>";
    $any = false;
    if ($s === "PENDING" && $canManage) {
        $any = true;
        echo "<form method='post' class='action-card'><input type='hidden' name='action' value='confirm_appointment'>$csrf<h3>" . icon("check") . " تأكيد الموعد</h3>";
        echo "<div class='field'><label>تعيين فني</label>" . $techSelect($ap["assigned_technician"]) . "</div>";
        echo "<div class='field'><label>ملاحظات للورشة</label><textarea name='workshop_notes' rows='2'></textarea></div>";
        echo "<label class='check-row'><input type='checkbox' name='create_wo' value='1' checked> <span>إنشاء أمر شغل «مسودة» مرتبط تلقائياً</span></label>";
        echo "<button class='btn btn-primary btn-block' type='submit'>تأكيد</button></form>";
    }
    if ($s === "CONFIRMED" && $canWork) {
        $any = true;
        if ($ap["scheduled_date"] <= $today) {
            echo "<form method='post' class='action-card'><input type='hidden' name='action' value='start_appointment'>$csrf<h3>" . icon("wrench") . " استلام الآلية وبدء العمل</h3><p class='form-hint'>ستتحول حالة الآلية إلى «تحت الصيانة» وتعود تلقائياً عند الإكمال.</p><button class='btn btn-primary btn-block' type='submit'>بدء العمل</button></form>";
        } else echo "<p class='form-hint'>يمكن بدء العمل ابتداءً من يوم الموعد (" . e(arDate($ap["scheduled_date"], false)) . ").</p>";
    }
    if ($s === "IN_PROGRESS" && $canWork) {
        $any = true;
        echo "<form method='post' class='action-card'><input type='hidden' name='action' value='complete_appointment'>$csrf<h3>" . icon("check") . " إكمال الصيانة</h3>";
        echo "<div class='form-grid'>";
        echo "<div class='field'><label>قراءة العداد الآن (كم)</label><input type='number' inputmode='decimal' step='0.1' min='" . e($ap["odometer_km"]) . "' name='odometer_km' placeholder='" . e(money($ap["odometer_km"])) . "'></div>";
        echo "<div class='field'><label>ساعات المحرك</label><input type='number' inputmode='decimal' step='0.1' min='0' name='engine_hours'></div>";
        echo "<div class='field'><label>الصيانة القادمة (تاريخ)</label><input type='date' name='next_service_due_date' min='" . date("Y-m-d", strtotime("+1 day")) . "'></div>";
        echo "<div class='field'><label>الصيانة القادمة (كم)</label><input type='number' inputmode='numeric' step='1' min='0' name='next_service_due_km'></div>";
        echo "</div><p class='form-hint'>اترك «الصيانة القادمة» فارغة ليحسبها النظام من الفترة الدورية للآلية (للصيانة الوقائية).</p>";
        echo "<div class='field'><label>ملاحظات الإنجاز</label><textarea name='workshop_notes' rows='2'></textarea></div>";
        echo "<button class='btn btn-primary btn-block' type='submit'>إكمال الموعد</button></form>";
    }
    if (in_array($s, ["PENDING", "CONFIRMED", "IN_PROGRESS"], true) && $canManage && $s !== "PENDING") {
        $any = true;
        echo "<form method='post' class='action-card'><input type='hidden' name='action' value='assign_appointment_tech'>$csrf<h3>" . icon("users") . " الفني المعيَّن</h3><div class='field'>" . $techSelect($ap["assigned_technician"]) . "</div><button class='btn btn-ghost btn-block' type='submit'>حفظ التعيين</button></form>";
    }
    if (in_array($s, ["CONFIRMED", "IN_PROGRESS"], true) && $canManage && !$ap["linked_work_order_id"]) {
        $any = true;
        echo "<form method='post' class='action-card'><input type='hidden' name='action' value='create_appointment_wo'>$csrf<button class='btn btn-ghost btn-block' type='submit'>" . icon("workorders") . " إنشاء أمر شغل مسودة</button></form>";
    }
    if (in_array($s, ["PENDING", "CONFIRMED"], true) && $canManage) {
        $any = true;
        echo "<details class='action-card'><summary>" . icon("appointments") . " إعادة جدولة</summary><form method='post'><input type='hidden' name='action' value='reschedule_appointment'>$csrf<div class='form-grid'>";
        echo apptWhenFields(["slot" => $ap["is_exact_time"] ? "CUSTOM" : $ap["preferred_slot"], "time" => date("H:i", strtotime($ap["scheduled_at"])), "scheduled_date" => max($ap["scheduled_date"], $today)], "r");
        echo "</div><button class='btn btn-ghost btn-block' type='submit'>حفظ الموعد الجديد</button></form></details>";
        if ($s === "CONFIRMED" && $ap["scheduled_date"] <= $today) {
            echo "<form method='post' class='action-card' data-confirm='تسجيل أن الآلية لم تحضر؟'><input type='hidden' name='action' value='no_show_appointment'>$csrf<button class='btn btn-ghost btn-block' type='submit'>لم تحضر الآلية</button></form>";
        }
        echo "<details class='action-card'><summary class='danger-text'>" . icon("trash") . " إلغاء الموعد</summary><form method='post' data-confirm='إلغاء هذا الموعد نهائياً؟'><input type='hidden' name='action' value='cancel_appointment'>$csrf";
        echo "<div class='field'><label>سبب الإلغاء *</label><input name='cancel_reason' required minlength='3' maxlength='250'></div><button class='btn btn-danger btn-block' type='submit'>تأكيد الإلغاء</button></form></details>";
    }
    if ($canWithdraw) {
        $any = true;
        echo "<form method='post' class='action-card' data-confirm='سحب طلب الموعد؟'><input type='hidden' name='action' value='withdraw_appointment'>$csrf<button class='btn btn-danger btn-block' type='submit'>سحب طلبي</button></form>";
    }
    if (!$any) echo "<div class='empty'>" . (in_array($s, APPT_ACTIVE, true) ? ($role === "TECHNICIAN" && $s !== "PENDING" ? "هذا الموعد غير مُعيَّن لك." : "لا توجد إجراءات متاحة لدورك — العرض فقط.") : "الموعد في حالة نهائية — لا إجراءات.") . "</div>";
    echo "</div></div>";
    echo "</div>";

    // سجل التغييرات من audit_logs (كل تغيير حالة مسجَّل)
    $log = $pdo->prepare("SELECT l.*, u.full_name FROM audit_logs l LEFT JOIN users u ON u.id = l.user_id WHERE l.entity = 'Appointment' AND l.entity_id = ? ORDER BY l.timestamp ASC");
    $log->execute([$ap["id"]]); $log = $log->fetchAll();
    echo "<div class='panel'><h2>سجل الموعد</h2><div class='body'><ul class='timeline'>";
    $actLabels = ["CREATE" => "إنشاء الطلب", "STATUS_CHANGE" => "تغيير الحالة", "RESCHEDULE" => "إعادة جدولة", "ASSIGN" => "تعيين فني"];
    foreach ($log as $l) echo "<li><b>" . e($actLabels[$l["action"]] ?? $l["action"]) . "</b> <span>" . e($l["details"]) . "</span><small>" . e(($l["full_name"] ?? "—") . " · " . date("Y-m-d H:i", strtotime($l["timestamp"]))) . "</small></li>";
    if (!$log) echo "<li><span>لا سجلات</span></li>";
    echo "</ul></div></div>";
}

function renderInstall(): void {
    echo "<div class='install-hero'><img src='./icons/icon-180.png' alt='' width='96' height='96'><h1>ثبّت FMS على جهازك</h1><p class='sub'>يعمل كتطبيق مستقل: أيقونة على الشاشة الرئيسية، ملء الشاشة بلا شريط متصفح، وشريط تنقل سفلي.</p>";
    echo "<div class='install-state' data-installed-note hidden>" . icon("check") . " التطبيق مثبَّت ويعمل الآن في الوضع المستقل.</div>";
    echo "<button class='btn btn-primary btn-lg' type='button' data-install-open>" . icon("install") . " أضف إلى الشاشة الرئيسية</button></div>";
    echo "<div class='form-grid'>";
    echo "<div class='panel'><h2> آيفون / آيباد (سفاري)</h2><div class='body'><ol class='install-steps'>";
    echo "<li><span class='step-n'>1</span><div>اضغط زر <b>المشاركة</b> " . icon("share-ios") . " في سفاري. في <b>iOS 26</b> تجده داخل زر <b>⋯</b> أسفل الشاشة.</div></li>";
    echo "<li><span class='step-n'>2</span><div>مرّر للأسفل واختر <b>«إضافة إلى الشاشة الرئيسية»</b> " . icon("add-square") . "</div></li>";
    echo "<li><span class='step-n'>3</span><div>أبقِ خيار <b>«فتح كتطبيق ويب»</b> مفعّلاً، ثم اضغط <b>«إضافة»</b>.</div></li>";
    echo "<li><span class='step-n'>4</span><div>افتح التطبيق من أيقونته — يعمل بملء الشاشة وسيبقيك مسجلاً عند اختيار «تذكرني».</div></li>";
    echo "</ol><p class='form-hint'>كروم أو إيدج على آيفون (iOS 16.4+): زر المشاركة في شريط العنوان ثم نفس الخطوات. داخل متصفح واتساب/إنستغرام افتح الرابط في سفاري أولاً.</p></div></div>";
    echo "<div class='panel'><h2>أندرويد وكمبيوتر</h2><div class='body'><ol class='install-steps'>";
    echo "<li><span class='step-n'>1</span><div>اضغط زر <b>«أضف إلى الشاشة الرئيسية»</b> أعلاه — يظهر مربع التثبيت مباشرة في كروم/إيدج.</div></li>";
    echo "<li><span class='step-n'>2</span><div>إن لم يظهر: قائمة المتصفح <b>⋮</b> ← <b>«تثبيت التطبيق»</b>.</div></li>";
    echo "<li><span class='step-n'>3</span><div>اضغط مطولاً على الأيقونة للوصول السريع: حجز صيانة، مواعيد اليوم، أوامر الشغل.</div></li>";
    echo "</ol></div></div></div>";
}

function renderHelp(): void {
    echo "<h1>دليل استخدام نظام إدارة الآليات والمعدات</h1><p class='sub'>مرجع سريع لكل قسم في النظام.</p>";

    $sections = [
        ["لوحة التحكم", "نظرة عامة سريعة على حالة الأسطول: عدد الآليات، الآليات العاملة، أوامر الشغل المفتوحة، الآليات التي تجاوزت عتبة التكلفة الكلية (TCO)، وأصناف المخزون التي تحتاج إعادة طلب. كل الأرقام محسوبة لحظياً من قاعدة البيانات."],
        ["الأصول", "السجل الكامل لكل آلية (جرافة، حفارة، رافعة...) مع رقم اللوحة ورقم الهيكل ونوع الملكية والقسم ومركز التكلفة والسائق المسؤول وجدول الصيانة الدورية والملاحظات وصورة الآلية. ابحث بأي من هذه الحقول من شريط البحث، أو فعّل \"مستحقة الصيانة\". لإضافة أصل جديد: اضغط \"إضافة أصل جديد\" — الرقم التسلسلي يجب أن يكون فريداً، لن يقبل النظام تكراره. اضغط \"التفاصيل\" على أي أصل لعرض بياناته الكاملة، تعديل حالته أو قيمته السوقية، أو حذفه (حذف ناعم — تبقى بياناته في القاعدة لأغراض السجل التاريخي لكنه يختفي من القوائم)."],
        ["أوامر الشغل", "دورة حياة كل عملية صيانة: مسودة ← معتمد ← قيد التنفيذ ← (بانتظار القطع إن نفدت) ← فحص الجودة ← مغلق. لا يمكن لأي كان تخطي هذا الترتيب، ولا إغلاق أمر الشغل إلا بعد: (1) تسجيل نتيجة فحص فني ناجحة، و(2) اعتماد مدير الورشة تحديداً — هذا مفروض من الخادم نفسه، لا يمكن تجاوزه من الواجهة. عندما يصل أمر الشغل لحالة \"قيد التنفيذ\"، يظهر حقل لتسجيل ساعات العمل الفعلية وأجر الساعة، فتُحسَب تكلفة الأجور تلقائياً."],
        ["المخزون وقطع الغيار", "كل قطع الغيار المتوفرة وكمياتها. لا يمكن صرف أي قطعة إلا لأمر شغل بحالة \"قيد التنفيذ\" فعلياً. يمكن لأمين المخزن ومدير الأسطول إدخال كميات جديدة (استلام) أو إجراء تسوية جرد (زيادة/نقص). كل حركة تُسجَّل في سجل حركات المخزون."],
        ["مواعيد الصيانة", "لحجز موعد في الورشة لأي آلية: من صفحة \"مواعيد الصيانة\" ← \"حجز موعد\"، أو من صفحة تفاصيل الآلية ← \"احجز صيانة\" (تُحدَّد الآلية تلقائياً). اختر التاريخ والفترة (صباحاً/ظهراً/مساءً أو وقتاً محدداً) ونوع الخدمة. قواعد يفرضها الخادم: لا حجز لآلية محذوفة أو مباعة أو مستبعدة، ولا موعدين لنفس الآلية في نفس اليوم والفترة، ولا حجز في الماضي. مسار الموعد: بانتظار التأكيد ← مؤكَّد ← في الورشة ← مكتمل (أو ملغى / لم تحضر). مدير الورشة والإدارة العليا يؤكدون ويعيّنون الفني ويعيدون الجدولة ويلغون، ويمكن عند التأكيد إنشاء أمر شغل مسودة مرتبط تلقائياً. الفني المعيَّن يبدأ العمل ويُكمله. عند إكمال صيانة وقائية يُحدَّث موعد الصيانة القادمة للآلية تلقائياً من فترتها الدورية (أيام/كم) أو يدوياً. أمين المخزن يرى المواعيد فقط. كل تغيير حالة مسجَّل في سجل التدقيق ويظهر في سجل الموعد نفسه."],
        ["تثبيت التطبيق على الجوال", "آيفون: من سفاري اضغط زر المشاركة (في iOS 26 داخل زر ⋯) ← \"إضافة إلى الشاشة الرئيسية\" ← \"إضافة\". أندرويد: زر \"تثبيت التطبيق\" أو قائمة المتصفح ⋮ ← \"تثبيت التطبيق\". بعد التثبيت يفتح بملء الشاشة كتطبيق مستقل، واسحب الصفحة للأسفل من أعلاها لتحديث البيانات. التفاصيل في صفحة \"تثبيت التطبيق\"."],
        ["الوثائق", "سجل وثائق كل أصل: تأمين، رخصة، فحص دوري، تسجيل، ضمان. عند اقتراب تاريخ الانتهاء (30 يوماً) أو انتهائه تظهر تنبيهات في لوحة التحكم وصفحة الوثائق."],
        ["التكلفة الكلية للملكية (TCO)", "لكل أصل، يمكن حساب TCO يدوياً بالضغط على \"احسب الآن\"، أو تلقائياً عند إغلاق أي أمر شغل. المعادلة: التكلفة الرأسمالية + تكاليف الصيانة المتراكمة (من أوامر الشغل المغلقة) + التكاليف التشغيلية − القيمة السوقية الحالية. إن بلغت نسبة (تكاليف الصيانة ÷ القيمة السوقية) 60٪ فأكثر، يُعلَّم الأصل تلقائياً بـ\"غير مجدٍ اقتصادياً\" — إشارة للإدارة للنظر في بيعه أو الاستغناء عنه."],
        ["المستخدمون (للإدارة العليا فقط)", "إضافة حسابات جديدة للموظفين وتحديد دور كل منهم. الدور يحدّد بدقة ما يمكن لكل مستخدم رؤيته وفعله في النظام — الصلاحيات مفروضة من الخادم نفسه في كل عملية، لا مجرد إخفاء أزرار في الواجهة."],
        ["سجل التدقيق", "سجل ثابت لكل عملية حساسة (إنشاء، تعديل، حذف، اعتماد) مع اسم من قام بها ووقتها بالضبط. هذا السجل للقراءة فقط ولا توجد أي وسيلة في النظام لتعديله أو حذفه، حتى للإدارة العليا."],
        ["المزادات", "لبيع الأصول التي انتهى عمرها الاقتصادي أو تقرّر الاستغناء عنها. عند إنشاء مزاد، يتحوّل الأصل تلقائياً لحالة \"معروضة للبيع\". أي مزايدة يجب أن تفوق أعلى مزايدة حالية بمقدار \"خطوة المزايدة\" على الأقل. الميزة الأهم: لو وضع أحدهم مزايدة خلال آخر دقائق قليلة من انتهاء المزاد، يُمدَّد المزاد تلقائياً (Anti-Sniping) لمنع الفوز بمزايدة أخيرة خاطفة قبل أن يتمكن الآخرون من الرد. ⚠️ تنويه مهم: المزايدة حالياً متاحة فقط لمستخدمي النظام الداخليين (لا بوابة مصادقة منفصلة للمشترين الخارجيين بعد)، ولا تحصيل فعلي لأي ضمان مالي."],
        ["الأدوار ومن يرى ماذا", "الإدارة العليا: كل شيء. مدير الأسطول: الأصول، أوامر الشغل، المخزون، TCO، المزادات. مدير الورشة: الأصول وأوامر الشغل والمخزون، ويملك وحده صلاحية اعتماد إغلاق أمر الشغل. أمين المخزن: المخزون فقط (إضافة أصناف وصرفها). فني الصيانة: أوامر الشغل فقط (تنفيذها وتسجيل نتيجة الفحص)."],
    ];
    foreach ($sections as [$title, $body]) {
        echo "<div class='help-section'><h3>" . e($title) . "</h3><p>" . e($body) . "</p></div>";
    }
}

/* =====================================================================
   التوجيه والعرض النهائي
   ===================================================================== */
$page = (string)($_GET["page"] ?? "dashboard");
$allowed = $NAV_BY_ROLE[$role] ?? [];
// صفحات تفاصيل غير موجودة في القائمة: تُسمح فقط إن كانت صفحتها الأم مسموحة لنفس الدور
$DETAIL_PARENT = ["asset_detail" => "assets", "auction_detail" => "auctions", "appointment_detail" => "appointments", "wo_print" => "workorders"];
if (isset($DETAIL_PARENT[$page])) {
    if (!in_array($DETAIL_PARENT[$page], $allowed, true)) $page = "dashboard";
} elseif ($page !== "install" && !in_array($page, $allowed, true)) {
    $page = "dashboard";
}
$parentPage = $DETAIL_PARENT[$page] ?? null;

$NAV_LABELS = [
    "dashboard" => "لوحة التحكم", "assets" => "الأصول", "appointments" => "مواعيد الصيانة", "workorders" => "أوامر الشغل",
    "inventory" => "المخزون", "tco" => "التكلفة الكلية", "auctions" => "المزادات", "users" => "المستخدمون",
    "documents" => "الوثائق", "audit" => "سجل التدقيق", "help" => "دليل الاستخدام", "install" => "تثبيت التطبيق",
    "asset_detail" => "تفاصيل الآلية", "auction_detail" => "تفاصيل المزاد", "appointment_detail" => "تفاصيل الموعد", "wo_print" => "تقرير أمر الشغل",
];
$TAB_LABELS = ["dashboard" => "الرئيسية", "assets" => "الآليات", "appointments" => "المواعيد", "workorders" => "أوامر الشغل", "inventory" => "المخزون"];
// شريط التبويبات: أول 4 أقسام للدور + «المزيد» (نمط iOS: 5 تبويبات كحد أقصى)
$tabKeys = array_slice(array_values(array_diff($allowed, ["help"])), 0, 4);
$moreKeys = array_values(array_diff($allowed, $tabKeys));
$activeTab = $parentPage ?? $page;
$moreActive = !in_array($activeTab, $tabKeys, true);

$apptBadge = 0;
if (can("manage_appointment", $role, $ACTION_ROLES)) {
    $apptBadge = (int)$pdo->query("SELECT COUNT(*) FROM maintenance_appointments WHERE status = 'PENDING' AND scheduled_date >= CURDATE()")->fetchColumn();
} elseif ($role === "TECHNICIAN") {
    $stB = $pdo->prepare("SELECT COUNT(*) FROM maintenance_appointments WHERE assigned_technician = ? AND status = 'CONFIRMED' AND scheduled_date = ?");
    $stB->execute([$user["id"], date("Y-m-d")]); $apptBadge = (int)$stB->fetchColumn();
}
$logoutUrl = "index.php?logout=1&t=" . urlencode(csrfToken());
$initial = function_exists("mb_substr") ? mb_substr(trim($user["full_name"]), 0, 1, "UTF-8") : "•";
?>
<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title><?= e($NAV_LABELS[$page] ?? "") ?> — FMS/EMS</title>
<?= pwaHeadTags() ?>
<style><?= pageStyles() ?></style>
</head>
<body class="page-<?= e($page) ?>">
<div class="nav-progress" aria-hidden="true"></div>
<div class="ptr" id="ptr" aria-hidden="true"><i></i></div>
<div class="app">
  <aside class="sidebar">
    <div class="brand">FMS / EMS<span>إدارة الأسطول والمعدات</span></div>
    <nav>
      <?php foreach ($allowed as $key): ?>
        <a class="nav-item <?= $activeTab === $key ? "is-active" : "" ?>" href="index.php?page=<?= $key ?>"><?= icon($key) ?> <?= e($NAV_LABELS[$key]) ?><?php if ($key === "appointments" && $apptBadge): ?> <span class="pill pill-warn" style="margin-inline-start:auto"><?= $apptBadge ?></span><?php endif; ?></a>
      <?php endforeach; ?>
      <a class="nav-item <?= $page === "install" ? "is-active" : "" ?>" href="index.php?page=install" data-install-row><?= icon("install-app") ?> تثبيت التطبيق</a>
    </nav>
    <div class="sidebar-footer">
      <div class="role-name"><?= e($user["full_name"]) ?><span><?= e(roleLabel($role)) ?></span></div>
      <a class="logout-link" href="<?= e($logoutUrl) ?>">تسجيل الخروج</a>
    </div>
  </aside>
  <div class="app-col">
    <header class="ios-topbar">
      <div class="tb-side">
        <?php if ($parentPage): ?>
          <a class="tb-back" href="index.php?page=<?= e($parentPage) ?>"><?= icon("chev-back") ?><span><?= e($TAB_LABELS[$parentPage] ?? $NAV_LABELS[$parentPage]) ?></span></a>
        <?php else: ?>
          <span class="tb-brand"><img src="./icons/icon-192.png" alt="" width="26" height="26">FMS</span>
        <?php endif; ?>
      </div>
      <div class="tb-title"><?= e($NAV_LABELS[$page] ?? "") ?></div>
      <div class="tb-side">
        <?php if (($page === "appointments" || $page === "dashboard") && can("request_appointment", $role, $ACTION_ROLES)): ?>
          <a class="tb-btn" href="index.php?page=appointments&view=book" aria-label="حجز موعد صيانة"><?= icon("calendar-plus") ?></a>
        <?php elseif ($page === "assets" && can("create_asset", $role, $ACTION_ROLES)): ?>
          <a class="tb-btn" href="index.php?page=assets&new=1" aria-label="إضافة أصل"><?= icon("plus") ?></a>
        <?php endif; ?>
      </div>
    </header>
    <main class="main" id="main">
      <?php if ($m = $_SESSION["flash"] ?? null): $t = $_SESSION["flash_type"] ?? "success"; unset($_SESSION["flash"]); ?>
        <div class="alert alert-<?= e($t) ?>" role="status"><?= e($m) ?></div>
      <?php endif; ?>

      <?php
      switch ($page) {
          case "dashboard": renderDashboard($pdo, $role); break;
          case "assets": renderAssets($pdo, $role, $ACTION_ROLES); break;
          case "asset_detail": renderAssetDetail($pdo, $role, $ACTION_ROLES); break;
          case "appointments": renderAppointments($pdo, $role, $ACTION_ROLES, (string)$user["id"]); break;
          case "appointment_detail": renderAppointmentDetail($pdo, $role, $ACTION_ROLES, (string)$user["id"]); break;
          case "workorders": renderWorkOrders($pdo, $role, $ACTION_ROLES, $user["id"]); break;
          case "inventory": renderInventory($pdo, $role, $ACTION_ROLES); break;
          case "tco": renderTco($pdo, $role, $ACTION_ROLES); break;
          case "auctions": renderAuctions($pdo, $role, $ACTION_ROLES); break;
          case "auction_detail": renderAuctionDetail($pdo, $role, $ACTION_ROLES); break;
          case "users": renderUsers($pdo, $role, $ACTION_ROLES); break;
          case "audit": renderAudit($pdo); break;
          case "documents": renderDocuments($pdo, $role, $ACTION_ROLES); break;
          case "wo_print": renderWoPrint($pdo, $role); break;
          case "install": renderInstall(); break;
          case "help": renderHelp(); break;
      }
      ?>
    </main>
  </div>

  <nav class="ios-tabbar" aria-label="التنقل الرئيسي">
    <?php foreach ($tabKeys as $key): ?>
      <a class="<?= $activeTab === $key ? "is-active" : "" ?>" href="index.php?page=<?= $key ?>"<?= $activeTab === $key ? ' aria-current="page"' : "" ?>><?= icon($key) ?><span><?= e($TAB_LABELS[$key] ?? $NAV_LABELS[$key]) ?></span><?php if ($key === "appointments" && $apptBadge): ?><b class="tab-badge"><?= $apptBadge > 99 ? "99+" : $apptBadge ?></b><?php endif; ?></a>
    <?php endforeach; ?>
    <a class="<?= $moreActive ? "is-active" : "" ?>" href="#more" data-open-more role="button" aria-haspopup="dialog"><?= icon("more") ?><span>المزيد</span></a>
  </nav>
</div>

<div class="sheet-backdrop" id="more-sheet" hidden>
  <div class="sheet" role="dialog" aria-modal="true" aria-label="المزيد">
    <div class="sheet-grabber" aria-hidden="true"></div>
    <div class="more-user"><span class="avatar"><?= e($initial) ?></span><div><b><?= e($user["full_name"]) ?></b><span><?= e(roleLabel($role)) ?></span></div></div>
    <?php if ($moreKeys): ?>
    <div class="ios-list">
      <?php foreach ($moreKeys as $key): ?>
        <a class="<?= $activeTab === $key ? "is-active" : "" ?>" href="index.php?page=<?= $key ?>"><?= icon($key) ?><span><?= e($NAV_LABELS[$key]) ?></span></a>
      <?php endforeach; ?>
    </div>
    <?php endif; ?>
    <div class="ios-list" data-install-row>
      <button type="button" data-install-open><?= icon("install-app") ?><span>أضف إلى الشاشة الرئيسية</span></button>
      <a href="index.php?page=install"><?= icon("help") ?><span>طريقة التثبيت على الآيفون</span></a>
    </div>
    <div class="ios-list">
      <a class="danger" href="<?= e($logoutUrl) ?>" data-no-progress><?= icon("logout") ?><span>تسجيل الخروج</span></a>
    </div>
    <button class="btn btn-ghost btn-block" type="button" data-sheet-close>إغلاق</button>
  </div>
</div>

<div id="pwa-install-btn" class="pwa-install-fab" style="display:none">
  <button type="button" class="fab-main" data-install-open><?= icon("install-app") ?> تثبيت التطبيق</button>
  <button type="button" class="fab-x" data-fab-dismiss aria-label="إخفاء">×</button>
</div>
<?= installSheetHtml() ?>
<?= appUiScript() ?>
<?= pwaRegisterScript() ?>
<?= chatbaseWidgetScript() ?>
</body>
</html>
