-- FMS/EMS migration v4: extended assets + maintenance appointments + auth tokens
-- Safe to run multiple times where IF NOT EXISTS / INSERT IGNORE applies.

CREATE TABLE IF NOT EXISTS schema_migrations (
    version INT PRIMARY KEY,
    applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Extended asset fields (ignore errors if columns already exist on some hosts)
ALTER TABLE assets ADD COLUMN plate_number VARCHAR(40) NULL;
ALTER TABLE assets ADD COLUMN chassis_number VARCHAR(120) NULL;
ALTER TABLE assets ADD COLUMN ownership_type ENUM('OWNED','LEASED','RENTED') NOT NULL DEFAULT 'OWNED';
ALTER TABLE assets ADD COLUMN department VARCHAR(120) NULL;
ALTER TABLE assets ADD COLUMN cost_center VARCHAR(120) NULL;
ALTER TABLE assets ADD COLUMN assigned_driver VARCHAR(190) NULL;
ALTER TABLE assets ADD COLUMN next_service_due_date DATE NULL;
ALTER TABLE assets ADD COLUMN next_service_due_km DECIMAL(12,2) NULL;
ALTER TABLE assets ADD COLUMN notes TEXT NULL;
ALTER TABLE assets ADD COLUMN photo_path VARCHAR(255) NULL;
ALTER TABLE assets ADD INDEX idx_plate (plate_number);
ALTER TABLE assets ADD INDEX idx_next_service (next_service_due_date);

CREATE TABLE IF NOT EXISTS maintenance_appointments (
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
    INDEX idx_appt_date (scheduled_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS auth_tokens (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    selector CHAR(24) NOT NULL UNIQUE,
    validator_hash CHAR(64) NOT NULL,
    user_id VARCHAR(36) NOT NULL,
    user_agent VARCHAR(190) NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_tok_user (user_id),
    INDEX idx_tok_exp (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

INSERT IGNORE INTO schema_migrations (version) VALUES (4);
