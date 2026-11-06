-- ============================================================
-- CyberShield - Database
-- Mata Kuliah : Keamanan Jaringan
-- Nama        : Muhamad Yusuf
-- NIM         : 242502040108
-- Kelas       : 3TI01
-- ============================================================

CREATE DATABASE IF NOT EXISTS cybershield_db;
USE cybershield_db;

-- ------------------------------------------------------------
-- Tabel 1: firewall_rules
-- Menyimpan aturan firewall: IP, port, protokol, aksi, status
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS firewall_rules (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  rule_name   VARCHAR(100) NOT NULL,
  ip_address  VARCHAR(45)  NOT NULL,
  port        INT          NOT NULL,
  protocol    ENUM('TCP','UDP','TCP/UDP') NOT NULL DEFAULT 'TCP',
  action      ENUM('ALLOW','BLOCK') NOT NULL,
  is_active   TINYINT(1)   NOT NULL DEFAULT 1,
  created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO firewall_rules (rule_name, ip_address, port, protocol, action, is_active) VALUES
('Izinkan HTTP Publik',  '0.0.0.0/0',       80,   'TCP', 'ALLOW', 1),
('Izinkan HTTPS Publik', '0.0.0.0/0',       443,  'TCP', 'ALLOW', 1),
('Blokir Telnet',        '0.0.0.0/0',       23,   'TCP', 'BLOCK', 1),
('Blokir RDP Eksternal', '203.0.113.0/24',  3389, 'TCP', 'BLOCK', 1);

-- ------------------------------------------------------------
-- Tabel 2: security_logs
-- Mencatat waktu kejadian, IP sumber, port tujuan,
-- jenis aktivitas, dan tindakan sistem
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_logs (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  event_time    DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
  source_ip     VARCHAR(45)  NOT NULL,
  dest_port     INT          NOT NULL,
  activity_type VARCHAR(100) NOT NULL,
  action        VARCHAR(20)  NOT NULL,
  description   TEXT
);

INSERT INTO security_logs (source_ip, dest_port, activity_type, action, description) VALUES
('185.220.101.7',  22,  'Brute Force SSH', 'DIBLOKIR', 'Percobaan login SSH berulang dari IP blacklist'),
('45.135.210.19',  80,  'DDoS Flood',      'DIBLOKIR', 'Banjir paket HTTP melebihi ambang batas'),
('103.75.196.44',  445, 'Port Scan',       'DIBLOKIR', 'Pemindaian port SMB terdeteksi'),
('192.168.1.10',   443, 'HTTPS Request',   'DIIZINKAN', 'Koneksi HTTPS normal dari jaringan internal');

-- ------------------------------------------------------------
-- Tabel 3: blacklist_ips
-- Daftar IP yang diblokir beserta alasan pemblokiran
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS blacklist_ips (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  ip_address VARCHAR(45)  NOT NULL UNIQUE,
  reason     VARCHAR(255) NOT NULL,
  blocked_at TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO blacklist_ips (ip_address, reason) VALUES
('45.135.210.19',  'Serangan DDoS'),
('103.75.196.44',  'Brute Force SSH'),
('185.220.101.7',  'Port Scan'),
('91.240.118.12',  'Malware C2'),
('193.142.59.88',  'Percobaan SQL Injection');
