-- =====================================================
-- Beasiswa Database Schema for MySQL (Laragon)
-- =====================================================

CREATE DATABASE IF NOT EXISTS beasiswa;
USE beasiswa;

-- =====================================================
-- Users Table (Authentication)
-- =====================================================
CREATE TABLE IF NOT EXISTS Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Insert default admin user (password: admin123)
INSERT INTO Users (username, password_hash, full_name, role, is_active)
VALUES ('admin', '$2a$10$rOvHPxfzO2.NFxqVx0CZnOiGhUh8NQOmN8KvJYsMnhqZbJZLQZI6e', 'Administrator', 'admin', 1)
ON DUPLICATE KEY UPDATE username = username;

-- =====================================================
-- EmployeeTEL Table (Karyawan)
-- =====================================================
CREATE TABLE IF NOT EXISTS EmployeeTEL (
    NIK VARCHAR(50) PRIMARY KEY,
    Employee_Name VARCHAR(255),
    Phone_Number VARCHAR(50),
    Join_Date DATE,
    Org_Group_Code VARCHAR(50),
    Organization_Name VARCHAR(255),
    Employee_PA VARCHAR(50)
);

-- =====================================================
-- ChildTEL Table (Data Anak Karyawan)
-- =====================================================
CREATE TABLE IF NOT EXISTS ChildTEL (
    id INT AUTO_INCREMENT PRIMARY KEY,
    NIK VARCHAR(50),
    Child_No INT,
    Child_Name VARCHAR(255),
    Gender VARCHAR(10),
    Birth_Place VARCHAR(100),
    Birth_Date DATE,
    FOREIGN KEY (NIK) REFERENCES EmployeeTEL(NIK) ON DELETE CASCADE
);

-- =====================================================
-- UniversitasList Table (Daftar Universitas)
-- =====================================================
CREATE TABLE IF NOT EXISTS UniversitasList (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nama_universitas VARCHAR(255) NOT NULL,
    akreditasi VARCHAR(10)
);

-- =====================================================
-- ParameterPenilaian Table (Parameter Scoring)
-- =====================================================
CREATE TABLE IF NOT EXISTS ParameterPenilaian (
    id INT AUTO_INCREMENT PRIMARY KEY,
    kategori VARCHAR(100) NOT NULL,
    key_nilai VARCHAR(100) NOT NULL,
    value_nilai DECIMAL(10, 2),
    UNIQUE KEY unique_kategori_key (kategori, key_nilai)
);

-- Insert default parameter values
INSERT INTO ParameterPenilaian (kategori, key_nilai, value_nilai) VALUES
('Accreditation', 'A', 30),
('Accreditation', 'B', 20),
('Accreditation', 'C', 10),
('Grade', 'A', 40),
('Grade', 'B', 30),
('Grade', 'C', 20),
('Grade', 'D', 10),
('Achievement', 'Internasional', 30),
('Achievement', 'Nasional', 20),
('Achievement', 'Provinsi', 15),
('Achievement', 'Kabupaten', 10),
('Achievement', 'Kecamatan', 5)
ON DUPLICATE KEY UPDATE value_nilai = VALUES(value_nilai);

-- =====================================================
-- ScholarshipApplicants Table (Data Pendaftar Beasiswa)
-- =====================================================
CREATE TABLE IF NOT EXISTS ScholarshipApplicants (
    id INT AUTO_INCREMENT PRIMARY KEY,
    NIK VARCHAR(50),
    Employee_Name VARCHAR(255),
    Phone_Number VARCHAR(50),
    Join_Date DATE,
    Org_Group_Code VARCHAR(50),
    Organization_Name VARCHAR(255),
    Employee_PA VARCHAR(50),
    Child_Name VARCHAR(255),
    Child_Phone_Number VARCHAR(50),
    Gender VARCHAR(10),
    Birth_Place VARCHAR(100),
    Birth_Date DATE,
    Age INT,
    Education_Level VARCHAR(50),
    Education_Name VARCHAR(255),
    Jurusan VARCHAR(255),
    Semester INT,
    Accreditation VARCHAR(10),
    Nilai_Rata_Rata_1 DECIMAL(5, 2),
    Nilai_Rata_Rata_2 DECIMAL(5, 2),
    Nilai_Akademik DECIMAL(5, 2),
    Grade VARCHAR(10),
    Achievement_1 VARCHAR(100),
    Achievement_2 VARCHAR(100),
    Achievement_3 VARCHAR(100),
    Achievement_4 VARCHAR(100),
    Remark TEXT,
    Grand_Total_Score DECIMAL(10, 2),
    Tidak_Menerima_Beasiswa_Lain VARCHAR(10),
    Tidak_Menerima_Beasiswa_TEL VARCHAR(10),
    Tanggungan_Pekerja VARCHAR(10),
    Surat_Keterangan VARCHAR(10),
    Received_Application DATE,
    Berkas VARCHAR(255),
    Periode_Tahun VARCHAR(20),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_nik (NIK),
    INDEX idx_child_name (Child_Name),
    INDEX idx_education_level (Education_Level)
);

-- =====================================================
-- FileStorage Table (File Uploads)
-- =====================================================
CREATE TABLE IF NOT EXISTS FileStorage (
    file_id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
    file_name VARCHAR(255) NOT NULL,
    file_type VARCHAR(100),
    file_size INT,
    file_data LONGBLOB,
    upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INT,
    description TEXT,
    FOREIGN KEY (uploaded_by) REFERENCES Users(id) ON DELETE SET NULL
);

-- =====================================================
-- ScholarshipDocuments Table (Dokumen Validasi)
-- =====================================================
CREATE TABLE IF NOT EXISTS ScholarshipDocuments (
    DocumentID INT AUTO_INCREMENT PRIMARY KEY,
    NIK VARCHAR(50),
    ChildName VARCHAR(255),
    DocumentType VARCHAR(50),
    FileName VARCHAR(255),
    FileType VARCHAR(100),
    FileSize INT,
    FileData LONGBLOB,
    UploadDate DATETIME DEFAULT CURRENT_TIMESTAMP,
    UploadedBy INT,
    INDEX idx_nik_doc (NIK),
    INDEX idx_child_doc (ChildName),
    INDEX idx_doc_type (DocumentType),
    FOREIGN KEY (UploadedBy) REFERENCES Users(id) ON DELETE SET NULL
);

-- =====================================================
-- DataExcel Table (For Excel Import)
-- =====================================================
CREATE TABLE IF NOT EXISTS DataExcel (
    id INT AUTO_INCREMENT PRIMARY KEY,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

SELECT 'Database beasiswa berhasil dibuat!' AS Message;
