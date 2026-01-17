const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const path = require("path");
const app = express();
const multer = require("multer");
const xlsx = require("xlsx");
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
});
const session = require("express-session");
const bcrypt = require("bcryptjs");

// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, "src")));

// Session configuration
const isProduction = process.env.NODE_ENV === "production";
app.use(
  session({
    secret: process.env.SESSION_SECRET || "your-strong-secret-key-here-123!@#",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,
      sameSite: isProduction ? "none" : "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
    proxy: isProduction,
  })
);

// Konfigurasi database MySQL (Laragon default)
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  database: process.env.DB_NAME || "beasiswa",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  port: parseInt(process.env.DB_PORT, 10) || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
};

// Inisialisasi pool koneksi
let pool;

async function initializeDB() {
  try {
    console.log("Connecting to MySQL database...");
    pool = mysql.createPool(dbConfig);

    // Test connection
    const connection = await pool.getConnection();
    console.log("✅ MySQL Database connected:", dbConfig.host);
    connection.release();
  } catch (err) {
    console.error("❌ Database connection failed:", err);
    process.exit(1);
  }
}

// Middleware untuk mendapatkan pool yang sudah terhubung
function getDBPool() {
  if (!pool) {
    throw new Error("Database not initialized. Call initializeDB() first.");
  }
  return pool;
}

// Authentication middleware
function authenticate(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
}

// ====================== USER ROUTES ======================

// 🔹 Get All Users (with pagination)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = "" } = req.query;
    const offset = (page - 1) * limit;
    const searchPattern = `%${search}%`;

    const dbPool = getDBPool();

    const [rows] = await dbPool.query(
      `SELECT id, username, full_name, role, is_active, created_at 
       FROM Users 
       WHERE username LIKE ? OR full_name LIKE ?
       ORDER BY id
       LIMIT ? OFFSET ?`,
      [searchPattern, searchPattern, parseInt(limit), offset]
    );

    const [countResult] = await dbPool.query(
      `SELECT COUNT(*) as total FROM Users
       WHERE username LIKE ? OR full_name LIKE ?`,
      [searchPattern, searchPattern]
    );

    res.json({
      data: rows,
      total: countResult[0].total,
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// Register user
app.post("/api/register", async (req, res) => {
  const { username, password, full_name } = req.body;

  if (!username || !password || !full_name) {
    return res.status(400).json({ message: "Data tidak lengkap" });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const dbPool = getDBPool();

    await dbPool.query(
      `INSERT INTO Users (username, password_hash, full_name, role, is_active)
       VALUES (?, ?, ?, 'user', 0)`,
      [username, hash, full_name]
    );

    res.json({
      message: "Registrasi berhasil, menunggu ACC admin",
    });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Username sudah digunakan" });
    }
    console.error(err);
    res.status(500).json({ message: "Registrasi gagal" });
  }
});

// 🔹 Create New User
app.post("/api/users", authenticate, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Only admin can create users" });
  }

  const { username, password, full_name, role } = req.body;

  try {
    if (!username || !password || !full_name) {
      return res
        .status(400)
        .json({ message: "Username, password, and full name are required" });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const dbPool = getDBPool();

    await dbPool.query(
      `INSERT INTO Users (username, password_hash, full_name, role)
       VALUES (?, ?, ?, ?)`,
      [username, hashedPassword, full_name, role || "user"]
    );

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Username already exists" });
    }
    console.error("Error creating user:", err);
    res.status(500).json({ message: "Failed to create user" });
  }
});

// 🔹 Update User
app.put("/api/users/:id", authenticate, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Only admin can update users" });
  }

  const { id } = req.params;
  const { username, full_name, role, is_active } = req.body;

  try {
    const dbPool = getDBPool();
    await dbPool.query(
      `UPDATE Users 
       SET username = ?, full_name = ?, role = ?, is_active = ? 
       WHERE id = ?`,
      [username, full_name, role, is_active ? 1 : 0, id]
    );

    res.json({ message: "User updated successfully" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") {
      return res.status(400).json({ message: "Username already exists" });
    }
    console.error("Error updating user:", err);
    res.status(500).json({ message: "Failed to update user" });
  }
});

// 🔹 Delete User
app.delete("/api/users/:id", authenticate, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Only admin can delete users" });
  }

  const { id } = req.params;

  try {
    const dbPool = getDBPool();
    await dbPool.query("DELETE FROM Users WHERE id = ?", [id]);
    res.json({ message: "User deleted successfully" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ message: "Failed to delete user" });
  }
});

// 🔹 Change Password
app.put("/api/users/:id/change-password", authenticate, async (req, res) => {
  const { id } = req.params;
  const { currentPassword, newPassword } = req.body;
  const userId = req.session.user.id;

  if (req.session.user.role !== "admin" && userId !== parseInt(id)) {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    const dbPool = getDBPool();

    if (req.session.user.role !== "admin") {
      const [userResult] = await dbPool.query(
        "SELECT password_hash FROM Users WHERE id = ?",
        [id]
      );

      if (userResult.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(currentPassword, userResult[0].password_hash);
      if (!isMatch) {
        return res.status(400).json({ message: "Current password is incorrect" });
      }
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ message: "New password must be at least 6 characters" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    await dbPool.query("UPDATE Users SET password_hash = ? WHERE id = ?", [hashedPassword, id]);

    res.json({ message: "Password changed successfully" });
  } catch (err) {
    console.error("Error changing password:", err);
    res.status(500).json({ message: "Failed to change password" });
  }
});

// 🔹 Get Single User
app.get("/api/users/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const dbPool = getDBPool();

    const [result] = await dbPool.query(
      `SELECT id, username, full_name, role, is_active, created_at 
       FROM Users WHERE id = ?`,
      [id]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(result[0]);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

// ====================== PAGE ROUTES ======================

app.use(express.static(path.join(__dirname, "public")));
app.use(express.static(path.join(__dirname, "src")));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/login.html"));
});

app.get("/input", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/input.html"));
});

app.get("/datakaryawan", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/karyawan.html"));
});

app.get("/beasiswa", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/newbeasiswa.html"));
});

app.get("/parameternilai", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "/src/parameternilai.html"));
});

app.get("/nilaisma", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/nilaisma.html"));
});

app.get("/users", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "/src/users.html"));
});

app.get("/home", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "/src/home.html"));
});

app.get("/files", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "/src/files.html"));
});

app.get("/uploadoc", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/upload.html"));
});

app.get("/import", authenticate, (req, res) => {
  res.sendFile(path.join(__dirname, "/src/import.html"));
});

// ====================== AUTH ROUTES ======================

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required" });
  }

  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(
      "SELECT * FROM Users WHERE username = ? AND is_active = 1",
      [username]
    );

    console.log(username, "Login..");

    if (result.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Username atau Password Salah" });
    }

    req.session.user = {
      id: user.id,
      username: user.username,
      full_name: user.full_name,
      role: user.role,
    };

    res.json({
      success: true,
      user: req.session.user,
      message: "Login successful",
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login" });
  }
});

// ACC user API
app.put("/api/users/:id/approve", authenticate, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Akses ditolak" });
  }

  try {
    const dbPool = getDBPool();
    await dbPool.query("UPDATE Users SET is_active = 1 WHERE id = ?", [req.params.id]);
    res.json({ message: "User berhasil di-ACC" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Gagal ACC user" });
  }
});

// Logout route
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Logout successful" });
    console.log("Logout...");
  });
});

// Check auth status
app.get("/api/check-auth", (req, res) => {
  if (req.session.user) {
    return res.json({
      authenticated: true,
      user: req.session.user,
    });
  }
  res.json({ authenticated: false });
});

// ====================== KARYAWAN & ANAK ROUTES ======================

// 🔹 Cari Data Karyawan berdasarkan NIK atau Nama
app.get("/api/karyawan", async (req, res) => {
  const { nik } = req.query;

  try {
    const dbPool = getDBPool();
    let query = "SELECT * FROM EmployeeTEL WHERE 1=1";
    const params = [];

    if (nik) {
      query += " AND NIK = ?";
      params.push(nik);
    }

    const [result] = await dbPool.query(query, params);
    res.json(result);
  } catch (err) {
    console.error("❌ Query error:", err);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Ambil Data Anak Berdasarkan NIK Karyawan
app.get("/api/anak", async (req, res) => {
  const { nik } = req.query;

  if (!nik) {
    return res.status(400).json({ message: "NIK karyawan diperlukan" });
  }

  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query("SELECT * FROM ChildTEL WHERE NIK = ?", [nik]);
    res.json(result);
  } catch (err) {
    console.error("❌ Query error:", err);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Cari Data Karyawan untuk input nilai SMA
app.get("/api/karyawannilai", async (req, res) => {
  const { nik } = req.query;

  try {
    const dbPool = getDBPool();
    let query = "SELECT * FROM ScholarshipApplicants WHERE 1=1";
    const params = [];

    if (nik) {
      query += " AND NIK = ? AND Education_Level LIKE 'SLTA'";
      params.push(nik);
    }

    const [result] = await dbPool.query(query, params);
    res.json(result);
  } catch (err) {
    console.error("❌ Query error:", err);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Ambil Data Anak untuk input nilai SMA
app.get("/api/anaknilai", async (req, res) => {
  const { nik } = req.query;

  if (!nik) {
    return res.status(400).json({ message: "NIK karyawan diperlukan" });
  }

  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(
      "SELECT * FROM ScholarshipApplicants WHERE NIK = ? AND Education_Level LIKE 'SLTA'",
      [nik]
    );
    res.json(result);
  } catch (err) {
    console.error("❌ Query error:", err);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// ====================== SCHOLARSHIP ROUTES ======================

// POST scholarship data
app.post("/api/scholarship", async (req, res) => {
  console.log("✅ Data yang diterima:", req.body);

  if (!Array.isArray(req.body)) {
    return res.status(400).json({ message: "Data harus berupa array" });
  }

  try {
    const dbPool = getDBPool();
    const query = `
      INSERT INTO ScholarshipApplicants (
        NIK, Employee_Name, Phone_Number, Join_Date, Org_Group_Code, Organization_Name, Employee_PA,
        Child_Name, Child_Phone_Number, Gender, Birth_Place, Birth_Date, Age, Education_Level,
        Education_Name, Jurusan, Semester, Accreditation, Nilai_Rata_Rata_1, Nilai_Rata_Rata_2,
        Nilai_Akademik, Grade, Achievement_1, Achievement_2, Achievement_3, Achievement_4, Remark,
        Grand_Total_Score, Tidak_Menerima_Beasiswa_Lain, Tidak_Menerima_Beasiswa_TEL,
        Tanggungan_Pekerja, Surat_Keterangan, Received_Application, Berkas, Periode_Tahun
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    for (const row of req.body) {
      await dbPool.query(query, [
        row.NIK, row.Employee_Name, row.Phone_Number, row.Join_Date,
        row.Org_Group_Code, row.Organization_Name, row.Employee_PA,
        row.Child_Name, row.Child_Phone_Number, row.Gender, row.Birth_Place,
        row.Birth_Date, row.Age, row.Education_Level, row.Education_Name,
        row.Jurusan, row.Semester, row.Accreditation, row.Nilai_Rata_Rata_1,
        row.Nilai_Rata_Rata_2, row.Nilai_Akademik, row.Grade, row.Achievement_1,
        row.Achievement_2, row.Achievement_3, row.Achievement_4, row.Remark,
        row.Grand_Total_Score, row.Tidak_Menerima_Beasiswa_Lain,
        row.Tidak_Menerima_Beasiswa_TEL, row.Tanggungan_Pekerja,
        row.Surat_Keterangan, row.Received_Application, row.Berkas, row.Periode_Tahun
      ]);
    }

    res.status(201).json({ message: "Data berhasil disimpan!" });
  } catch (err) {
    console.error("❌ Error saving data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat menyimpan data",
      error: err.message,
    });
  }
});

// 🔹 Ambil Data Universitas
app.get("/api/education-names", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query("SELECT * FROM UniversitasList");
    res.json(result);
    console.log(result);
  } catch (err) {
    console.error("❌ Error fetching data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat mengambil data",
      error: err.message,
    });
  }
});

// Parameter Nilai
app.get("/api/parameternilai", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(
      "SELECT kategori, key_nilai, value_nilai FROM ParameterPenilaian"
    );

    const parameterMaps = result.reduce((acc, row) => {
      if (!acc[row.kategori]) {
        acc[row.kategori] = {};
      }
      acc[row.kategori][row.key_nilai] = row.value_nilai;
      return acc;
    }, {});

    res.json(parameterMaps);
  } catch (error) {
    console.error("❌ Error fetching parameter nilai:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: error.message });
  }
});

// Delete scholarship data
app.delete("/api/scholarship/:NIK/:Child_Name", async (req, res) => {
  const { NIK, Child_Name } = req.params;

  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(
      "DELETE FROM ScholarshipApplicants WHERE NIK = ? AND Child_Name = ?",
      [NIK, Child_Name]
    );

    console.log(Child_Name);

    if (result.affectedRows === 1) {
      res.status(200).json({ message: "Data berhasil dihapus" });
    } else {
      res.status(404).json({ message: "Data tidak ditemukan" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Gagal menghapus data" });
  }
});

// Edit scholarship data
app.put("/api/scholarship/:NIK/:Child_Name", async (req, res) => {
  const { NIK, Child_Name } = req.params;
  const updatedData = req.body;

  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(
      `UPDATE ScholarshipApplicants
       SET Employee_Name = ?, Phone_Number = ?, Join_Date = ?, Org_Group_Code = ?,
           Organization_Name = ?, Employee_PA = ?, Child_Name = ?, Child_Phone_Number = ?,
           Gender = ?, Birth_Place = ?, Birth_Date = ?, Age = ?, Education_Level = ?,
           Education_Name = ?, Jurusan = ?, Semester = ?, Accreditation = ?,
           Nilai_Rata_Rata_1 = ?, Nilai_Rata_Rata_2 = ?, Nilai_Akademik = ?, Grade = ?,
           Achievement_1 = ?, Achievement_2 = ?, Achievement_3 = ?, Achievement_4 = ?,
           Remark = ?, Tidak_Menerima_Beasiswa_Lain = ?, Tidak_Menerima_Beasiswa_TEL = ?,
           Tanggungan_Pekerja = ?, Surat_Keterangan = ?, Received_Application = ?,
           Berkas = ?, Periode_Tahun = ?
       WHERE NIK = ? AND Child_Name = ?`,
      [
        updatedData.Employee_Name, updatedData.Phone_Number, updatedData.Join_Date,
        updatedData.Org_Group_Code, updatedData.Organization_Name, updatedData.Employee_PA,
        updatedData.Child_Name, updatedData.Child_Phone_Number, updatedData.Gender,
        updatedData.Birth_Place, updatedData.Birth_Date, updatedData.Age,
        updatedData.Education_Level, updatedData.Education_Name, updatedData.Jurusan,
        updatedData.Semester, updatedData.Accreditation, updatedData.Nilai_Rata_Rata_1 || 0,
        updatedData.Nilai_Rata_Rata_2 || 0, updatedData.Nilai_Akademik, updatedData.Grade,
        updatedData.Achievement_1, updatedData.Achievement_2, updatedData.Achievement_3,
        updatedData.Achievement_4, updatedData.Remark, updatedData.Tidak_Menerima_Beasiswa_Lain,
        updatedData.Tidak_Menerima_Beasiswa_TEL, updatedData.Tanggungan_Pekerja,
        updatedData.Surat_Keterangan, updatedData.Received_Application, updatedData.Berkas,
        updatedData.Periode_Tahun, NIK, Child_Name
      ]
    );

    console.log(Child_Name);

    if (result.affectedRows === 1) {
      res.status(200).json({ message: "Data berhasil diperbarui" });
    } else {
      res.status(404).json({ message: "Data tidak ditemukan" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Gagal memperbarui data" });
  }
});

// Get all scholarship data
app.get("/api/scholarship", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query("SELECT * FROM ScholarshipApplicants");
    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat mengambil data",
      error: err.message,
    });
  }
});

// Get all karyawan data
app.get("/api/datakaryawan", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query("SELECT * FROM EmployeeTEL");
    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat mengambil data",
      error: err.message,
    });
  }
});

// Update parameter nilai
app.put("/api/parameternilai/:kategori/:key_nilai", async (req, res) => {
  const { kategori, key_nilai } = req.params;
  const { value_nilai } = req.body;

  try {
    const dbPool = getDBPool();
    await dbPool.query(
      "UPDATE ParameterPenilaian SET value_nilai = ? WHERE kategori = ? AND key_nilai = ?",
      [value_nilai, kategori, key_nilai]
    );
    res.json({ message: "Data berhasil diupdate" });
  } catch (error) {
    console.error("❌ Error updating parameter nilai:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server", error: error.message });
  }
});

// Update nilai akademik SMA
app.post("/api/update-academic-scores", async (req, res) => {
  if (!req.body || !req.body.updates) {
    return res.status(400).json({
      success: false,
      message: "Data updates diperlukan",
    });
  }

  const connection = await getDBPool().getConnection();

  try {
    await connection.beginTransaction();

    for (const data of req.body.updates) {
      if (!data.NIK || !data.Child_Name || !data.Nilai_Akademik) {
        throw new Error("Data NIK, Child_Name, dan Nilai_Akademik diperlukan");
      }

      const [result] = await connection.query(
        `UPDATE ScholarshipApplicants 
         SET Nilai_Akademik = ?, Nilai_Rata_Rata_1 = ?, Nilai_Rata_Rata_2 = ?
         WHERE NIK = ? AND Child_Name = ?`,
        [data.Nilai_Akademik, data.Nilai_Rata_Rata_1, data.Nilai_Rata_Rata_2, data.NIK, data.Child_Name]
      );

      if (result.affectedRows === 0) {
        console.warn(`Data tidak ditemukan untuk NIK: ${data.NIK}, Anak: ${data.Child_Name}`);
      }
    }

    await connection.commit();
    res.json({
      success: true,
      message: "Update nilai akademik berhasil",
      records_updated: req.body.updates.length,
    });
  } catch (error) {
    await connection.rollback();
    console.error("Database error:", error);
    res.status(500).json({
      success: false,
      message: "Gagal update nilai akademik",
      error: error.message,
    });
  } finally {
    connection.release();
  }
});

// ====================== FILE STORAGE ROUTES ======================

// 🔹 Upload File
app.post("/api/files", authenticate, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const { originalname, mimetype, size, buffer } = req.file;
    const { description } = req.body;
    const uploadedBy = req.session.user.id;

    const dbPool = getDBPool();
    await dbPool.query(
      `INSERT INTO FileStorage (file_id, file_name, file_type, file_size, file_data, uploaded_by, description)
       VALUES (UUID(), ?, ?, ?, ?, ?, ?)`,
      [originalname, mimetype, size, buffer, uploadedBy, description || null]
    );

    res.status(201).json({ message: "File uploaded successfully" });
  } catch (err) {
    console.error("❌ File upload error:", err);
    res.status(500).json({ message: "Failed to upload file", error: err.message });
  }
});

// 🔹 Get All Files Metadata
app.get("/api/files", authenticate, async (req, res) => {
  try {
    const dbPool = getDBPool();
    const [result] = await dbPool.query(`
      SELECT 
        file_id, file_name, file_type, file_size, upload_date, uploaded_by,
        u.username as uploaded_by_username, description
      FROM FileStorage fs
      LEFT JOIN Users u ON fs.uploaded_by = u.id
      ORDER BY upload_date DESC
    `);
    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching files:", err);
    res.status(500).json({ message: "Failed to fetch files", error: err.message });
  }
});

// 🔹 Download File
app.get("/api/files/:file_id", authenticate, async (req, res) => {
  try {
    const { file_id } = req.params;
    const dbPool = getDBPool();

    const [result] = await dbPool.query(
      "SELECT file_name, file_type, file_data FROM FileStorage WHERE file_id = ?",
      [file_id]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }

    const file = result[0];
    res.setHeader("Content-Type", file.file_type);
    res.setHeader("Content-Disposition", `attachment; filename="${file.file_name}"`);
    res.send(file.file_data);
  } catch (err) {
    console.error("❌ File download error:", err);
    res.status(500).json({ message: "Failed to download file", error: err.message });
  }
});

// 🔹 Delete File
app.delete("/api/files/:file_id", authenticate, async (req, res) => {
  try {
    const { file_id } = req.params;
    const userId = req.session.user.id;
    const dbPool = getDBPool();

    const [checkResult] = await dbPool.query(
      "SELECT uploaded_by FROM FileStorage WHERE file_id = ?",
      [file_id]
    );

    if (checkResult.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }

    const uploadedBy = checkResult[0].uploaded_by;

    if (req.session.user.role !== "admin" && userId !== uploadedBy) {
      return res.status(403).json({ message: "Not authorized to delete this file" });
    }

    await dbPool.query("DELETE FROM FileStorage WHERE file_id = ?", [file_id]);
    res.json({ message: "File deleted successfully" });
  } catch (err) {
    console.error("❌ File delete error:", err);
    res.status(500).json({ message: "Failed to delete file", error: err.message });
  }
});

// ====================== SCHOLARSHIP DOCUMENTS ROUTES ======================

// 🔹 Upload Dokumen Validasi
app.post("/api/scholarship/documents", authenticate, upload.single("document"), async (req, res) => {
  const connection = await getDBPool().getConnection();

  try {
    if (!req.file) {
      return res.status(400).json({ message: "No file uploaded" });
    }

    const { NIK, childName, documentType } = req.body;
    const { originalname, mimetype, size, buffer } = req.file;
    const uploadedBy = req.session.user.id;

    if (!NIK || !documentType) {
      return res.status(400).json({ message: "NIK and documentType are required" });
    }

    const validDocumentTypes = ["beasiswa_lain", "beasiswa_tel", "tanggungan", "sekolah", "NilaiRapot"];
    if (!validDocumentTypes.includes(documentType)) {
      return res.status(400).json({ message: "Invalid document type" });
    }

    if (size > 10 * 1024 * 1024) {
      return res.status(400).json({ message: "File size exceeds 10MB limit" });
    }

    const allowedMimeTypes = [
      "application/pdf", "image/jpeg", "image/png",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ];
    if (!allowedMimeTypes.includes(mimetype)) {
      return res.status(400).json({ message: "Unsupported file type" });
    }

    await connection.beginTransaction();

    // Check if document exists
    const [checkResult] = await connection.query(
      `SELECT DocumentID FROM ScholarshipDocuments 
       WHERE NIK = ? AND DocumentType = ? AND ChildName = ?`,
      [NIK, documentType, childName]
    );

    let action = "uploaded";

    if (checkResult.length > 0) {
      // Update existing document
      const documentId = checkResult[0].DocumentID;
      await connection.query(
        `UPDATE ScholarshipDocuments SET
          FileName = ?, FileType = ?, FileSize = ?, FileData = ?,
          UploadedBy = ?, UploadDate = NOW()
         WHERE DocumentID = ? AND ChildName = ?`,
        [originalname, mimetype, size, buffer, uploadedBy, documentId, childName]
      );
      action = "updated";
    } else {
      // Insert new document
      await connection.query(
        `INSERT INTO ScholarshipDocuments 
         (NIK, ChildName, DocumentType, FileName, FileType, FileSize, FileData, UploadDate, UploadedBy)
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW(), ?)`,
        [NIK, childName || null, documentType, originalname, mimetype, size, buffer, uploadedBy]
      );
    }

    // Update validation status
    let updateField = "";
    if (documentType === "beasiswa_lain") updateField = "Tidak_Menerima_Beasiswa_Lain";
    else if (documentType === "beasiswa_tel") updateField = "Tidak_Menerima_Beasiswa_TEL";
    else if (documentType === "tanggungan") updateField = "Tanggungan_Pekerja";
    else if (documentType === "sekolah") updateField = "Surat_Keterangan";

    if (updateField) {
      await connection.query(
        `UPDATE ScholarshipApplicants SET ${updateField} = 'Yes' WHERE NIK = ?`,
        [NIK]
      );
    }

    await connection.commit();

    res.status(200).json({
      success: true,
      message: `Document ${action} successfully`,
      action: action,
      documentType: documentType,
    });
  } catch (err) {
    await connection.rollback();
    console.error("❌ Document upload error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to upload document",
      error: err.message,
    });
  } finally {
    connection.release();
  }
});

// 🔹 Get Dokumen Validasi by NIK & ChildName
app.get("/api/scholarship/:nik/:childName/documents", authenticate, async (req, res) => {
  try {
    const { nik, childName } = req.params;
    const dbPool = getDBPool();

    const [result] = await dbPool.query(
      `SELECT DocumentID, NIK, ChildName, DocumentType, FileName, FileType, FileSize, UploadDate,
              u.username AS UploadedByUsername
       FROM ScholarshipDocuments d
       LEFT JOIN Users u ON d.UploadedBy = u.id
       WHERE NIK = ? AND ChildName = ?
       ORDER BY UploadDate DESC`,
      [nik, childName]
    );

    res.json(result);
  } catch (err) {
    console.error("❌ Error fetching documents:", err);
    res.status(500).json({ message: "Failed to fetch documents", error: err.message });
  }
});

// 🔹 Download Dokumen Validasi
app.get("/api/scholarship/documents/:documentId", authenticate, async (req, res) => {
  try {
    const { documentId } = req.params;
    const dbPool = getDBPool();

    const [result] = await dbPool.query(
      "SELECT FileName, FileType, FileData FROM ScholarshipDocuments WHERE DocumentID = ?",
      [documentId]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "Document not found" });
    }

    const document = result[0];
    res.setHeader("Content-Type", document.FileType);
    res.setHeader("Content-Disposition", `attachment; filename="${document.FileName}"`);
    res.send(document.FileData);
  } catch (err) {
    console.error("❌ Document download error:", err);
    res.status(500).json({ message: "Failed to download document", error: err.message });
  }
});

// 🔹 Preview Dokumen Validasi
app.get("/api/scholarship/documents/preview/:documentId", authenticate, async (req, res) => {
  try {
    const { documentId } = req.params;
    const userId = req.session.user.id;
    const dbPool = getDBPool();

    const [result] = await dbPool.query(
      "SELECT FileName, FileType, FileData, UploadedBy FROM ScholarshipDocuments WHERE DocumentID = ?",
      [documentId]
    );

    if (result.length === 0) {
      return res.status(404).json({ message: "Document not found" });
    }

    const document = result[0];

    if (req.session.user.role !== "admin" && userId !== document.UploadedBy) {
      return res.status(403).json({ message: "Not authorized to view this document" });
    }

    const supportedPreviewTypes = ["application/pdf", "image/jpeg", "image/png", "image/gif"];

    if (supportedPreviewTypes.includes(document.FileType)) {
      res.setHeader("Content-Type", document.FileType);
      res.setHeader("Content-Disposition", `inline; filename="${encodeURIComponent(document.FileName)}"`);
      res.send(document.FileData);
    } else {
      res.setHeader("Content-Type", document.FileType);
      res.setHeader("Content-Disposition", `attachment; filename="${encodeURIComponent(document.FileName)}"`);
      res.send(document.FileData);
    }
  } catch (err) {
    console.error("❌ Document preview error:", err);
    res.status(500).json({ message: "Failed to preview document", error: err.message });
  }
});

// 🔹 Delete Dokumen
app.delete("/api/scholarship/documents/:documentId/:childName", authenticate, async (req, res) => {
  const connection = await getDBPool().getConnection();

  try {
    const { documentId, childName } = req.params;
    const userId = req.session.user.id;

    if (!documentId || isNaN(documentId)) {
      return res.status(400).json({ message: "Invalid document ID" });
    }

    await connection.beginTransaction();

    const [checkResult] = await connection.query(
      `SELECT UploadedBy, NIK, DocumentType, ChildName 
       FROM ScholarshipDocuments 
       WHERE DocumentID = ? AND ChildName = ?`,
      [documentId, childName]
    );

    if (checkResult.length === 0) {
      await connection.rollback();
      return res.status(404).json({ message: "Document not found" });
    }

    const docInfo = checkResult[0];

    if (req.session.user.role !== "admin" && userId !== docInfo.UploadedBy) {
      await connection.rollback();
      return res.status(403).json({ message: "Not authorized to delete this document" });
    }

    await connection.query("DELETE FROM ScholarshipDocuments WHERE DocumentID = ?", [documentId]);

    await connection.commit();

    res.json({
      success: true,
      message: "Document deleted successfully",
      documentId: documentId,
    });
  } catch (err) {
    await connection.rollback();
    console.error("❌ Document delete error:", err);
    res.status(500).json({
      success: false,
      message: "Failed to delete document",
      error: err.message,
    });
  } finally {
    connection.release();
  }
});

// ====================== EXCEL UPLOAD ======================

app.post("/upload", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).send("Tidak ada file yang diupload.");
    }

    const workbook = xlsx.read(req.file.buffer, { type: "buffer" });
    const sheetName = workbook.SheetNames[0];
    const worksheet = workbook.Sheets[sheetName];
    const jsonData = xlsx.utils.sheet_to_json(worksheet);

    if (jsonData.length === 0) {
      return res.status(400).send("File Excel kosong.");
    }

    const dbPool = getDBPool();
    const tableName = "DataExcel";
    const columns = Object.keys(jsonData[0]);

    // Create table if not exists
    let createTableQuery = `CREATE TABLE IF NOT EXISTS ${tableName} (id INT AUTO_INCREMENT PRIMARY KEY, `;
    columns.forEach((col, index) => {
      createTableQuery += `\`${col}\` VARCHAR(255)`;
      if (index < columns.length - 1) createTableQuery += ", ";
    });
    createTableQuery += ")";

    await dbPool.query(createTableQuery);

    // Insert data
    for (const row of jsonData) {
      const keys = Object.keys(row);
      const placeholders = keys.map(() => "?").join(", ");
      const values = keys.map((key) => row[key]);
      const insertQuery = `INSERT INTO ${tableName} (${keys.map(k => `\`${k}\``).join(", ")}) VALUES (${placeholders})`;
      await dbPool.query(insertQuery, values);
    }

    res.status(200).send({
      message: "Data berhasil diupload ke MySQL",
      totalData: jsonData.length,
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).send("Terjadi kesalahan saat memproses file.");
  }
});

// ====================== SAVE ALL SCORES ======================

app.post("/api/save-all-scores", authenticate, async (req, res) => {
  const { scores } = req.body;

  if (!Array.isArray(scores)) {
    return res.status(400).json({
      error: "Invalid data format",
      details: "Expected array of scores",
    });
  }

  if (scores.length === 0) {
    return res.status(400).json({
      error: "Empty data",
      details: "No scores provided",
    });
  }

  const connection = await getDBPool().getConnection();

  try {
    await connection.beginTransaction();
    let successCount = 0;
    const errors = [];

    for (const item of scores) {
      try {
        let scoreValue = item.grandTotalScore;
        if (typeof scoreValue === "string") {
          scoreValue = parseFloat(scoreValue.replace(",", "."));
        }
        const roundedScore = Math.round(scoreValue * 100) / 100;

        const [result] = await connection.query(
          `UPDATE ScholarshipApplicants
           SET Grand_Total_Score = ?
           WHERE NIK = ? AND Child_Name = ?`,
          [roundedScore, item.NIK, item.Child_Name]
        );

        if (result.affectedRows > 0) {
          successCount++;
        } else {
          errors.push({
            NIK: item.NIK,
            Child_Name: item.Child_Name,
            error: "Data not found",
          });
        }
      } catch (err) {
        errors.push({
          NIK: item.NIK,
          Child_Name: item.Child_Name,
          error: err.message,
        });
      }
    }

    await connection.commit();

    return res.json({
      success: true,
      message: `Successfully updated ${successCount} records`,
      details: {
        totalRecords: scores.length,
        successCount,
        failedCount: errors.length,
        errors: errors.length > 0 ? errors : undefined,
      },
    });
  } catch (err) {
    await connection.rollback();
    console.error("❌ Bulk save error:", err);
    return res.status(500).json({
      error: "Database operation failed",
      details: err.message,
    });
  } finally {
    connection.release();
  }
});

// ====================== SERVER SHUTDOWN ======================

process.on("SIGINT", async () => {
  console.log("🛑 Closing database connection...");
  if (pool) await pool.end();
  console.log("✅ Database connection closed.");
  process.exit(0);
});

// ====================== START SERVER ======================

const PORT = process.env.PORT || 5001;
const HOST = process.env.NODE_ENV === "production" ? "0.0.0.0" : "localhost";

initializeDB().then(() => {
  app.listen(PORT, HOST, () => {
    console.log(`🚀 Server running on ${HOST}:${PORT}`);
  });
});
