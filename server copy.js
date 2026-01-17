const express = require("express");
const sql = require("mssql");
const cors = require("cors");
const path = require("path");
const ipserver = "10.35.2.200";
const app = express();
const multer = require("multer");
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 50 * 1024 * 1024, // 50MB limit
  },
});
const session = require("express-session");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
// Middleware
app.use(
  cors({
    origin: true,
    credentials: true,
  })
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files
app.use(express.static(path.join(__dirname, "src")));
// Session configuration
app.use(
  session({
    secret: "your-strong-secret-key-here-123!@#",
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: false, // Set true if using HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  })
);

// Konfigurasi database
const dbConfig = {
  server: process.env.DB_SERVER || "10.38.96.18",
  database: process.env.DB_NAME || "data",
  user: process.env.DB_USER || "sa",
  password: process.env.DB_PASSWORD || "#T3lpps3cr3t*",
  port: parseInt(process.env.DB_PORT, 10) || 1433,
  options: {
    encrypt: false,
    trustServerCertificate: true,
  },
};

// Inisialisasi pool koneksi
let pool;

async function initializeDB() {
  try {
    console.log("Connecting to database...");
    pool = await sql.connect(dbConfig);
    console.log("✅ Database connected successfully");

    // Buat tabel Users jika belum ada
    // await createUsersTable();
  } catch (err) {
    console.error("❌ Database connection failed:", err);
    process.exit(1);
  }
}

// async function createUsersTable() {
//   try {
//     const query = `
//       IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='Users' AND xtype='U')
//       CREATE TABLE Users (
//         id INT IDENTITY(1,1) PRIMARY KEY,
//         username VARCHAR(50) NOT NULL UNIQUE,
//         password_hash VARCHAR(255) NOT NULL,
//         full_name NVARCHAR(100),
//         role VARCHAR(20) NOT NULL DEFAULT 'user',
//         is_active BIT NOT NULL DEFAULT 1,
//         created_at DATETIME DEFAULT GETDATE()
//       )
//     `;
//     await pool.request().query(query);
//     console.log("✅ Users table ready");

//     // Buat admin default jika belum ada
//     await createDefaultAdmin();
//   } catch (err) {
//     console.error("❌ Error creating Users table:", err);
//   }
// }

// async function createDefaultAdmin() {
//   try {
//     const adminUsername = "sendinauli";

//     const adminPassword = "sendi1238";
//     const salt = await bcrypt.genSalt(10);
//     const hashedPassword = await bcrypt.hash(adminPassword, salt);

//     await pool
//       .request()
//       .input("username", sql.VarChar, adminUsername)
//       .input("password_hash", sql.VarChar, hashedPassword)
//       .input("full_name", sql.NVarChar, "Administrator")
//       .input("role", sql.VarChar, "admin").query(`
//           INSERT INTO Users (username, password_hash, full_name, role)
//           VALUES (@username, @password_hash, @full_name, @role)
//         `);

//     console.log("✅ Default admin user created");
//     console.log("⚠️ IMPORTANT: Change the default admin password immediately!");
//     console.log(
//       `Temporary credentials - Username: ${adminUsername}, Password: ${adminPassword}`
//     );
//   } catch (err) {
//     console.error("❌ Error creating default admin:", err);
//   }
// }

// 🔹 Get All Users (with pagination)
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = "" } = req.query;
    const offset = (page - 1) * limit;

    const dbPool = getDBPool();
    let query = `
      SELECT id, username, full_name, role, is_active, created_at 
      FROM Users 
      WHERE username LIKE '%' + @search + '%' OR full_name LIKE '%' + @search + '%'
      ORDER BY id
      OFFSET @offset ROWS
      FETCH NEXT @limit ROWS ONLY
    `;

    const countQuery = `
      SELECT COUNT(*) as total FROM Users
      WHERE username LIKE '%' + @search + '%' OR full_name LIKE '%' + @search + '%'
    `;

    const request = dbPool
      .request()
      .input("search", sql.VarChar, search)
      .input("offset", sql.Int, offset)
      .input("limit", sql.Int, parseInt(limit));

    const result = await request.query(query);
    const countResult = await dbPool
      .request()
      .input("search", sql.VarChar, search)
      .query(countQuery);

    res.json({
      data: result.recordset,
      total: countResult.recordset[0].total,
      page: parseInt(page),
      limit: parseInt(limit),
    });
  } catch (err) {
    console.error("Error fetching users:", err);
    res.status(500).json({ message: "Failed to fetch users" });
  }
});

// 🔹 Create New User
app.post("/api/users", authenticate, async (req, res) => {
  if (req.session.user.role !== "admin") {
    return res.status(403).json({ message: "Only admin can create users" });
  }

  const { username, password, full_name, role } = req.body;

  try {
    // Validasi input
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

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const dbPool = getDBPool();
    await dbPool
      .request()
      .input("username", sql.VarChar, username)
      .input("password_hash", sql.VarChar, hashedPassword)
      .input("full_name", sql.NVarChar, full_name)
      .input("role", sql.VarChar, role || "user").query(`
        INSERT INTO Users (username, password_hash, full_name, role)
        VALUES (@username, @password_hash, @full_name, @role)
      `);

    res.status(201).json({ message: "User created successfully" });
  } catch (err) {
    if (err.number === 2627) {
      // SQL Server duplicate key error
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
    await dbPool
      .request()
      .input("id", sql.Int, id)
      .input("username", sql.VarChar, username)
      .input("full_name", sql.NVarChar, full_name)
      .input("role", sql.VarChar, role)
      .input("is_active", sql.Bit, is_active).query(`
        UPDATE Users 
        SET username = @username, 
            full_name = @full_name, 
            role = @role, 
            is_active = @is_active 
        WHERE id = @id
      `);

    res.json({ message: "User updated successfully" });
  } catch (err) {
    if (err.number === 2627) {
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
    await dbPool
      .request()
      .input("id", sql.Int, id)
      .query("DELETE FROM Users WHERE id = @id");

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

  // Hanya admin atau user yang bersangkutan yang bisa ganti password
  if (req.session.user.role !== "admin" && userId !== parseInt(id)) {
    return res.status(403).json({ message: "Not authorized" });
  }

  try {
    const dbPool = getDBPool();

    // Verifikasi password lama untuk non-admin
    if (req.session.user.role !== "admin") {
      const userResult = await dbPool
        .request()
        .input("id", sql.Int, id)
        .query("SELECT password_hash FROM Users WHERE id = @id");

      if (userResult.recordset.length === 0) {
        return res.status(404).json({ message: "User not found" });
      }

      const isMatch = await bcrypt.compare(
        currentPassword,
        userResult.recordset[0].password_hash
      );
      if (!isMatch) {
        return res
          .status(400)
          .json({ message: "Current password is incorrect" });
      }
    }

    if (newPassword.length < 6) {
      return res
        .status(400)
        .json({ message: "New password must be at least 6 characters" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await dbPool
      .request()
      .input("id", sql.Int, id)
      .input("password_hash", sql.VarChar, hashedPassword)
      .query("UPDATE Users SET password_hash = @password_hash WHERE id = @id");

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
    const result = await dbPool.request().input("id", sql.Int, id).query(`
        SELECT id, username, full_name, role, is_active, created_at 
        FROM Users 
        WHERE id = @id
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    res.json(result.recordset[0]);
  } catch (err) {
    console.error("Error fetching user:", err);
    res.status(500).json({ message: "Failed to fetch user" });
  }
});

// ====================== ROUTES ======================

// Serve static files
app.use(express.static(path.join(__dirname, "src")));

// Authentication middleware
function authenticate(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.status(401).json({ message: "Unauthorized" });
}

// Login route
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Username and password are required" });
  }

  try {
    const dbPool = getDBPool();
    const result = await dbPool
      .request()
      .input("username", sql.VarChar, username)
      .query(
        "SELECT * FROM Users WHERE username = @username AND is_active = 1"
      );
    console.log("Login..");
    console.log("Username :", username);

    console.log("Password :", password);
    if (result.recordset.length === 0) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(password, user.password_hash);

    if (!isMatch) {
      return res.status(401).json({ message: "Username atau Password Salah" });
    }

    // Create user session without sensitive data
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

// Logout route
app.post("/api/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("Logout error:", err);
      return res.status(500).json({ message: "Logout failed" });
    }
    res.clearCookie("connect.sid");
    res.json({ success: true, message: "Logout successful" });
    console.log("Logout..");
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

// Middleware untuk mendapatkan pool yang sudah terhubung
function getDBPool() {
  if (!pool) {
    throw new Error("Database not initialized. Call initializeDB() first.");
  }
  return pool;
}

// ====================== EXISTING ROUTES (TANPA PERUBAHAN) ======================

// Rute yang sudah ada tetap sama seperti sebelumnya
// With this:
app.use(express.static(path.join(__dirname, "public"))); // For your JS/CSS files
app.use(express.static(path.join(__dirname, "src"))); // For your HTML files
app.use(express.static("public")); // Folder 'public' berisi file statis seperti JS, CSS, dll.
app.get("/", (req, res) => {
  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/login.html"));
});

app.get("/input", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/input.html"));
});

app.get("/beasiswa", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/newbeasiswa.html"));
});

app.get("/parameternilai", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/parameternilai.html"));
});

app.get("/nilaisma", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/nilaisma.html"));
});

app.get("/users", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/users.html"));
});

app.get("/home", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/home.html"));
});

app.get("/files", (req, res) => {
  res.sendFile(path.join(__dirname, "/src/files.html"));
});

// 🔹 Endpoint: Cari Data Karyawan berdasarkan NIK atau Nama
app.get("/api/karyawan", async (req, res) => {
  const { nik } = req.query;

  try {
    const dbPool = getDBPool();
    let query = "SELECT * FROM EmployeeTEL WHERE 1=1";
    const request = dbPool.request();

    if (nik) {
      query += " AND NIK = @nik";
      request.input("nik", sql.VarChar, nik);
    }

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Query error:", err);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Endpoint: Ambil Data Anak Berdasarkan NIK Karyawan dari `ChildTEL`
app.get("/api/anak", async (req, res) => {
  const { nik } = req.query;

  if (!nik) {
    return res.status(400).json({ message: "NIK karyawan diperlukan" });
  }

  try {
    const dbPool = getDBPool();
    const result = await dbPool
      .request()
      .input("nik", sql.VarChar, nik)
      .query("SELECT * FROM ChildTEL WHERE NIK = @nik");

    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Query error:", err);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Endpoint: Cari Data Karyawan dan anak berdasarkan NIK untuk input nilai sma
app.get("/api/karyawannilai", async (req, res) => {
  const { nik } = req.query;

  try {
    const dbPool = getDBPool();
    let query = "SELECT * FROM ScholarshipApplicants WHERE 1=1";
    const request = dbPool.request();

    if (nik) {
      query += " AND NIK = @nik and Education_Level like 'SLTA'";
      request.input("nik", sql.VarChar, nik);
    }

    const result = await request.query(query);
    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Query error:", err);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// 🔹 Endpoint: Ambil Data Anak Berdasarkan NIK Karyawan dari `ChildTEL untuk input nilai sma`
app.get("/api/anaknilai", async (req, res) => {
  const { nik } = req.query;

  if (!nik) {
    return res.status(400).json({ message: "NIK karyawan diperlukan" });
  }

  try {
    const dbPool = getDBPool();
    const result = await dbPool
      .request()
      .input("nik", sql.VarChar, nik)
      .query(
        "SELECT * FROM ScholarshipApplicants WHERE NIK = @nik and Education_Level like 'SLTA'"
      );

    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Query error:", err);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: err.message });
  }
});

// data post dari html
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
        Nilai_Akademik, Grade, Achievement_1, Achievement_2, Achievement_3, Remark,
        Grand_Total_Score, Tidak_Menerima_Beasiswa_Lain, Tidak_Menerima_Beasiswa_TEL,
        Tanggungan_Pekerja, Surat_Keterangan, Received_Application, Periode_Tahun
      ) VALUES (
        @NIK, @Employee_Name, @Phone_Number, @Join_Date, @Org_Group_Code, @Organization_Name, @Employee_PA,
        @Child_Name, @Child_Phone_Number, @Gender, @Birth_Place, @Birth_Date, @Age, @Education_Level,
        @Education_Name, @Jurusan, @Semester, @Accreditation, @Nilai_Rata_Rata_1, @Nilai_Rata_Rata_2,
        @Nilai_Akademik, @Grade, @Achievement_1, @Achievement_2, @Achievement_3, @Remark,
        @Grand_Total_Score, @Tidak_Menerima_Beasiswa_Lain, @Tidak_Menerima_Beasiswa_TEL,
        @Tanggungan_Pekerja, @Surat_Keterangan, @Received_Application, @Periode_Tahun
      )
    `;

    for (const row of req.body) {
      const request = dbPool.request();
      request.input("NIK", sql.VarChar, row.NIK);
      request.input("Employee_Name", sql.NVarChar, row.Employee_Name);
      request.input("Phone_Number", sql.VarChar, row.Phone_Number);
      request.input("Join_Date", sql.Date, row.Join_Date);
      request.input("Org_Group_Code", sql.VarChar, row.Org_Group_Code);
      request.input("Organization_Name", sql.NVarChar, row.Organization_Name);
      request.input("Employee_PA", sql.VarChar, row.Employee_PA);
      request.input("Child_Name", sql.NVarChar, row.Child_Name);
      request.input("Child_Phone_Number", sql.VarChar, row.Child_Phone_Number);
      request.input("Gender", sql.VarChar, row.Gender);
      request.input("Birth_Place", sql.NVarChar, row.Birth_Place);
      request.input("Birth_Date", sql.Date, row.Birth_Date);
      request.input("Age", sql.Int, row.Age);
      request.input("Education_Level", sql.VarChar, row.Education_Level);
      request.input("Education_Name", sql.NVarChar, row.Education_Name);
      request.input("Jurusan", sql.NVarChar, row.Jurusan);
      request.input("Semester", sql.Int, row.Semester);
      request.input("Accreditation", sql.VarChar, row.Accreditation);
      request.input(
        "Nilai_Rata_Rata_1",
        sql.Decimal(5, 2),
        row.Nilai_Rata_Rata_1
      );
      request.input(
        "Nilai_Rata_Rata_2",
        sql.Decimal(5, 2),
        row.Nilai_Rata_Rata_2
      );
      request.input("Nilai_Akademik", sql.Decimal(5, 2), row.Nilai_Akademik);
      request.input("Grade", sql.VarChar, row.Grade);
      request.input("Achievement_1", sql.VarChar, row.Achievement_1);
      request.input("Achievement_2", sql.VarChar, row.Achievement_2);
      request.input("Achievement_3", sql.VarChar, row.Achievement_3);
      request.input("Remark", sql.NVarChar, row.Remark);
      request.input(
        "Grand_Total_Score",
        sql.Decimal(5, 2),
        row.Grand_Total_Score
      );
      request.input(
        "Tidak_Menerima_Beasiswa_Lain",
        sql.VarChar,
        row.Tidak_Menerima_Beasiswa_Lain
      );
      request.input(
        "Tidak_Menerima_Beasiswa_TEL",
        sql.VarChar,
        row.Tidak_Menerima_Beasiswa_TEL
      );
      request.input("Tanggungan_Pekerja", sql.VarChar, row.Tanggungan_Pekerja);
      request.input("Surat_Keterangan", sql.VarChar, row.Surat_Keterangan);
      request.input("Received_Application", sql.Date, row.Received_Application);
      request.input("Periode_Tahun", sql.VarChar, row.Periode_Tahun);

      await request.query(query);
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

// 🔹 Endpoint: Ambil Data Universitas
app.get("/api/education-names", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const query = "SELECT * FROM UniversitasList";
    const result = await dbPool.request().query(query);

    res.json(result.recordset);
    console.log(result.recordset);
  } catch (err) {
    console.error("❌ Error fetching data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat mengambil data",
      error: err.message,
    });
  }
});

//endpoint parameter nilai
app.get("/api/parameternilai", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const query =
      "SELECT kategori, key_nilai, value_nilai FROM ParameterPenilaian";
    const result = await dbPool.request().query(query);

    // Ubah data menjadi format yang sesuai
    const parameterMaps = result.recordset.reduce((acc, row) => {
      if (!acc[row.kategori]) {
        acc[row.kategori] = {};
      }
      acc[row.kategori][row.key_nilai] = row.value_nilai;
      return acc;
    }, {});

    res.json(parameterMaps); // Kirim data ke frontend
  } catch (error) {
    console.error("❌ Error fetching parameter nilai:", error);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: error.message });
  }
});

//buat fitur untuk edit data dari tabel parameter penilaian di frontend html

//kode Delete
app.delete("/api/scholarship/:NIK", async (req, res) => {
  const { NIK } = req.params; // Ambil NIK dari parameter URL

  try {
    const pool = getDBPool(); // Ambil pool koneksi database

    // Query untuk menghapus data
    const query = `
      DELETE FROM ScholarshipApplicants
      WHERE NIK = @NIK
    `;

    // Eksekusi query
    const request = pool.request();
    request.input("NIK", sql.VarChar, NIK); // Pastikan tipe data sesuai dengan kolom di database

    const result = await request.query(query);

    // Cek apakah data berhasil dihapus
    if (result.rowsAffected[0] === 1) {
      res.status(200).json({ message: "Data berhasil dihapus" });
    } else {
      res.status(404).json({ message: "Data tidak ditemukan" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Gagal menghapus data" });
  }
});

//kode baru edit
// Endpoint untuk edit berdasarkan NIK
app.put("/api/scholarship/:NIK", async (req, res) => {
  const { NIK } = req.params; // Ambil NIK dari parameter URL
  const updatedData = req.body; // Data yang dikirim dari frontend

  try {
    const pool = getDBPool(); // Ambil pool koneksi database

    // Query untuk update data
    const query = `
      UPDATE ScholarshipApplicants
      SET 
        Employee_Name = @Employee_Name,
        Phone_Number = @Phone_Number,
        Join_Date = @Join_Date,
        Org_Group_Code = @Org_Group_Code,
        Organization_Name = @Organization_Name,
        Employee_PA = @Employee_PA,
        Child_Name = @Child_Name,
        Child_Phone_Number = @Child_Phone_Number,
        Gender = @Gender,
        Birth_Place = @Birth_Place,
        Birth_Date = @Birth_Date,
        Age = @Age,
        Education_Level = @Education_Level,
        Education_Name = @Education_Name,
        Jurusan = @Jurusan,
        Semester = @Semester,
        Accreditation = @Accreditation,
        Nilai_Rata_Rata_1 = @Nilai_Rata_Rata_1,
        Nilai_Rata_Rata_2 = @Nilai_Rata_Rata_2,
        Nilai_Akademik = @Nilai_Akademik,
        Grade = @Grade,
        Achievement_1 = @Achievement_1,
        Achievement_2 = @Achievement_2,
        Achievement_3 = @Achievement_3,
        Remark = @Remark,
        Tidak_Menerima_Beasiswa_Lain = @Tidak_Menerima_Beasiswa_Lain,
        Tidak_Menerima_Beasiswa_TEL = @Tidak_Menerima_Beasiswa_TEL,
        Tanggungan_Pekerja = @Tanggungan_Pekerja,
        Surat_Keterangan = @Surat_Keterangan,
        Received_Application = @Received_Application,
        Periode_Tahun = @Periode_Tahun
      WHERE NIK = @NIK
    `;

    // Eksekusi query
    const request = pool.request();
    request.input("NIK", sql.VarChar, NIK); // Pastikan tipe data sesuai dengan kolom di database
    request.input("Employee_Name", sql.VarChar, updatedData.Employee_Name);
    request.input("Phone_Number", sql.VarChar, updatedData.Phone_Number);
    request.input("Join_Date", sql.Date, updatedData.Join_Date);
    request.input("Org_Group_Code", sql.VarChar, updatedData.Org_Group_Code);
    request.input(
      "Organization_Name",
      sql.VarChar,
      updatedData.Organization_Name
    );
    request.input("Employee_PA", sql.VarChar, updatedData.Employee_PA);
    request.input("Child_Name", sql.VarChar, updatedData.Child_Name);
    request.input(
      "Child_Phone_Number",
      sql.VarChar,
      updatedData.Child_Phone_Number
    );
    request.input("Gender", sql.VarChar, updatedData.Gender);
    request.input("Birth_Place", sql.VarChar, updatedData.Birth_Place);
    request.input("Birth_Date", sql.Date, updatedData.Birth_Date);
    request.input("Age", sql.Int, updatedData.Age);
    request.input("Education_Level", sql.VarChar, updatedData.Education_Level);
    request.input("Education_Name", sql.VarChar, updatedData.Education_Name);
    request.input("Jurusan", sql.VarChar, updatedData.Jurusan);
    request.input("Semester", sql.Int, updatedData.Semester);
    request.input("Accreditation", sql.VarChar, updatedData.Accreditation);
    request.input(
      "Nilai_Rata_Rata_1",
      sql.Float,
      updatedData.Nilai_Rata_Rata_1
    );
    request.input(
      "Nilai_Rata_Rata_2",
      sql.Float,
      updatedData.Nilai_Rata_Rata_2
    );
    request.input("Nilai_Akademik", sql.Float, updatedData.Nilai_Akademik);
    request.input("Grade", sql.VarChar, updatedData.Grade);
    request.input("Achievement_1", sql.VarChar, updatedData.Achievement_1);
    request.input("Achievement_2", sql.VarChar, updatedData.Achievement_2);
    request.input("Achievement_3", sql.VarChar, updatedData.Achievement_3);
    request.input("Remark", sql.VarChar, updatedData.Remark);
    request.input(
      "Tidak_Menerima_Beasiswa_Lain",
      sql.VarChar,
      updatedData.Tidak_Menerima_Beasiswa_Lain
    );
    request.input(
      "Tidak_Menerima_Beasiswa_TEL",
      sql.VarChar,
      updatedData.Tidak_Menerima_Beasiswa_TEL
    );
    request.input(
      "Tanggungan_Pekerja",
      sql.VarChar,
      updatedData.Tanggungan_Pekerja
    );
    request.input(
      "Surat_Keterangan",
      sql.VarChar,
      updatedData.Surat_Keterangan
    );
    request.input(
      "Received_Application",
      sql.Date,
      updatedData.Received_Application
    );
    request.input("Periode_Tahun", sql.VarChar, updatedData.Periode_Tahun);

    const result = await request.query(query);

    // Cek apakah data berhasil diupdate
    if (result.rowsAffected[0] === 1) {
      res.status(200).json({ message: "Data berhasil diperbarui" });
    } else {
      res.status(404).json({ message: "Data tidak ditemukan" });
    }
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Gagal memperbarui data" });
  }
});

app.get("/api/scholarship", async (req, res) => {
  try {
    const dbPool = getDBPool();
    const query = "SELECT * FROM ScholarshipApplicants"; // Query untuk mengambil semua data
    const result = await dbPool.request().query(query);

    res.json(result.recordset); // Kirim data ke frontend
  } catch (err) {
    console.error("❌ Error fetching data:", err);
    res.status(500).json({
      message: "Terjadi kesalahan saat mengambil data",
      error: err.message,
    });
  }
});

// Endpoint untuk update parameter nilai
app.put("/api/parameternilai/:kategori/:key_nilai", async (req, res) => {
  const { kategori, key_nilai } = req.params;
  const { value_nilai } = req.body;

  try {
    const dbPool = getDBPool();
    const query = `
      UPDATE ParameterPenilaian
      SET value_nilai = @value_nilai
      WHERE kategori = @kategori AND key_nilai = @key_nilai
    `;
    await dbPool
      .request()
      .input("value_nilai", value_nilai)
      .input("kategori", kategori)
      .input("key_nilai", key_nilai)
      .query(query);

    res.json({ message: "Data berhasil diupdate" });
  } catch (error) {
    console.error("❌ Error updating parameter nilai:", error);
    res
      .status(500)
      .json({ message: "Terjadi kesalahan pada server", error: error.message });
  }
});

//update kirim nilai akademik sma

// Endpoint khusus untuk nilai akademik
app.post("/api/update-academic-scores", async (req, res) => {
  // Validasi request
  if (!req.body || !req.body.updates) {
    return res.status(400).json({
      success: false,
      message: "Data updates diperlukan",
    });
  }

  try {
    const dbPool = getDBPool();
    const transaction = new sql.Transaction(dbPool);

    await transaction.begin();

    try {
      for (const data of req.body.updates) {
        // Validasi data
        if (!data.NIK || !data.Child_Name || !data.Nilai_Akademik) {
          throw new Error(
            "Data NIK, Child_Name, dan Nilai_Akademik diperlukan"
          );
        }

        // Update database
        const request = new sql.Request(transaction);
        const result = await request
          .input("Nilai_Akademik", sql.Decimal(5, 2), data.Nilai_Akademik)
          .input("Nilai_Rata_Rata_1", sql.Float, data.Nilai_Rata_Rata_1)
          .input("Nilai_Rata_Rata_2", sql.Float, data.Nilai_Rata_Rata_2)
          .input("NIK", sql.VarChar, data.NIK)
          .input("Child_Name", sql.NVarChar, data.Child_Name).query(`
            UPDATE ScholarshipApplicants 
            SET 
            Nilai_Akademik = @Nilai_Akademik,
            Nilai_Rata_Rata_1 = @Nilai_Rata_Rata_1,
            Nilai_Rata_Rata_2 = @Nilai_Rata_Rata_2
            WHERE NIK = @NIK AND Child_Name = @Child_Name
          `);

        if (result.rowsAffected[0] === 0) {
          console.warn(
            `Data tidak ditemukan untuk NIK: ${data.NIK}, Anak: ${data.Child_Name}`
          );
        }
      }

      await transaction.commit();
      res.json({
        success: true,
        message: "Update nilai akademik berhasil",
        records_updated: req.body.updates.length,
      });
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  } catch (error) {
    console.error("Database error:", error);
    res.status(500).json({
      success: false,
      message: "Gagal update nilai akademik",
      error: error.message,
    });
  }
});

// 🔹 Upload File
app.post(
  "/api/files",
  authenticate,

  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "No file uploaded" });
      }

      const { originalname, mimetype, size, buffer } = req.file;
      const { description } = req.body;
      const uploadedBy = req.session.user.id;

      const dbPool = getDBPool();
      await dbPool
        .request()
        .input("file_name", sql.NVarChar, originalname)
        .input("file_type", sql.NVarChar, mimetype)
        .input("file_size", sql.Int, size)
        .input("file_data", sql.VarBinary, buffer)
        .input("uploaded_by", sql.Int, uploadedBy)
        .input("description", sql.NVarChar, description || null).query(`
        INSERT INTO FileStorage 
        (file_name, file_type, file_size, file_data, uploaded_by, description)
        VALUES 
        (@file_name, @file_type, @file_size, @file_data, @uploaded_by, @description)
      `);

      res.status(201).json({ message: "File uploaded successfully" });
    } catch (err) {
      console.error("❌ File upload error:", err);
      res
        .status(500)
        .json({ message: "Failed to upload file", error: err.message });
    }
  }
);

// 🔹 Get All Files Metadata
app.get("/api/files", authenticate, async (req, res) => {
  try {
    const dbPool = getDBPool();
    const result = await dbPool.request().query(`
      SELECT 
        file_id, 
        file_name, 
        file_type, 
        file_size, 
        upload_date, 
        uploaded_by,
        u.username as uploaded_by_username,
        description
      FROM FileStorage fs
      LEFT JOIN Users u ON fs.uploaded_by = u.id
      ORDER BY upload_date DESC
    `);

    res.json(result.recordset);
  } catch (err) {
    console.error("❌ Error fetching files:", err);
    res
      .status(500)
      .json({ message: "Failed to fetch files", error: err.message });
  }
});

// 🔹 Download File
app.get("/api/files/:file_id", authenticate, async (req, res) => {
  try {
    const { file_id } = req.params;

    const dbPool = getDBPool();
    const result = await dbPool
      .request()
      .input("file_id", sql.UniqueIdentifier, file_id).query(`
        SELECT file_name, file_type, file_data 
        FROM FileStorage 
        WHERE file_id = @file_id
      `);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }

    const file = result.recordset[0];

    res.setHeader("Content-Type", file.file_type);
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${file.file_name}"`
    );
    res.send(file.file_data);
  } catch (err) {
    console.error("❌ File download error:", err);
    res
      .status(500)
      .json({ message: "Failed to download file", error: err.message });
  }
});

// 🔹 Delete File
app.delete("/api/files/:file_id", authenticate, async (req, res) => {
  try {
    const { file_id } = req.params;
    const userId = req.session.user.id;

    const dbPool = getDBPool();

    // Check if user is admin or the uploader
    const checkResult = await dbPool
      .request()
      .input("file_id", sql.UniqueIdentifier, file_id).query(`
        SELECT uploaded_by FROM FileStorage WHERE file_id = @file_id
      `);

    if (checkResult.recordset.length === 0) {
      return res.status(404).json({ message: "File not found" });
    }

    const uploadedBy = checkResult.recordset[0].uploaded_by;

    if (req.session.user.role !== "admin" && userId !== uploadedBy) {
      return res
        .status(403)
        .json({ message: "Not authorized to delete this file" });
    }

    await dbPool
      .request()
      .input("file_id", sql.UniqueIdentifier, file_id)
      .query("DELETE FROM FileStorage WHERE file_id = @file_id");

    res.json({ message: "File deleted successfully" });
  } catch (err) {
    console.error("❌ File delete error:", err);
    res
      .status(500)
      .json({ message: "Failed to delete file", error: err.message });
  }
});

// Proper shutdown: Menutup koneksi database saat server berhenti
process.on("SIGINT", async () => {
  console.log("🛑 Closing database connection...");
  if (pool) await pool.close();
  console.log("✅ Database connection closed.");
  process.exit(0);
});

// Jalankan server setelah koneksi berhasil
const PORT = process.env.PORT || 5001;
initializeDB().then(() => {
  app.listen(PORT, ipserver, () => {
    console.log(`🚀 Server berjalan di ${ipserver}:${PORT}`);
  });
});
