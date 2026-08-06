const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const pool = require("../config/db");

const router = express.Router();

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

router.post("/register", async (req, res) => {
  try {
    const fullname = String(req.body.fullname || "").trim();
    const email = normalizeEmail(req.body.email);
    const phone = String(req.body.phone || "").trim();
    const password = String(req.body.password || "");

    if (!fullname || !email || !phone || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Ranpli tout chan yo. Modpas la dwe gen omwen 8 karaktè."
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE email = $1",
      [email]
    );

    if (existing.rowCount > 0) {
      return res.status(409).json({
        success: false,
        message: "Email sa deja egziste."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const adminEmail = String(
      process.env.ADMIN_EMAIL || "fastpayhaiti@gmail.com"
    ).toLowerCase();

    const role = email === adminEmail ? "admin" : "customer";

    const result = await pool.query(
      `INSERT INTO users
       (fullname, email, phone, password_hash, role, balance, status)
       VALUES ($1, $2, $3, $4, $5, 0, 'Active')
       RETURNING id, fullname, email, phone, role, balance, status, created_at`,
      [fullname, email, phone, passwordHash, role]
    );

    return res.status(201).json({
      success: true,
      message: "Kont lan kreye avèk siksè.",
      user: result.rows[0]
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive kreye kont lan."
    });
  }
});

router.post("/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email ak modpas obligatwa."
      });
    }

    const result = await pool.query(
      `SELECT id, fullname, email, phone, password_hash,
              role, balance, status, created_at
       FROM users
       WHERE email = $1`,
      [email]
    );

    if (result.rowCount === 0) {
      return res.status(401).json({
        success: false,
        message: "Email oswa modpas pa kòrèk."
      });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!validPassword) {
      return res.status(401).json({
        success: false,
        message: "Email oswa modpas pa kòrèk."
      });
    }

    if (user.status !== "Active") {
      return res.status(403).json({
        success: false,
        message: "Kont sa pa aktif."
      });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    delete user.password_hash;

    return res.json({
      success: true,
      message: "Koneksyon reyisi.",
      token,
      user
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive konekte kont lan."
    });
  }
});

module.exports = router;
