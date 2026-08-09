const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
require("dotenv").config();

const app = express();
const PORT = Number(process.env.PORT || 10000);

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || "fastpayhaiti@gmail.com"
).trim().toLowerCase();

const allowedOrigins = [
  process.env.FRONTEND_ORIGIN,
  "https://dlmwallet.com",
  "https://www.dlmwallet.com",
  "http://localhost:5500",
  "http://127.0.0.1:5500"
].filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(
        new Error("Origin sa pa otorize pa CORS.")
      );
    },
    methods: ["GET", "POST", "PATCH", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "X-DLM-PIN-Token"]
  })
);

app.use(express.json({ limit: "6mb" }));

if (!process.env.MONGO_URI) {
  throw new Error(
    "MONGO_URI manke nan environment variables."
  );
}

if (!process.env.JWT_SECRET) {
  throw new Error(
    "JWT_SECRET manke nan environment variables."
  );
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected");
  })
  .catch((error) => {
    console.error(
      "MongoDB error:",
      error.message
    );
    process.exit(1);
  });

/* =========================
   SCHEMAS
========================= */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true
    },
    phone: {
      type: String,
      required: true,
      unique: true,
      trim: true
    },
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true
    },
    password: {
      type: String,
      required: true
    },
    balance: {
      type: Number,
      default: 0,
      min: 0
    },
    role: {
      type: String,
      enum: ["customer", "admin"],
      default: "customer"
    },
    status: {
      type: String,
      enum: ["Active", "Blocked"],
      default: "Active"
    },
    pinHash: {
      type: String,
      default: null
    },
    pinEnabled: {
      type: Boolean,
      default: false
    },
    pinUpdatedAt: {
      type: Date,
      default: null
    },
    pinFailedAttempts: {
      type: Number,
      default: 0,
      min: 0
    },
    pinLockedUntil: {
      type: Date,
      default: null
    },
    pinVersion: {
      type: Number,
      default: 0,
      min: 0
    },
    authVersion: {
      type: Number,
      default: 0,
      min: 0
    },
    passwordResetTokenHash: {
      type: String,
      default: null
    },
    passwordResetExpiresAt: {
      type: Date,
      default: null
    },
    passwordResetRequestedAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    type: {
      type: String,
      enum: [
        "deposit",
        "withdraw",
        "transfer",
        "admin_credit",
        "admin_debit",
        "topup",
        "giftcard"
      ],
      required: true
    },
    amount: {
      type: Number,
      required: true,
      min: 0.01
    },
    status: {
      type: String,
      enum: ["pending", "completed", "rejected"],
      default: "completed"
    },
    description: {
      type: String,
      default: ""
    },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    }
  },
  { timestamps: true }
);

const depositRequestSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    amount: {
      type: Number,
      required: true,
      min: 0.01
    },
    currency: {
      type: String,
      enum: ["USD"],
      default: "USD"
    },
    method: {
      type: String,
      enum: ["MonCash", "NatCash", "Bank"],
      required: true
    },
    reference: {
      type: String,
      required: true,
      trim: true
    },
    note: {
      type: String,
      default: "",
      trim: true
    },
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending"
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    reviewedAt: {
      type: Date,
      default: null
    },
    rejectionReason: {
      type: String,
      default: ""
    }
  },
  { timestamps: true }
);

depositRequestSchema.index(
  { method: 1, reference: 1 },
  { unique: true }
);

const reserveSchema = new mongoose.Schema(
  {
    key: {
      type: String,
      unique: true,
      default: "main"
    },
    currency: {
      type: String,
      default: "USD"
    },
    cashReserve: {
      type: Number,
      default: 0,
      min: 0
    },
    customerLiability: {
      type: Number,
      default: 0,
      min: 0
    }
  },
  { timestamps: true }
);


const serviceOrderSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true
    },
    service: {
      type: String,
      enum: ["Netflix", "Prime Video"],
      required: true
    },
    plan: {
      type: String,
      required: true,
      trim: true
    },
    amount: {
      type: Number,
      required: true,
      min: 0.01
    },
    paymentMethod: {
      type: String,
      enum: ["wallet"],
      default: "wallet",
      required: true
    },
    paymentReference: {
      type: String,
      default: "",
      trim: true
    },
    status: {
      type: String,
      enum: ["pending", "processing", "completed", "rejected"],
      default: "pending"
    },
    walletCharged: {
      type: Boolean,
      default: false
    },
    customerEmail: {
      type: String,
      required: true,
      lowercase: true,
      trim: true
    },
    deliveryMessage: {
      type: String,
      default: "",
      trim: true
    },
    adminNote: {
      type: String,
      default: "",
      trim: true
    },
    reviewedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },
    reviewedAt: {
      type: Date,
      default: null
    }
  },
  { timestamps: true }
);


const kycProfileSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, unique: true },
    documentType: { type: String, enum: ["national_id","passport","drivers_license"], required: true },
    documentNumber: { type: String, required: true, trim: true },
    documentFront: { type: String, required: true },
    documentBack: { type: String, default: "" },
    selfieImage: { type: String, required: true },
    status: { type: String, enum: ["pending","verified","rejected"], default: "pending" },
    rejectionReason: { type: String, default: "" },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    reviewedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

const virtualCardRequestSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    fee: { type: Number, default: 10, min: 10 },
    currency: { type: String, default: "USD" },
    status: { type: String, enum: ["pending","approved","rejected"], default: "pending" },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    reviewedAt: { type: Date, default: null }
  },
  { timestamps: true }
);

/* =========================
   MODELS
========================= */

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model(
  "Transaction",
  transactionSchema
);
const DepositRequest = mongoose.model(
  "DepositRequest",
  depositRequestSchema
);
const Reserve = mongoose.model(
  "Reserve",
  reserveSchema
);

const ServiceOrder = mongoose.model(
  "ServiceOrder",
  serviceOrderSchema
);

const KycProfile = mongoose.model("KycProfile", kycProfileSchema);
const VirtualCardRequest = mongoose.model("VirtualCardRequest", virtualCardRequestSchema);


/* =========================
   HELPERS
========================= */

function normalizeEmail(value) {
  return String(value || "")
    .trim()
    .toLowerCase();
}

function publicUser(user) {
  return {
    id: user._id,
    name: user.name,
    phone: user.phone,
    email: user.email,
    balance: Number(user.balance || 0),
    role: user.role,
    status: user.status,
    pinEnabled: Boolean(user.pinEnabled),
    createdAt: user.createdAt
  };
}

function createToken(user) {
  return jwt.sign(
    {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      authVersion: Number(user.authVersion || 0)
    },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );
}

async function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({
      success: false,
      message: "Ou dwe konekte."
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    const user = await User.findById(
      decoded.userId
    ).select(
      "_id email role status authVersion"
    );

    if (
      !user ||
      user.status !== "Active" ||
      Number(decoded.authVersion || 0) !==
        Number(user.authVersion || 0)
    ) {
      return res.status(401).json({
        success: false,
        message:
          "Session lan ekspire. Konekte ankò."
      });
    }

    req.user = {
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
      authVersion: Number(user.authVersion || 0)
    };

    return next();
  } catch {
    return res.status(401).json({
      success: false,
      message:
        "Session lan pa valab oswa li ekspire."
    });
  }
}

function requireAdmin(req, res, next) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res.status(403).json({
      success: false,
      message: "Aksè admin sèlman."
    });
  }

  return next();
}


/* =========================
   SECURITY HELPERS
========================= */

const PIN_MAX_ATTEMPTS = 5;
const PIN_LOCK_MINUTES = 15;
const PIN_TOKEN_TTL = "10m";
const PASSWORD_RESET_MINUTES = 15;

const COMMON_PINS = new Set([
  "000000",
  "111111",
  "123456",
  "654321",
  "121212",
  "112233",
  "123123",
  "101010",
  "222222",
  "333333",
  "444444",
  "555555",
  "666666",
  "777777",
  "888888",
  "999999"
]);

function validatePin(pin) {
  const value = String(pin || "");

  if (!/^\d{6}$/.test(value)) {
    return {
      ok: false,
      message: "PIN lan dwe gen egzakteman 6 chif."
    };
  }

  if (COMMON_PINS.has(value)) {
    return {
      ok: false,
      message: "Chwazi yon PIN ki pi difisil."
    };
  }

  return { ok: true };
}

function validateNewPassword(password) {
  const value = String(password || "");

  if (value.length < 10) {
    return {
      ok: false,
      message:
        "Nouvo modpas la dwe gen omwen 10 karaktè."
    };
  }

  if (value.length > 128) {
    return {
      ok: false,
      message: "Modpas la twò long."
    };
  }

  return { ok: true };
}

function createPinToken(user) {
  return jwt.sign(
    {
      type: "pin_unlock",
      userId: user._id.toString(),
      pinVersion: Number(user.pinVersion || 0)
    },
    process.env.JWT_SECRET,
    { expiresIn: PIN_TOKEN_TTL }
  );
}

async function requirePinUnlock(req, res, next) {
  try {
    const pinToken = String(
      req.headers["x-dlm-pin-token"] || ""
    ).trim();

    if (!pinToken) {
      return res.status(428).json({
        success: false,
        code: "PIN_REQUIRED",
        message: "Debloke kont lan ak PIN ou."
      });
    }

    const decoded = jwt.verify(
      pinToken,
      process.env.JWT_SECRET
    );

    if (
      decoded.type !== "pin_unlock" ||
      decoded.userId !== req.user.userId
    ) {
      return res.status(401).json({
        success: false,
        code: "PIN_INVALID",
        message: "PIN session lan pa valab."
      });
    }

    const user = await User.findById(
      req.user.userId
    ).select(
      "pinEnabled pinVersion status"
    );

    if (
      !user ||
      user.status !== "Active" ||
      !user.pinEnabled ||
      Number(decoded.pinVersion || 0) !==
        Number(user.pinVersion || 0)
    ) {
      return res.status(401).json({
        success: false,
        code: "PIN_INVALID",
        message: "PIN session lan ekspire."
      });
    }

    return next();
  } catch {
    return res.status(401).json({
      success: false,
      code: "PIN_INVALID",
      message: "PIN session lan ekspire."
    });
  }
}

async function sendPasswordResetEmail(user, rawToken) {
  const apiKey = String(
    process.env.RESEND_API_KEY || ""
  ).trim();

  const from = String(
    process.env.PASSWORD_RESET_FROM ||
    "DLM Wallet <security@dlmwallet.com>"
  ).trim();

  if (!apiKey) {
    throw new Error(
      "PASSWORD_EMAIL_NOT_CONFIGURED"
    );
  }

  const resetUrl =
    `${String(
      process.env.FRONTEND_ORIGIN ||
      "https://dlmwallet.com"
    ).replace(/\/$/, "")}` +
    `/reset-password.html?token=${encodeURIComponent(rawToken)}`;

  const response = await fetch(
    "https://api.resend.com/emails",
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
        "User-Agent": "DLM-Wallet/1.0"
      },
      body: JSON.stringify({
        from,
        to: [user.email],
        subject: "Reset your DLM Wallet password",
        html:
          `<div style="font-family:Arial,sans-serif;line-height:1.6">` +
          `<h2>DLM Wallet Security</h2>` +
          `<p>Nou resevwa yon demann pou reset modpas ou.</p>` +
          `<p><a href="${resetUrl}">Reset password</a></p>` +
          `<p>Lyen sa ap ekspire nan ${PASSWORD_RESET_MINUTES} minit.</p>` +
          `<p>Si se pa ou, inyore mesaj sa.</p>` +
          `</div>`
      })
    }
  );

  if (!response.ok) {
    const details =
      await response.text().catch(() => "");
    throw new Error(
      `PASSWORD_EMAIL_FAILED ${response.status} ${details}`
    );
  }

  return true;
}

async function getOrCreateReserve(
  session = null
) {
  const options = {
    new: true,
    upsert: true,
    setDefaultsOnInsert: true
  };

  if (session) {
    options.session = session;
  }

  return Reserve.findOneAndUpdate(
    { key: "main" },
    {
      $setOnInsert: {
        key: "main",
        currency: "USD",
        cashReserve: 0,
        customerLiability: 0
      }
    },
    options
  );
}

function reserveView(reserve) {
  const cashReserve =
    Number(
      reserve?.cashReserve || 0
    );

  const customerLiability =
    Number(
      reserve?.customerLiability || 0
    );

  return {
    currency:
      reserve?.currency || "USD",
    cashReserve,
    customerLiability,
    availableReserve:
      cashReserve -
      customerLiability
  };
}

/* =========================
   PUBLIC
========================= */

app.get("/", (_req, res) => {
  res.json({
    service: "DLM Wallet API",
    status: "online"
  });
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

/* =========================
   REGISTER / LOGIN
========================= */

app.post(
  "/register",
  async (req, res) => {
    try {
      const name = String(
        req.body.name ||
        req.body.fullname ||
        ""
      ).trim();

      const phone = String(
        req.body.phone || ""
      ).trim();

      const email =
        normalizeEmail(
          req.body.email
        );

      const password = String(
        req.body.password || ""
      );

      if (
        !name ||
        !phone ||
        !email ||
        password.length < 8
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Ranpli tout chan yo. Modpas la dwe gen omwen 8 karaktè."
          });
      }

      const existingUser =
        await User.findOne({
          $or: [
            { email },
            { phone }
          ]
        });

      if (existingUser) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Imel oswa telefòn sa deja egziste."
          });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const role =
        email === ADMIN_EMAIL
          ? "admin"
          : "customer";

      const user =
        await User.create({
          name,
          phone,
          email,
          password:
            hashedPassword,
          balance: 0,
          role,
          status: "Active"
        });

      return res
        .status(201)
        .json({
          success: true,
          message:
            "Kont lan kreye avèk siksè.",
          user:
            publicUser(user)
        });
    } catch (error) {
      console.error(
        "REGISTER_ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Sèvè a pa rive kreye kont lan."
        });
    }
  }
);

app.post(
  "/login",
  async (req, res) => {
    try {
      const email =
        normalizeEmail(
          req.body.email
        );

      const password = String(
        req.body.password || ""
      );

      if (!email || !password) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Imel ak modpas obligatwa."
          });
      }

      const user =
        await User.findOne({
          email
        });

      if (!user) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "Imel oswa modpas pa kòrèk."
          });
      }

      const isMatch =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!isMatch) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "Imel oswa modpas pa kòrèk."
          });
      }

      if (
        user.status !== "Active"
      ) {
        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kont sa bloke oswa li pa aktif."
          });
      }

      return res.json({
        success: true,
        message:
          "Koneksyon reyisi.",
        token:
          createToken(user),
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "LOGIN_ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Sèvè a pa rive konekte kont lan."
        });
    }
  }
);

/* =========================
   USER ACCOUNT
========================= */

app.get(
  "/me",
  requireAuth,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.user.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Kont lan pa egziste."
          });
      }

      return res.json({
        success: true,
        user:
          publicUser(user)
      });
    } catch {
      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive chaje kont lan."
        });
    }
  }
);

app.get(
  "/balance",
  requireAuth,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.user.userId
        ).select(
          "name email balance role status pinEnabled"
        );

      if (!user) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Itilizatè a pa jwenn."
          });
      }

      return res.json({
        success: true,
        userId: user._id,
        name: user.name,
        email: user.email,
        balance:
          Number(
            user.balance || 0
          ),
        role: user.role,
        status: user.status,
        pinEnabled:
          Boolean(
            user.pinEnabled
          )
      });
    } catch {
      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive chaje balans lan."
        });
    }
  }
);

/* =========================
   PIN
========================= */

app.post(
  "/pin/set",
  requireAuth,
  async (req, res) => {
    try {
      const pin = String(
        req.body.pin || ""
      ).trim();

      if (
        !/^\d{6}$/.test(pin)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "PIN lan dwe genyen egzakteman 6 chif."
          });
      }

      const user =
        await User.findById(
          req.user.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Kont lan pa jwenn."
          });
      }

      user.pinHash =
        await bcrypt.hash(
          pin,
          12
        );

      user.pinEnabled = true;
      user.pinUpdatedAt =
        new Date();

      await user.save();

      return res.json({
        success: true,
        message:
          "PIN sekirite a aktive avèk siksè."
      });
    } catch (error) {
      console.error(
        "PIN_SET_ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive aktive PIN lan."
        });
    }
  }
);

app.post(
  "/pin/verify",
  requireAuth,
  async (req, res) => {
    try {
      const pin = String(
        req.body.pin || ""
      ).trim();

      if (
        !/^\d{6}$/.test(pin)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "PIN lan dwe genyen 6 chif."
          });
      }

      const user =
        await User.findById(
          req.user.userId
        );

      if (
        !user ||
        !user.pinEnabled ||
        !user.pinHash
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "PIN poko aktive sou kont sa."
          });
      }

      const valid =
        await bcrypt.compare(
          pin,
          user.pinHash
        );

      if (!valid) {
        return res
          .status(401)
          .json({
            success: false,
            message:
              "PIN pa kòrèk."
          });
      }

      return res.json({
        success: true,
        message: "PIN verifye."
      });
    } catch {
      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive verifye PIN lan."
        });
    }
  }
);

/* =========================
   DEPOSITS
========================= */

app.post(
  "/deposits",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      const method = String(
        req.body.method || ""
      ).trim();

      const reference = String(
        req.body.reference || ""
      ).trim();

      const note = String(
        req.body.note || ""
      ).trim();

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Montan depo a pa valab."
          });
      }

      if (
        ![
          "MonCash",
          "NatCash",
          "Bank"
        ].includes(method)
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Metòd depo a pa valab."
          });
      }

      if (!reference) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Reference tranzaksyon an obligatwa."
          });
      }

      const user =
        await User.findById(
          req.user.userId
        );

      if (
        !user ||
        user.status !== "Active"
      ) {
        return res
          .status(403)
          .json({
            success: false,
            message:
              "Kont lan pa aktif."
          });
      }

      const duplicate =
        await DepositRequest.findOne({
          method,
          reference
        });

      if (duplicate) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Reference sa deja itilize."
          });
      }

      const deposit =
        await DepositRequest.create({
          userId:
            user._id,
          amount,
          currency: "USD",
          method,
          reference,
          note,
          status:
            "pending"
        });

      return res
        .status(201)
        .json({
          success: true,
          message:
            "Demann depo a voye. Li ap tann verifikasyon admin.",
          deposit
        });
    } catch (error) {
      console.error(
        "DEPOSIT_REQUEST_ERROR:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive kreye demann depo a."
        });
    }
  }
);

app.get(
  "/deposits/mine",
  requireAuth,
  async (req, res) => {
    try {
      const deposits =
        await DepositRequest.find({
          userId:
            req.user.userId
        }).sort({
          createdAt: -1
        });

      return res.json({
        success: true,
        deposits
      });
    } catch {
      return res
        .status(500)
        .json({
          success: false,
          message:
            "Pa rive chaje depo yo."
        });
    }
  }
);

/* =========================
   WITHDRAW / TRANSFER
========================= */

app.post(
  "/withdraw",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      if (
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Montan an pa valab."
          });
      }

      const user =
        await User.findOneAndUpdate(
          {
            _id:
              req.user.userId,
            balance: {
              $gte: amount
            },
            status:
              "Active"
          },
          {
            $inc: {
              balance:
                -amount
            }
          },
          {
            new: true
          }
        );

      if (!user) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Balans pa sifi oswa kont lan pa aktif."
          });
      }

      await Transaction.create({
        userId:
          user._id,
        type:
          "withdraw",
        amount,
        status:
          "completed",
        description:
          String(
            req.body.description ||
            "Customer withdrawal"
          )
      });

      await Reserve.findOneAndUpdate(
        { key: "main" },
        {
          $inc: {
            customerLiability:
              -amount
          }
        }
      );

      return res.json({
        success: true,
message: "Retrè a fèt avèk siksè.",
balance: Number(user.balance)
});

} catch (error) {
  console.error("WITHDRAW_ERROR:", error);

  return res.status(500).json({
    success: false,
    message: "Sèvè a pa rive fè retrè a."
  });
}
});
/* =========================
   TRANSFER
========================= */

app.post(
  "/transfer",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);

      const recipientEmail = normalizeEmail(
        req.body.recipientEmail
      );

      if (
        !recipientEmail ||
        !Number.isFinite(amount) ||
        amount <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Imel moun k ap resevwa a ak montan valab obligatwa."
        });
      }

      if (
        recipientEmail ===
        normalizeEmail(req.user.email)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Ou pa ka transfere sou pwòp kont ou."
        });
      }

      const sender =
        await User.findOneAndUpdate(
          {
            _id: req.user.userId,
            balance: {
              $gte: amount
            },
            status: "Active"
          },
          {
            $inc: {
              balance: -amount
            }
          },
          {
            new: true
          }
        );

      if (!sender) {
        return res.status(400).json({
          success: false,
          message:
            "Balans pa sifi oswa kont lan pa aktif."
        });
      }

      const recipient =
        await User.findOneAndUpdate(
          {
            email: recipientEmail,
            status: "Active"
          },
          {
            $inc: {
              balance: amount
            }
          },
          {
            new: true
          }
        );

      if (!recipient) {
        await User.findByIdAndUpdate(
          sender._id,
          {
            $inc: {
              balance: amount
            }
          }
        );

        return res.status(404).json({
          success: false,
          message:
            "Kont k ap resevwa a pa jwenn."
        });
      }

      await Transaction.create([
        {
          userId: sender._id,
          type: "transfer",
          amount,
          status: "completed",
          description:
            `Voye bay ${recipient.email}`
        },
        {
          userId: recipient._id,
          type: "deposit",
          amount,
          status: "completed",
          description:
            `Resevwa nan men ${sender.email}`
        }
      ]);

      return res.json({
        success: true,
        message:
          "Transfè a fèt avèk siksè.",
        balance:
          Number(sender.balance)
      });

    } catch (error) {
      console.error(
        "TRANSFER_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Sèvè a pa rive fè transfè a."
      });
    }
  }
);


/* =========================
   TRANSACTIONS
========================= */

app.get(
  "/transactions",
  requireAuth,
  async (req, res) => {
    try {
      const transactions =
        await Transaction.find({
          userId: req.user.userId
        }).sort({
          createdAt: -1
        });

      return res.json({
        success: true,
        transactions
      });

    } catch (error) {
      console.error(
        "TRANSACTIONS_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive chaje tranzaksyon yo."
      });
    }
  }
);



/* =========================
   ADMIN ALL TRANSACTIONS
========================= */

app.get(
  "/admin/transactions",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const type = String(req.query.type || "").trim();
      const status = String(req.query.status || "").trim();
      const userId = String(req.query.userId || "").trim();

      const filter = {};

      if (type) {
        filter.type = type;
      }

      if (status) {
        filter.status = status;
      }

      if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        filter.userId = userId;
      }

      const transactions = await Transaction.find(filter)
        .populate("userId", "name email phone balance status")
        .populate("createdBy", "name email")
        .sort({ createdAt: -1 })
        .limit(500);

      return res.json({
        success: true,
        transactions
      });
    } catch (error) {
      console.error("ADMIN_TRANSACTIONS_ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Pa rive chaje tout tranzaksyon yo."
      });
    }
  }
);

/* =========================
   ADMIN USERS
========================= */

app.get(
  "/admin/users",
  requireAuth,
  requireAdmin,
  async (_req, res) => {
    try {
      const users =
        await User.find()
          .select(
            "-password -pinHash"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        success: true,
        users:
          users.map(publicUser)
      });

    } catch (error) {
      console.error(
        "ADMIN_USERS_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive chaje kliyan yo."
      });
    }
  }
);


/* =========================
   ADMIN DEPOSITS
========================= */

app.get(
  "/admin/deposits",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const status = String(
        req.query.status || ""
      ).trim();

      const filter = {};

      if (
        [
          "pending",
          "approved",
          "rejected"
        ].includes(status)
      ) {
        filter.status = status;
      }

      const deposits =
        await DepositRequest.find(
          filter
        )
          .populate(
            "userId",
            "name email phone balance"
          )
          .populate(
            "reviewedBy",
            "name email"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        success: true,
        deposits
      });

    } catch (error) {
      console.error(
        "ADMIN_DEPOSITS_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive chaje demann depo yo."
      });
    }
  }
);


/* =========================
   ADMIN APPROVE DEPOSIT
========================= */

app.patch(
  "/admin/deposits/:id/approve",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const session =
      await mongoose.startSession();

    try {
      let payload = null;

      await session.withTransaction(
        async () => {
          const deposit =
            await DepositRequest.findOne({
              _id: req.params.id,
              status: "pending"
            }).session(session);

          if (!deposit) {
            const error =
              new Error(
                "Demann depo sa pa pending oswa li pa egziste."
              );

            error.statusCode = 409;

            throw error;
          }

          const user =
            await User.findById(
              deposit.userId
            ).session(session);

          if (!user) {
            const error =
              new Error(
                "Kliyan an pa jwenn."
              );

            error.statusCode = 404;

            throw error;
          }

          if (
            user.status !== "Active"
          ) {
            const error =
              new Error(
                "Kont kliyan an pa aktif."
              );

            error.statusCode = 403;

            throw error;
          }

          user.balance =
            Number(
              user.balance || 0
            ) +
            Number(
              deposit.amount
            );

          await user.save({
            session
          });

          deposit.status =
            "approved";

          deposit.reviewedBy =
            req.user.userId;

          deposit.reviewedAt =
            new Date();

          await deposit.save({
            session
          });

          await Transaction.create(
            [
              {
                userId:
                  user._id,

                type:
                  "deposit",

                amount:
                  deposit.amount,

                status:
                  "completed",

                description:
                  `${deposit.method} deposit approved - ref ${deposit.reference}`,

                createdBy:
                  req.user.userId
              }
            ],
            {
              session
            }
          );

          const reserve =
            await getOrCreateReserve(
              session
            );

          reserve.cashReserve =
            Number(
              reserve.cashReserve || 0
            ) +
            Number(
              deposit.amount
            );

          reserve.customerLiability =
            Number(
              reserve.customerLiability || 0
            ) +
            Number(
              deposit.amount
            );

          await reserve.save({
            session
          });

          payload = {
            success: true,

            message:
              "Depo a approve. Balans kliyan an monte otomatikman.",

            deposit,

            user:
              publicUser(user),

            reserve:
              reserveView(reserve)
          };
        }
      );

      return res.json(
        payload
      );

    } catch (error) {
      console.error(
        "APPROVE_DEPOSIT_ERROR:",
        error
      );

      return res
        .status(
          error.statusCode || 500
        )
        .json({
          success: false,

          message:
            error.message ||
            "Pa rive approve depo a."
        });

    } finally {
      session.endSession();
    }
  }
);


/* =========================
   ADMIN REJECT DEPOSIT
========================= */

app.patch(
  "/admin/deposits/:id/reject",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const reason = String(
        req.body.reason || ""
      ).trim();

      const deposit =
        await DepositRequest.findOneAndUpdate(
          {
            _id: req.params.id,
            status: "pending"
          },
          {
            $set: {
              status: "rejected",

              reviewedBy:
                req.user.userId,

              reviewedAt:
                new Date(),

              rejectionReason:
                reason
            }
          },
          {
            new: true
          }
        );

      if (!deposit) {
        return res.status(409).json({
          success: false,
          message:
            "Demann depo sa pa pending oswa li pa egziste."
        });
      }

      return res.json({
        success: true,
        message:
          "Depo a rejte.",
        deposit
      });

    } catch (error) {
      console.error(
        "REJECT_DEPOSIT_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive rejte depo a."
      });
    }
  }
);


/* =========================
   ADMIN RESERVE
========================= */

app.get(
  "/admin/reserve",
  requireAuth,
  requireAdmin,
  async (_req, res) => {
    try {
      const reserve =
        await getOrCreateReserve();

      return res.json({
        success: true,
        reserve:
          reserveView(reserve)
      });

    } catch (error) {
      console.error(
        "ADMIN_RESERVE_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive chaje reserve la."
      });
    }
  }
);


/* =========================
   ADMIN RESERVE ADJUST
========================= */

app.patch(
  "/admin/reserve/adjust",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      if (
        !Number.isFinite(amount) ||
        amount === 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Montan reserve la pa valab."
        });
      }

      const reserve =
        await getOrCreateReserve();

      const nextCash =
        Number(
          reserve.cashReserve || 0
        ) + amount;

      if (nextCash < 0) {
        return res.status(400).json({
          success: false,
          message:
            "Cash reserve la pa ka negatif."
        });
      }

      reserve.cashReserve =
        nextCash;

      await reserve.save();

      return res.json({
        success: true,
        message:
          "Reserve la modifye.",
        reserve:
          reserveView(reserve)
      });

    } catch (error) {
      console.error(
        "ADMIN_RESERVE_ADJUST_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive modifye reserve la."
      });
    }
  }
);


/* =========================
   ADMIN USER BALANCE
========================= */

app.patch(
  "/admin/users/:id/balance",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      const description =
        String(
          req.body.description ||
          "Admin balance adjustment"
        ).trim();

      if (
        !Number.isFinite(amount) ||
        amount === 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Montan an pa valab."
        });
      }

      const user =
        await User.findOneAndUpdate(
          {
            _id:
              req.params.id,

            balance: {
              $gte:
                amount < 0
                  ? Math.abs(amount)
                  : 0
            }
          },
          {
            $inc: {
              balance: amount
            }
          },
          {
            new: true
          }
        );

      if (!user) {
        return res.status(400).json({
          success: false,
          message:
            "Kliyan an pa jwenn oswa balans lan pa ka vin negatif."
        });
      }

      await Transaction.create({
        userId:
          user._id,

        type:
          amount > 0
            ? "admin_credit"
            : "admin_debit",

        amount:
          Math.abs(amount),

        status:
          "completed",

        description,

        createdBy:
          req.user.userId
      });

      const reserve =
        await getOrCreateReserve();

      reserve.customerLiability =
        Math.max(
          0,
          Number(
            reserve.customerLiability || 0
          ) + amount
        );

      await reserve.save();

      return res.json({
        success: true,

        message:
          "Balans kliyan an modifye.",

        user:
          publicUser(user),

        reserve:
          reserveView(reserve)
      });

    } catch (error) {
      console.error(
        "ADMIN_BALANCE_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive modifye balans kliyan an."
      });
    }
  }
);


/* =========================
   ADMIN USER STATUS
========================= */

app.patch(
  "/admin/users/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const status =
        String(
          req.body.status || ""
        );

      if (
        ![
          "Active",
          "Blocked"
        ].includes(status)
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Status la pa valab."
        });
      }

      const user =
        await User.findByIdAndUpdate(
          req.params.id,
          {
            status
          },
          {
            new: true
          }
        );

      if (!user) {
        return res.status(404).json({
          success: false,
          message:
            "Kliyan an pa jwenn."
        });
      }

      return res.json({
        success: true,
        message:
          "Status kliyan an modifye.",
        user:
          publicUser(user)
      });

    } catch (error) {
      console.error(
        "ADMIN_STATUS_ERROR:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Pa rive modifye status kliyan an."
      });
    }
  }
);



/* =========================
   RELOADLY
========================= */

const RELOADLY_MODE = String(
  process.env.RELOADLY_MODE || "sandbox"
).trim().toLowerCase();

const RELOADLY_CLIENT_ID = String(
  process.env.RELOADLY_CLIENT_ID || ""
).trim();

const RELOADLY_CLIENT_SECRET = String(
  process.env.RELOADLY_CLIENT_SECRET || ""
).trim();

function reloadlyBases() {
  const live = RELOADLY_MODE === "live" || RELOADLY_MODE === "production";

  return {
    airtime: live
      ? "https://topups.reloadly.com"
      : "https://topups-sandbox.reloadly.com",

    giftcards: live
      ? "https://giftcards.reloadly.com"
      : "https://giftcards-sandbox.reloadly.com"
  };
}

function reloadlyConfigured() {
  return Boolean(
    RELOADLY_CLIENT_ID &&
    RELOADLY_CLIENT_SECRET
  );
}

async function reloadlyJson(url, options = {}) {
  const response = await fetch(url, options);
  const text = await response.text();

  let data = {};

  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = {
      message: text || "Reloadly te retounen yon repons ki pa JSON."
    };
  }

  if (!response.ok) {
    const error = new Error(
      data.message ||
      data.error_description ||
      data.errorCode ||
      `Reloadly request failed (${response.status}).`
    );

    error.statusCode = response.status;
    error.reloadly = data;
    throw error;
  }

  return data;
}

const reloadlyTokenCache = {
  airtime: null,
  giftcards: null
};

async function getReloadlyToken(product) {
  if (!reloadlyConfigured()) {
    const error = new Error(
      "Reloadly poko configure sou server la."
    );
    error.statusCode = 503;
    throw error;
  }

  const bases = reloadlyBases();
  const audience =
    product === "giftcards"
      ? bases.giftcards
      : bases.airtime;

  const cached = reloadlyTokenCache[product];
  const now = Date.now();

  if (
    cached &&
    cached.token &&
    cached.expiresAt > now + 60000
  ) {
    return cached.token;
  }

  const data = await reloadlyJson(
    "https://auth.reloadly.com/oauth/token",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json"
      },
      body: JSON.stringify({
        client_id: RELOADLY_CLIENT_ID,
        client_secret: RELOADLY_CLIENT_SECRET,
        grant_type: "client_credentials",
        audience
      })
    }
  );

  const token = data.access_token;

  if (!token) {
    const error = new Error(
      "Reloadly pa retounen access token."
    );
    error.statusCode = 502;
    throw error;
  }

  const expiresIn = Number(data.expires_in || 3600);

  reloadlyTokenCache[product] = {
    token,
    expiresAt: now + expiresIn * 1000
  };

  return token;
}

async function reloadlyRequest(product, path, options = {}) {
  const bases = reloadlyBases();
  const base = product === "giftcards" ? bases.giftcards : bases.airtime;
  const token = await getReloadlyToken(product);

  const accept =
    product === "giftcards"
      ? "application/com.reloadly.giftcards-v1+json"
      : "application/com.reloadly.topups-v1+json";

  return reloadlyJson(
    `${base}${path}`,
    {
      ...options,
      headers: {
        Accept: accept,
        Authorization: `Bearer ${token}`,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...(options.headers || {})
      }
    }
  );
}

function normalizePhone(value) {
  return String(value || "").replace(/[^0-9]/g, "");
}

async function deductCustomerBalance(userId, amount) {
  return User.findOneAndUpdate(
    {
      _id: userId,
      balance: { $gte: amount },
      status: "Active"
    },
    {
      $inc: { balance: -amount }
    },
    {
      new: true
    }
  );
}

async function refundCustomerBalance(userId, amount) {
  return User.findByIdAndUpdate(
    userId,
    {
      $inc: { balance: amount }
    },
    {
      new: true
    }
  );
}

async function reduceCustomerLiability(amount) {
  const reserve = await getOrCreateReserve();
  reserve.customerLiability = Math.max(
    0,
    Number(reserve.customerLiability || 0) - Number(amount || 0)
  );
  await reserve.save();
  return reserve;
}

app.get(
  "/reloadly/status",
  requireAuth,
  async (_req, res) => {
    return res.json({
      success: true,
      configured: reloadlyConfigured(),
      mode: RELOADLY_MODE,
      airtimeBase: reloadlyBases().airtime,
      giftcardsBase: reloadlyBases().giftcards
    });
  }
);

/* =========================
   RELOADLY GIFTCARDS SEARCH
========================= */

app.get(
  "/reloadly/giftcards",
  requireAuth,
  async (req, res) => {
    try {
      const search = String(req.query.search || "")
        .trim()
        .toLowerCase();

      const country = String(req.query.country || "")
        .trim()
        .toUpperCase();

      const path = country
        ? `/countries/${encodeURIComponent(country)}/products?size=200&page=1`
        : "/products?size=200&page=1";

      const data = await reloadlyRequest(
        "giftcards",
        path
      );

      let products = Array.isArray(data)
        ? data
        : Array.isArray(data.content)
          ? data.content
          : [];

      if (search) {
        products = products.filter((product) => {
          const haystack = [
            product.productName,
            product.brand?.brandName,
            product.country?.name,
            product.country?.isoName
          ]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();

          return haystack.includes(search);
        });
      }

      return res.json({
        success: true,
        products
      });

    } catch (error) {
      console.error(
        "RELOADLY_GIFTCARDS_SEARCH_ERROR:",
        error.reloadly || error
      );

      return res.status(
        error.statusCode && error.statusCode < 600
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          "Pa rive chaje pwodwi Reloadly yo."
      });
    }
  }
);


/* =========================
   RELOADLY GIFTCARD PRODUCT DETAILS
========================= */

app.get(
  "/reloadly/giftcards/:productId",
  requireAuth,
  async (req, res) => {
    try {
      const productId = Number(req.params.productId);

      if (!Number.isInteger(productId) || productId <= 0) {
        return res.status(400).json({
          success: false,
          message: "Product ID pa valab."
        });
      }

      const product = await reloadlyRequest(
        "giftcards",
        `/products/${productId}`
      );

      return res.json({
        success: true,
        product
      });
    } catch (error) {
      console.error(
        "RELOADLY_GIFTCARD_PRODUCT_ERROR:",
        error.reloadly || error
      );

      return res.status(
        error.statusCode && error.statusCode < 600
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          "Pa rive chaje detay pwodwi a."
      });
    }
  }
);

/* =========================
   RELOADLY GIFTCARD ORDER
========================= */

app.post(
  "/reloadly/giftcards/order",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    let chargedUser = null;
    let total = 0;

    try {
      const productId = Number(req.body.productId);
      const quantity = Math.max(1, Number(req.body.quantity || 1));
      const unitPrice = Number(req.body.unitPrice || req.body.amount);
      const countryCode = String(req.body.countryCode || "US")
        .trim()
        .toUpperCase();

      const recipientEmail = normalizeEmail(
        req.body.recipientEmail || req.user.email
      );

      const additionalRequirements =
        req.body.additionalRequirements &&
        typeof req.body.additionalRequirements === "object"
          ? req.body.additionalRequirements
          : null;

      if (
        !Number.isInteger(productId) ||
        productId <= 0 ||
        !Number.isFinite(quantity) ||
        quantity <= 0 ||
        !Number.isFinite(unitPrice) ||
        unitPrice <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "productId, quantity ak unitPrice/amount dwe valab."
        });
      }

      total = Number((quantity * unitPrice).toFixed(2));

      chargedUser = await deductCustomerBalance(
        req.user.userId,
        total
      );

      if (!chargedUser) {
        return res.status(400).json({
          success: false,
          message:
            "Balans pa sifi oswa kont lan pa aktif."
        });
      }

      const customIdentifier =
        `dlm-gc-${req.user.userId}-${Date.now()}`;

      const order = await reloadlyRequest(
        "giftcards",
        "/orders",
        {
          method: "POST",
          body: JSON.stringify({
            productId,
            countryCode,
            quantity,
            unitPrice,
            customIdentifier,
            senderName: chargedUser.name || "DLM Wallet",
            recipientEmail,
            ...(additionalRequirements
              ? { productAdditionalRequirements: additionalRequirements }
              : {})
          })
        }
      );

      await Transaction.create({
        userId: chargedUser._id,
        type: "giftcard",
        amount: total,
        status: "completed",
        description:
          `Reloadly gift card order ${order.transactionId || customIdentifier}`
      });

      const reserve = await reduceCustomerLiability(total);

      return res.json({
        success: true,
        message:
          "Gift card la achte avèk siksè.",
        order,
        balance: Number(chargedUser.balance),
        reserve: reserveView(reserve)
      });

    } catch (error) {
      if (chargedUser && total > 0) {
        await refundCustomerBalance(
          chargedUser._id,
          total
        ).catch(() => null);
      }

      console.error(
        "RELOADLY_GIFTCARD_ORDER_ERROR:",
        error.reloadly || error
      );

      return res.status(
        error.statusCode && error.statusCode < 600
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          "Gift card la pa rive achte. Balans kliyan an pa pèdi."
      });
    }
  }
);

/* =========================
   RELOADLY REDEEM CODE
========================= */

app.get(
  "/reloadly/giftcards/orders/:transactionId/cards",
  requireAuth,
  async (req, res) => {
    try {
      const transactionId = String(req.params.transactionId || "").trim();

      if (!transactionId) {
        return res.status(400).json({
          success: false,
          message: "transactionId obligatwa."
        });
      }

      const cards = await reloadlyRequest(
        "giftcards",
        `/orders/transactions/${encodeURIComponent(transactionId)}/cards`,
        {
          headers: {
            Accept: "application/com.reloadly.giftcards-v2+json"
          }
        }
      );

      return res.json({
        success: true,
        cards
      });

    } catch (error) {
      return res.status(
        error.statusCode && error.statusCode < 600
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          "Pa rive jwenn redeem code la."
      });
    }
  }
);

/* =========================
   RELOADLY AIRTIME TOPUP
========================= */

app.post(
  "/reloadly/topup",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    let chargedUser = null;
    let amount = 0;

    try {
      amount = Number(req.body.amount);
      const countryCode = String(req.body.countryCode || "")
        .trim()
        .toUpperCase();
      const phone = normalizePhone(req.body.phone);

      if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        !/^[A-Z]{2}$/.test(countryCode) ||
        phone.length < 6
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Nimewo, country code ak montan topup la pa valab."
        });
      }

      const operator = await reloadlyRequest(
        "airtime",
        `/operators/auto-detect/phone/${encodeURIComponent(phone)}/countries/${encodeURIComponent(countryCode)}`
      );

      const operatorId = Number(operator.operatorId || operator.id);

      if (!Number.isInteger(operatorId) || operatorId <= 0) {
        return res.status(400).json({
          success: false,
          message:
            "Reloadly pa rive detekte operatè nimewo sa."
        });
      }

      chargedUser = await deductCustomerBalance(
        req.user.userId,
        amount
      );

      if (!chargedUser) {
        return res.status(400).json({
          success: false,
          message:
            "Balans pa sifi oswa kont lan pa aktif."
        });
      }

      const customIdentifier =
        `dlm-topup-${req.user.userId}-${Date.now()}`;

      const topup = await reloadlyRequest(
        "airtime",
        "/topups",
        {
          method: "POST",
          body: JSON.stringify({
            operatorId,
            amount,
            useLocalAmount: false,
            customIdentifier,
            recipientPhone: {
              countryCode,
              number: phone
            }
          })
        }
      );

      await Transaction.create({
        userId: chargedUser._id,
        type: "topup",
        amount,
        status: "completed",
        description:
          `Reloadly topup ${topup.transactionId || customIdentifier} - ${countryCode} ${phone}`
      });

      const reserve = await reduceCustomerLiability(amount);

      return res.json({
        success: true,
        message:
          "Topup la voye avèk siksè.",
        operator: {
          operatorId,
          name: operator.name || operator.operatorName || ""
        },
        topup,
        balance: Number(chargedUser.balance),
        reserve: reserveView(reserve)
      });

    } catch (error) {
      if (chargedUser && amount > 0) {
        await refundCustomerBalance(
          chargedUser._id,
          amount
        ).catch(() => null);
      }

      console.error(
        "RELOADLY_TOPUP_ERROR:",
        error.reloadly || error
      );

      return res.status(
        error.statusCode && error.statusCode < 600
          ? error.statusCode
          : 500
      ).json({
        success: false,
        message:
          error.message ||
          "Topup la echwe. Balans kliyan an pa pèdi."
      });
    }
  }
);


/* =========================
   MANUAL DIGITAL SERVICE ORDERS
   Netflix / Prime Video
========================= */

app.post(
  "/service-orders",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    try {
      const service = String(req.body.service || "").trim();
      const plan = String(req.body.plan || "").trim();
      const amount = Number(req.body.amount);
      const paymentMethod = "wallet";
      const paymentReference = String(req.body.paymentReference || "").trim();

      if (!["Netflix", "Prime Video"].includes(service)) {
        return res.status(400).json({
          success: false,
          message: "Sèvis la pa valab."
        });
      }

      if (!plan || !Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({
          success: false,
          message: "Plan ak montan an obligatwa."
        });
      }

      const user = await User.findById(req.user.userId);

      if (!user || user.status !== "Active") {
        return res.status(403).json({
          success: false,
          message: "Kont lan pa aktif."
        });
      }

      let walletCharged = false;

      if (paymentMethod === "wallet") {
        const charged = await deductCustomerBalance(user._id, amount);

        if (!charged) {
          return res.status(400).json({
            success: false,
            message: "Balans pa sifi oswa kont lan pa aktif."
          });
        }

        walletCharged = true;
      }

      try {
        const order = await ServiceOrder.create({
          userId: user._id,
          service,
          plan,
          amount,
          paymentMethod,
          paymentReference,
          walletCharged,
          customerEmail: user.email,
          status: "pending"
        });

        if (walletCharged) {
          await Transaction.create({
            userId: user._id,
            type: "admin_debit",
            amount,
            status: "completed",
            description: `${service} manual service order ${order._id}`
          });

          await reduceCustomerLiability(amount);
        }

        return res.status(201).json({
          success: true,
          message:
            paymentMethod === "wallet"
              ? "Kòmand lan resevwa. Li ap tann tretman admin."
              : "Kòmand lan resevwa. Admin ap verifye peman an anvan tretman.",
          order
        });
      } catch (error) {
        if (walletCharged) {
          await refundCustomerBalance(user._id, amount).catch(() => null);
        }
        throw error;
      }
    } catch (error) {
      console.error("SERVICE_ORDER_CREATE_ERROR:", error);
      return res.status(500).json({
        success: false,
        message: error.message || "Pa rive kreye kòmand lan."
      });
    }
  }
);

app.get(
  "/service-orders/mine",
  requireAuth,
  async (req, res) => {
    try {
      const orders = await ServiceOrder.find({
        userId: req.user.userId
      }).sort({ createdAt: -1 });

      return res.json({
        success: true,
        orders
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Pa rive chaje kòmand yo."
      });
    }
  }
);

app.get(
  "/admin/service-orders",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const status = String(req.query.status || "").trim();
      const filter = {};

      if (
        ["pending", "processing", "completed", "rejected"].includes(status)
      ) {
        filter.status = status;
      }

      const orders = await ServiceOrder.find(filter)
        .populate("userId", "name email phone balance")
        .populate("reviewedBy", "name email")
        .sort({ createdAt: -1 });

      return res.json({
        success: true,
        orders
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Pa rive chaje kòmand sèvis yo."
      });
    }
  }
);

app.patch(
  "/admin/service-orders/:id",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const action = String(req.body.action || "").trim();
      const deliveryMessage = String(
        req.body.deliveryMessage || ""
      ).trim();
      const adminNote = String(req.body.adminNote || "").trim();

      if (!["processing", "complete", "reject"].includes(action)) {
        return res.status(400).json({
          success: false,
          message: "Aksyon admin lan pa valab."
        });
      }

      const order = await ServiceOrder.findById(req.params.id);

      if (!order) {
        return res.status(404).json({
          success: false,
          message: "Kòmand lan pa jwenn."
        });
      }

      if (["completed", "rejected"].includes(order.status)) {
        return res.status(409).json({
          success: false,
          message: "Kòmand sa deja fini."
        });
      }

      if (action === "processing") {
        order.status = "processing";
      }

      if (action === "complete") {
        if (!deliveryMessage) {
          return res.status(400).json({
            success: false,
            message: "Mete mesaj/detay livrezon an anvan ou complete."
          });
        }

        order.status = "completed";
        order.deliveryMessage = deliveryMessage;
      }

      if (action === "reject") {
        order.status = "rejected";

        if (order.walletCharged) {
          await refundCustomerBalance(order.userId, order.amount);

          const reserve = await getOrCreateReserve();
          reserve.customerLiability =
            Number(reserve.customerLiability || 0) +
            Number(order.amount || 0);
          await reserve.save();

          order.walletCharged = false;
        }
      }

      order.adminNote = adminNote;
      order.reviewedBy = req.user.userId;
      order.reviewedAt = new Date();

      await order.save();

      return res.json({
        success: true,
        message: "Kòmand sèvis la modifye.",
        order
      });
    } catch (error) {
      console.error("ADMIN_SERVICE_ORDER_ERROR:", error);
      return res.status(500).json({
        success: false,
        message: error.message || "Pa rive modifye kòmand lan."
      });
    }
  }
);


/* =========================
   KYC / CARD APPLICATION
========================= */

function validKycImage(value) {
  const text = String(value || "");
  return /^data:image\/(jpeg|jpg|png|webp);base64,/i.test(text) && text.length <= 2200000;
}

app.get("/kyc/status", requireAuth, async (req, res) => {
  try {
    const kyc = await KycProfile.findOne({ userId: req.user.userId })
      .select("-documentFront -documentBack -selfieImage");

    return res.json({
      success: true,
      kyc: kyc || { status: "not_submitted" }
    });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive chaje KYC la." });
  }
});

app.post("/kyc/submit", requireAuth, async (req, res) => {
  try {
    const documentType = String(req.body.documentType || "").trim();
    const documentNumber = String(req.body.documentNumber || "").trim();
    const documentFront = String(req.body.documentFront || "");
    const documentBack = String(req.body.documentBack || "");
    const selfieImage = String(req.body.selfieImage || "");

    if (!["national_id","passport","drivers_license"].includes(documentType)) {
      return res.status(400).json({ success: false, message: "Kalite pyès la pa valab." });
    }

    if (
      documentNumber.length < 4 ||
      !validKycImage(documentFront) ||
      !validKycImage(selfieImage) ||
      (documentBack && !validKycImage(documentBack))
    ) {
      return res.status(400).json({
        success: false,
        message: "Verifye nimewo pyès la ak foto yo."
      });
    }

    const existing = await KycProfile.findOne({ userId: req.user.userId });

    if (existing && existing.status === "verified") {
      return res.status(409).json({ success: false, message: "KYC deja verifye." });
    }

    const kyc = await KycProfile.findOneAndUpdate(
      { userId: req.user.userId },
      {
        $set: {
          documentType,
          documentNumber,
          documentFront,
          documentBack,
          selfieImage,
          status: "pending",
          rejectionReason: "",
          reviewedBy: null,
          reviewedAt: null
        }
      },
      { new: true, upsert: true, setDefaultsOnInsert: true }
    );

    return res.status(201).json({
      success: true,
      message: "KYC la voye. Li ap tann verifikasyon.",
      kyc: { id: kyc._id, status: kyc.status }
    });
  } catch (error) {
    console.error("KYC_SUBMIT_ERROR:", error);
    return res.status(500).json({ success: false, message: "Pa rive voye KYC la." });
  }
});

app.get("/admin/kyc", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const items = await KycProfile.find({})
      .populate("userId", "name email phone")
      .sort({ createdAt: -1 });

    return res.json({ success: true, items });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive chaje KYC yo." });
  }
});

app.patch("/admin/kyc/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const action = String(req.body.action || "").trim();
    const rejectionReason = String(req.body.rejectionReason || "").trim();

    if (!["verify","reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Aksyon an pa valab." });
    }

    const kyc = await KycProfile.findById(req.params.id);

    if (!kyc) {
      return res.status(404).json({ success: false, message: "KYC la pa jwenn." });
    }

    if (action === "reject" && !rejectionReason) {
      return res.status(400).json({ success: false, message: "Mete rezon rejè a." });
    }

    kyc.status = action === "verify" ? "verified" : "rejected";
    kyc.rejectionReason = action === "reject" ? rejectionReason : "";
    kyc.reviewedBy = req.user.userId;
    kyc.reviewedAt = new Date();

    await kyc.save();

    return res.json({
      success: true,
      message: action === "verify" ? "KYC verifye." : "KYC rejte."
    });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive modifye KYC la." });
  }
});

app.get("/card/status", requireAuth, async (req, res) => {
  try {
    const [user, kyc, cardRequest] = await Promise.all([
      User.findById(req.user.userId).select("balance"),
      KycProfile.findOne({ userId: req.user.userId }).select("status"),
      VirtualCardRequest.findOne({ userId: req.user.userId }).sort({ createdAt: -1 })
    ]);

    return res.json({
      success: true,
      balance: Number(user?.balance || 0),
      minimumBalance: 10,
      kycStatus: kyc?.status || "not_submitted",
      cardRequest: cardRequest || null
    });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive chaje status kat la." });
  }
});

app.post("/card/request", requireAuth, async (req, res) => {
  try {
    const fee = 10;

    const kyc = await KycProfile.findOne({ userId: req.user.userId });

    if (!kyc || kyc.status !== "verified") {
      return res.status(403).json({
        success: false,
        message: "KYC dwe verifye anvan ou mande kat la."
      });
    }

    const existing = await VirtualCardRequest.findOne({
      userId: req.user.userId,
      status: { $in: ["pending","approved"] }
    });

    if (existing) {
      return res.status(409).json({ success: false, message: "Ou deja gen yon demann kat aktif." });
    }

    const user = await User.findOneAndUpdate(
      {
        _id: req.user.userId,
        balance: { $gte: fee },
        status: "Active"
      },
      { $inc: { balance: -fee } },
      { new: true }
    );

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Ou bezwen omwen $10 USD sou DLM Wallet ou."
      });
    }

    try {
      const request = await VirtualCardRequest.create({
        userId: user._id,
        fee,
        currency: "USD",
        status: "pending"
      });

      await Transaction.create({
        userId: user._id,
        type: "admin_debit",
        amount: fee,
        status: "completed",
        description: `Virtual card application ${request._id}`
      });

      await Reserve.findOneAndUpdate(
        { key: "main" },
        { $inc: { customerLiability: -fee } }
      );

      return res.status(201).json({
        success: true,
        message: "Demann kat la resevwa. Li ap tann revizyon.",
        balance: Number(user.balance),
        request
      });
    } catch (error) {
      await User.findByIdAndUpdate(user._id, { $inc: { balance: fee } });
      throw error;
    }
  } catch (error) {
    console.error("CARD_REQUEST_ERROR:", error);
    return res.status(500).json({ success: false, message: "Pa rive kreye demann kat la." });
  }
});

app.get("/admin/card-requests", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const requests = await VirtualCardRequest.find({})
      .populate("userId", "name email phone balance")
      .sort({ createdAt: -1 });

    return res.json({ success: true, requests });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive chaje demann kat yo." });
  }
});

app.patch("/admin/card-requests/:id", requireAuth, requireAdmin, async (req, res) => {
  try {
    const action = String(req.body.action || "").trim();

    if (!["approve","reject"].includes(action)) {
      return res.status(400).json({ success: false, message: "Aksyon an pa valab." });
    }

    const request = await VirtualCardRequest.findById(req.params.id);

    if (!request) {
      return res.status(404).json({ success: false, message: "Demann kat la pa jwenn." });
    }

    if (request.status !== "pending") {
      return res.status(409).json({ success: false, message: "Demann sa deja trete." });
    }

    request.status = action === "approve" ? "approved" : "rejected";
    request.reviewedBy = req.user.userId;
    request.reviewedAt = new Date();

    await request.save();

    if (action === "reject") {
      await User.findByIdAndUpdate(request.userId, { $inc: { balance: request.fee } });

      const reserve = await getOrCreateReserve();
      reserve.customerLiability =
        Number(reserve.customerLiability || 0) + Number(request.fee || 0);
      await reserve.save();
    }

    return res.json({
      success: true,
      message:
        action === "approve"
          ? "Demann kat la apwouve. Konekte yon card issuer pou emèt kat reyèl la."
          : "Demann kat la rejte epi frè a retounen sou wallet la."
    });
  } catch {
    return res.status(500).json({ success: false, message: "Pa rive trete demann kat la." });
  }
});


/* =========================
   PIN SECURITY
========================= */

app.get(
  "/pin/status",
  requireAuth,
  async (req, res) => {
    try {
      const user = await User.findById(
        req.user.userId
      ).select(
        "pinEnabled pinLockedUntil pinFailedAttempts"
      );

      return res.json({
        success: true,
        pinEnabled: Boolean(user?.pinEnabled),
        lockedUntil: user?.pinLockedUntil || null,
        failedAttempts:
          Number(user?.pinFailedAttempts || 0)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive chaje PIN status la."
      });
    }
  }
);

app.post(
  "/pin/setup",
  requireAuth,
  async (req, res) => {
    try {
      const pin = String(req.body.pin || "");
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const pinCheck = validatePin(pin);

      if (!pinCheck.ok) {
        return res.status(400).json({
          success: false,
          message: pinCheck.message
        });
      }

      const user = await User.findById(
        req.user.userId
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Kont lan pa jwenn."
        });
      }

      if (user.pinEnabled) {
        return res.status(409).json({
          success: false,
          message:
            "PIN deja aktive. Sèvi ak Change PIN."
        });
      }

      const passwordOk =
        await bcrypt.compare(
          currentPassword,
          user.password
        );

      if (!passwordOk) {
        return res.status(401).json({
          success: false,
          message: "Modpas la pa kòrèk."
        });
      }

      user.pinHash =
        await bcrypt.hash(pin, 12);

      user.pinEnabled = true;
      user.pinUpdatedAt = new Date();
      user.pinFailedAttempts = 0;
      user.pinLockedUntil = null;
      user.pinVersion =
        Number(user.pinVersion || 0) + 1;

      await user.save();

      return res.json({
        success: true,
        message: "PIN aktive.",
        pinToken: createPinToken(user)
      });
    } catch (error) {
      console.error("PIN_SETUP_ERROR:", error);

      return res.status(500).json({
        success: false,
        message: "Pa rive aktive PIN lan."
      });
    }
  }
);

app.post(
  "/pin/verify",
  requireAuth,
  async (req, res) => {
    try {
      const pin = String(req.body.pin || "");

      const user = await User.findById(
        req.user.userId
      );

      if (!user || !user.pinEnabled) {
        return res.status(400).json({
          success: false,
          message: "PIN poko aktive sou kont sa."
        });
      }

      const now = new Date();

      if (
        user.pinLockedUntil &&
        user.pinLockedUntil > now
      ) {
        return res.status(423).json({
          success: false,
          code: "PIN_LOCKED",
          lockedUntil: user.pinLockedUntil,
          message:
            "PIN bloke tanporèman apre twòp tantativ."
        });
      }

      const ok =
        await bcrypt.compare(
          pin,
          user.pinHash || ""
        );

      if (!ok) {
        user.pinFailedAttempts =
          Number(user.pinFailedAttempts || 0) + 1;

        if (
          user.pinFailedAttempts >=
          PIN_MAX_ATTEMPTS
        ) {
          user.pinLockedUntil =
            new Date(
              Date.now() +
              PIN_LOCK_MINUTES * 60 * 1000
            );

          user.pinFailedAttempts = 0;
        }

        await user.save();

        return res.status(401).json({
          success: false,
          code:
            user.pinLockedUntil
              ? "PIN_LOCKED"
              : "PIN_INCORRECT",
          lockedUntil:
            user.pinLockedUntil || null,
          message:
            user.pinLockedUntil
              ? "Twòp tantativ. PIN bloke pou 15 minit."
              : "PIN pa kòrèk."
        });
      }

      user.pinFailedAttempts = 0;
      user.pinLockedUntil = null;

      await user.save();

      return res.json({
        success: true,
        message: "Kont debloke.",
        pinToken: createPinToken(user)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive verifye PIN lan."
      });
    }
  }
);

app.post(
  "/pin/change",
  requireAuth,
  requirePinUnlock,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPin = String(
        req.body.newPin || ""
      );

      const pinCheck =
        validatePin(newPin);

      if (!pinCheck.ok) {
        return res.status(400).json({
          success: false,
          message: pinCheck.message
        });
      }

      const user = await User.findById(
        req.user.userId
      );

      const passwordOk =
        await bcrypt.compare(
          currentPassword,
          user.password
        );

      if (!passwordOk) {
        return res.status(401).json({
          success: false,
          message: "Modpas la pa kòrèk."
        });
      }

      user.pinHash =
        await bcrypt.hash(newPin, 12);

      user.pinUpdatedAt = new Date();
      user.pinFailedAttempts = 0;
      user.pinLockedUntil = null;
      user.pinVersion =
        Number(user.pinVersion || 0) + 1;

      await user.save();

      return res.json({
        success: true,
        message: "PIN modifye.",
        pinToken: createPinToken(user)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive modifye PIN lan."
      });
    }
  }
);

app.post(
  "/pin/reset",
  requireAuth,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPin = String(
        req.body.newPin || ""
      );

      const pinCheck =
        validatePin(newPin);

      if (!pinCheck.ok) {
        return res.status(400).json({
          success: false,
          message: pinCheck.message
        });
      }

      const user = await User.findById(
        req.user.userId
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Kont lan pa jwenn."
        });
      }

      const passwordOk =
        await bcrypt.compare(
          currentPassword,
          user.password
        );

      if (!passwordOk) {
        return res.status(401).json({
          success: false,
          message: "Modpas la pa kòrèk."
        });
      }

      user.pinHash =
        await bcrypt.hash(newPin, 12);

      user.pinEnabled = true;
      user.pinUpdatedAt = new Date();
      user.pinFailedAttempts = 0;
      user.pinLockedUntil = null;
      user.pinVersion =
        Number(user.pinVersion || 0) + 1;

      await user.save();

      return res.json({
        success: true,
        message: "PIN reset.",
        pinToken: createPinToken(user)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive reset PIN lan."
      });
    }
  }
);

/* =========================
   PASSWORD SECURITY
========================= */

app.post(
  "/password/change",
  requireAuth,
  async (req, res) => {
    try {
      const currentPassword = String(
        req.body.currentPassword || ""
      );

      const newPassword = String(
        req.body.newPassword || ""
      );

      const passwordCheck =
        validateNewPassword(newPassword);

      if (!passwordCheck.ok) {
        return res.status(400).json({
          success: false,
          message: passwordCheck.message
        });
      }

      const user = await User.findById(
        req.user.userId
      );

      const ok =
        await bcrypt.compare(
          currentPassword,
          user.password
        );

      if (!ok) {
        return res.status(401).json({
          success: false,
          message: "Modpas aktyèl la pa kòrèk."
        });
      }

      const same =
        await bcrypt.compare(
          newPassword,
          user.password
        );

      if (same) {
        return res.status(400).json({
          success: false,
          message:
            "Nouvo modpas la dwe diferan."
        });
      }

      user.password =
        await bcrypt.hash(
          newPassword,
          12
        );

      user.authVersion =
        Number(user.authVersion || 0) + 1;

      user.pinVersion =
        Number(user.pinVersion || 0) + 1;

      await user.save();

      const token = createToken(user);

      return res.json({
        success: true,
        message:
          "Modpas modifye. Lòt sessions yo revoke.",
        token,
        user: safeUser(user)
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive modifye modpas la."
      });
    }
  }
);

app.post(
  "/password/forgot",
  async (req, res) => {
    const genericMessage =
      "Si email sa egziste, n ap voye enstriksyon reset la.";

    try {
      const email = normalizeEmail(
        req.body.email
      );

      const user =
        await User.findOne({ email });

      if (!user) {
        return res.json({
          success: true,
          message: genericMessage
        });
      }

      if (
        user.passwordResetRequestedAt &&
        Date.now() -
          new Date(
            user.passwordResetRequestedAt
          ).getTime() <
          60 * 1000
      ) {
        return res.json({
          success: true,
          message: genericMessage
        });
      }

      const rawToken =
        crypto.randomBytes(32)
          .toString("hex");

      const hash =
        crypto.createHash("sha256")
          .update(rawToken)
          .digest("hex");

      user.passwordResetTokenHash = hash;
      user.passwordResetExpiresAt =
        new Date(
          Date.now() +
          PASSWORD_RESET_MINUTES *
            60 * 1000
        );

      user.passwordResetRequestedAt =
        new Date();

      await user.save();

      try {
        await sendPasswordResetEmail(
          user,
          rawToken
        );
      } catch (error) {
        console.error(
          "PASSWORD_RESET_EMAIL_ERROR:",
          error.message
        );

        if (
          error.message ===
          "PASSWORD_EMAIL_NOT_CONFIGURED"
        ) {
          return res.status(503).json({
            success: false,
            message:
              "Email reset la poko configure sou server la."
          });
        }

        return res.status(502).json({
          success: false,
          message:
            "Pa rive voye email reset la."
        });
      }

      return res.json({
        success: true,
        message: genericMessage
      });
    } catch {
      return res.json({
        success: true,
        message: genericMessage
      });
    }
  }
);

app.post(
  "/password/reset",
  async (req, res) => {
    try {
      const token = String(
        req.body.token || ""
      ).trim();

      const newPassword = String(
        req.body.newPassword || ""
      );

      const passwordCheck =
        validateNewPassword(newPassword);

      if (!passwordCheck.ok) {
        return res.status(400).json({
          success: false,
          message: passwordCheck.message
        });
      }

      const hash =
        crypto.createHash("sha256")
          .update(token)
          .digest("hex");

      const user =
        await User.findOne({
          passwordResetTokenHash: hash,
          passwordResetExpiresAt: {
            $gt: new Date()
          }
        });

      if (!user) {
        return res.status(400).json({
          success: false,
          message:
            "Lyen reset la pa valab oswa li ekspire."
        });
      }

      user.password =
        await bcrypt.hash(
          newPassword,
          12
        );

      user.passwordResetTokenHash = null;
      user.passwordResetExpiresAt = null;
      user.passwordResetRequestedAt = null;

      user.authVersion =
        Number(user.authVersion || 0) + 1;

      user.pinVersion =
        Number(user.pinVersion || 0) + 1;

      await user.save();

      return res.json({
        success: true,
        message:
          "Modpas reset. Ou ka konekte ankò."
      });
    } catch {
      return res.status(500).json({
        success: false,
        message: "Pa rive reset modpas la."
      });
    }
  }
);

/* =========================
   404 HANDLER
========================= */

app.use((req, res) => {
  return res.status(404).json({
    success: false,
    message:
      `Route ${req.method} ${req.path} pa egziste.`
  });
});


/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, _req, res, _next) => {
    console.error(
      "UNHANDLED_ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        error.message ||
        "Yon erè entèn rive sou sèvè a."
    });
  }
);


/* =========================
   START SERVER
========================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `DLM Wallet server running on port ${PORT}`
    );
  }
);
