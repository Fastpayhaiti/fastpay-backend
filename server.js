const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
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
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);

app.use(express.json({ limit: "100kb" }));

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
        "admin_debit"
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
      role: user.role
    },
    process.env.JWT_SECRET,
    { expiresIn: "12h" }
  );
}

function requireAuth(req, res, next) {
  const header =
    req.headers.authorization || "";

  const [type, token] =
    header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({
      success: false,
      message: "Ou dwe konekte."
    });
  }

  try {
    req.user = jwt.verify(
      token,
      process.env.JWT_SECRET
    );
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
        message:
         
