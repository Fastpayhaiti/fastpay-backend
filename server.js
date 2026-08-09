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
    },
    externalId: {
      type: String,
      default: null,
      index: true
    },
    metadata: {
      type: mongoose.Schema.Types.Mixed,
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

const withdrawalRequestSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    amount: { type: Number, required: true, min: 0.01 },
    currency: { type: String, enum: ["USD"], default: "USD" },
    method: { type: String, enum: ["MonCash", "NatCash", "Bank"], required: true },
    account: { type: String, required: true, trim: true },
    note: { type: String, default: "", trim: true },
    status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
    reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", default: null },
    reviewedAt: { type: Date, default: null },
    rejectionReason: { type: String, default: "" }
  },
  { timestamps: true }
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
const WithdrawalRequest = mongoose.model(
  "WithdrawalRequest",
  withdrawalRequestSchema
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
   WITHDRAWALS
========================= */

app.post(
  "/withdraw",
  requireAuth,
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);
      const method = String(req.body.method || "").trim();
      const account = String(req.body.account || "").trim();
      const note = String(req.body.note || "").trim();

      if (!Number.isFinite(amount) || amount <= 0) {
        return res.status(400).json({ success: false, message: "Montan retrè a pa valab." });
      }
      if (!["MonCash", "NatCash", "Bank"].includes(method)) {
        return res.status(400).json({ success: false, message: "Metòd retrè a pa valab." });
      }
      if (!account) {
        return res.status(400).json({ success: false, message: "Nimewo oswa kont pou resevwa lajan an obligatwa." });
      }

      const user = await User.findOneAndUpdate(
        { _id: req.user.userId, balance: { $gte: amount }, status: "Active" },
        { $inc: { balance: -amount } },
        { new: true }
      );

      if (!user) {
        return res.status(400).json({ success: false, message: "Balans pa sifi oswa kont lan pa aktif." });
      }

      try {
        const withdrawal = await WithdrawalRequest.create({
          userId: user._id, amount, currency: "USD", method, account, note, status: "pending"
        });
        return res.status(201).json({
          success: true,
          message: "Demann retrè a voye. Li ap tann verifikasyon admin.",
          withdrawal,
          balance: Number(user.balance)
        });
      } catch (error) {
        await User.findByIdAndUpdate(user._id, { $inc: { balance: amount } });
        throw error;
      }
    } catch (error) {
      console.error("WITHDRAW_REQUEST_ERROR:", error);
      return res.status(500).json({ success: false, message: "Pa rive kreye demann retrè a." });
    }
  }
);

app.get(
  "/withdrawals/mine",
  requireAuth,
  async (req, res) => {
    try {
      const withdrawals = await WithdrawalRequest.find({ userId: req.user.userId }).sort({ createdAt: -1 });
      return res.json({ success: true, withdrawals });
    } catch (error) {
      console.error("MY_WITHDRAWALS_ERROR:", error);
      return res.status(500).json({ success: false, message: "Pa rive chaje demann retrè yo." });
    }
  }
);

/* =========================
   TRANSFER
========================= */

app.post(
  "/transfer",
  requireAuth,
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
   ADMIN WITHDRAWALS
========================= */

app.get(
  "/admin/withdrawals",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const status = String(req.query.status || "").trim();
      const filter = {};
      if (["pending", "approved", "rejected"].includes(status)) filter.status = status;
      const withdrawals = await WithdrawalRequest.find(filter)
        .populate("userId", "name email phone balance")
        .populate("reviewedBy", "name email")
        .sort({ createdAt: -1 });
      return res.json({ success: true, withdrawals });
    } catch (error) {
      console.error("ADMIN_WITHDRAWALS_ERROR:", error);
      return res.status(500).json({ success: false, message: "Pa rive chaje demann retrè yo." });
    }
  }
);

app.patch(
  "/admin/withdrawals/:id/approve",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const session = await mongoose.startSession();
    try {
      let payload;
      await session.withTransaction(async () => {
        const withdrawal = await WithdrawalRequest.findOne({ _id: req.params.id, status: "pending" }).session(session);
        if (!withdrawal) { const e = new Error("Demann retrè sa pa pending oswa li pa egziste."); e.statusCode = 409; throw e; }
        const reserve = await getOrCreateReserve(session);
        const amount = Number(withdrawal.amount);
        if (Number(reserve.cashReserve || 0) < amount || Number(reserve.customerLiability || 0) < amount) {
          const e = new Error("Reserve sistèm nan pa sifi pou approve retrè sa."); e.statusCode = 400; throw e;
        }
        withdrawal.status = "approved";
        withdrawal.reviewedBy = req.user.userId;
        withdrawal.reviewedAt = new Date();
        await withdrawal.save({ session });
        await Transaction.create([{
          userId: withdrawal.userId, type: "withdraw", amount, status: "completed",
          description: `${withdrawal.method} withdrawal approved`, createdBy: req.user.userId
        }], { session });
        reserve.cashReserve = Number(reserve.cashReserve || 0) - amount;
        reserve.customerLiability = Number(reserve.customerLiability || 0) - amount;
        await reserve.save({ session });
        payload = { success: true, message: "Retrè a approve avèk siksè.", withdrawal, reserve: reserveView(reserve) };
      });
      return res.json(payload);
    } catch (error) {
      console.error("APPROVE_WITHDRAWAL_ERROR:", error);
      return res.status(error.statusCode || 500).json({ success: false, message: error.message || "Pa rive approve retrè a." });
    } finally {
      session.endSession();
    }
  }
);

app.patch(
  "/admin/withdrawals/:id/reject",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    const session = await mongoose.startSession();
    try {
      let payload;
      await session.withTransaction(async () => {
        const withdrawal = await WithdrawalRequest.findOne({ _id: req.params.id, status: "pending" }).session(session);
        if (!withdrawal) { const e = new Error("Demann retrè sa pa pending oswa li pa egziste."); e.statusCode = 409; throw e; }
        const user = await User.findByIdAndUpdate(
          withdrawal.userId, { $inc: { balance: Number(withdrawal.amount) } }, { new: true, session }
        );
        if (!user) { const e = new Error("Kliyan an pa jwenn."); e.statusCode = 404; throw e; }
        withdrawal.status = "rejected";
        withdrawal.reviewedBy = req.user.userId;
        withdrawal.reviewedAt = new Date();
        withdrawal.rejectionReason = String(req.body.reason || "").trim();
        await withdrawal.save({ session });
        payload = { success: true, message: "Retrè a rejte epi balans kliyan an retounen.", withdrawal, user: publicUser(user) };
      });
      return res.json(payload);
    } catch (error) {
      console.error("REJECT_WITHDRAWAL_ERROR:", error);
      return res.status(error.statusCode || 500).json({ success: false, message: error.message || "Pa rive rejte retrè a." });
    } finally {
      session.endSession();
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
      const transactions = await Transaction.find({})
        .populate("userId", "name email phone")
        .populate("createdBy", "name email")
        .sort({ createdAt: -1 })
        .limit(1000);
      return res.json({ success: true, transactions });
    } catch (error) {
      console.error("ADMIN_TRANSACTIONS_ERROR:", error);
      return res.status(500).json({ success: false, message: "Pa rive chaje tout tranzaksyon yo." });
    }
  }
);


/* =========================
   RELOADLY INTEGRATION
   Airtime topups + Gift Card catalog
========================= */

const RELOADLY_MODE = String(process.env.RELOADLY_MODE || "sandbox").trim().toLowerCase();
const RELOADLY_CLIENT_ID = String(process.env.RELOADLY_CLIENT_ID || "").trim();
const RELOADLY_CLIENT_SECRET = String(process.env.RELOADLY_CLIENT_SECRET || "").trim();
const RELOADLY_AIRTIME_URL = RELOADLY_MODE === "live"
  ? "https://topups.reloadly.com"
  : "https://topups-sandbox.reloadly.com";
const RELOADLY_GIFTCARD_URL = RELOADLY_MODE === "live"
  ? "https://giftcards.reloadly.com"
  : "https://giftcards-sandbox.reloadly.com";

const reloadlyTokenCache = new Map();

function reloadlyConfigured() {
  return Boolean(RELOADLY_CLIENT_ID && RELOADLY_CLIENT_SECRET);
}

async function reloadlyToken(audience) {
  if (!reloadlyConfigured()) {
    const e = new Error("Reloadly poko configure sou Render. Mete RELOADLY_CLIENT_ID ak RELOADLY_CLIENT_SECRET.");
    e.statusCode = 503;
    throw e;
  }

  const cached = reloadlyTokenCache.get(audience);
  if (cached && cached.expiresAt > Date.now() + 60000) return cached.token;

  const response = await fetch("https://auth.reloadly.com/oauth/token", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_id: RELOADLY_CLIENT_ID,
      client_secret: RELOADLY_CLIENT_SECRET,
      grant_type: "client_credentials",
      audience
    })
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    const e = new Error(data.message || data.error_description || "Reloadly authentication echwe.");
    e.statusCode = 502;
    throw e;
  }

  reloadlyTokenCache.set(audience, {
    token: data.access_token,
    expiresAt: Date.now() + Math.max(60, Number(data.expires_in || 3600)) * 1000
  });
  return data.access_token;
}

async function reloadlyRequest(baseUrl, path, options = {}) {
  const token = await reloadlyToken(baseUrl);
  const response = await fetch(`${baseUrl}${path}`, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    body: options.body ? JSON.stringify(options.body) : undefined
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const e = new Error(data.message || data.errorCode || `Reloadly request echwe (${response.status}).`);
    e.statusCode = response.status >= 400 && response.status < 500 ? 400 : 502;
    e.reloadly = data;
    throw e;
  }
  return data;
}


function roundMoney(value) {
  return Math.round((Number(value) + Number.EPSILON) * 100) / 100;
}

function giftCardSenderUnitPrice(product, unitPrice) {
  const recipientPrice = Number(unitPrice);
  if (!Number.isFinite(recipientPrice) || recipientPrice <= 0) return null;

  if (String(product.denominationType || "").toUpperCase() === "FIXED") {
    const allowed = Array.isArray(product.fixedRecipientDenominations)
      ? product.fixedRecipientDenominations.map(Number)
      : [];
    if (!allowed.some(v => Math.abs(v - recipientPrice) < 0.001)) return null;

    const maps = Array.isArray(product.fixedRecipientToSenderDenominationsMap)
      ? product.fixedRecipientToSenderDenominationsMap
      : [];
    for (const entry of maps) {
      if (!entry || typeof entry !== "object") continue;
      for (const [k, v] of Object.entries(entry)) {
        if (Math.abs(Number(k) - recipientPrice) < 0.001) return Number(v);
      }
    }
  } else {
    const min = Number(product.minRecipientDenomination || 0);
    const max = Number(product.maxRecipientDenomination || product.maxrecipientDenomination || 0);
    if (min && recipientPrice < min) return null;
    if (max && recipientPrice > max) return null;
  }

  const rate = Number(product.recipientCurrencyToSenderCurrencyExchangeRate || 1);
  return recipientPrice * rate;
}

app.get("/reloadly/status", requireAuth, async (_req, res) => {
  return res.json({
    success: true,
    configured: reloadlyConfigured(),
    mode: RELOADLY_MODE === "live" ? "live" : "sandbox",
    airtime: true,
    giftCardsCatalog: true
  });
});

app.get("/reloadly/operators/countries/:countryCode", requireAuth, async (req, res) => {
  try {
    const countryCode = String(req.params.countryCode || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(countryCode)) return res.status(400).json({ success:false, message:"Country code la pa valab." });
    const data = await reloadlyRequest(RELOADLY_AIRTIME_URL, `/operators/countries/${encodeURIComponent(countryCode)}?includeBundles=true&includeData=true&includePin=true&suggestedAmounts=true&suggestedAmountsMap=true`);
    return res.json({ success:true, operators:data });
  } catch (error) {
    console.error("RELOADLY_OPERATORS_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message });
  }
});

app.get("/reloadly/operators/auto-detect", requireAuth, async (req, res) => {
  try {
    const phone = String(req.query.phone || "").replace(/[^0-9+]/g, "");
    const countryCode = String(req.query.countryCode || "HT").trim().toUpperCase();
    if (!phone) return res.status(400).json({ success:false, message:"Nimewo telefòn lan obligatwa." });
    const data = await reloadlyRequest(RELOADLY_AIRTIME_URL, `/operators/auto-detect/phone/${encodeURIComponent(phone)}/countries/${encodeURIComponent(countryCode)}?suggestedAmounts=true&suggestedAmountsMap=true`);
    return res.json({ success:true, operator:data });
  } catch (error) {
    console.error("RELOADLY_AUTODETECT_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message });
  }
});

app.post("/reloadly/topups", requireAuth, async (req, res) => {
  let debitedUser = null;
  try {
    const amount = Number(req.body.amount);
    const operatorId = Number(req.body.operatorId);
    const countryCode = String(req.body.countryCode || "HT").trim().toUpperCase();
    const number = String(req.body.number || "").replace(/[^0-9]/g, "");

    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ success:false, message:"Montan topup la pa valab." });
    if (!Number.isInteger(operatorId) || operatorId <= 0) return res.status(400).json({ success:false, message:"Operator ID la pa valab." });
    if (!/^[A-Z]{2}$/.test(countryCode) || !number) return res.status(400).json({ success:false, message:"Country code oswa nimewo telefòn lan pa valab." });

    debitedUser = await User.findOneAndUpdate(
      { _id:req.user.userId, balance:{ $gte:amount }, status:"Active" },
      { $inc:{ balance:-amount } },
      { new:true }
    );
    if (!debitedUser) return res.status(400).json({ success:false, message:"Balans pa sifi oswa kont lan pa aktif." });

    const customIdentifier = `DLM-TOPUP-${debitedUser._id}-${Date.now()}`;
    const data = await reloadlyRequest(RELOADLY_AIRTIME_URL, "/topups", {
      method:"POST",
      body:{
        operatorId,
        amount,
        useLocalAmount:false,
        customIdentifier,
        recipientPhone:{ countryCode, number }
      }
    });

    await Transaction.create({
      userId:debitedUser._id,
      type:"topup",
      amount,
      status:"completed",
      description:`Reloadly topup ${countryCode} ${number} - ${data.transactionId || customIdentifier}`,
      externalId:String(data.transactionId || customIdentifier),
      metadata:{
        provider:"Reloadly",
        operatorName:data.operatorName || "",
        recipientPhone:data.recipientPhone || `${countryCode}${number}`
      }
    });

    return res.json({
      success:true,
      message:"Topup la voye avèk siksè.",
      balance:Number(debitedUser.balance),
      topup:{
        transactionId:data.transactionId,
        status:data.status,
        operatorName:data.operatorName,
        recipientPhone:data.recipientPhone,
        deliveredAmount:data.deliveredAmount,
        deliveredAmountCurrencyCode:data.deliveredAmountCurrencyCode
      }
    });
  } catch (error) {
    if (debitedUser) {
      try { await User.findByIdAndUpdate(debitedUser._id, { $inc:{ balance:Number(req.body.amount || 0) } }); } catch {}
    }
    console.error("RELOADLY_TOPUP_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message || "Topup la echwe; balans kliyan an retounen." });
  }
});

app.get("/reloadly/giftcards/products", requireAuth, async (req, res) => {
  try {
    const countryCode = String(req.query.countryCode || "US").trim().toUpperCase();
    const size = Math.min(100, Math.max(1, Number(req.query.size || 50)));
    const page = Math.max(1, Number(req.query.page || 1));
    const data = await reloadlyRequest(RELOADLY_GIFTCARD_URL, `/products?countryCode=${encodeURIComponent(countryCode)}&size=${size}&page=${page}`);
    return res.json({ success:true, products:data });
  } catch (error) {
    console.error("RELOADLY_GIFTCARDS_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message });
  }
});

app.get("/reloadly/giftcards/products/:productId", requireAuth, async (req, res) => {
  try {
    const productId = Number(req.params.productId);
    if (!Number.isInteger(productId) || productId <= 0) return res.status(400).json({ success:false, message:"Product ID la pa valab." });
    const data = await reloadlyRequest(RELOADLY_GIFTCARD_URL, `/products/${productId}`);
    return res.json({ success:true, product:data });
  } catch (error) {
    console.error("RELOADLY_GIFTCARD_PRODUCT_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message });
  }
});



/* =========================
   RELOADLY GIFT CARD ORDER
========================= */

app.post("/reloadly/giftcards/orders", requireAuth, async (req, res) => {
  let debitedUser = null;
  let chargedAmount = 0;

  try {
    const productId = Number(req.body.productId);
    const quantity = Math.max(1, Math.min(5, Number(req.body.quantity || 1)));
    const unitPrice = Number(req.body.unitPrice);
    const recipientEmail = normalizeEmail(req.body.recipientEmail || req.user.email);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({ success:false, message:"Product ID la pa valab." });
    }
    if (!Number.isInteger(quantity) || quantity <= 0) {
      return res.status(400).json({ success:false, message:"Quantity a pa valab." });
    }
    if (!Number.isFinite(unitPrice) || unitPrice <= 0) {
      return res.status(400).json({ success:false, message:"Pri gift card la pa valab." });
    }

    const product = await reloadlyRequest(RELOADLY_GIFTCARD_URL, `/products/${productId}`);
    if (String(product.status || "ACTIVE").toUpperCase() !== "ACTIVE") {
      return res.status(400).json({ success:false, message:"Gift card sa pa disponib kounye a." });
    }

    if (String(product.senderCurrencyCode || "USD").toUpperCase() !== "USD") {
      return res.status(400).json({ success:false, message:"Pwodwi sa pa ka vann ak wallet USD sa pou kounye a." });
    }

    const senderUnitPrice = giftCardSenderUnitPrice(product, unitPrice);
    if (!Number.isFinite(senderUnitPrice) || senderUnitPrice <= 0) {
      return res.status(400).json({ success:false, message:"Denomination sa pa valab pou gift card sa." });
    }

    const feePerCard = Number(product.senderFee || 0);
    chargedAmount = roundMoney((senderUnitPrice + feePerCard) * quantity);

    debitedUser = await User.findOneAndUpdate(
      { _id:req.user.userId, balance:{ $gte:chargedAmount }, status:"Active" },
      { $inc:{ balance:-chargedAmount } },
      { new:true }
    );

    if (!debitedUser) {
      return res.status(400).json({ success:false, message:`Balans pa sifi. Acha sa bezwen anviwon $${chargedAmount.toFixed(2)} USD.` });
    }

    const customIdentifier = `DLM-GIFT-${debitedUser._id}-${Date.now()}`;
    const data = await reloadlyRequest(RELOADLY_GIFTCARD_URL, "/orders", {
      method:"POST",
      headers:{ Accept:"application/com.reloadly.giftcards-v1+json" },
      body:{
        productId,
        quantity,
        unitPrice,
        customIdentifier,
        senderName:debitedUser.name || "DLM Wallet",
        recipientEmail
      }
    });

    const actualCost = Number(data.amount);
    if (Number.isFinite(actualCost) && actualCost >= 0 && actualCost < chargedAmount) {
      const refund = roundMoney(chargedAmount - actualCost);
      await User.findByIdAndUpdate(debitedUser._id, { $inc:{ balance:refund } });
      debitedUser.balance = Number(debitedUser.balance) + refund;
      chargedAmount = actualCost;
    }

    await Transaction.create({
      userId:debitedUser._id,
      type:"giftcard",
      amount:roundMoney(chargedAmount),
      status:"completed",
      description:`Reloadly gift card ${data.product?.productName || product.productName || productId} - ${data.transactionId || customIdentifier}`,
      externalId:String(data.transactionId || customIdentifier),
      metadata:{
        provider:"Reloadly",
        productId,
        productName:data.product?.productName || product.productName || "Gift Card",
        unitPrice,
        quantity,
        recipientEmail,
        status:data.status || "SUCCESSFUL"
      }
    });

    return res.json({
      success:true,
      message:"Gift card la achte avèk siksè.",
      balance:Number(debitedUser.balance),
      order:{
        transactionId:data.transactionId,
        status:data.status,
        product:data.product,
        recipientEmail:data.recipientEmail || recipientEmail,
        amount:roundMoney(chargedAmount)
      }
    });
  } catch (error) {
    if (debitedUser) {
      try {
        await User.findByIdAndUpdate(debitedUser._id, { $inc:{ balance:chargedAmount } });
      } catch {}
    }
    console.error("RELOADLY_GIFTCARD_ORDER_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({
      success:false,
      message:error.message || "Acha gift card la echwe; balans kliyan an retounen."
    });
  }
});

app.get("/reloadly/giftcards/orders/:transactionId/cards", requireAuth, async (req, res) => {
  try {
    const transactionId = String(req.params.transactionId || "").trim();
    if (!transactionId) return res.status(400).json({ success:false, message:"Transaction ID obligatwa." });

    const owned = await Transaction.findOne({
      userId:req.user.userId,
      type:"giftcard",
      externalId:transactionId
    });

    if (!owned) return res.status(404).json({ success:false, message:"Gift card sa pa jwenn sou kont ou." });

    const data = await reloadlyRequest(
      RELOADLY_GIFTCARD_URL,
      `/orders/transactions/${encodeURIComponent(transactionId)}/cards`,
      { headers:{ Accept:"application/com.reloadly.giftcards-v2+json" } }
    );

    return res.json({ success:true, cards:data });
  } catch (error) {
    console.error("RELOADLY_GIFTCARD_CODES_ERROR:", error.reloadly || error);
    return res.status(error.statusCode || 500).json({ success:false, message:error.message || "Pa rive chaje gift card code la." });
  }
});

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
