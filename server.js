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

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error("Origin sa pa otorize pa CORS."));
  },
  methods: ["GET", "POST", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "100kb" }));

if (!process.env.MONGO_URI) {
  throw new Error("MONGO_URI manke nan environment variables.");
}

if (!process.env.JWT_SECRET) {
  throw new Error("JWT_SECRET manke nan environment variables.");
}

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((error) => {
    console.error("MongoDB error:", error.message);
    process.exit(1);
  });

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true },
    phone: { type: String, required: true, unique: true, trim: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0, min: 0 },
    role: {
      type: String,
      enum: ["customer", "admin"],
      default: "customer"
    },
    status: {
      type: String,
      enum: ["Active", "Blocked"],
      default: "Active"
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
      enum: ["deposit", "withdraw", "transfer", "admin_credit", "admin_debit"],
      required: true
    },
    amount: { type: Number, required: true, min: 0.01 },
    status: {
      type: String,
      enum: ["pending", "completed", "rejected"],
      default: "completed"
    },
    description: { type: String, default: "" },
    createdBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
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
  const header = req.headers.authorization || "";
  const [type, token] = header.split(" ");

  if (type !== "Bearer" || !token) {
    return res.status(401).json({
      success: false,
      message: "Ou dwe konekte."
    });
  }

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Session lan pa valab oswa li ekspire."
    });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Aksè admin sèlman."
    });
  }
  return next();
}

app.get("/", (_req, res) => {
  res.json({
    service: "DLM Wallet API",
    status: "online"
  });
});

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    database: mongoose.connection.readyState === 1 ? "connected" : "disconnected"
  });
});

app.post("/register", async (req, res) => {
  try {
    const name = String(req.body.name || req.body.fullname || "").trim();
    const phone = String(req.body.phone || "").trim();
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!name || !phone || !email || password.length < 8) {
      return res.status(400).json({
        success: false,
        message: "Ranpli tout chan yo. Modpas la dwe gen omwen 8 karaktè."
      });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Imel oswa telefòn sa deja egziste."
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const role = email === ADMIN_EMAIL ? "admin" : "customer";

    const user = await User.create({
      name,
      phone,
      email,
      password: hashedPassword,
      balance: 0,
      role,
      status: "Active"
    });

    return res.status(201).json({
      success: true,
      message: "Kont lan kreye avèk siksè.",
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER_ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive kreye kont lan."
    });
  }
});

app.post("/login", async (req, res) => {
  try {
    const email = normalizeEmail(req.body.email);
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Imel ak modpas obligatwa."
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Imel oswa modpas pa kòrèk."
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Imel oswa modpas pa kòrèk."
      });
    }

    if (user.status !== "Active") {
      return res.status(403).json({
        success: false,
        message: "Kont sa bloke oswa li pa aktif."
      });
    }

    return res.json({
      success: true,
      message: "Koneksyon reyisi.",
      token: createToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN_ERROR:", error);
    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive konekte kont lan."
    });
  }
});

app.get("/me", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Kont lan pa egziste."
      });
    }

    return res.json({
      success: true,
      user: publicUser(user)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Pa rive chaje kont lan."
    });
  }
});

app.get("/balance", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select(
      "name email balance role status"
    );

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Itilizatè a pa jwenn."
      });
    }

    return res.json({
      success: true,
      userId: user._id,
      name: user.name,
      email: user.email,
      balance: Number(user.balance || 0),
      role: user.role,
      status: user.status
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Pa rive chaje balans lan."
    });
  }
});

app.post("/withdraw", requireAuth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);

    if (!Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Montan an pa valab."
      });
    }

    const user = await User.findOneAndUpdate(
      {
        _id: req.user.userId,
        balance: { $gte: amount },
        status: "Active"
      },
      { $inc: { balance: -amount } },
      { new: true }
    );

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Balans pa sifi oswa kont lan pa aktif."
      });
    }

    await Transaction.create({
      userId: user._id,
      type: "withdraw",
      amount,
      status: "completed",
      description: String(req.body.description || "Customer withdrawal")
    });

    return res.json({
      success: true,
      message: "Retrè a fèt avèk siksè.",
      balance: Number(user.balance)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive fè retrè a."
    });
  }
});

app.post("/transfer", requireAuth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const recipientEmail = normalizeEmail(req.body.recipientEmail);

    if (!recipientEmail || !Number.isFinite(amount) || amount <= 0) {
      return res.status(400).json({
        success: false,
        message: "Imel moun k ap resevwa a ak montan valab obligatwa."
      });
    }

    if (recipientEmail === normalizeEmail(req.user.email)) {
      return res.status(400).json({
        success: false,
        message: "Ou pa ka transfere sou pwòp kont ou."
      });
    }

    const sender = await User.findOneAndUpdate(
      {
        _id: req.user.userId,
        balance: { $gte: amount },
        status: "Active"
      },
      { $inc: { balance: -amount } },
      { new: true }
    );

    if (!sender) {
      return res.status(400).json({
        success: false,
        message: "Balans pa sifi oswa kont lan pa aktif."
      });
    }

    const recipient = await User.findOneAndUpdate(
      {
        email: recipientEmail,
        status: "Active"
      },
      { $inc: { balance: amount } },
      { new: true }
    );

    if (!recipient) {
      await User.findByIdAndUpdate(sender._id, {
        $inc: { balance: amount }
      });

      return res.status(404).json({
        success: false,
        message: "Kont k ap resevwa a pa jwenn."
      });
    }

    await Transaction.create([
      {
        userId: sender._id,
        type: "transfer",
        amount,
        status: "completed",
        description: `Voye bay ${recipient.email}`
      },
      {
        userId: recipient._id,
        type: "deposit",
        amount,
        status: "completed",
        description: `Resevwa nan men ${sender.email}`
      }
    ]);

    return res.json({
      success: true,
      message: "Transfè a fèt avèk siksè.",
      balance: Number(sender.balance)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Sèvè a pa rive fè transfè a."
    });
  }
});

app.get("/transactions", requireAuth, async (req, res) => {
  try {
    const transactions = await Transaction.find({
      userId: req.user.userId
    }).sort({ createdAt: -1 });

    return res.json({
      success: true,
      transactions
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Pa rive chaje tranzaksyon yo."
    });
  }
});

app.get("/admin/users", requireAuth, requireAdmin, async (_req, res) => {
  try {
    const users = await User.find()
      .select("-password")
      .sort({ createdAt: -1 });

    return res.json({
      success: true,
      users: users.map(publicUser)
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Pa rive chaje kliyan yo."
    });
  }
});

app.patch(
  "/admin/users/:id/balance",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const amount = Number(req.body.amount);
      const description = String(
        req.body.description || "Admin balance adjustment"
      ).trim();

      if (!Number.isFinite(amount) || amount === 0) {
        return res.status(400).json({
          success: false,
          message: "Montan an pa valab."
        });
      }

      const user = await User.findOneAndUpdate(
        {
          _id: req.params.id,
          balance: { $gte: amount < 0 ? Math.abs(amount) : 0 }
        },
        { $inc: { balance: amount } },
        { new: true }
      );

      if (!user) {
        return res.status(400).json({
          success: false,
          message: "Kliyan an pa jwenn oswa balans lan pa ka vin negatif."
        });
      }

      await Transaction.create({
        userId: user._id,
        type: amount > 0 ? "admin_credit" : "admin_debit",
        amount: Math.abs(amount),
        status: "completed",
        description,
        createdBy: req.user.userId
      });

      return res.json({
        success: true,
        message: "Balans kliyan an modifye.",
        user: publicUser(user)
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Pa rive modifye balans kliyan an."
      });
    }
  }
);

app.patch(
  "/admin/users/:id/status",
  requireAuth,
  requireAdmin,
  async (req, res) => {
    try {
      const status = String(req.body.status || "");

      if (!["Active", "Blocked"].includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Status la pa valab."
        });
      }

      const user = await User.findByIdAndUpdate(
        req.params.id,
        { status },
        { new: true }
      );

      if (!user) {
        return res.status(404).json({
          success: false,
          message: "Kliyan an pa jwenn."
        });
      }

      return res.json({
        success: true,
        message: "Status kliyan an modifye.",
        user: publicUser(user)
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "Pa rive modifye status kliyan an."
      });
    }
  }
);

app.use((error, _req, res, _next) => {
  console.error("UNHANDLED_ERROR:", error);

  return res.status(500).json({
    success: false,
    message: "Yon erè entèn rive sou sèvè a."
  });
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`DLM Wallet server running on port ${PORT}`);
});
