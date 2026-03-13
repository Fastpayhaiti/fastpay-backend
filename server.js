const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB error:", err.message));

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    balance: { type: Number, default: 0 }
  },
  { timestamps: true }
);

const transactionSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    type: { type: String, enum: ["deposit", "withdraw", "transfer"], required: true },
    amount: { type: Number, required: true },
    status: { type: String, default: "completed" }
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);
const Transaction = mongoose.model("Transaction", transactionSchema);

app.get("/", (req, res) => {
  res.json({ message: "FastPay backend is running" });
});

app.post("/register", async (req, res) => {
  try {
    const { name, phone, email, password } = req.body;

    if (!name || !phone || !email || !password) {
      return res.status(400).json({ message: "Tout chan yo obligatwa" });
    }

    const existingUser = await User.findOne({
      $or: [{ email }, { phone }]
    });

    if (existingUser) {
      return res.status(400).json({ message: "Imel oswa telefòn deja egziste" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      phone,
      email,
      password: hashedPassword,
      balance: 0
    });

    res.status(201).json({
      message: "Kont kreye avèk siksè",
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Imel ak modpas obligatwa" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "Kont lan pa egziste" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Modpas pa bon" });
    }

    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login fèt avèk siksè",
      token,
      user: {
        id: user._id,
        name: user.name,
        phone: user.phone,
        email: user.email,
        balance: user.balance
      }
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.get("/balance/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("name email balance");

    if (!user) {
      return res.status(404).json({ message: "Itilizatè pa jwenn" });
    }

    res.json({
      userId: user._id,
      name: user.name,
      email: user.email,
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.post("/deposit", async (req, res) => {
  try {
    const { userId, amount } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({ message: "userId ak montan valab obligatwa" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Itilizatè pa jwenn" });
    }

    user.balance += Number(amount);
    await user.save();

    await Transaction.create({
      userId,
      type: "deposit",
      amount
    });

    res.json({
      message: "Depo fèt avèk siksè",
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.post("/withdraw", async (req, res) => {
  try {
    const { userId, amount } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({ message: "userId ak montan valab obligatwa" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Itilizatè pa jwenn" });
    }

    if (user.balance < amount) {
      return res.status(400).json({ message: "Balans pa sifi" });
    }

    user.balance -= Number(amount);
    await user.save();

    await Transaction.create({
      userId,
      type: "withdraw",
      amount
    });

    res.json({
      message: "Retrè fèt avèk siksè",
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.post("/transfer", async (req, res) => {
  try {
    const { userId, amount } = req.body;

    if (!userId || !amount || amount <= 0) {
      return res.status(400).json({ message: "userId ak montan valab obligatwa" });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "Itilizatè pa jwenn" });
    }

    if (user.balance < amount) {
      return res.status(400).json({ message: "Balans pa sifi" });
    }

    user.balance -= Number(amount);
    await user.save();

    await Transaction.create({
      userId,
      type: "transfer",
      amount
    });

    res.json({
      message: "Transfè fèt avèk siksè",
      balance: user.balance
    });
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.get("/transactions/:userId", async (req, res) => {
  try {
    const transactions = await Transaction.find({ userId: req.params.userId })
      .sort({ createdAt: -1 });

    res.json(transactions);
  } catch (error) {
    res.status(500).json({ message: "Erè sèvè", error: error.message });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
