const express = require("express");
const router = express.Router();

router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      message: "Ranpli tout chan yo."
    });
  }

  return res.json({
    success: true,
    message: "Kont kreye avèk siksè.",
    user: {
      name,
      email,
      balance: 0,
      role: "client"
    }
  });
});

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Email ak modpas obligatwa."
    });
  }

  return res.json({
    success: true,
    message: "Login reyisi.",
    token: "DLM_WALLET_TOKEN",
    user: {
      email,
      balance: 0,
      role: "client"
    }
  });
});

module.exports = router;
