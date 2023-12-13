const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");

const User = require("../models/UserSchema");
const Budget = require("../models/BudgetSchema");

const router = express.Router();

const auth = async (req, res, next) => {
  const token = req.cookies.token;

  try {
    if (!token) {
      throw new Error("No token, authorization denied");
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.userId);

    if (!user || user.status !== "Active") {
      throw new Error("User not authorized");
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({ msg: error.message || "Token is not valid" });
  }
};

const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  next();
};

const handleServerError = (res, error) => {
  console.error(error);
  return res
    .status(500)
    .json({ error: error.message || "Internal server error" });
};

const validatePassword = (password) => {
  const errors = [];

  if (password.length < 6) {
    errors.push("Password must be at least 6 characters long");
  }

  if (!/\d/.test(password)) {
    errors.push("Password must contain at least one number");
  }

  return errors;
};

const registerValidation = [
  body("name").trim().notEmpty().withMessage("Name is required"),
  body("userName")
    .trim()
    .isLength({ min: 1 })
    .withMessage("Username is required")
    .custom(async (value) => {
      const existingUser = await User.findOne({ userName: value });

      if (existingUser) {
        throw new Error("Username is already taken");
      }

      if (!/^[A-Z]/.test(value)) {
        throw new Error("Username must start with a capital letter");
      }

      return true;
    }),
  body("email").isEmail().withMessage("Invalid email address"),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long")
    .matches(/\d/)
    .withMessage("Password must contain at least one number"),
];

router.post("/register", registerValidation, async (req, res) => {
  try {
    const { name, userName, password, email } = req.body;

    if (!name || !userName || !password || !email) {
      return res.status(400).json({
        error: "Registration failed",
        message: "Missing required fields",
      });
    }

    const existingUser = await User.findOne({ $or: [{ userName }, { email }] });

    if (existingUser) {
      return res.status(400).json({
        error: "Registration failed",
        message: "Username or email already exists",
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      userName,
      password: hashedPassword,
      email,
      status: "Registered",
    });

    await newUser.save();

    return res
      .status(201)
      .json({ message: "User registered successfully", user: newUser });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/login", async (req, res) => {
  try {
    const { userName, password } = req.body;

    const user = await User.findOne({ userName });
    if (
      !user ||
      user.status === "Deactivated" ||
      !(await bcrypt.compare(password, user.password))
    )
      return res
        .status(401)
        .json({ error: "Can't access deactivated account" });

    user.status = "Active";
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "365d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: "Login successful" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/logout", async (req, res) => {
  try {
    const { userName } = req.body;

    const user = await User.findOne({ userName });
    if (!user || user.status !== "Active")
      return res.status(404).json({ error: "User not found" });

    user.status = "Inactive";
    await user.save();

    res.clearCookie("token");

    return res.status(200).json({ message: "Logout successful" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/deactivate", async (req, res) => {
  try {
    const { userName } = req.body;

    const user = await User.findOne({ userName });
    if (!user || user.status !== "Active")
      return res.status(404).json({ error: "User not found" });

    user.status = "Deactivated";
    user.deactivationDate = new Date();
    await user.save();

    return res
      .status(200)
      .json({ message: "Account deactivated successfully" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/forgot-password", async (req, res) => {
  try {
    const { email, newPassword } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ error: "User not found" });

    const passwordErrors = validatePassword(newPassword);
    if (passwordErrors.length > 0)
      return res.status(400).json({ error: passwordErrors.join(", ") });

    user.status = "Updating Credentials";
    await user.save();

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "365d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      maxAge: 365 * 24 * 60 * 60 * 1000,
    });

    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.post("/add-budget", auth, async (req, res) => {
  try {
    const { category, subcategory, paymentType, moneyAmount, creationDate } =
      req.body;

    const newBudgetItem = new Budget({
      userId: req.user._id,
      category,
      subcategory,
      paymentType,
      moneyAmount,
      creationDate,
    });

    await newBudgetItem.save();

    return res.status(201).json({
      message: "Budget item added successfully",
      budgetItem: newBudgetItem,
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.put("/edit-budget/:id", auth, async (req, res) => {
  try {
    const { category, subcategory, paymentType, moneyAmount } = req.body;

    const updatedBudgetItem = await Budget.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { category, subcategory, paymentType, moneyAmount },
      { new: true }
    );

    if (!updatedBudgetItem)
      return res.status(404).json({ error: "Budget item not found" });

    return res.status(200).json({
      message: "Budget item updated successfully",
      budgetItem: updatedBudgetItem,
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.delete("/delete-budget/:id", auth, async (req, res) => {
  try {
    const deletedBudgetItem = await Budget.findOneAndDelete({
      _id: req.params.id,
      userId: req.user._id,
    });

    if (!deletedBudgetItem)
      return res.status(404).json({ error: "Budget item not found" });

    return res
      .status(200)
      .json({ message: "Budget item deleted successfully" });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.put("/favorite-budget/:id", auth, async (req, res) => {
  try {
    const updatedBudgetItem = await Budget.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { isFavorite: true },
      { new: true }
    );

    if (!updatedBudgetItem)
      return res.status(404).json({ error: "Budget item not found" });

    return res.status(200).json({
      message: "Budget item marked as favorite",
      budgetItem: updatedBudgetItem,
    });
  } catch (error) {
    handleServerError(res, error);
  }
});

router.get("/filter-budget", auth, async (req, res) => {
  try {
    const { category, moneyAmount } = req.query;

    const filter = { userId: req.user._id };
    if (category) filter.category = category;
    if (moneyAmount) filter.moneyAmount = moneyAmount;

    const filteredBudgetItems = await Budget.find(filter);

    return res.status(200).json({ budgetItems: filteredBudgetItems });
  } catch (error) {
    handleServerError(res, error);
  }
});

module.exports = router;
