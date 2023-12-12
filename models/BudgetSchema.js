const mongoose = require("mongoose");

const budgetSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  category: String,
  subcategory: String,
  paymentType: String,
  moneyAmount: Number,
  creationDate: { type: Date, default: Date.now },
  isFavorite: { type: Boolean, default: false },
});

const Budget = mongoose.model("Budget", budgetSchema);

module.exports = Budget;
