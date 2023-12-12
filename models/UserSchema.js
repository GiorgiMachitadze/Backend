const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  name: String,
  userName: { type: String, unique: true },
  password: String,
  email: { type: String, unique: true },
  status: { type: String },
  registrationDate: { type: Date, default: Date.now },
  deactivationDate: Date,
});

const User = mongoose.model("User", userSchema);

module.exports = User;
