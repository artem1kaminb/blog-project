const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  // --- НОВЕ ПОЛЕ ---
  role: {
    type: String, 
    default: 'user' // За замовчуванням усі — звичайні користувачі
  }
});

const User = mongoose.model('User', userSchema);
module.exports = User;