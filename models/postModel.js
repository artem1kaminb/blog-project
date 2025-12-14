const mongoose = require('mongoose');

const postSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: true
  },
  author: {
    type: String, // Ми залишимо ім'я для зручності відображення
    required: true
  },
  owner: { 
    type: mongoose.Schema.Types.ObjectId, // Це спеціальний тип даних "ID Користувача"
    ref: 'User', // Вказуємо, що це ID з колекції користувачів
    required: true 
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

const Post = mongoose.model('Post', postSchema);
module.exports = Post;