let mongoose = require("mongoose");
let Schema = mongoose.Schema;

let postSchema = new Schema({
  title: {
    type: String,
    required: true,
  },
  author: {
    type: String,
    required: true,
  },
  description: { // Додано для виконання Task 1
    type: String,
    required: true
  },
  createdAt: { // Щоб знати дату створення (бонус)
    type: Date,
    default: Date.now
  }
});

let postModel = mongoose.model("postModel", postSchema);

module.exports = postModel;