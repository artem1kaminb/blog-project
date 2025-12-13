const express = require('express');
const mongoose = require('mongoose');
const Post = require('./models/postModel');

const app = express();

// --- ВАЖЛИВО: Встав сюди свій рядок підключення знову ---
const dbURI = 'mongodb+srv://manvelart231_db_user:jSexQ33HpreoYhDf@cluster0.iifflu5.mongodb.net/?appName=Cluster0' 

mongoose.connect(dbURI)
  .then((result) => {
    console.log('Connected to DB');
    app.listen(3000, () => {
      console.log('Сервер працює на http://localhost:3000');
    });
  })
  .catch((err) => console.log(err));

app.set('view engine', 'ejs');

// Цей рядок дозволяє серверу розуміти дані з форми (те, що ти вводиш)
app.use(express.urlencoded({ extended: true }));

// --- МАРШРУТИ ---

// 1. Головна сторінка (показує список)
app.get('/', (req, res) => {
  Post.find().sort({ createdAt: -1 }) // Знайти всі пости і посортувати (нові зверху)
    .then((result) => {
      res.render('index', { posts: result }); // Відмалювати index.ejs і передати туди пости
    })
    .catch((err) => console.log(err));
});

// 2. Сторінка додавання (показує форму)
app.get('/add-post', (req, res) => {
  res.render('create');
});

// 3. Обробка форми (зберігає пост в базу)
app.post('/posts', (req, res) => {
  const post = new Post(req.body); // Створюємо об'єкт з даних форми

  post.save() // Зберігаємо в MongoDB
    .then((result) => {
      res.redirect('/'); // Повертаємо користувача на головну
    })
    .catch((err) => console.log(err));
});