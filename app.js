const express = require('express');
const mongoose = require('mongoose');
const Post = require('./models/postModel');

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// --- ВАЖЛИВО: Встав сюди свій рядок підключення ---
// Перевір, чи правильний пароль!
const dbURI = 'mongodb+srv://manvelart231_db_user:jSexQ33HpreoYhDf@cluster0.iifflu5.mongodb.net/?appName=Cluster0' 

// 1. Спочатку запускаємо сервер (щоб Render бачив, що ми живі)
// Render видає свій порт у process.env.PORT, якщо його немає - беремо 3000
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Сервер працює на порту ${PORT}`);
});

// 2. Потім підключаємося до бази
mongoose.connect(dbURI)
  .then(() => console.log('Connected to DB'))
  .catch((err) => console.log('DB Connection Error:', err));


// --- МАРШРУТИ ---

app.get('/', (req, res) => {
  Post.find().sort({ createdAt: -1 })
    .then((result) => {
      res.render('index', { posts: result });
    })
    .catch((err) => {
        console.log(err);
        res.send("Помилка завантаження постів: " + err.message);
    });
});

app.get('/add-post', (req, res) => {
  res.render('create');
});

app.post('/posts', (req, res) => {
  const post = new Post(req.body);
  post.save()
    .then(() => res.redirect('/'))
    .catch((err) => console.log(err));
});