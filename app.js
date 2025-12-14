const session = require('express-session'); // <--- ДОДАЙ ЦЕ
const User = require('./models/userModel'); // <--- ДОДАЙ ЦЕ (імпорт нової моделі)
const express = require('express');
const mongoose = require('mongoose');
const Post = require('./models/postModel');
const bcrypt = require('bcrypt');

const app = express();

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));

// Налаштування сесії (щоб пам'ятати користувача)
app.use(session({
  secret: 'my secret key', // Секретний код для шифрування куків
  resave: false,
  saveUninitialized: false
}));

// Проміжна функція: зберігаємо дані користувача для всіх сторінок
app.use((req, res, next) => {
  res.locals.user = req.session.username; // Тепер ми бачимо ІМ'Я користувача у всіх файлах
  res.locals.userId = req.session.userId;
  res.locals.role = req.session.role; // Щоб знати роль на всіх сторінках
  next();
});

// --- ВАЖЛИВО: Встав сюди свій рядок підключення ---
// Перевір, чи правильний пароль!
const dbURI = 'mongodb+srv://manvelart231_db_user:jSexQ33HpreoYhDf@cluster0.iifflu5.mongodb.net/?appName=Cluster0' 

// --- АВТОРИЗАЦІЯ (Реєстрація та Вхід) ---

// 1. Показати сторінку реєстрації
app.get('/register', (req, res) => {
    res.render('register');
});

// 2. Обробка реєстрації
app.post('/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        // Перевірка, чи існує користувач
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.render('register', { error: 'Цей логін вже зайнятий!' });
        }
        // Шифруємо пароль
        const hashedPassword = await bcrypt.hash(password, 10);
        // Створюємо користувача
// --- МАГІЯ: Якщо нікнейм "admin", даємо права адміна ---
        const role = (username === 'admin') ? 'admin' : 'user';

        const user = new User({ 
            username, 
            password: hashedPassword,
            role: role // Записуємо роль у базу
        });
        await user.save();
        res.redirect('/login'); // Перекидаємо на вхід
    } catch (err) {
        console.log(err);
        res.send("Помилка реєстрації");
    }
});

// 3. Показати сторінку входу
app.get('/login', (req, res) => {
    res.render('login');
});

// 4. Обробка входу
// 4. Обробка входу (З ПІДКАЗКАМИ В КОНСОЛЬ)
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(`Пробуємо увійти як: ${username}`); // <--- Підказка 1

        // Шукаємо користувача
        const user = await User.findOne({ username });
        
        if (!user) {
            console.log("Помилка: Такого користувача немає в базі!"); // <--- Підказка 2
            return res.render('login', { error: 'Такого користувача не існує. Спочатку зареєструйся!' });
        }

        // Перевіряємо пароль
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("Помилка: Невірний пароль!"); // <--- Підказка 3
            return res.render('login', { error: 'Невірний пароль' });
        }

        // Успіх!
        console.log(`Успішний вхід! Роль: ${user.role}`); // <--- Підказка 4
        req.session.userId = user._id;
        req.session.username = user.username;
        req.session.role = user.role;
        res.redirect('/');
    } catch (err) {
        console.log("Глобальна помилка:", err);
        res.send("Помилка входу");
    }
});

// 5. Вихід з акаунту
app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

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



// --- РОБОТА З ПОСТАМИ ---

// 1. Створення поста
app.post('/posts', (req, res) => {
  // Якщо користувач не увійшов - не даємо створити пост
  if (!req.session.userId) {
      return res.redirect('/login');
  }

  const post = new Post({
      title: req.body.title,
      description: req.body.description,
      author: req.session.username, // Зберігаємо ім'я (щоб показувати на сайті)
      owner: req.session.userId     // Зберігаємо ID (щоб знати, хто РЕАЛЬНИЙ власник)
  });

  post.save()
    .then(() => res.redirect('/'))
    .catch((err) => console.log(err));
});

// 2. Видалення поста (ТЕПЕР БЕЗПЕЧНЕ)
// 2. Видалення поста (ОНОВЛЕНО ДЛЯ АДМІНА)
app.post('/posts/:id/delete', async (req, res) => {
    try {
        // Якщо користувач не увійшов - на вихід
        if (!req.session.userId) {
            return res.redirect('/login');
        }

        const post = await Post.findById(req.params.id);
        
        // --- ГОЛОВНА ЗМІНА ТУТ ---
        // Ми перевіряємо: 
        // 1. Чи це власник поста (post.owner === userId)
        // 2. АБО (||) чи це Адмін (role === 'admin')
        if (post.owner.toString() === req.session.userId || req.session.role === 'admin') {
            await Post.findByIdAndDelete(req.params.id);
            console.log("Пост успішно видалено!");
        } else {
            console.log("Спроба видалити чужий пост без прав адміна.");
        }
        res.redirect('/');
    } catch (err) {
        console.log(err);
        res.redirect('/');
    }
});
// --- РЕДАГУВАННЯ ---

// 1. Показати сторінку редагування
app.get('/posts/:id/edit', async (req, res) => {
    try {
        if (!req.session.userId) return res.redirect('/login');

        const post = await Post.findById(req.params.id);

        // Перевірка: чи це твій пост?
        if (post.owner.toString() !== req.session.userId) {
            return res.redirect('/'); // Якщо чужий - кидаємо на головну
        }

        res.render('edit', { post: post });
    } catch (err) {
        console.log(err);
        res.redirect('/');
    }
});

// 2. Зберегти оновлений пост
app.post('/posts/:id/edit', async (req, res) => {
    try {
        if (!req.session.userId) return res.redirect('/login');

        const post = await Post.findById(req.params.id);

        // Знову перевіряємо права перед збереженням
        if (post.owner.toString() === req.session.userId) {
            // Оновлюємо тільки заголовок і текст
            await Post.findByIdAndUpdate(req.params.id, {
                title: req.body.title,
                description: req.body.description
            });
            console.log("Пост оновлено!");
        }
        
        res.redirect('/');
    } catch (err) {
        console.log(err);
        res.redirect('/');
    }
});

// Запуск сервера (цей код має бути в самому низу)
app.listen(3000, () => {
    console.log('Сервер запущено! Відкрий http://localhost:3000');
});