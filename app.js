const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const bcrypt = require('bcrypt');
const User = require('./models/userModel');
const Post = require('./models/postModel');
require('dotenv').config();

// ---  ІМПОРТ ЗАХИСТУ  ---
const helmet = require('helmet');
//const mongoSanitize = require('express-mongo-sanitize');
//const xss = require('xss-clean');
const rateLimit = require('express-rate-limit');

const app = express();
app.set('trust proxy', 1); // Довіряти проксі (потрібно для Render + Secure Cookies)

const Joi = require('joi');

// Правила для реєстрації
const registerSchema = Joi.object({
    username: Joi.string().alphanum().min(3).max(30).required(), // Тільки букви/цифри, від 3 до 30 символів
    password: Joi.string().min(6).required() // Пароль мінімум 6 символів
});

// Правила для поста
const postSchema = Joi.object({
    title: Joi.string().min(3).max(100).required(), // Заголовок не довше 100 букв
    description: Joi.string().min(5).required()     // Текст хоча б 5 букв
});

// 1. Helmet (Захищає заголовки). 
// Вимикаємо CSP, щоб не блокував  скрипти темної теми
app.use(helmet({ contentSecurityPolicy: false }));

// 2. Rate Limiting (Обмеження кількості запитів)
// Якщо хтось довбатиме сайт більше 100 разів за 15 хв - його заблокує
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 хвилин
  max: 100, // ліміт 100 запитів з одного IP
  message: 'Забагато запитів з цієї IP-адреси, спробуйте пізніше.'
});
app.use(limiter);





// ---------------------------------------------

app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));


// 3. Data Sanitization (Проти NoSQL Injection)
// Не дає хакерам увійти без пароля через {"$gt": ""}
//app.use(mongoSanitize());
// Налаштування сесії (щоб пам'ятати користувача)
// Налаштування сесії (ЗАХИЩЕНЕ)
// Перетворює <script>alert(1)</script> на безпечний текст
//app.use(xss());



app.use(session({
  secret: process.env.SESSION_SECRET, // В ідеалі це теж треба сховати в .env, як і пароль до бази
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true, // Хакери не зможуть прочитати куки через JS
    secure: process.env.NODE_ENV === 'production', // Працює тільки на HTTPS (на Render це буде true)
    maxAge: 1000 * 60 * 60 * 24 // Сесія живе 1 добу
  }
}));

// Проміжна функція: зберігаємо дані користувача для всіх сторінок
app.use((req, res, next) => {
  res.locals.user = req.session.username; // Тепер ми бачимо ІМ'Я користувача у всіх файлах
  res.locals.userId = req.session.userId;
  res.locals.role = req.session.role; // Щоб знати роль на всіх сторінках
  next();
});

const dbURI = process.env.MONGO_URI; // Ось тут має бути власна база даних 

// --- АВТОРИЗАЦІЯ (Реєстрація та Вхід) ---

// 1. Показати сторінку реєстрації
app.get('/register', (req, res) => {
    res.render('register');
});

// 2. Обробка реєстрації
app.post('/register', async (req, res) => {
    try {
      // 1. ВАЛІДАЦІЯ (НОВЕ)
        // Перевіряємо те, що прийшло (req.body) за нашими правилами
        const { error } = registerSchema.validate(req.body);
        if (error) {
            // Якщо є помилка - сваримося і не пускаємо далі
            return res.render('register', { error: error.details[0].message });
        }
        const { username, password } = req.body;
        // Перевірка, чи існує користувач
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.render('register', { error: 'Цей логін вже зайнятий!' });
        }
        // Шифруємо пароль
        const hashedPassword = await bcrypt.hash(password, 10);
        // Створюємо користувача
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
app.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log(`Пробуємо увійти як: ${username}`); 

        // Шукаємо користувача
        const user = await User.findOne({ username });
        
        if (!user) {
            console.log("Помилка: Такого користувача немає в базі!"); //  Підказка 2
            return res.render('login', { error: 'Такого користувача не існує. Спочатку зареєструйся!' });
        }

        // Перевіряємо пароль
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            console.log("Помилка: Невірний пароль!"); // Підказка 3
            return res.render('login', { error: 'Невірний пароль' });
        }

        console.log(`Успішний вхід! Роль: ${user.role}`);
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

// підключаємося до бази
mongoose.connect(dbURI)
  .then(() => console.log('Connected to DB'))
  .catch((err) => console.log('DB Connection Error:', err));




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
  if (!req.session.userId) {
        return res.redirect('/login');
    }

    // 1. ВАЛІДАЦІЯ (НОВЕ)
    // Ми беремо з форми тільки title і description. Author і Owner ми беремо з сесії, їх перевіряти не треба.
    const { error } = postSchema.validate({ 
        title: req.body.title, 
        description: req.body.description 
    });
    
    if (error) {
        // Тут ми просто повернемо помилку текстом, або можна зробити res.render('create', { error: ... })
        return res.send(`Помилка: ${error.details[0].message} <br> <a href="/add-post">Назад</a>`);
    }
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

// 2. Видалення поста 
app.post('/posts/:id/delete', async (req, res) => {
    try {
        // Якщо користувач не увійшов - на вихід
        if (!req.session.userId) {
            return res.redirect('/login');
        }

        const post = await Post.findById(req.params.id);
        

        // 1. Чи це власник поста (post.owner === userId)
        // 2.  чи це Адмін (role === 'admin')
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
// 2. Зберегти оновлений пост (ВИПРАВЛЕНО: ТЕПЕР З ВАЛІДАЦІЄЮ)
app.post('/posts/:id/edit', async (req, res) => {
    try {
        if (!req.session.userId) return res.redirect('/login');

        // --- 1. ВАЛІДАЦІЯ (Закриваємо дірку в захисті) ---
        // Перевіряємо новий текст тими ж правилами, що і при створенні
        const { error } = postSchema.validate({ 
            title: req.body.title, 
            description: req.body.description 
        });
        
        if (error) {
            // Якщо текст задовгий або короткий - не зберігаємо
            return res.send(`Помилка редагування: ${error.details[0].message} <br> <a href="/">На головну</a>`);
        }

        const post = await Post.findById(req.params.id);

        // --- 2. ЗБЕРЕЖЕННЯ ---
        // Перевіряємо, чи це власник, і зберігаємо тільки якщо валідація пройшла успішно
        if (post.owner.toString() === req.session.userId) {
            await Post.findByIdAndUpdate(req.params.id, {
                title: req.body.title,
                description: req.body.description
            });
            console.log("Пост успішно оновлено!");
        }
        
        res.redirect('/');
    } catch (err) {
        console.log(err);
        res.redirect('/');
    }
});

// Запуск сервера
app.listen(3000, () => {
    console.log('Сервер запущено! Відкрий http://localhost:3000');
});