const express = require('express');
const session = require('express-session');
const path = require('path');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();

// Добавьте это перед всеми маршрутами
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "img-src 'self' data: https://cdn.glitch.global");
  next();
});

// Middleware безопасности
app.use(helmet({
  contentSecurityPolicy: false, // Отключаем встроенный CSP
  crossOriginResourcePolicy: { policy: "cross-origin" } // Для Glitch
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Настройка CORS для Glitch
app.use((req, res, next) => {
  const allowedOrigins = [
    `https://${process.env.PROJECT_DOMAIN}.glitch.me`,
    'https://glitch.com',
    'http://localhost:3000'
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-CSRF-Token');
  res.header('Access-Control-Allow-Credentials', 'true');
  
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  
  next();
});

// Лимитер для авторизации
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Слишком много попыток, попробуйте позже'
});

// Настройка сессии для Glitch
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key-123',
  resave: true,
  saveUninitialized: false,
  cookie: {
    secure: false, // Glitch использует HTTP
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 60 * 60 * 1000
  }
}));

// Подключение к SQLite
const db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
  if (err) {
    console.error('❌ Ошибка подключения к БД:', err.message);
    process.exit(1);
  }
  console.log('✅ Подключено к SQLite базе данных');
});

// Создание таблиц
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP
  )`);
});

// Валидация данных пользователя
const validateUserData = (data) => {
  const errors = [];
  
  if (!data.username || data.username.length < 4) {
    errors.push('Логин должен содержать минимум 4 символа');
  }
  
  if (!data.password || data.password.length < 8) {
    errors.push('Пароль должен содержать минимум 8 символов');
  }
  
  if (!data.name || data.name.length < 2) {
    errors.push('Имя должно содержать минимум 2 символа');
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!data.email || !emailRegex.test(data.email)) {
    errors.push('Введите корректный email');
  }
  
  return errors;
};

// API Routes

// Регистрация
app.post('/api/register', authLimiter, async (req, res) => {
  try {
    const validationErrors = validateUserData(req.body);
    if (validationErrors.length > 0) {
      return res.status(400).json({ errors: validationErrors });
    }

    db.get(`SELECT id FROM users WHERE email = ? OR username = ?`, 
      [req.body.email, req.body.username], 
      async (err, row) => {
        if (err) {
          console.error('Ошибка проверки пользователя:', err);
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        if (row) {
          return res.status(409).json({ error: 'Email или логин уже заняты' });
        }
        
        try {
          const hashedPassword = await bcrypt.hash(req.body.password, 12);
          
          db.run(
            `INSERT INTO users (username, password, name, email) VALUES (?, ?, ?, ?)`,
            [req.body.username, hashedPassword, req.body.name, req.body.email],
            function(err) {
              if (err) {
                console.error('Ошибка создания пользователя:', err);
                return res.status(500).json({ error: 'Ошибка при создании пользователя' });
              }
              
              req.session.regenerate(err => {
                if (err) {
                  console.error('Ошибка регенерации сессии:', err);
                  return res.status(500).json({ error: 'Ошибка сервера' });
                }
                
                req.session.user = {
                  id: this.lastID,
                  username: req.body.username,
                  name: req.body.name
                };
                
                req.session.save(err => {
                  if (err) {
                    console.error('Ошибка сохранения сессии:', err);
                    return res.status(500).json({ error: 'Ошибка сервера' });
                  }
                  
                  res.json({ 
                    success: true,
                    user: req.session.user
                  });
                });
              });
            }
          );
        } catch (hashError) {
          console.error('Ошибка хеширования пароля:', hashError);
          res.status(500).json({ error: 'Ошибка сервера' });
        }
      }
    );
  } catch (error) {
    console.error('Ошибка регистрации:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Вход
app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: 'Заполните все поля' });
    }

    db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
      if (err) {
        console.error('Ошибка БД:', err);
        return res.status(500).json({ error: 'Ошибка сервера' });
      }
      
      if (!user) {
        return res.status(401).json({ error: 'Неверные данные' });
      }
      
      const match = await bcrypt.compare(password, user.password);
      
      if (!match) {
        return res.status(401).json({ error: 'Неверные данные' });
      }
      
      req.session.regenerate(err => {
        if (err) {
          console.error('Ошибка регенерации сессии:', err);
          return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        req.session.user = {
          id: user.id,
          username: user.username,
          name: user.name
        };
        
        req.session.save(err => {
          if (err) {
            console.error('Ошибка сохранения сессии:', err);
            return res.status(500).json({ error: 'Ошибка сервера' });
          }
          
          res.json({ 
            success: true,
            user: req.session.user
          });
        });
      });
    });
  } catch (error) {
    console.error('Ошибка входа:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Выход
app.post('/api/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Ошибка выхода:', err);
      return res.status(500).json({ error: 'Ошибка при выходе' });
    }
    
    res.clearCookie('connect.sid');
    res.json({ success: true });
  });
});

// Проверка статуса авторизации
app.get('/api/auth-status', (req, res) => {
  if (!req.session.user) {
    return res.json({ isAuthenticated: false });
  }
  
  res.json({
    isAuthenticated: true,
    user: req.session.user
  });
});

// Статические файлы
app.use(express.static(path.join(__dirname, 'public')));

// Обработка маршрутов
app.get(['/', '/about', '/services', '/contacts', '/login', '/register', '/account'], (req, res) => {
  const page = req.path === '/' ? 'index' : req.path.substring(1);
  res.sendFile(path.join(__dirname, 'public', `${page}.html`));
});

// Обработка 404
app.use((req, res) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Обработка ошибок
app.use((err, req, res, next) => {
  console.error('Ошибка:', err.stack);
  res.status(500).json({ 
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : null
  });
});

// Запуск сервера
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Сервер запущен на порту ${PORT}`);
  console.log(`👉 Доступен по адресу: https://${process.env.PROJECT_DOMAIN}.glitch.me`);
});