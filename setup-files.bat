@echo off
echo Creating PolyLearn Backend Files...

REM Create directories
mkdir config 2>nul
mkdir controllers 2>nul
mkdir middleware 2>nul
mkdir models 2>nul
mkdir routes 2>nul
mkdir database 2>nul

echo ✅ Directories created

REM Create .env file
echo # Server Configuration> .env
echo PORT=5000>> .env
echo NODE_ENV=development>> .env
echo.>> .env
echo # MySQL Database Configuration>> .env
echo DB_HOST=localhost>> .env
echo DB_USER=root>> .env
echo DB_PASSWORD=>> .env
echo DB_NAME=polylearn_db>> .env
echo DB_PORT=3306>> .env
echo.>> .env
echo # JWT Authentication>> .env
echo JWT_SECRET=polylearn_secret_key_change_in_production>> .env
echo JWT_EXPIRE=7d>> .env
echo.>> .env
echo # CORS>> .env
echo CORS_ORIGIN=http://localhost:3000>> .env

echo ✅ .env file created

REM Create simplified server.js
echo const express = require('express');> server.js
echo const cors = require('cors');>> server.js
echo require('dotenv').config();>> server.js
echo.>> server.js
echo const app = express();>> server.js
echo.>> server.js
echo // Middleware>> server.js
echo app.use(cors());>> server.js
echo app.use(express.json());>> server.js
echo.>> server.js
echo // Health check route>> server.js
echo app.get('/api/health', (req, res) => {>> server.js
echo     res.json({>> server.js
echo         success: true,>> server.js
echo         message: 'PolyLearn API is running',>> server.js
echo         timestamp: new Date().toISOString()>> server.js
echo     });>> server.js
echo });>> server.js
echo.>> server.js
echo // Simple auth routes (demo)>> server.js
echo app.post('/api/auth/login', (req, res) => {>> server.js
echo     const { email, password } = req.body;>> server.js
echo     console.log('Login attempt:', email);>> server.js
echo.>> server.js
echo     // Demo authentication>> server.js
echo     if (email && password) {>> server.js
echo         res.json({>> server.js
echo             success: true,>> server.js
echo             message: 'Login successful',>> server.js
echo             token: 'demo_jwt_token',>> server.js
echo             user: {>> server.js
echo                 id: 1,>> server.js
echo                 username: email.split('@')[0],>> server.js
echo                 email: email,>> server.js
echo                 full_name: email.split('@')[0],>> server.js
echo                 lessons_completed: 12,>> server.js
echo                 exercises_completed: 84,>> server.js
echo                 quiz_score: 925,>> server.js
echo                 average_time: 45>> server.js
echo             }>> server.js
echo         });>> server.js
echo     } else {>> server.js
echo         res.status(400).json({>> server.js
echo             success: false,>> server.js
echo             message: 'Email and password required'>> server.js
echo         });>> server.js
echo     }>> server.js
echo });>> server.js
echo.>> server.js
echo app.post('/api/auth/register', (req, res) => {>> server.js
echo     const { username, email, password } = req.body;>> server.js
echo     console.log('Registration:', username, email);>> server.js
echo.>> server.js
echo     if (username && email && password) {>> server.js
echo         res.json({>> server.js
echo             success: true,>> server.js
echo             message: 'Registration successful',>> server.js
echo             token: 'demo_jwt_token',>> server.js
echo             user: {>> server.js
echo                 id: 2,>> server.js
echo                 username: username,>> server.js
echo                 email: email,>> server.js
echo                 full_name: username,>> server.js
echo                 lessons_completed: 0,>> server.js
echo                 exercises_completed: 0,>> server.js
echo                 quiz_score: 0,>> server.js
echo                 average_time: 0>> server.js
echo             }>> server.js
echo         });>> server.js
echo     } else {>> server.js
echo         res.status(400).json({>> server.js
echo             success: false,>> server.js
echo             message: 'All fields required'>> server.js
echo         });>> server.js
echo     }>> server.js
echo });>> server.js
echo.>> server.js
echo // Dashboard route>> server.js
echo app.get('/api/users/dashboard', (req, res) => {>> server.js
echo     res.json({>> server.js
echo         success: true,>> server.js
echo         dashboard: {>> server.js
echo             user: {>> server.js
echo                 id: 1,>> server.js
echo                 username: 'demo',>> server.js
echo                 full_name: 'Demo User',>> server.js
echo                 email: 'demo@example.com'>> server.js
echo             },>> server.js
echo             progress: {>> server.js
echo                 lessons_completed: 12,>> server.js
echo                 total_lessons: 20,>> server.js
echo                 exercises_completed: 84,>> server.js
echo                 total_exercises: 100,>> server.js
echo                 quiz_score: 925,>> server.js
echo                 average_time: 45,>> server.js
echo                 streak_days: 14,>> server.js
echo                 achievements: 8,>> server.js
echo                 accuracy_rate: 92.5>> server.js
echo             }>> server.js
echo         }>> server.js
echo     });>> server.js
echo });>> server.js
echo.>> server.js
echo // Start server>> server.js
echo const PORT = process.env.PORT || 5000;>> server.js
echo app.listen(PORT, () => {>> server.js
echo     console.log(`🚀 Server running on port ${PORT}`);>> server.js
echo     console.log(`🌐 API URL: http://localhost:${PORT}`);>> server.js
echo     console.log(`📊 Health check: http://localhost:${PORT}/api/health`);>> server.js
echo });>> server.js

echo ✅ server.js created

REM Create database schema
echo -- PolyLearn Database Schema> database\schema.sql
echo.>> database\schema.sql
echo CREATE DATABASE IF NOT EXISTS polylearn_db;>> database\schema.sql
echo USE polylearn_db;>> database\schema.sql
echo.>> database\schema.sql
echo CREATE TABLE users (>> database\schema.sql
echo     user_id INT PRIMARY KEY AUTO_INCREMENT,>> database\schema.sql
echo     username VARCHAR(50) UNIQUE NOT NULL,>> database\schema.sql
echo     email VARCHAR(100) UNIQUE NOT NULL,>> database\schema.sql
echo     password_hash VARCHAR(255) NOT NULL,>> database\schema.sql
echo     full_name VARCHAR(100),>> database\schema.sql
echo     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP>> database\schema.sql
echo );>> database\schema.sql
echo.>> database\schema.sql
echo CREATE TABLE user_progress (>> database\schema.sql
echo     progress_id INT PRIMARY KEY AUTO_INCREMENT,>> database\schema.sql
echo     user_id INT,>> database\schema.sql
echo     lessons_completed INT DEFAULT 0,>> database\schema.sql
echo     total_lessons INT DEFAULT 20,>> database\schema.sql
echo     exercises_completed INT DEFAULT 0,>> database\schema.sql
echo     total_exercises INT DEFAULT 100,>> database\schema.sql
echo     quiz_score INT DEFAULT 0,>> database\schema.sql
echo     average_time INT DEFAULT 0,>> database\schema.sql
echo     streak_days INT DEFAULT 0,>> database\schema.sql
echo     achievements INT DEFAULT 0,>> database\schema.sql
echo     accuracy_rate DECIMAL(5,2) DEFAULT 0.00,>> database\schema.sql
echo     FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE>> database\schema.sql
echo );>> database\schema.sql
echo.>> database\schema.sql
echo -- Insert test user (password: test123)>> database\schema.sql
echo INSERT INTO users (username, email, password_hash, full_name) VALUES>> database\schema.sql
echo ('demo', 'demo@example.com', '$2b$10$LcREA1Z8q.Dp4n7VQHvZ.eN.YWqm70xLXvL.t.N8BGsbQHk3S9mXK', 'Demo User');>> database\schema.sql
echo.>> database\schema.sql
echo INSERT INTO user_progress (user_id, lessons_completed, exercises_completed, quiz_score, average_time) VALUES>> database\schema.sql
echo (1, 12, 84, 925, 45);>> database\schema.sql

echo ✅ database/schema.sql created

echo.
echo ============================================
echo 🎉 SETUP COMPLETE!
echo ============================================
echo.
echo Next steps:
echo 1. Update .env with your MySQL password
echo 2. Run MySQL Workbench and execute database/schema.sql
echo 3. Start backend: npm run dev
echo 4. Open frontend in browser
echo.
pause