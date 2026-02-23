
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
require('dotenv').config();
const crypto = require('crypto');  

const app = express();



// ============================================
// MIDDLEWARE
// ============================================
app.use(cors({
    origin: ['http://localhost:3000', 'http://127.0.0.1:5500', 'http://localhost:5500', 'http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ============================================
// STATIC FILES & VIDEO CONFIGURATION
// ============================================
const frontendPath = path.join(__dirname, '../frontend');
app.use(express.static(frontendPath));

// Videos directory for serving
const videosPath = path.join(frontendPath, 'videos');
app.use('/videos', express.static(videosPath));

// Upload directories
const VIDEOS_DIR = path.join(__dirname, '../frontend/videos');
const UPLOADS_DIR = path.join(__dirname, 'uploads/videos');

// Create directories if they don't exist
[VIDEOS_DIR, UPLOADS_DIR].forEach(dir => {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
        console.log(`📁 Created directory: ${dir}`);
    }
});

// Serve uploads
const uploadsAbsolutePath = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(uploadsAbsolutePath));

console.log('📁 Uploads directory (absolute):', uploadsAbsolutePath);
console.log('📁 Uploads exists?', fs.existsSync(uploadsAbsolutePath));


// Serve videos from frontend/videos (kung doon naka-save)
app.use('/videos', express.static(path.join(__dirname, '../frontend/videos')));

// Serve uploads from uploads/videos (kung doon din ang files)
app.use('/uploads/videos', express.static(path.join(__dirname, 'uploads/videos')));
// ============================================
// MULTER CONFIGURATION - VIDEO UPLOAD
// ============================================
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, VIDEOS_DIR); // Save directly to frontend/videos
    },
    filename: (req, file, cb) => {
        const uniqueName = Date.now() + path.extname(file.originalname);
        cb(null, uniqueName);
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 500 * 1024 * 1024 }, // 500MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['video/mp4', 'video/webm', 'video/ogg', 'video/quicktime'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only video files are allowed.'));
        }
    }
});



// ============================================
// DATABASE CONNECTION - FIXED
// ============================================
const pool = mysql.createPool({
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || 'thesis',
    database: process.env.DB_NAME || 'polylearn_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    enableKeepAlive: true,
    keepAliveInitialDelay: 0
});

const promisePool = pool.promise();

// Test connection
pool.getConnection((err, connection) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
    } else {
        console.log('✅ Connected to MySQL database');
        connection.release();
    }
});

// ============================================
// AUTHENTICATION MIDDLEWARE - ADDED HERE
// ============================================
// ============================================
// TOOL MANAGER DATABASE SETUP
// ============================================

// Create calculator history table if it doesn't exist
async function initializeToolTables() {
    try {
        console.log('🔄 Initializing Tool Manager tables...');
        
        await promisePool.execute(`
            CREATE TABLE IF NOT EXISTS calculator_history (
                history_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                expression TEXT NOT NULL,
                result VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                INDEX idx_user_history (user_id, created_at)
            )
        `);
        
        console.log('✅ calculator_history table created/verified');
        
    } catch (error) {
        console.error('❌ Error initializing tool tables:', error.message);
    }
}

// Call this after database connection
initializeToolTables();
// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

// Middleware to verify JWT token
// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'Access denied. No token provided.' 
        });
    }

    // Add this line - hardcoded fallback
    const JWT_SECRET = process.env.JWT_SECRET || 'demo_secret_key_for_development_only';
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            console.error('Token verification error:', err.message);
            return res.status(403).json({ 
                success: false, 
                message: 'Invalid or expired token.' 
            });
        }
        
        req.user = user;
        next();
    });
}
// Optional: Admin-only middleware
function requireAdmin(req, res, next) {
    if (req.user && req.user.role === 'admin') {
        next();
    } else {
        return res.status(403).json({ 
            success: false, 
            message: 'Admin access required.' 
        });
    }
}
// Middleware para sa regular users
// ============================================
// FIXED: AUTHENTICATE USER MIDDLEWARE
// ============================================
const authenticateUser = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'No token provided' 
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'demo_secret_key_for_development_only');
        
        // ✅ Siguraduhing may id property
        if (!decoded.id) {
            console.error('❌ Token has no id property:', decoded);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid token format' 
            });
        }
        
        req.user = { 
            id: decoded.id,
            username: decoded.username,
            email: decoded.email,
            role: decoded.role
        };
        
        console.log(`✅ User authenticated: ID ${req.user.id}, Role: ${req.user.role}`);
        next();
    } catch (error) {
        console.error('❌ Token verification error:', error.message);
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
};

// Middleware para sa admin users
const authenticateAdmin = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ 
            success: false, 
            message: 'No token provided' 
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'demo_secret_key_for_development_only');
        
        if (decoded.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Admin access required' 
            });
        }
        
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    } catch (error) {
        return res.status(401).json({ 
            success: false, 
            message: 'Invalid token' 
        });
    }
};

// ============================================
// JWT FUNCTIONS
// ============================================
const generateToken = (userId, username, email, role) => {
    return jwt.sign(
        { 
            id: userId, 
            username, 
            email, 
            role 
        }, 
        process.env.JWT_SECRET || 'demo_secret_key_for_development_only', 
        {
            expiresIn: process.env.JWT_EXPIRE || '1h'
        }
    );
};

const verifyToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'demo_secret_key_for_development_only');
        
        try {
            const [users] = await promisePool.execute(
                'SELECT user_id FROM users WHERE user_id = ? AND is_active = 1',
                [decoded.id]
            );
            
            if (users.length === 0) {
                return res.status(401).json({
                    success: false,
                    message: 'User no longer exists or is inactive'
                });
            }
        } catch (dbError) {
            console.error('❌ Database error during token verification:', dbError.message);
            return res.status(500).json({
                success: false,
                message: 'Database connection error. Please try again.'
            });
        }
        
        req.user = { 
            id: decoded.id,
            username: decoded.username,
            email: decoded.email,
            role: decoded.role
        };
        next();
        
    } catch (error) {
        console.error('❌ Token verification error:', error.message);
        
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token has expired. Please login again.'
            });
        }
        
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
};


// ============================================
// BACKWARD COMPATIBILITY ROUTES
// ============================================

app.post('/api/quizzes/:quizId/start', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/${req.params.quizId}/start to /api/quiz/${req.params.quizId}/start`);
    req.url = `/api/quiz/${req.params.quizId}/start`;
    app._router.handle(req, res);
});

app.get('/api/quizzes/:quizId/questions', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/${req.params.quizId}/questions to /api/quiz/${req.params.quizId}/questions`);
    req.url = `/api/quiz/${req.params.quizId}/questions`;
    app._router.handle(req, res);
});

app.post('/api/quizzes/answer', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/answer to /api/quiz/answer`);
    req.url = `/api/quiz/answer`;
    app._router.handle(req, res);
});

app.post('/api/quizzes/attempt/:attemptId/complete', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/attempt/${req.params.attemptId}/complete to /api/quiz/attempt/${req.params.attemptId}/complete`);
    req.url = `/api/quiz/attempt/${req.params.attemptId}/complete`;
    app._router.handle(req, res);
});

app.get('/api/quizzes/attempt/:attemptId/results', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/attempt/${req.params.attemptId}/results to /api/quiz/attempt/${req.params.attemptId}/results`);
    req.url = `/api/quiz/attempt/${req.params.attemptId}/results`;
    app._router.handle(req, res);
});

app.get('/api/quizzes/user/attempts', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/user/attempts to /api/quiz/user/attempts`);
    req.url = `/api/quiz/user/attempts`;
    app._router.handle(req, res);
});

app.get('/api/quizzes/leaderboard/:period', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/leaderboard/${req.params.period} to /api/quiz/leaderboard/${req.params.period}`);
    req.url = `/api/quiz/leaderboard/${req.params.period}`;
    app._router.handle(req, res);
});

app.get('/api/quizzes/user/points', verifyToken, async (req, res) => {
    console.log(`🔄 Redirecting /api/quizzes/user/points to /api/quiz/user/points`);
    req.url = `/api/quiz/user/points`;
    app._router.handle(req, res);
});
// ============================================
// PROGRESS TRACKING HELPER FUNCTIONS
// ============================================

// Helper function to log user activity
async function logUserActivity(userId, activityType, relatedId = null, details = {}) {
    try {
        // First check if table exists
        try {
            await promisePool.execute(`
                INSERT INTO user_activity_log 
                (user_id, activity_type, related_id, details, activity_timestamp)
                VALUES (?, ?, ?, ?, NOW())
            `, [userId, activityType, relatedId, JSON.stringify(details)]);
            
            console.log(`📝 Activity logged: ${activityType} for user ${userId}`);
        } catch (tableError) {
            if (tableError.code === 'ER_NO_SUCH_TABLE') {
                console.log('⚠️ user_activity_log table not found, creating it...');
                
                await promisePool.execute(`
                    CREATE TABLE IF NOT EXISTS user_activity_log (
                        activity_id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        activity_type VARCHAR(50) NOT NULL,
                        related_id INT,
                        details JSON,
                        activity_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        INDEX idx_user_activity (user_id, activity_timestamp),
                        INDEX idx_activity_type (activity_type, activity_timestamp)
                    )
                `);
                
                await promisePool.execute(`
                    INSERT INTO user_activity_log 
                    (user_id, activity_type, related_id, details, activity_timestamp)
                    VALUES (?, ?, ?, ?, NOW())
                `, [userId, activityType, relatedId, JSON.stringify(details)]);
            } else {
                throw tableError;
            }
        }
        
        // Update daily progress
        await updateDailyProgress(userId, activityType, 0);
        
        // Update progress heatmap
        await updateProgressHeatmap(userId);
        
    } catch (error) {
        console.error('❌ Error logging activity:', error.message);
    }
}

// Helper function to update daily progress
async function updateDailyProgress(userId, activityType, pointsEarned = 0) {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        const [existing] = await promisePool.execute(
            'SELECT * FROM daily_progress WHERE user_id = ? AND progress_date = ?',
            [userId, today]
        );
        
        if (existing.length > 0) {
            if (activityType === 'lesson_completed') {
                await promisePool.execute(`
                    UPDATE daily_progress 
                    SET lessons_completed = lessons_completed + 1,
                        points_earned = points_earned + ?
                    WHERE user_id = ? AND progress_date = ?
                `, [pointsEarned, userId, today]);
            } else if (activityType === 'practice_completed') {
                await promisePool.execute(`
                    UPDATE daily_progress 
                    SET exercises_completed = exercises_completed + 1,
                        points_earned = points_earned + ?
                    WHERE user_id = ? AND progress_date = ?
                `, [pointsEarned, userId, today]);
            } else if (activityType === 'quiz_completed') {
                await promisePool.execute(`
                    UPDATE daily_progress 
                    SET quizzes_completed = quizzes_completed + 1,
                        points_earned = points_earned + ?
                    WHERE user_id = ? AND progress_date = ?
                `, [pointsEarned, userId, today]);
            }
        } else {
            const newRecord = {
                lessons_completed: activityType === 'lesson_completed' ? 1 : 0,
                exercises_completed: activityType === 'practice_completed' ? 1 : 0,
                quizzes_completed: activityType === 'quiz_completed' ? 1 : 0,
                points_earned: pointsEarned
            };
            
            await promisePool.execute(`
                INSERT INTO daily_progress 
                (user_id, progress_date, lessons_completed, exercises_completed, quizzes_completed, points_earned, streak_maintained)
                VALUES (?, ?, ?, ?, ?, ?, TRUE)
            `, [userId, today, newRecord.lessons_completed, newRecord.exercises_completed, newRecord.quizzes_completed, newRecord.points_earned]);
        }
        
        await checkAndUpdateStreak(userId);
        
    } catch (error) {
        console.error('❌ Error updating daily progress:', error.message);
    }
}

// Helper function to update progress heatmap
async function updateProgressHeatmap(userId) {
    try {
        const today = new Date().toISOString().split('T')[0];
        
        const [existing] = await promisePool.execute(
            'SELECT * FROM progress_heatmap WHERE user_id = ? AND activity_date = ?',
            [userId, today]
        );
        
        if (existing.length > 0) {
            await promisePool.execute(`
                UPDATE progress_heatmap 
                SET activity_count = activity_count + 1
                WHERE user_id = ? AND activity_date = ?
            `, [userId, today]);
        } else {
            await promisePool.execute(`
                INSERT INTO progress_heatmap 
                (user_id, activity_date, activity_count, total_time_minutes, points_earned)
                VALUES (?, ?, 1, 0, 0)
            `, [userId, today]);
        }
    } catch (error) {
        console.error('❌ Error updating progress heatmap:', error.message);
    }
}

// Helper function to check and update streak
async function checkAndUpdateStreak(userId) {
    try {
        const today = new Date().toISOString().split('T')[0];
        const yesterday = new Date(Date.now() - 86400000).toISOString().split('T')[0];
        
        const [yesterdayActivity] = await promisePool.execute(
            'SELECT 1 FROM user_activity_log WHERE user_id = ? AND DATE(activity_timestamp) = ? LIMIT 1',
            [userId, yesterday]
        );
        
        const [yesterdayProgress] = await promisePool.execute(
            'SELECT streak_maintained FROM daily_progress WHERE user_id = ? AND progress_date = ?',
            [userId, yesterday]
        );
        
        const wasActiveYesterday = yesterdayActivity.length > 0 || 
                                  (yesterdayProgress.length > 0 && yesterdayProgress[0].streak_maintained);
        
        await promisePool.execute(`
            UPDATE daily_progress 
            SET streak_maintained = ?
            WHERE user_id = ? AND progress_date = ?
        `, [wasActiveYesterday, userId, today]);
        
    } catch (error) {
        console.error('❌ Error updating streak:', error.message);
    }
}

// Helper function to award points
async function awardPoints(userId, pointsType, pointsAmount, description = '', referenceId = null) {
    try {
        await promisePool.execute(`
            INSERT INTO user_points 
            (user_id, points_type, points_amount, description, reference_id)
            VALUES (?, ?, ?, ?, ?)
        `, [userId, pointsType, pointsAmount, description, referenceId]);

        await logUserActivity(userId, 'points_earned', referenceId, {
            points_type: pointsType,
            points_amount: pointsAmount,
            description: description
        });
        
        console.log(`💰 Awarded ${pointsAmount} points to user ${userId} for ${pointsType}`);
        
    } catch (error) {
        console.error('❌ Error awarding points:', error.message);
    }
}

// Helper function to check if already completed
async function checkIfAlreadyCompleted(userId, contentId) {
    try {
        const [existing] = await promisePool.execute(
            'SELECT completion_status FROM user_content_progress WHERE user_id = ? AND content_id = ?',
            [userId, contentId]
        );
        
        return existing.length > 0 && existing[0].completion_status === 'completed';
    } catch (error) {
        console.error('❌ Error checking completion status:', error.message);
        return false;
    }
}

// Helper function to get total lessons count
async function getTotalLessonsCount() {
    try {
        const [result] = await promisePool.execute(`
            SELECT COUNT(*) as count FROM topic_content_items WHERE is_active = TRUE
        `);
        return result[0].count;
    } catch (error) {
        console.error('Get total lessons count error:', error.message);
        return 0;
    }
}

// ============================================
// AUTH ROUTES
// ============================================

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    
    console.log('📝 Login attempt for email:', email);
    
    if (!email || !password) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email and password are required' 
        });
    }
    
    try {
        const [users] = await promisePool.execute(
            'SELECT user_id, username, email, password_hash, full_name, role, is_active FROM users WHERE email = ?', 
            [email]
        );
        
        if (users.length === 0) {
            console.log('❌ User not found for email:', email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        const user = users[0];
        
        if (user.is_active !== 1) {
            console.log('❌ User is inactive:', user.email);
            return res.status(403).json({ 
                success: false, 
                message: 'Account is deactivated. Please contact administrator.' 
            });
        }
        
        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        
        if (!isPasswordValid) {
            console.log('❌ Invalid password for user:', user.email);
            return res.status(401).json({ 
                success: false, 
                message: 'Invalid credentials' 
            });
        }
        
        const token = generateToken(user.user_id, user.username, user.email, user.role);
        
        let progressData = {};
        if (user.role === 'student') {
            try {
                const [progress] = await promisePool.execute(
                    'SELECT * FROM user_progress WHERE user_id = ?',
                    [user.user_id]
                );
                progressData = progress[0] || {};
            } catch (progressError) {
                console.log('⚠️ Progress table not found or error:', progressError.message);
            }
        }
        
        try {
            await promisePool.execute(
                'UPDATE users SET last_login = NOW() WHERE user_id = ?',
                [user.user_id]
            );
        } catch (updateError) {
            console.log('⚠️ Could not update last_login:', updateError.message);
        }
        
        await logUserActivity(user.user_id, 'login');
        
        const userResponse = {
            id: user.user_id,
            username: user.username,
            email: user.email,
            full_name: user.full_name || user.username,
            role: user.role || 'student'
        };
        
        if (user.role === 'student') {
            userResponse.lessons_completed = progressData.lessons_completed || 0;
            userResponse.exercises_completed = progressData.exercises_completed || 0;
            userResponse.quiz_score = progressData.quiz_score || 0;
            userResponse.average_time = progressData.average_time || 0;
            userResponse.streak_days = progressData.streak_days || 0;
            userResponse.achievements = progressData.achievements || 0;
            userResponse.accuracy_rate = progressData.accuracy_rate || 0;
        }
        
        console.log('✅ Login successful! User:', user.username, 'Role:', user.role);
        
        res.json({
            success: true,
            token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Login failed. Please try again.',
            error: error.message 
        });
    }
});

app.post('/api/auth/register', async (req, res) => {
    console.log('📝 REGISTER REQUEST RECEIVED:', req.body);
    
    const { username, email, password, full_name, role, role_secret } = req.body;
    
    if (!username || !email || !password) {
        console.log('❌ Missing required fields');
        return res.status(400).json({
            success: false,
            message: 'Username, email and password are required'
        });
    }
    
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.status(400).json({
            success: false,
            message: 'Invalid email format'
        });
    }
    
    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: 'Password must be at least 6 characters long'
        });
    }
    
    try {
        const [existing] = await promisePool.execute(
            'SELECT * FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existing.length > 0) {
            console.log('❌ User already exists');
            return res.status(400).json({
                success: false,
                message: 'User with this email or username already exists'
            });
        }
        
        const [users] = await promisePool.execute('SELECT COUNT(*) as count FROM users');
        const userCount = users[0].count;
        
        let finalRole = 'student';
        
        if (userCount === 0) {
            finalRole = 'admin';
            console.log('👑 First user registration - assigning admin role');
        } else {
            const teacher_secret = process.env.TEACHER_SECRET || 'TEACHER123';
            const admin_secret = process.env.ADMIN_SECRET || 'ADMIN123';
            
            if (role === 'teacher') {
                if (!role_secret) {
                    return res.status(400).json({
                        success: false,
                        message: 'Access code is required for teacher registration'
                    });
                }
                
                if (role_secret.toUpperCase() !== teacher_secret.toUpperCase()) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid teacher registration code'
                    });
                }
                
                finalRole = 'teacher';
                
            } else if (role === 'admin') {
                if (!role_secret) {
                    return res.status(400).json({
                        success: false,
                        message: 'Access code is required for administrator registration'
                    });
                }
                
                if (role_secret.toUpperCase() !== admin_secret.toUpperCase()) {
                    return res.status(400).json({
                        success: false,
                        message: 'Invalid admin registration code'
                    });
                }
                
                finalRole = 'admin';
            } else {
                finalRole = 'student';
            }
        }
        
        console.log('✅ Final role determined:', finalRole);
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        console.log('💾 Inserting user into database...');
        const [result] = await promisePool.execute(
            'INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES (?, ?, ?, ?, ?, 1)',
            [username, email, hashedPassword, full_name || username, finalRole]
        );
        
        console.log('✅ User inserted with ID:', result.insertId);
        
        if (finalRole === 'student') {
            try {
                await promisePool.execute(
                    'INSERT INTO user_progress (user_id) VALUES (?)',
                    [result.insertId]
                );
                console.log('✅ User progress record created');
                
                const defaultWidgets = [
                    ['progress_summary', 'top-left'],
                    ['recent_activity', 'top-right'],
                    ['goals', 'middle-left'],
                    ['stats', 'middle-right'],
                    ['badges', 'bottom-left'],
                    ['leaderboard', 'bottom-right']
                ];
                
                for (const [widgetType, position] of defaultWidgets) {
                    await promisePool.execute(
                        'INSERT INTO dashboard_widgets (user_id, widget_type, widget_position, is_visible) VALUES (?, ?, ?, TRUE)',
                        [result.insertId, widgetType, position]
                    );
                }
                console.log('✅ Dashboard widgets initialized');
                
            } catch (progressError) {
                console.log('⚠️ Could not initialize progress records:', progressError.message);
            }
        }
        
        const token = generateToken(result.insertId, username, email, finalRole);
        
        const [newUser] = await promisePool.execute(
            `SELECT * FROM users WHERE user_id = ?`,
            [result.insertId]
        );
        
        const userData = newUser[0];
        
        const userResponse = {
            id: userData.user_id,
            username: userData.username,
            email: userData.email,
            full_name: userData.full_name || userData.username,
            role: userData.role || 'student'
        };
        
        console.log('✅ Registration successful!');
        
        res.status(201).json({
            success: true,
            message: `Registration successful. You are registered as ${finalRole}.`,
            token: token,
            user: userResponse
        });
        
    } catch (error) {
        console.error('❌ Registration error:', error.message);
        
        let errorMessage = 'Registration failed';
        if (error.code === 'ER_NO_SUCH_TABLE') {
            errorMessage = 'Database tables not created. Please run the schema.sql file in MySQL.';
        } else if (error.code === 'ER_DUP_ENTRY') {
            errorMessage = 'User already exists';
        }
        
        res.status(500).json({
            success: false,
            message: errorMessage,
            error: error.message
        });
    }
});


// ============================================
// USER PROFILE ENDPOINTS - ADD THIS
// ============================================

// Get user profile
app.get('/api/user/profile', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`👤 Fetching profile for user ID: ${userId}`);
        
        // Get user data from database
        const [users] = await promisePool.query(
            `SELECT 
                user_id as id,
                username,
                email,
                full_name,
                role,
                created_at as joined_date,
                last_login
            FROM users 
            WHERE user_id = ?`,
            [userId]
        );
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const user = users[0];
        
        // Get user stats
        const [stats] = await promisePool.query(`
            SELECT 
                (SELECT COUNT(*) FROM user_content_progress WHERE user_id = ? AND completion_status = 'completed') as lessons_completed,
                (SELECT COUNT(*) FROM user_quiz_attempts WHERE user_id = ? AND completion_status = 'completed') as quizzes_completed,
                (SELECT COUNT(*) FROM user_practice_progress WHERE user_id = ? AND completion_status = 'completed') as exercises_completed,
                (SELECT COALESCE(SUM(points_amount), 0) FROM user_points WHERE user_id = ?) as total_points
        `, [userId, userId, userId, userId]);
        
        const profile = {
            ...user,
            lessons_completed: stats[0]?.lessons_completed || 0,
            quizzes_completed: stats[0]?.quizzes_completed || 0,
            exercises_completed: stats[0]?.exercises_completed || 0,
            total_points: stats[0]?.total_points || 0
        };
        
        console.log(`✅ Profile loaded for ${user.username}`);
        
        res.json({
            success: true,
            profile: profile
        });
        
    } catch (error) {
        console.error('❌ Error fetching profile:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to load profile',
            error: error.message 
        });
    }
});

// Update user profile
app.put('/api/user/profile', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { full_name, username, email } = req.body;
        
        console.log(`✏️ Updating profile for user ${userId}:`, { full_name, username, email });
        
        // Build update query
        const updates = [];
        const values = [];
        
        if (full_name) {
            updates.push('full_name = ?');
            values.push(full_name);
        }
        
        if (username) {
            // Check if username is already taken
            const [existing] = await promisePool.query(
                'SELECT user_id FROM users WHERE username = ? AND user_id != ?',
                [username, userId]
            );
            
            if (existing.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Username already taken'
                });
            }
            
            updates.push('username = ?');
            values.push(username);
        }
        
        if (email) {
            // Check if email is already taken
            const [existing] = await promisePool.query(
                'SELECT user_id FROM users WHERE email = ? AND user_id != ?',
                [email, userId]
            );
            
            if (existing.length > 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Email already registered'
                });
            }
            
            updates.push('email = ?');
            values.push(email);
        }
        
        if (updates.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        // Add updated_at and userId
        updates.push('updated_at = NOW()');
        values.push(userId);
        
        // Execute update
        await promisePool.query(
            `UPDATE users SET ${updates.join(', ')} WHERE user_id = ?`,
            values
        );
        
        // Get updated user data
        const [users] = await promisePool.query(
            'SELECT user_id as id, username, email, full_name, role FROM users WHERE user_id = ?',
            [userId]
        );
        
        console.log(`✅ Profile updated for user ${userId}`);
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            profile: users[0]
        });
        
    } catch (error) {
        console.error('❌ Error updating profile:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update profile',
            error: error.message 
        });
    }
});

// Change password
app.post('/api/user/change-password', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { current_password, new_password, confirm_password } = req.body;
        
        console.log(`🔐 Password change requested for user ${userId}`);
        
        // Validation
        if (!current_password || !new_password || !confirm_password) {
            return res.status(400).json({
                success: false,
                message: 'All fields are required'
            });
        }
        
        if (new_password !== confirm_password) {
            return res.status(400).json({
                success: false,
                message: 'New passwords do not match'
            });
        }
        
        if (new_password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters'
            });
        }
        
        // Get current password hash
        const [users] = await promisePool.query(
            'SELECT password_hash FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Verify current password
        const isValid = await bcrypt.compare(current_password, users[0].password_hash);
        
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }
        
        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(new_password, salt);
        
        // Update password
        await promisePool.query(
            'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?',
            [hashedPassword, userId]
        );
        
        console.log(`✅ Password changed for user ${userId}`);
        
        res.json({
            success: true,
            message: 'Password changed successfully'
        });
        
    } catch (error) {
        console.error('❌ Error changing password:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to change password',
            error: error.message 
        });
    }
});

// ============================================
// SECTION NAVIGATION FUNCTION
// ============================================

/**
 * Show a specific section in the dashboard
 * @param {string} sectionId - The ID of the section to show
 */
function showSection(sectionId) {
    console.log(`📂 Showing section: ${sectionId}`);
    
    // Hide all sections first
    const sections = document.querySelectorAll('.dashboard-section');
    sections.forEach(section => {
        section.classList.remove('active');
        section.style.display = 'none';
    });
    
    // Show the selected section
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
        targetSection.style.display = 'block';
        
        // Update active state in navigation
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
        });
        
        // Find and activate the clicked link
        const activeLink = document.querySelector(`[onclick="showSection('${sectionId}')"]`);
        if (activeLink) {
            activeLink.classList.add('active');
        }
        
        console.log(`✅ Section "${sectionId}" is now visible`);
    } else {
        console.error(`❌ Section "${sectionId}" not found`);
    }
}


// ============================================
// ✅ ADMIN ROUTES - USERS
// ============================================

// Get all real users from database
// ============================================
// ✅ ADMIN ROUTES - USERS (FIXED VERSION)
// ============================================

// Get all real users from database - FIXED
app.get('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching users from database...');
        
        // Check if users table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'users'");
        if (tables.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Users table does not exist'
            });
        }
        
        // FIRST: Get column information para malaman kung anong columns ang available
        const [columns] = await promisePool.query("SHOW COLUMNS FROM users");
        console.log('📋 Available columns:', columns.map(c => c.Field).join(', '));
        
        // Create a map ng available columns
        const columnNames = columns.map(c => c.Field);
        
        // Build query based on available columns
        let selectFields = [];
        
        // Required fields
        if (columnNames.includes('user_id')) selectFields.push('user_id as id');
        else if (columnNames.includes('id')) selectFields.push('id');
        
        if (columnNames.includes('username')) selectFields.push('username');
        if (columnNames.includes('email')) selectFields.push('email');
        if (columnNames.includes('full_name')) selectFields.push('full_name as name');
        else if (columnNames.includes('name')) selectFields.push('name');
        
        if (columnNames.includes('role')) selectFields.push('role');
        
        // Status - check kung may is_active o status column
        if (columnNames.includes('is_active')) selectFields.push('is_active as status');
        else if (columnNames.includes('status')) selectFields.push('status');
        
        // Dates
        if (columnNames.includes('created_at')) selectFields.push('created_at as registrationDate');
        else if (columnNames.includes('registrationDate')) selectFields.push('registrationDate');
        
        if (columnNames.includes('last_login')) selectFields.push('last_login as lastLogin');
        else if (columnNames.includes('lastLogin')) selectFields.push('lastLogin');
        
        // Use created_at as lastActive kung walang updated_at
        if (columnNames.includes('updated_at')) {
            selectFields.push('updated_at as lastActive');
        } else if (columnNames.includes('created_at')) {
            selectFields.push('created_at as lastActive');
        } else {
            selectFields.push('NULL as lastActive');
        }
        
        // Build the query
        const query = `SELECT ${selectFields.join(', ')} FROM users ORDER BY created_at DESC`;
        console.log('📝 Query:', query);
        
        const [users] = await promisePool.query(query);
        
        console.log(`✅ Found ${users.length} users in database`);
        
        // Process users para i-ensure na may laman ang lahat ng fields
        const processedUsers = users.map(user => ({
            id: user.id || 0,
            username: user.username || '',
            email: user.email || '',
            name: user.name || user.username || 'Unknown',
            role: user.role || 'student',
            status: user.status === 1 ? 'active' : (user.status === 0 ? 'inactive' : 'active'),
            registrationDate: user.registrationDate || new Date().toISOString().split('T')[0],
            lastLogin: user.lastLogin || 'Never',
            lastActive: user.lastActive ? formatDateForUser(user.lastActive) : 'Never',
            avatar: getInitialsFromName(user.name || user.username || 'User')
        }));
        
        res.json({
            success: true,
            users: processedUsers
        });
        
    } catch (error) {
        console.error('❌ Error fetching users:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + error.message 
        });
    }
});

// Helper function para sa initials
function getInitialsFromName(name) {
    if (!name) return 'U';
    return name
        .split(' ')
        .map(word => word.charAt(0))
        .join('')
        .toUpperCase()
        .substring(0, 2);
}

// Helper function para sa date formatting
function formatDateForUser(date) {
    if (!date) return 'Never';
    try {
        const d = new Date(date);
        const now = new Date();
        const diffMs = now - d;
        const diffMins = Math.floor(diffMs / 60000);
        const diffHours = Math.floor(diffMs / 3600000);
        const diffDays = Math.floor(diffMs / 86400000);
        
        if (diffMins < 1) return 'Just now';
        if (diffMins < 60) return `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
        if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
        if (diffDays < 7) return `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
        
        return d.toLocaleDateString();
    } catch (e) {
        return 'Unknown';
    }
}



// Get all real feedback from database
// ===== FIXED: Get all real feedback from database =====
app.get('/api/admin/feedback', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching feedback from database...');
        
        const [feedback] = await promisePool.query(`
            SELECT 
                f.feedback_id as id,
                f.user_id,
                u.username as user,
                u.full_name as user_name,
                f.feedback_type as type,
                f.feedback_message as message,
                f.rating,
                f.status,
                f.admin_notes as response,
                f.admin_id as responded_by,
                f.created_at as date,
                f.reviewed_at as response_date,
                -- Generate subject from message (first 50 chars)
                LEFT(f.feedback_message, 50) as subject,
                -- Determine priority based on type or rating
                CASE 
                    WHEN f.feedback_type = 'bug' THEN 'high'
                    WHEN f.feedback_type = 'suggestion' THEN 'medium'
                    ELSE 'low'
                END as priority
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
            ORDER BY f.created_at DESC
        `);
        
        console.log(`✅ Found ${feedback.length} feedback entries`);
        
        // Process feedback to ensure all fields exist
        const processedFeedback = feedback.map(f => ({
            ...f,
            // Ensure subject exists
            subject: f.subject || (f.message ? f.message.substring(0, 30) + '...' : 'No subject'),
            // Set default priority if not set
            priority: f.priority || 'medium'
        }));
        
        res.json({
            success: true,
            feedback: processedFeedback
        });
        
    } catch (error) {
        console.error('❌ Error fetching feedback:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});
// ============================================
// QUIZ PERFORMANCE CHART DATA - LAST 30 DAYS (FIXED TIMEZONE)
// ============================================
app.get('/api/admin/quiz-performance', authenticateAdmin, async (req, res) => {
    try {
        console.log('📊 ===== QUIZ PERFORMANCE ENDPOINT HIT =====');
        
        // STEP 1: Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_quiz_attempts'");
        
        if (tables.length === 0) {
            return res.json({
                success: true,
                chart: {
                    labels: generateLast30DaysLabels(),
                    attempts: new Array(30).fill(0),
                    avg_scores: new Array(30).fill(0)
                }
            });
        }
        
        // STEP 2: Get daily data for last 30 days - FIXED TIMEZONE
        console.log('🔍 Fetching daily data for last 30 days...');
        
        // Use DATE function to handle timezone correctly
        const [dailyData] = await promisePool.execute(`
            SELECT 
                DATE(end_time) as attempt_date,
                COUNT(*) as attempt_count,
                COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts
            WHERE completion_status = 'completed'
                AND end_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(end_time)
            ORDER BY attempt_date ASC
        `);
        
        console.log(`✅ Found ${dailyData.length} days with quiz activity`);
        
        // STEP 3: Generate data for last 30 days
        const labels = [];
        const attempts = new Array(30).fill(0);
        const avgScores = new Array(30).fill(0);
        
        // Get current date at midnight for consistent comparison
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        // Create a map for quick lookup
        const dataMap = {};
        dailyData.forEach(day => {
            // Convert date string to YYYY-MM-DD format
            const dateStr = new Date(day.attempt_date).toISOString().split('T')[0];
            dataMap[dateStr] = {
                attempts: parseInt(day.attempt_count),
                avgScore: Math.round(day.avg_score)
            };
        });
        
        // Loop through last 30 days
        for (let i = 29; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            date.setHours(0, 0, 0, 0);
            
            const dateStr = date.toISOString().split('T')[0];
            const dayAbbr = date.toLocaleDateString('en-US', { weekday: 'short' });
            
            // Add to labels array (from oldest to newest)
            labels.unshift(dayAbbr);
            
            // Check if we have data for this date
            const dayData = dataMap[dateStr];
            if (dayData) {
                // Index 29-i for oldest to newest
                const index = 29 - i;
                attempts[index] = dayData.attempts;
                avgScores[index] = dayData.avgScore;
            }
        }
        
        res.json({
            success: true,
            chart: {
                labels: labels,
                attempts: attempts,
                avg_scores: avgScores
            }
        });
        
    } catch (error) {
        console.error('❌ ERROR in quiz-performance endpoint:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch quiz performance data',
            error: error.message
        });
    }
});

// Helper function to generate labels
function generateLast30DaysLabels() {
    const labels = [];
    for (let i = 29; i >= 0; i--) {
        const date = new Date();
        date.setDate(date.getDate() - i);
        labels.push(date.toLocaleDateString('en-US', { weekday: 'short' }));
    }
    return labels;
}
// ============================================
// FEEDBACK ENDPOINTS
// ============================================

// Submit feedback (public - no authentication required)
app.post('/api/feedback/submit', async (req, res) => {
    try {
        console.log('📝 Received feedback submission:', req.body);
        
        const { 
            feedback_type, 
            feedback_message, 
            rating, 
            user_agent, 
            page_url 
        } = req.body;
        
        // Validate required fields
        if (!feedback_type || !feedback_message) {
            return res.status(400).json({
                success: false,
                message: 'Feedback type and message are required'
            });
        }
        
        // Get user ID from token if authenticated
        let userId = null;
        const token = req.headers.authorization?.split(' ')[1];
        
        if (token) {
            try {
                const decoded = jwt.verify(token, process.env.JWT_SECRET || 'demo_secret_key_for_development_only');
                userId = decoded.id;
            } catch (e) {
                // Token invalid, but that's ok - feedback can be anonymous
                console.log('Anonymous feedback (invalid token)');
            }
        }
        
        // Get IP address
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        
        // Insert into database
        const [result] = await promisePool.query(
            `INSERT INTO feedback 
             (user_id, feedback_type, feedback_message, rating, user_agent, page_url, ip_address, status, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'new', NOW())`,
            [
                userId,
                feedback_type,
                feedback_message,
                rating || null,
                user_agent || null,
                page_url || null,
                ipAddress || null
            ]
        );
        
        console.log(`✅ Feedback saved with ID: ${result.insertId}`);
        
        res.status(201).json({
            success: true,
            message: 'Feedback submitted successfully',
            feedback_id: result.insertId
        });
        
    } catch (error) {
        console.error('❌ Error saving feedback:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to save feedback',
            error: error.message
        });
    }
});

// Get feedback statistics (admin only)
app.get('/api/feedback/stats', authenticateAdmin, async (req, res) => {
    try {
        // Get total count
        const [total] = await promisePool.query('SELECT COUNT(*) as count FROM feedback');
        
        // Get counts by status
        const [byStatus] = await promisePool.query(`
            SELECT status, COUNT(*) as count 
            FROM feedback 
            GROUP BY status
        `);
        
        // Get average rating
        const [avgRating] = await promisePool.query(`
            SELECT COALESCE(AVG(rating), 0) as average 
            FROM feedback 
            WHERE rating IS NOT NULL
        `);
        
        // Get recent trends (last 7 days)
        const [trends] = await promisePool.query(`
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as count
            FROM feedback
            WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        `);
        
        const statusMap = {};
        byStatus.forEach(row => {
            statusMap[row.status] = row.count;
        });
        
        res.json({
            success: true,
            stats: {
                total: total[0].count,
                by_status: statusMap,
                average_rating: parseFloat(avgRating[0].average).toFixed(1),
                trends: trends
            }
        });
        
    } catch (error) {
        console.error('Error fetching feedback stats:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get all feedback (admin only)
app.get('/api/feedback/all', authenticateAdmin, async (req, res) => {
    try {
        const { limit = 20, page = 1, status } = req.query;
        const offset = (page - 1) * limit;
        
        let query = `
            SELECT 
                f.feedback_id as id,
                f.user_id,
                u.username,
                u.full_name,
                f.feedback_type as type,
                f.feedback_message as message,
                f.rating,
                f.status,
                f.admin_notes,
                f.created_at,
                f.reviewed_at,
                f.resolved_at,
                f.page_url,
                f.user_agent
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
        `;
        
        const queryParams = [];
        
        if (status && status !== 'all') {
            query += ` WHERE f.status = ?`;
            queryParams.push(status);
        }
        
        query += ` ORDER BY f.created_at DESC LIMIT ? OFFSET ?`;
        queryParams.push(parseInt(limit), parseInt(offset));
        
        const [feedback] = await promisePool.query(query, queryParams);
        
        // Get total count for pagination
        let countQuery = 'SELECT COUNT(*) as total FROM feedback';
        if (status && status !== 'all') {
            countQuery += ` WHERE status = ?`;
        }
        const [totalResult] = await promisePool.query(
            countQuery, 
            status && status !== 'all' ? [status] : []
        );
        
        res.json({
            success: true,
            feedback: feedback,
            pagination: {
                total: totalResult[0].total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(totalResult[0].total / limit)
            }
        });
        
    } catch (error) {
        console.error('Error fetching feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get single feedback by ID (admin only)
app.get('/api/feedback/:feedbackId', authenticateAdmin, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        
        const [feedback] = await promisePool.query(`
            SELECT 
                f.*,
                u.username,
                u.full_name,
                u.email
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
            WHERE f.feedback_id = ?
        `, [feedbackId]);
        
        if (feedback.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Feedback not found'
            });
        }
        
        res.json({
            success: true,
            feedback: feedback[0]
        });
        
    } catch (error) {
        console.error('Error fetching feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Update feedback status (admin only)
app.post('/api/feedback/:feedbackId/update-status', authenticateAdmin, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        const { status, admin_notes } = req.body;
        const adminId = req.userId;
        
        // Check if feedback exists
        const [existing] = await promisePool.query(
            'SELECT * FROM feedback WHERE feedback_id = ?',
            [feedbackId]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Feedback not found'
            });
        }
        
        const updateFields = [];
        const updateValues = [];
        
        if (status) {
            updateFields.push('status = ?');
            updateValues.push(status);
            
            // Set timestamps based on status
            if (status === 'reviewed') {
                updateFields.push('reviewed_at = NOW()');
            } else if (status === 'resolved' || status === 'closed') {
                updateFields.push('resolved_at = NOW()');
            }
        }
        
        if (admin_notes !== undefined) {
            updateFields.push('admin_notes = ?');
            updateValues.push(admin_notes);
        }
        
        if (adminId) {
            updateFields.push('admin_id = ?');
            updateValues.push(adminId);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        updateValues.push(feedbackId);
        
        await promisePool.query(
            `UPDATE feedback SET ${updateFields.join(', ')} WHERE feedback_id = ?`,
            updateValues
        );
        
        res.json({
            success: true,
            message: 'Feedback updated successfully'
        });
        
    } catch (error) {
        console.error('Error updating feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Delete feedback (admin only)
app.delete('/api/feedback/:feedbackId', authenticateAdmin, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        
        const [result] = await promisePool.query(
            'DELETE FROM feedback WHERE feedback_id = ?',
            [feedbackId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Feedback not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Feedback deleted successfully'
        });
        
    } catch (error) {
        console.error('Error deleting feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get current logged-in user
app.get('/api/user/current', authenticateUser, async (req, res) => {
    try {
        const [user] = await promisePool.query(
            'SELECT user_id as id, username, email, full_name, role, is_active as status FROM users WHERE user_id = ?',
            [req.userId]
        );
        
        if (user.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: user[0]
        });
    } catch (error) {
        console.error('❌ Error fetching current user:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + error.message 
        });
    }
});

// Add this TEMPORARY debug route BEFORE your settings endpoints
app.get('/api/user/debug', authenticateUser, (req, res) => {
    console.log('🔍 DEBUG: authenticateUser worked! User:', req.user);
    res.json({ 
        success: true, 
        message: 'Auth working',
        user: req.user 
    });
});
// ============================================
// USER SETTINGS ENDPOINTS - ADD ALL OF THESE
// ============================================

// ===== GET USER PREFERENCES =====
app.get('/api/user/preferences', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🎯 Loading preferences for user ${userId}`);
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_preferences'");
        
        if (tables.length === 0) {
            // Create table if it doesn't exist
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS user_preferences (
                    pref_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL UNIQUE,
                    adaptive_difficulty BOOLEAN DEFAULT TRUE,
                    preferred_difficulty VARCHAR(20) DEFAULT 'Intermediate',
                    practice_count INT DEFAULT 10,
                    show_solutions BOOLEAN DEFAULT TRUE,
                    language VARCHAR(50) DEFAULT 'English',
                    municipality VARCHAR(100),
                    timezone VARCHAR(50) DEFAULT 'Asia/Manila',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Created user_preferences table');
        }
        
        // Get preferences
        const [prefs] = await promisePool.query(
            'SELECT * FROM user_preferences WHERE user_id = ?',
            [userId]
        );
        
        if (prefs.length > 0) {
            res.json({ 
                success: true, 
                preferences: prefs[0] 
            });
        } else {
            // Return default preferences
            res.json({
                success: true,
                preferences: {
                    adaptive_difficulty: true,
                    preferred_difficulty: 'Intermediate',
                    practice_count: 10,
                    show_solutions: true,
                    language: 'English',
                    timezone: 'Asia/Manila'
                }
            });
        }
    } catch (error) {
        console.error('❌ Error getting preferences:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ===== SAVE USER PREFERENCES =====
app.post('/api/user/preferences', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const prefs = req.body;
        
        console.log(`💾 Saving preferences for user ${userId}:`, prefs);
        
        await promisePool.query(
            `INSERT INTO user_preferences 
             (user_id, adaptive_difficulty, preferred_difficulty, practice_count, 
              show_solutions, language, municipality, timezone)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             adaptive_difficulty = VALUES(adaptive_difficulty),
             preferred_difficulty = VALUES(preferred_difficulty),
             practice_count = VALUES(practice_count),
             show_solutions = VALUES(show_solutions),
             language = VALUES(language),
             municipality = VALUES(municipality),
             timezone = VALUES(timezone),
             updated_at = NOW()`,
            [
                userId, 
                prefs.adaptive_difficulty || true, 
                prefs.preferred_difficulty || 'Intermediate',
                prefs.practice_count || 10,
                prefs.show_solutions || true,
                prefs.language || 'English',
                prefs.municipality || null,
                prefs.timezone || 'Asia/Manila'
            ]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error saving preferences:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== GET NOTIFICATION SETTINGS =====
app.get('/api/user/notifications', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🔔 Loading notification settings for user ${userId}`);
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_notifications'");
        
        if (tables.length === 0) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS user_notifications (
                    notif_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL UNIQUE,
                    weekly_report BOOLEAN DEFAULT TRUE,
                    feature_announcements BOOLEAN DEFAULT TRUE,
                    practice_reminders BOOLEAN DEFAULT TRUE,
                    achievement_alerts BOOLEAN DEFAULT TRUE,
                    email_notifications BOOLEAN DEFAULT TRUE,
                    push_notifications BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Created user_notifications table');
        }
        
        const [notifs] = await promisePool.query(
            'SELECT * FROM user_notifications WHERE user_id = ?',
            [userId]
        );
        
        if (notifs.length > 0) {
            res.json({ success: true, notifications: notifs[0] });
        } else {
            res.json({
                success: true,
                notifications: {
                    weekly_report: true,
                    feature_announcements: true,
                    practice_reminders: true,
                    achievement_alerts: true,
                    email_notifications: true,
                    push_notifications: true
                }
            });
        }
    } catch (error) {
        console.error('❌ Error getting notifications:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ===== SAVE NOTIFICATION SETTINGS =====
app.post('/api/user/notifications', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const notifs = req.body;
        
        console.log(`💾 Saving notifications for user ${userId}:`, notifs);
        
        await promisePool.query(
            `INSERT INTO user_notifications 
             (user_id, weekly_report, feature_announcements, practice_reminders, 
              achievement_alerts, email_notifications, push_notifications)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             weekly_report = VALUES(weekly_report),
             feature_announcements = VALUES(feature_announcements),
             practice_reminders = VALUES(practice_reminders),
             achievement_alerts = VALUES(achievement_alerts),
             email_notifications = VALUES(email_notifications),
             push_notifications = VALUES(push_notifications),
             updated_at = NOW()`,
            [
                userId,
                notifs.weekly_report !== false,
                notifs.feature_announcements !== false,
                notifs.practice_reminders !== false,
                notifs.achievement_alerts !== false,
                notifs.email_notifications !== false,
                notifs.push_notifications !== false
            ]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error saving notifications:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ===== GET PRIVACY SETTINGS =====
app.get('/api/user/privacy', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🔒 Loading privacy settings for user ${userId}`);
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_privacy'");
        
        if (tables.length === 0) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS user_privacy (
                    privacy_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL UNIQUE,
                    two_factor_auth BOOLEAN DEFAULT FALSE,
                    profile_visibility VARCHAR(20) DEFAULT 'Private',
                    data_sharing BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Created user_privacy table');
        }
        
        const [privacy] = await promisePool.query(
            'SELECT * FROM user_privacy WHERE user_id = ?',
            [userId]
        );
        
        if (privacy.length > 0) {
            res.json({ success: true, privacy: privacy[0] });
        } else {
            res.json({
                success: true,
                privacy: {
                    two_factor_auth: false,
                    profile_visibility: 'Private',
                    data_sharing: false
                }
            });
        }
    } catch (error) {
        console.error('❌ Error getting privacy:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== SAVE PRIVACY SETTINGS =====
app.post('/api/user/privacy', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const privacy = req.body;
        
        console.log(`💾 Saving privacy for user ${userId}:`, privacy);
        
        await promisePool.query(
            `INSERT INTO user_privacy 
             (user_id, two_factor_auth, profile_visibility, data_sharing)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             two_factor_auth = VALUES(two_factor_auth),
             profile_visibility = VALUES(profile_visibility),
             data_sharing = VALUES(data_sharing),
             updated_at = NOW()`,
            [
                userId,
                privacy.two_factor_auth || false,
                privacy.profile_visibility || 'Private',
                privacy.data_sharing || false
            ]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error saving privacy:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== GET DISPLAY SETTINGS =====
app.get('/api/user/display', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🎨 Loading display settings for user ${userId}`);
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_display'");
        
        if (tables.length === 0) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS user_display (
                    display_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL UNIQUE,
                    theme VARCHAR(20) DEFAULT 'light',
                    math_style VARCHAR(20) DEFAULT 'Modern',
                    high_contrast BOOLEAN DEFAULT FALSE,
                    font_size VARCHAR(20) DEFAULT 'Medium',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Created user_display table');
        }
        
        const [display] = await promisePool.query(
            'SELECT * FROM user_display WHERE user_id = ?',
            [userId]
        );
        
        if (display.length > 0) {
            res.json({ success: true, display: display[0] });
        } else {
            res.json({
                success: true,
                display: {
                    theme: 'light',
                    math_style: 'Modern',
                    high_contrast: false,
                    font_size: 'Medium'
                }
            });
        }
    } catch (error) {
        console.error('❌ Error getting display:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== SAVE DISPLAY SETTINGS =====
app.post('/api/user/display', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const display = req.body;
        
        console.log(`💾 Saving display for user ${userId}:`, display);
        
        await promisePool.query(
            `INSERT INTO user_display 
             (user_id, theme, math_style, high_contrast, font_size)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
             theme = VALUES(theme),
             math_style = VALUES(math_style),
             high_contrast = VALUES(high_contrast),
             font_size = VALUES(font_size),
             updated_at = NOW()`,
            [
                userId,
                display.theme || 'light',
                display.math_style || 'Modern',
                display.high_contrast || false,
                display.font_size || 'Medium'
            ]
        );
        
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error saving display:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== RESET ALL SETTINGS =====
app.post('/api/user/reset-settings', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🔄 Resetting all settings for user ${userId}`);
        
        // Delete all user settings
        await promisePool.query('DELETE FROM user_preferences WHERE user_id = ?', [userId]);
        await promisePool.query('DELETE FROM user_notifications WHERE user_id = ?', [userId]);
        await promisePool.query('DELETE FROM user_privacy WHERE user_id = ?', [userId]);
        await promisePool.query('DELETE FROM user_display WHERE user_id = ?', [userId]);
        
        res.json({ success: true, message: 'Settings reset successfully' });
    } catch (error) {
        console.error('❌ Error resetting settings:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ===== UPLOAD PROFILE PICTURE =====



// Configure multer for profile pictures
const profileStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, 'uploads/profiles');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const userId = req.user.id;
        const ext = path.extname(file.originalname);
        cb(null, `profile_${userId}_${Date.now()}${ext}`);
    }
});

const profileUpload = multer({ 
    storage: profileStorage,
    limits: { fileSize: 2 * 1024 * 1024 }, // 2MB limit
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (allowedTypes.includes(file.mimetype)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only JPEG, PNG and GIF are allowed.'));
        }
    }
});
app.post('/api/user/upload-photo', authenticateUser, profileUpload.single('profile_picture'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ success: false, message: 'No file uploaded' });
        }
        
        const userId = req.user.id;
        const filePath = `/uploads/profiles/${req.file.filename}`;
        
        // Update user profile picture path in database
        await promisePool.query(
            'UPDATE users SET profile_picture = ? WHERE user_id = ?',
            [filePath, userId]
        );
        
        res.json({ 
            success: true, 
            message: 'Profile picture uploaded successfully',
            file_path: filePath
        });
    } catch (error) {
        console.error('❌ Error uploading profile picture:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== CONNECT EXTERNAL ACCOUNT =====
app.post('/api/user/connect/:provider', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { provider } = req.params;
        
        console.log(`🔗 Connecting ${provider} for user ${userId}`);
        
        // This is a placeholder - implement actual OAuth later
        res.json({ 
            success: true, 
            message: `${provider} account connected successfully (placeholder)`
        });
    } catch (error) {
        console.error('❌ Error connecting account:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== CONNECT EXTERNAL ACCOUNT =====
app.post('/api/user/connect/:provider', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { provider } = req.params;
        
        console.log(`🔗 Connecting ${provider} for user ${userId}`);
        
        // This is a placeholder - implement actual OAuth later
        res.json({ 
            success: true, 
            message: `${provider} account connected successfully (placeholder)`
        });
    } catch (error) {
        console.error('❌ Error connecting account:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== DEACTIVATE ACCOUNT =====
app.post('/api/user/deactivate', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`🔴 Deactivating account for user ${userId}`);
        
        // Soft delete - set is_active to 0
        await promisePool.query(
            'UPDATE users SET is_active = 0, updated_at = NOW() WHERE user_id = ?',
            [userId]
        );
        
        res.json({ success: true, message: 'Account deactivated successfully' });
    } catch (error) {
        console.error('❌ Error deactivating account:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== DELETE ACCOUNT PERMANENTLY =====
app.delete('/api/user/delete', authenticateUser, async (req, res) => {
    const connection = await promisePool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const userId = req.user.id;
        
        console.log(`🗑️ Permanently deleting account for user ${userId}`);
        
        // Delete all user data (cascading will handle related tables)
        await connection.query('DELETE FROM users WHERE user_id = ?', [userId]);
        
        await connection.commit();
        
        res.json({ success: true, message: 'Account deleted permanently' });
    } catch (error) {
        await connection.rollback();
        console.error('❌ Error deleting account:', error);
        res.status(500).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
});

// ===== EXPORT USER DATA =====
app.get('/api/user/export-data', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📤 Exporting data for user ${userId}`);
        
        // Collect all user data
        const [user] = await promisePool.query(
            'SELECT user_id, username, email, full_name, role, created_at FROM users WHERE user_id = ?',
            [userId]
        );
        
        const [preferences] = await promisePool.query(
            'SELECT * FROM user_preferences WHERE user_id = ?',
            [userId]
        );
        
        const [progress] = await promisePool.query(
            'SELECT * FROM user_content_progress WHERE user_id = ?',
            [userId]
        );
        
        const [quizzes] = await promisePool.query(
            'SELECT * FROM user_quiz_attempts WHERE user_id = ?',
            [userId]
        );
        
        const data = {
            user: user[0],
            preferences: preferences[0] || {},
            progress: progress,
            quizzes: quizzes,
            export_date: new Date().toISOString()
        };
        
        res.json({ success: true, data: data });
    } catch (error) {
        console.error('❌ Error exporting data:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ===== CLEAR LEARNING HISTORY =====
app.post('/api/user/clear-history', authenticateUser, async (req, res) => {
    const connection = await promisePool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const userId = req.user.id;
        
        console.log(`🧹 Clearing learning history for user ${userId}`);
        
        // Delete all learning progress
        await connection.query('DELETE FROM user_content_progress WHERE user_id = ?', [userId]);
        await connection.query('DELETE FROM user_quiz_attempts WHERE user_id = ?', [userId]);
        await connection.query('DELETE FROM user_practice_progress WHERE user_id = ?', [userId]);
        await connection.query('DELETE FROM user_activity_log WHERE user_id = ?', [userId]);
        await connection.query('DELETE FROM daily_progress WHERE user_id = ?', [userId]);
        
        await connection.commit();
        
        res.json({ success: true, message: 'Learning history cleared successfully' });
    } catch (error) {
        await connection.rollback();
        console.error('❌ Error clearing history:', error);
        res.status(500).json({ success: false, message: error.message });
    } finally {
        connection.release();
    }
});
// ============================================
// USER MANAGEMENT ENDPOINTS - ADD THIS
// ============================================

// UPDATE user
app.put('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { name, email, role, status } = req.body;
        
        console.log(`📝 Updating user ${userId}:`, { name, email, role, status });
        
        // Check if user exists
        const [user] = await promisePool.query(
            'SELECT user_id FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (user.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Convert status (active/inactive) to is_active (1/0)
        const isActive = status === 'active' || status === 1 || status === '1' ? 1 : 0;
        
        // Update user in database
        const [result] = await promisePool.query(
            `UPDATE users 
             SET full_name = ?, 
                 email = ?, 
                 role = ?, 
                 is_active = ?,
                 updated_at = NOW()
             WHERE user_id = ?`,
            [name, email, role, isActive, userId]
        );
        
        console.log(`✅ User ${userId} updated successfully`);
        
        res.json({
            success: true,
            message: 'User updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating user:', error);
        
        // Check for duplicate email error
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                success: false,
                message: 'Email already exists'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Database error: ' + error.message
        });
    }
});

// CREATE new user
app.post('/api/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const { username, full_name, email, password, role, is_active } = req.body;
        
        console.log('📝 Creating new user:', { username, full_name, email, role });
        
        // Check if user already exists
        const [existing] = await promisePool.query(
            'SELECT user_id FROM users WHERE email = ? OR username = ?',
            [email, username]
        );
        
        if (existing.length > 0) {
            return res.status(400).json({
                success: false,
                message: 'User with this email or username already exists'
            });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Insert user
        const [result] = await promisePool.query(
            `INSERT INTO users 
             (username, full_name, email, password_hash, role, is_active, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [username, full_name, email, hashedPassword, role, is_active]
        );
        
        console.log(`✅ User created with ID: ${result.insertId}`);
        
        res.status(201).json({
            success: true,
            message: 'User created successfully',
            user_id: result.insertId
        });
        
    } catch (error) {
        console.error('❌ Error creating user:', error);
        res.status(500).json({
            success: false,
            message: 'Database error: ' + error.message
        });
    }
});

// DELETE user
app.delete('/api/admin/users/:userId', authenticateAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        console.log(`🗑️ Deleting user ID: ${userId}`);
        
        // Check if user exists
        const [user] = await promisePool.query(
            'SELECT user_id, full_name FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (user.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        // Delete related records first (if tables exist)
        try {
            await promisePool.query('DELETE FROM user_activity_log WHERE user_id = ?', [userId]);
        } catch (e) { console.log('No user_activity_log table'); }
        
        try {
            await promisePool.query('DELETE FROM user_progress WHERE user_id = ?', [userId]);
        } catch (e) { console.log('No user_progress table'); }
        
        try {
            await promisePool.query('DELETE FROM user_points WHERE user_id = ?', [userId]);
        } catch (e) { console.log('No user_points table'); }
        
        try {
            await promisePool.query('DELETE FROM daily_progress WHERE user_id = ?', [userId]);
        } catch (e) { console.log('No daily_progress table'); }
        
        try {
            await promisePool.query('DELETE FROM notifications WHERE user_id = ?', [userId]);
        } catch (e) { console.log('No notifications table'); }
        
        // Delete the user
        const [result] = await promisePool.query(
            'DELETE FROM users WHERE user_id = ?',
            [userId]
        );
        
        console.log(`✅ User ${userId} "${user[0].full_name}" deleted successfully`);
        
        res.json({
            success: true,
            message: `User "${user[0].full_name}" deleted successfully`
        });
        
    } catch (error) {
        console.error('❌ Error deleting user:', error);
        res.status(500).json({
            success: false,
            message: 'Database error: ' + error.message
        });
    }
});
// ============================================
// ✅ ADMIN ROUTES - STRUCTURE
// ============================================


// ============================================
// DASHBOARD ENDPOINTS
// ============================================

// Get dashboard stats
// ============================================
// DASHBOARD STATS ENDPOINT - FIXED VERSION
// ============================================
// ============================================
// DASHBOARD STATS ENDPOINT - COMPLETELY FIXED
// ============================================
app.get('/api/admin/dashboard/stats', authenticateAdmin, async (req, res) => {
    try {
        console.log('📊 Fetching dashboard stats...');
        
        // Get total lessons
        let totalLessons = 0;
        try {
            const [result] = await promisePool.query(
                'SELECT COUNT(*) as count FROM topic_content_items'
            );
            totalLessons = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting total lessons:', e.message);
        }
        
        // Get active users
        let activeUsers = 0;
        try {
            const [result] = await promisePool.query(
                'SELECT COUNT(*) as count FROM users WHERE is_active = 1'
            );
            activeUsers = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting active users:', e.message);
        }
        
        // Get completion rate - SIMPLIFIED
        let completionRate = 0;
        try {
            // Check if user_progress table exists
            const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_progress'");
            if (tables.length > 0) {
                const [result] = await promisePool.query(
                    'SELECT COALESCE(AVG(quiz_score), 0) as rate FROM user_progress'
                );
                completionRate = Math.round(result[0]?.rate || 0);
            }
        } catch (e) {
            console.error('Error getting completion rate:', e.message);
        }
        
        // Get new users this week
        let newThisWeek = 0;
        try {
            const [result] = await promisePool.query(`
                SELECT COUNT(*) as count 
                FROM users 
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            `);
            newThisWeek = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting new users:', e.message);
        }
        
        const stats = {
            total_lessons: totalLessons,
            active_users: activeUsers,
            completion_rate: completionRate,
            new_this_week: newThisWeek
        };
        
        console.log('✅ Dashboard stats:', stats);
        
        res.json({
            success: true,
            stats: stats
        });
        
    } catch (error) {
        console.error('❌ Dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ADMIN ACTIVITY LOG ENDPOINT
// ============================================

app.get('/api/admin/activity-log', authenticateAdmin, async (req, res) => {
    try {
        const { type = 'all', limit = 20 } = req.query;
        
        console.log(`📋 Fetching activity log (type: ${type}, limit: ${limit})...`);
        
        let query = `
            SELECT 
                al.activity_id as id,
                al.user_id,
                al.activity_type,
                al.related_id,
                al.details,
                al.points_earned,
                al.activity_timestamp as timestamp,
                u.username,
                u.full_name as user_name,
                u.role as user_role
            FROM user_activity_log al
            JOIN users u ON al.user_id = u.user_id
            WHERE 1=1
        `;
        
        const params = [];
        
        if (type !== 'all') {
            query += ` AND al.activity_type = ?`;
            params.push(type);
        }
        
        query += ` ORDER BY al.activity_timestamp DESC LIMIT ?`;
        params.push(parseInt(limit));
        
        const [activities] = await promisePool.execute(query, params);
        
        console.log(`✅ Found ${activities.length} activities`);
        
        const formattedActivities = activities.map(activity => {
            let details = {};
            try {
                details = activity.details ? JSON.parse(activity.details) : {};
            } catch (e) {
                details = {};
            }
            
            return {
                id: activity.id,
                user_id: activity.user_id,
                user_name: activity.user_name || activity.username || 'Unknown',
                user_role: activity.user_role,
                activity_type: activity.activity_type,
                description: formatActivityDescription(activity, details),
                points_earned: activity.points_earned || 0,
                timestamp: activity.timestamp,
                time_ago: getTimeAgo(activity.timestamp),
                icon: getActivityIcon(activity.activity_type),
                color: getActivityColor(activity.activity_type)
            };
        });
        
        res.json({
            success: true,
            activities: formattedActivities
        });
        
    } catch (error) {
        console.error('❌ Error fetching activity log:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch activity log',
            error: error.message
        });
    }
});
// ============================================
// PERMANENT FIX: VIDEO ENDPOINT
// ============================================
// ============================================
// PERMANENT FIX: VIDEO ENDPOINT
// ============================================
// ============================================
// FIXED: VIDEO ENDPOINT - Skip video_uploads, use topic_content_items directly
// ============================================
app.get('/api/videos/content/:contentId', verifyToken, async (req, res) => {
    try {
        const { contentId } = req.params;
        
        console.log(`🎬 Fetching video for content ID: ${contentId}`);
        
        // ===== DIRECT TO topic_content_items (skip video_uploads) =====
        const [lessons] = await promisePool.query(`
            SELECT 
                content_id,
                content_title,
                video_filename,
                content_url,
                video_duration_seconds
            FROM topic_content_items
            WHERE content_id = ? AND is_active = 1
        `, [contentId]);
        
        if (lessons.length > 0) {
            const lesson = lessons[0];
            
            // Check if has video_filename (uploaded video)
            if (lesson.video_filename) {
                // ✅ FIXED: Use /videos/ instead of /uploads/videos/
                const videoUrl = `http://localhost:5000/videos/${lesson.video_filename}`;
                
                console.log(`✅ Found video_filename in lesson: ${lesson.video_filename}`);
                console.log(`📺 Video URL: ${videoUrl}`);
                
                return res.json({
                    success: true,
                    video: {
                        url: videoUrl,
                        title: lesson.content_title || 'Video Lesson',
                        duration: lesson.video_duration_seconds || 600,
                        filename: lesson.video_filename,
                        source: 'lesson_video_filename',
                        content_id: contentId
                    }
                });
            }
            
            // Check if has YouTube URL
            if (lesson.content_url) {
                console.log(`✅ Found content_url: ${lesson.content_url}`);
                
                return res.json({
                    success: true,
                    video: {
                        url: lesson.content_url,
                        title: lesson.content_title || 'Video Lesson',
                        duration: lesson.video_duration_seconds || 600,
                        source: lesson.content_url.includes('youtube') ? 'youtube' : 'url',
                        content_id: contentId
                    }
                });
            }
        }
        
        // ===== No video found =====
        console.log(`⚠️ No video found for content ID: ${contentId}`);
        
        res.json({
            success: false,
            message: 'No video found for this content'
        });
        
    } catch (error) {
        console.error('❌ Error in video endpoint:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ============================================
// LESSON STATS ENDPOINT
// ============================================
app.get('/api/admin/lessons/stats', authenticateAdmin, async (req, res) => {
    try {
        console.log('📚 Fetching lesson stats...');
        
        // Get published today
        let publishedToday = 0;
        try {
            const [result] = await promisePool.query(`
                SELECT COUNT(*) as count 
                FROM topic_content_items 
                WHERE DATE(created_at) = CURDATE()
            `);
            publishedToday = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting published today:', e.message);
        }
        
        // Get draft count (assuming is_active = 0 means draft)
        let draftCount = 0;
        try {
            const [result] = await promisePool.query(
                'SELECT COUNT(*) as count FROM topic_content_items WHERE is_active = 0 OR is_active IS NULL'
            );
            draftCount = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting draft count:', e.message);
        }
        
        // Get needs review (lessons without description)
        let needsReview = 0;
        try {
            const [result] = await promisePool.query(`
                SELECT COUNT(*) as count 
                FROM topic_content_items 
                WHERE content_description IS NULL OR content_description = ''
            `);
            needsReview = result[0]?.count || 0;
        } catch (e) {
            console.error('Error getting needs review:', e.message);
        }
        
        // Get engagement rate (simplified)
        let engagementRate = 0;
        try {
            // Students who completed at least one lesson
            const [completed] = await promisePool.query(`
                SELECT COUNT(DISTINCT user_id) as count 
                FROM user_content_progress 
                WHERE completion_status = 'completed'
            `);
            
            // Total students
            const [total] = await promisePool.query(`
                SELECT COUNT(*) as count 
                FROM users 
                WHERE role = 'student'
            `);
            
            if (total[0]?.count > 0) {
                engagementRate = Math.round((completed[0]?.count || 0) * 100 / total[0].count);
            }
        } catch (e) {
            console.error('Error getting engagement rate:', e.message);
        }
        
        const stats = {
            published_today: publishedToday,
            draft_count: draftCount,
            needs_review: needsReview,
            engagement_rate: engagementRate
        };
        
        console.log('✅ Lesson stats:', stats);
        
        res.json({
            success: true,
            stats: stats
        });
        
    } catch (error) {
        console.error('❌ Lesson stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});
// Get recent lessons for dashboard
app.get('/api/admin/lessons/recent', authenticateAdmin, async (req, res) => {
    try {
        const [lessons] = await promisePool.query(`
            SELECT 
                tci.content_id,
                tci.content_title,
                tci.content_description,
                tci.content_type,
                tci.created_at,
                tci.updated_at,
                mt.topic_title,
                cm.module_name,
                u.full_name as created_by
            FROM topic_content_items tci
            LEFT JOIN module_topics mt ON tci.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN users u ON 1=1
            WHERE tci.is_active = TRUE
            ORDER BY tci.created_at DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            lessons: lessons
        });
        
    } catch (error) {
        console.error('Error fetching recent lessons:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Database error: ' + error.message 
        });
    }
});
// ===== GET ADMIN STRUCTURE (Lessons, Modules, Topics) =====
app.get('/api/admin/structure', verifyToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const [lessons] = await promisePool.query(
            'SELECT lesson_id as id, lesson_name as name FROM lessons WHERE is_active = TRUE'
        );
        
        const [modules] = await promisePool.query(`
            SELECT module_id as id, module_name as name, lesson_id 
            FROM course_modules 
            WHERE is_active = TRUE
        `);
        
        const [topics] = await promisePool.query(`
            SELECT topic_id as id, topic_title as name, module_id 
            FROM module_topics 
            WHERE is_active = TRUE
        `);
        
        res.json({
            success: true,
            structure: {
                lessons: lessons,
                modules: modules,
                topics: topics
            }
        });
        
    } catch (error) {
        console.error('Error fetching structure:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch structure'
        });
    }
});

// ===== GET ALL LESSONS FOR ADMIN =====
app.get('/api/admin/lessons', verifyToken, async (req, res) => {
    try {
        // Check if user is admin or teacher
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        console.log('📥 Fetching lessons for admin...');
        
        const sql = `
            SELECT 
                tci.content_id,
                tci.content_title,
                tci.content_description,
                tci.content_type,
                tci.content_url,
                tci.video_filename,
                tci.created_at,
                mt.topic_id,
                mt.topic_title,
                cm.module_id,
                cm.module_name,
                l.lesson_id,
                l.lesson_name
            FROM topic_content_items tci
            LEFT JOIN module_topics mt ON tci.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE tci.is_active = TRUE
            ORDER BY tci.created_at DESC
        `;
        
        const [lessons] = await promisePool.query(sql);
        
        console.log(`✅ Found ${lessons.length} lessons for admin`);
        
        res.json({
            success: true,
            lessons: lessons || []
        });
        
    } catch (error) {
        console.error('❌ Error fetching admin lessons:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch lessons',
            error: error.message
        });
    }
});

// ===== CREATE / UPDATE LESSON (WITH VIDEO UPLOAD) =====
app.post('/api/admin/lessons', 
    verifyToken,
    (req, res, next) => {
        // Check if user is admin or teacher
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        next();
    },
    (req, res, next) => {
        upload.single('video_file')(req, res, function(err) {
            if (err) {
                console.error('❌ Upload error:', err);
                return res.status(400).json({
                    success: false,
                    message: 'File upload failed: ' + err.message
                });
            }
            next();
        });
    },
    async (req, res) => {
        try {
            console.log('📥 ===== ADMIN LESSONS ENDPOINT HIT =====');
            
            const { 
                title, 
                description, 
                topic_id,
                content_type, 
                youtube_url,
                module_id,
                content_id,
                is_update = 'false'
            } = req.body;
            
            const videoFile = req.file;
            const isUpdate = is_update === 'true' || is_update === true;
            
            // ===== VALIDATION =====
            if (!title) {
                return res.status(400).json({
                    success: false,
                    message: 'Title is required'
                });
            }
            
            if (!isUpdate && !topic_id) {
                return res.status(400).json({
                    success: false,
                    message: 'topic_id is required for new lessons'
                });
            }
            
            // ===== PREPARE CONTENT URLS =====
            let contentUrl = null;
            let filePath = null;
            let videoFilename = null;
            
            if (youtube_url) {
                contentUrl = youtube_url;
                console.log('🔗 YouTube URL:', contentUrl);
            } else if (videoFile) {
                videoFilename = videoFile.filename;
                contentUrl = `/videos/${videoFile.filename}`;
                filePath = `/uploads/videos/${videoFile.filename}`;
                console.log('🎬 Video saved:', videoFilename);
            }
            
            const userId = req.user.id;
            
            // ===== UPDATE EXISTING LESSON =====
            if (isUpdate) {
                console.log('🔄 UPDATING lesson ID:', content_id);
                
                let updateFields = [];
                let updateValues = [];
                
                updateFields.push('content_title = ?');
                updateValues.push(title);
                
                updateFields.push('content_description = ?');
                updateValues.push(description || null);
                
                if (topic_id) {
                    updateFields.push('topic_id = ?');
                    updateValues.push(topic_id);
                }
                
                if (module_id) {
                    updateFields.push('module_id = ?');
                    updateValues.push(module_id);
                }
                
                if (youtube_url) {
                    updateFields.push('content_url = ?');
                    updateValues.push(youtube_url);
                    updateFields.push('video_filename = ?');
                    updateValues.push(null);
                } else if (videoFile) {
                    updateFields.push('video_filename = ?');
                    updateValues.push(videoFilename);
                    updateFields.push('content_url = ?');
                    updateValues.push(contentUrl);
                }
                
                updateFields.push('updated_at = NOW()');
                updateValues.push(content_id);
                
                const updateQuery = `UPDATE topic_content_items SET ${updateFields.join(', ')} WHERE content_id = ?`;
                
                await promisePool.query(updateQuery, updateValues);
                console.log('✅ Lesson updated in topic_content_items');
                
                // ===== HANDLE VIDEO_UPLOADS TABLE =====
                if (videoFile) {
                    try {
                        await promisePool.query(`
                            CREATE TABLE IF NOT EXISTS video_uploads (
                                upload_id INT AUTO_INCREMENT PRIMARY KEY,
                                content_id INT NOT NULL,
                                original_filename VARCHAR(255),
                                stored_filename VARCHAR(255),
                                file_path VARCHAR(500),
                                file_size BIGINT,
                                uploaded_by INT,
                                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                                is_active BOOLEAN DEFAULT TRUE,
                                FOREIGN KEY (content_id) REFERENCES topic_content_items(content_id) ON DELETE CASCADE
                            )
                        `);
                        
                        const [existingVideo] = await promisePool.query(
                            'SELECT * FROM video_uploads WHERE content_id = ?',
                            [content_id]
                        );
                        
                        if (existingVideo.length > 0) {
                            await promisePool.query(
                                `UPDATE video_uploads 
                                 SET original_filename = ?,
                                     stored_filename = ?,
                                     file_path = ?,
                                     file_size = ?,
                                     uploaded_by = ?,
                                     updated_at = NOW()
                                 WHERE content_id = ?`,
                                [
                                    videoFile.originalname,
                                    videoFile.filename,
                                    filePath,
                                    videoFile.size,
                                    userId,
                                    content_id
                                ]
                            );
                        } else {
                            await promisePool.query(
                                `INSERT INTO video_uploads 
                                 (content_id, original_filename, stored_filename, file_path, 
                                  file_size, uploaded_by, is_active)
                                 VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
                                [
                                    content_id,
                                    videoFile.originalname,
                                    videoFile.filename,
                                    filePath,
                                    videoFile.size,
                                    userId
                                ]
                            );
                        }
                    } catch (videoError) {
                        console.error('❌ Video record error:', videoError);
                    }
                }
                
                return res.json({
                    success: true,
                    message: 'Lesson updated successfully',
                    lesson: {
                        content_id: parseInt(content_id),
                        content_title: title,
                        content_description: description,
                        content_type: content_type,
                        video_filename: videoFilename,
                        content_url: contentUrl
                    }
                });
            }
            
            // ===== INSERT NEW LESSON =====
            console.log('🆕 INSERTING new lesson');
            
            const [orderResult] = await promisePool.query(
                'SELECT MAX(content_order) as max_order FROM topic_content_items WHERE topic_id = ?',
                [topic_id]
            );
            
            const nextOrder = (orderResult[0]?.max_order || 0) + 1;
            
            const [contentResult] = await promisePool.query(
                `INSERT INTO topic_content_items 
                 (topic_id, content_type, content_title, content_description, 
                  content_url, content_order, is_active, video_filename, module_id)
                 VALUES (?, ?, ?, ?, ?, ?, TRUE, ?, ?)`,
                [
                    topic_id,
                    content_type || 'video',
                    title,
                    description || null,
                    contentUrl,
                    nextOrder,
                    videoFilename,
                    module_id || null
                ]
            );
            
            const newContentId = contentResult.insertId;
            console.log('✅ New lesson created with ID:', newContentId);
            
            // ===== INSERT INTO VIDEO_UPLOADS =====
            if (videoFile) {
                try {
                    await promisePool.query(`
                        CREATE TABLE IF NOT EXISTS video_uploads (
                            upload_id INT AUTO_INCREMENT PRIMARY KEY,
                            content_id INT NOT NULL,
                            original_filename VARCHAR(255),
                            stored_filename VARCHAR(255),
                            file_path VARCHAR(500),
                            file_size BIGINT,
                            uploaded_by INT,
                            upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                            is_active BOOLEAN DEFAULT TRUE,
                            FOREIGN KEY (content_id) REFERENCES topic_content_items(content_id) ON DELETE CASCADE
                        )
                    `);
                    
                    await promisePool.query(
                        `INSERT INTO video_uploads 
                         (content_id, original_filename, stored_filename, file_path, 
                          file_size, uploaded_by, is_active)
                         VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
                        [
                            newContentId,
                            videoFile.originalname,
                            videoFile.filename,
                            filePath,
                            videoFile.size,
                            userId
                        ]
                    );
                    console.log('✅ Video record inserted');
                } catch (videoError) {
                    console.error('❌ Video record error:', videoError);
                }
            }
            
            res.json({
                success: true,
                message: 'Lesson saved successfully',
                lesson: {
                    content_id: newContentId,
                    content_title: title,
                    content_description: description,
                    content_type: content_type,
                    video_filename: videoFilename,
                    content_url: contentUrl,
                    content_order: nextOrder
                }
            });
            
        } catch (error) {
            console.error('❌ ERROR:', error);
            
            if (req.file) {
                try {
                    fs.unlinkSync(req.file.path);
                } catch (unlinkError) {}
            }
            
            res.status(500).json({
                success: false,
                message: 'Failed to save lesson',
                error: error.message
            });
        }
    }
);

// ===== DELETE LESSON =====
app.delete('/api/admin/lessons/:contentId', verifyToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin role required.'
            });
        }
        
        const { contentId } = req.params;
        
        console.log(`🗑️ Deleting lesson ID: ${contentId}`);
        
        const [existing] = await promisePool.query(
            'SELECT content_id, content_title FROM topic_content_items WHERE content_id = ?',
            [contentId]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Lesson not found'
            });
        }
        
        const lessonTitle = existing[0].content_title;
        
        // Hard delete
        await promisePool.query(
            'DELETE FROM video_uploads WHERE content_id = ?',
            [contentId]
        );
        
        try {
            await promisePool.query(
                'DELETE FROM user_content_progress WHERE content_id = ?',
                [contentId]
            );
        } catch (progressError) {
            console.log('⚠️ No user_content_progress table or no records');
        }
        
        await promisePool.query(
            'DELETE FROM topic_content_items WHERE content_id = ?',
            [contentId]
        );
        
        console.log(`✅ Lesson ${contentId} "${lessonTitle}" deleted successfully`);
        
        res.json({
            success: true,
            message: `Lesson "${lessonTitle}" deleted successfully`,
            deleted_id: contentId
        });
        
    } catch (error) {
        console.error('❌ Error deleting lesson:', error);
        
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete lesson because it is referenced in other tables'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Failed to delete lesson',
            error: error.message
        });
    }
});


// ============================================
// LESSON POPULARITY ENDPOINT - FIXED VERSION
// ============================================
app.get('/api/admin/lesson-popularity', authenticateAdmin, async (req, res) => {
    try {
        const filter = req.query.filter || 'views';
        
        console.log(`📊 Fetching lesson popularity data with filter: ${filter}`);
        
        // SIMPLIFIED QUERY - IWASAN ANG COMPLEX CONDITIONS
        const [lessons] = await promisePool.execute(`
            SELECT 
                tci.content_id,
                tci.content_title,
                tci.content_type,
                COUNT(DISTINCT ucp.user_id) as view_count,
                COALESCE(AVG(ucp.score), 0) as avg_score
            FROM topic_content_items tci
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id
            WHERE tci.is_active = TRUE
            GROUP BY tci.content_id, tci.content_title, tci.content_type
            ORDER BY view_count DESC
            LIMIT 10
        `);
        
        console.log(`✅ Found ${lessons.length} lessons`);
        
        // Prepare data for chart
        const chartData = {
            labels: lessons.map(l => {
                let title = l.content_title || 'Untitled';
                return title.length > 25 ? title.substring(0, 22) + '...' : title;
            }),
            datasets: [{
                label: filter === 'views' ? 'Views' : 'Average Score (%)',
                data: lessons.map(l => {
                    if (filter === 'views') return parseInt(l.view_count) || 0;
                    return Math.round(l.avg_score || 0);
                }),
                backgroundColor: 'rgba(122, 0, 0, 0.8)',
                borderColor: 'rgba(122, 0, 0, 1)',
                borderWidth: 1
            }]
        };
        
        // Also return raw data
        const lessonData = lessons.map(l => ({
            id: l.content_id,
            title: l.content_title,
            type: l.content_type,
            views: parseInt(l.view_count) || 0,
            avg_score: Math.round(l.avg_score || 0)
        }));
        
        res.json({
            success: true,
            chart: chartData,
            lessons: lessonData,
            total: lessons.length,
            filter: filter
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ POST /api/quiz/answer (ALTERNATIVE VERSION)
// ============================================
app.post('/api/quiz/answer', authenticateUser, async (req, res) => {
    try {
        const { attempt_id, question_id, selected_option_id, user_answer } = req.body;
        
        console.log(`📝 Saving answer for attempt ${attempt_id}, question ${question_id}`);
        
        // Check if answer is correct
        let isCorrect = false;
        if (selected_option_id) {
            const [options] = await promisePool.query(
                'SELECT is_correct FROM quiz_options WHERE option_id = ?',
                [selected_option_id]
            );
            isCorrect = options[0]?.is_correct === 1;
        }
        
        // Save answer
        await promisePool.query(
            `INSERT INTO quiz_answers 
             (attempt_id, question_id, selected_option_id, user_answer, is_correct) 
             VALUES (?, ?, ?, ?, ?)`,
            [attempt_id, question_id, selected_option_id || null, user_answer || null, isCorrect]
        );
        
        res.json({ success: true, is_correct: isCorrect });

    } catch (error) {
        console.error('Error saving answer:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});



// ============================================
// ✅ GET /api/quiz/user/attempts - Get user's quiz attempts
// ============================================
app.get('/api/quiz/user/attempts', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { limit = 10 } = req.query;
        
        const [attempts] = await promisePool.query(`
            SELECT 
                uqa.attempt_id,
                uqa.quiz_id,
                q.quiz_title,
                q.difficulty,
                q.total_questions,
                uqa.score,
                uqa.correct_answers,
                uqa.time_spent_seconds,
                uqa.end_time as completed_at,
                uqa.passed,
                qc.category_name
            FROM user_quiz_attempts uqa
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            WHERE uqa.user_id = ? AND uqa.completion_status = 'completed'
            ORDER BY uqa.end_time DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        res.json({
            success: true,
            attempts: attempts
        });
        
    } catch (error) {
        console.error('Error fetching quiz attempts:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            attempts: [] 
        });
    }
});

// ============================================
// ✅ GET /api/quizzes/available - Available quizzes for user
// ============================================
app.get('/api/quizzes/available', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        console.log(`📥 Fetching available quizzes for user ID: ${userId}`);
        
        // First, check if quizzes table exists and has data
        const [tableCheck] = await promisePool.query("SHOW TABLES LIKE 'quizzes'");
        if (tableCheck.length === 0) {
            console.log('⚠️ Quizzes table does not exist');
            return res.json({
                success: true,
                quizzes: []
            });
        }
        
        // Get all active quizzes with category info
        const [quizzes] = await promisePool.query(`
            SELECT 
                q.quiz_id,
                q.quiz_title,
                q.description,
                q.difficulty,
                q.duration_minutes,
                q.total_questions,
                q.passing_score,
                q.max_attempts,
                q.is_active,
                q.created_at,
                qc.category_id,
                qc.category_name,
                qc.color as category_color,
                qc.icon as category_icon
            FROM quizzes q
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            WHERE q.is_active = 1 OR q.is_active IS NULL
            ORDER BY q.created_at DESC
        `);
        
        console.log(`✅ Found ${quizzes.length} quizzes in database`);
        
        if (quizzes.length === 0) {
            return res.json({
                success: true,
                quizzes: [],
                message: 'No quizzes available yet'
            });
        }
        
        // Get user's attempt history for each quiz
        const quizzesWithProgress = [];
        
        for (const quiz of quizzes) {
            // Get user's attempts for this quiz
            const [attempts] = await promisePool.query(`
                SELECT 
                    COUNT(*) as attempt_count,
                    COALESCE(MAX(score), 0) as best_score,
                    SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count
                FROM user_quiz_attempts 
                WHERE user_id = ? AND quiz_id = ? AND completion_status = 'completed'
            `, [userId, quiz.quiz_id]);
            
            // Get last attempt date
            const [lastAttempt] = await promisePool.query(`
                SELECT end_time 
                FROM user_quiz_attempts 
                WHERE user_id = ? AND quiz_id = ? 
                ORDER BY end_time DESC 
                LIMIT 1
            `, [userId, quiz.quiz_id]);
            
            quizzesWithProgress.push({
                quiz_id: quiz.quiz_id,
                quiz_title: quiz.quiz_title,
                description: quiz.description || 'Test your knowledge with this quiz',
                difficulty: quiz.difficulty || 'medium',
                duration_minutes: quiz.duration_minutes || 10,
                total_questions: quiz.total_questions || 0,
                passing_score: quiz.passing_score || 70,
                max_attempts: quiz.max_attempts || 3,
                category: {
                    id: quiz.category_id,
                    name: quiz.category_name || 'General',
                    color: quiz.category_color || '#3498db',
                    icon: quiz.category_icon || 'fas fa-question-circle'
                },
                user_progress: {
                    attempts: attempts[0]?.attempt_count || 0,
                    best_score: Math.round(attempts[0]?.best_score || 0),
                    passed: (attempts[0]?.passed_count || 0) > 0,
                    last_attempted: lastAttempt[0]?.end_time || null,
                    can_attempt: (attempts[0]?.attempt_count || 0) < (quiz.max_attempts || 3)
                },
                created_at: quiz.created_at
            });
        }
        
        res.json({
            success: true,
            quizzes: quizzesWithProgress,
            total: quizzesWithProgress.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching quizzes:', error);
        console.error('Error code:', error.code);
        console.error('Error message:', error.message);
        
        res.status(500).json({
            success: false,
            message: 'Failed to fetch quizzes',
            error: error.message,
            // Return empty array so UI doesn't break
            quizzes: []
        });
    }
});

// ============================================
// ✅ GET /api/dashboard/badges - Get user badges
// ============================================
app.get('/api/dashboard/badges', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Check if badges table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'badges'");
        
        if (tables.length === 0) {
            return res.json({
                success: true,
                badges: []
            });
        }
        
        const [badges] = await promisePool.query(`
            SELECT 
                b.badge_id,
                b.badge_name,
                b.description,
                b.icon,
                b.color,
                ub.awarded_at as earned_at
            FROM badges b
            JOIN user_badges ub ON b.badge_id = ub.badge_id
            WHERE ub.user_id = ?
            ORDER BY ub.awarded_at DESC
        `, [userId]);
        
        res.json({
            success: true,
            badges: badges || []
        });
        
    } catch (error) {
        console.error('Error fetching badges:', error);
        res.json({
            success: true,
            badges: []
        });
    }
});


// Award badge to user (call this when user completes achievements)
app.post('/api/badges/award', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { badge_name, description, icon, color, points } = req.body;
        
        // First, get or create the badge
        let [badges] = await promisePool.query(
            'SELECT badge_id FROM badges WHERE badge_name = ?',
            [badge_name]
        );
        
        let badgeId;
        if (badges.length === 0) {
            // Create new badge
            const [result] = await promisePool.query(
                'INSERT INTO badges (badge_name, description, icon, color, points_awarded) VALUES (?, ?, ?, ?, ?)',
                [badge_name, description || '', icon || 'fas fa-award', color || '#3498db', points || 10]
            );
            badgeId = result.insertId;
        } else {
            badgeId = badges[0].badge_id;
        }
        
        // Check if user already has this badge
        const [existing] = await promisePool.query(
            'SELECT * FROM user_badges WHERE user_id = ? AND badge_id = ?',
            [userId, badgeId]
        );
        
        if (existing.length === 0) {
            // Award badge to user
            await promisePool.query(
                'INSERT INTO user_badges (user_id, badge_id) VALUES (?, ?)',
                [userId, badgeId]
            );
            
            // Award points
            await promisePool.query(
                'INSERT INTO user_points (user_id, points_type, points_amount, description, reference_id) VALUES (?, ?, ?, ?, ?)',
                [userId, 'badge_earned', points || 10, `Earned badge: ${badge_name}`, badgeId]
            );
            
            // Log activity
            await promisePool.query(
                'INSERT INTO user_activity_log (user_id, activity_type, related_id, details, points_earned) VALUES (?, ?, ?, ?, ?)',
                [userId, 'badge_earned', badgeId, JSON.stringify({ badge_name }), points || 10]
            );
            
            console.log(`✅ Awarded badge "${badge_name}" to user ${userId}`);
        }
        
        res.json({
            success: true,
            message: 'Badge awarded successfully'
        });
        
    } catch (error) {
        console.error('❌ Error awarding badge:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ACCURACY RATE ENDPOINT
// ============================================

// Get user accuracy rate
app.get('/api/progress/accuracy-rate', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching accuracy rate for user ${userId}`);
        
        // Calculate quiz accuracy
        const [quizAccuracy] = await promisePool.query(`
            SELECT 
                COUNT(*) as total_attempts,
                SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count,
                COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Calculate practice accuracy
        const [practiceAccuracy] = await promisePool.query(`
            SELECT 
                COUNT(*) as total_attempts,
                COALESCE(AVG(percentage), 0) as avg_percentage
            FROM practice_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Calculate lesson completion rate
        const [lessonProgress] = await promisePool.query(`
            SELECT 
                COUNT(*) as total_started,
                SUM(CASE WHEN completion_status = 'completed' THEN 1 ELSE 0 END) as completed_count
            FROM user_content_progress
            WHERE user_id = ?
        `, [userId]);
        
        // Get total lessons available
        const [totalLessons] = await promisePool.query(`
            SELECT COUNT(*) as total
            FROM topic_content_items
            WHERE is_active = 1
        `, []);
        
        // Calculate overall accuracy rate
        const quizAvg = Math.round(quizAccuracy[0]?.avg_score || 0);
        const practiceAvg = Math.round(practiceAccuracy[0]?.avg_percentage || 0);
        
        let overallAccuracy = 0;
        let count = 0;
        
        if (quizAvg > 0) {
            overallAccuracy += quizAvg;
            count++;
        }
        if (practiceAvg > 0) {
            overallAccuracy += practiceAvg;
            count++;
        }
        
        overallAccuracy = count > 0 ? Math.round(overallAccuracy / count) : 0;
        
        // Calculate lesson completion percentage
        const lessonCompletion = lessonProgress[0]?.total_started > 0
            ? Math.round((lessonProgress[0]?.completed_count / lessonProgress[0]?.total_started) * 100)
            : 0;
        
        res.json({
            success: true,
            accuracy: {
                overall: overallAccuracy,
                quiz: quizAvg,
                practice: practiceAvg,
                lesson_completion: lessonCompletion,
                total_lessons_completed: lessonProgress[0]?.completed_count || 0,
                total_lessons: totalLessons[0]?.total || 0,
                total_quizzes_passed: quizAccuracy[0]?.passed_count || 0,
                total_quizzes_attempted: quizAccuracy[0]?.total_attempts || 0,
                total_practice_completed: practiceAccuracy[0]?.total_attempts || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching accuracy rate:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================
// 📈 GET WEEKLY ACCURACY DATA
// ============================================
app.get('/api/progress/weekly-accuracy', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get last 7 days of quiz attempts
        const [quizData] = await promisePool.query(`
            SELECT 
                DATE(end_time) as date,
                AVG(score) as avg_score
            FROM user_quiz_attempts
            WHERE user_id = ? 
                AND completion_status = 'completed'
                AND end_time >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(end_time)
            ORDER BY date
        `, [userId]);
        
        // Get last 7 days of practice attempts
        const [practiceData] = await promisePool.query(`
            SELECT 
                DATE(created_at) as date,
                AVG(percentage) as avg_percentage
            FROM practice_attempts
            WHERE user_id = ? 
                AND completion_status = 'completed'
                AND created_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            GROUP BY DATE(created_at)
            ORDER BY date
        `, [userId]);
        
        // Create a map of dates
        const dateMap = {};
        const labels = [];
        const accuracy = [];
        
        // Generate last 7 days
        for (let i = 6; i >= 0; i--) {
            const date = new Date();
            date.setDate(date.getDate() - i);
            const dateStr = date.toISOString().split('T')[0];
            const dayName = date.toLocaleDateString('en-US', { weekday: 'short' });
            
            labels.push(dayName);
            
            // Find accuracy for this date
            let dayAccuracy = 0;
            let count = 0;
            
            const quizDay = quizData.find(d => d.date.toISOString().split('T')[0] === dateStr);
            const practiceDay = practiceData.find(d => d.date.toISOString().split('T')[0] === dateStr);
            
            if (quizDay) {
                dayAccuracy += quizDay.avg_score;
                count++;
            }
            if (practiceDay) {
                dayAccuracy += practiceDay.avg_percentage;
                count++;
            }
            
            accuracy.push(count > 0 ? Math.round(dayAccuracy / count) : 0);
        }
        
        res.json({
            success: true,
            data: {
                labels: labels,
                accuracy: accuracy
            }
        });
        
    } catch (error) {
        console.error('Error fetching weekly accuracy:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// 🚀 OPTIMIZED: Get overall progress - FASTER QUERIES
// ============================================
app.get('/api/progress/overall', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching overall progress for user ${userId}`);
        
        // Run all queries in parallel para mas mabilis
        const [
            lessonsCompleted,
            totalLessons,
            totalPoints,
            practiceCompleted,
            quizzesCompleted,
            totalTime,
            weeklyProgress,
            userProgress
        ] = await Promise.all([
            // Lessons completed
            promisePool.query(`
                SELECT COUNT(*) as count 
                FROM user_content_progress 
                WHERE user_id = ? AND completion_status = 'completed'
            `, [userId]),
            
            // Total lessons available
            promisePool.query(`
                SELECT COUNT(*) as count 
                FROM topic_content_items 
                WHERE is_active = 1
            `, []),
            
            // Total points
            promisePool.query(`
                SELECT COALESCE(SUM(points_amount), 0) as total
                FROM user_points 
                WHERE user_id = ?
            `, [userId]),
            
            // Practice completed
            promisePool.query(`
                SELECT COUNT(*) as count
                FROM practice_attempts
                WHERE user_id = ? AND completion_status = 'completed'
            `, [userId]),
            
            // Quizzes completed
            promisePool.query(`
                SELECT COUNT(*) as count
                FROM user_quiz_attempts
                WHERE user_id = ? AND completion_status = 'completed'
            `, [userId]),
            
            // Total time
            promisePool.query(`
                SELECT COALESCE(SUM(time_spent_seconds), 0) / 60 as total_minutes
                FROM user_content_progress
                WHERE user_id = ?
            `, [userId]),
            
            // Weekly progress
            promisePool.query(`
                SELECT 
                    COALESCE(SUM(lessons_completed), 0) as weekly_lessons,
                    COALESCE(SUM(exercises_completed), 0) as weekly_exercises,
                    COALESCE(SUM(quizzes_completed), 0) as weekly_quizzes,
                    COALESCE(SUM(points_earned), 0) as weekly_points,
                    COALESCE(SUM(time_spent_minutes), 0) as weekly_minutes
                FROM daily_progress
                WHERE user_id = ? 
                    AND progress_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            `, [userId]),
            
            // User progress for average time
            promisePool.query(`
                SELECT average_time 
                FROM user_progress 
                WHERE user_id = ?
            `, [userId]).catch(() => [[{}]]) // Ignore error if table doesn't exist
        ]);
        
        // Calculate values
        const completed = lessonsCompleted[0]?.[0]?.count || 0;
        const total = totalLessons[0]?.[0]?.count || 1;
        const percentage = Math.min(100, Math.round((completed / total) * 100));
        
        const weekly = weeklyProgress[0]?.[0] || {
            weekly_lessons: 0,
            weekly_exercises: 0,
            weekly_quizzes: 0,
            weekly_points: 0,
            weekly_minutes: 0
        };
        
        const totalMinutes = Math.round(totalTime[0]?.[0]?.total_minutes || 0);
        const averageTime = userProgress[0]?.[0]?.average_time || 0;
        
        const response = {
            success: true,
            overall: {
                lessons_completed: completed,
                total_lessons: total,
                percentage: percentage,
                bar_width: `${percentage}%`,
                bar_class: percentage >= 70 ? 'progress-good' : (percentage >= 40 ? 'progress-medium' : 'progress-low'),
                total_points: parseInt(totalPoints[0]?.[0]?.total || 0),
                practice_completed: parseInt(practiceCompleted[0]?.[0]?.count || 0),
                quizzes_completed: parseInt(quizzesCompleted[0]?.[0]?.count || 0),
                total_time_spent_minutes: totalMinutes,
                average_time: averageTime,
                weekly: {
                    lessons: parseInt(weekly.weekly_lessons || 0),
                    exercises: parseInt(weekly.weekly_exercises || 0),
                    quizzes: parseInt(weekly.weekly_quizzes || 0),
                    points: parseInt(weekly.weekly_points || 0),
                    minutes: parseInt(weekly.weekly_minutes || 0)
                }
            }
        };
        
        console.log('✅ Overall progress fetched in', Date.now() - req.startTime, 'ms');
        res.json(response);
        
    } catch (error) {
        console.error('❌ Error fetching overall progress:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Add request timer middleware
app.use((req, res, next) => {
    req.startTime = Date.now();
    next();
});

// ============================================
// ✅ DEBUG: Get practice exercises count
// ============================================
app.get('/api/debug/practice/count', authenticateUser, async (req, res) => {
    try {
        const [result] = await promisePool.query(
            'SELECT COUNT(*) as count FROM practice_exercises WHERE is_active = 1'
        );
        
        res.json({
            success: true,
            count: result[0]?.count || 0
        });
        
    } catch (error) {
        console.error('Error getting practice count:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});



// ============================================
// ⏱️ UPDATE USER PROGRESS TIME - Direct to user_progress table
// ============================================
app.post('/api/progress/update-user-progress-time', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { total_time_spent_minutes, session_seconds } = req.body;
        
        console.log(`⏱️ Updating user_progress for user ${userId}: +${total_time_spent_minutes} minutes`);
        
        // Check if user_progress record exists
        const [existing] = await promisePool.execute(
            'SELECT progress_id FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        if (existing.length > 0) {
            // Update existing record
            await promisePool.execute(`
                UPDATE user_progress 
                SET total_time_spent_minutes = total_time_spent_minutes + ?,
                    updated_at = NOW()
                WHERE user_id = ?
            `, [total_time_spent_minutes, userId]);
            
            // Get updated value
            const [updated] = await promisePool.execute(
                'SELECT total_time_spent_minutes FROM user_progress WHERE user_id = ?',
                [userId]
            );
            
            res.json({ 
                success: true, 
                total_time_spent_minutes: updated[0]?.total_time_spent_minutes || 0
            });
            
        } else {
            // Insert new record
            await promisePool.execute(`
                INSERT INTO user_progress (user_id, total_time_spent_minutes, updated_at)
                VALUES (?, ?, NOW())
            `, [userId, total_time_spent_minutes]);
            
            res.json({ 
                success: true, 
                total_time_spent_minutes: total_time_spent_minutes
            });
        }
        
        // Also update daily_progress
        const today = new Date().toISOString().split('T')[0];
        
        await promisePool.execute(`
            INSERT INTO daily_progress (user_id, progress_date, time_spent_minutes)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                time_spent_minutes = time_spent_minutes + ?,
                updated_at = NOW()
        `, [userId, today, total_time_spent_minutes, total_time_spent_minutes]);
        
        // Log activity
        await promisePool.execute(`
            INSERT INTO user_activity_log (user_id, activity_type, details, activity_timestamp)
            VALUES (?, 'timer_session', ?, NOW())
        `, [userId, JSON.stringify({
            minutes: total_time_spent_minutes,
            seconds: session_seconds || 0,
            source: 'active_time_tracker'
        })]);
        
    } catch (error) {
        console.error('Error updating user_progress time:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============================================
// 🔄 RESET USER PROGRESS TIME
// ============================================
app.post('/api/progress/reset-user-progress-time', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        await promisePool.execute(`
            UPDATE user_progress 
            SET total_time_spent_minutes = 0,
                updated_at = NOW()
            WHERE user_id = ?
        `, [userId]);
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Error resetting user_progress time:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// ============================================
// 📊 GET USER PROGRESS TIME
// ============================================
app.get('/api/progress/get-user-progress-time', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [result] = await promisePool.execute(`
            SELECT total_time_spent_minutes 
            FROM user_progress 
            WHERE user_id = ?
        `, [userId]);
        
        // Ito ay seconds talaga, hindi minutes
        const totalSeconds = result[0]?.total_time_spent_minutes || 0;
        const totalMinutes = Math.floor(totalSeconds / 60);
        
        res.json({ 
            success: true, 
            total_time_spent_minutes: totalSeconds, // Return as seconds
            total_minutes: totalMinutes, // Also return as minutes for clarity
            formatted: formatTimeFromSeconds(totalSeconds)
        });
        
    } catch (error) {
        console.error('Error getting user_progress time:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Helper function
function formatTimeFromSeconds(seconds) {
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    
    if (hours > 0) {
        return `${hours}h ${mins}m`;
    } else {
        return `${mins}m`;
    }
}

// Helper function to format time
function formatTimeFromMinutes(minutes) {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    
    if (hours > 0) {
        return `${hours}h ${mins}m`;
    } else {
        return `${mins}m`;
    }
}


// ============================================
// ✅ FIXED: SAVE QUIZ ANSWER - WITH ALL COLUMNS
// ============================================
app.post('/api/quizzes/:attemptId/answer', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        const { question_id, selected_option_id, user_answer, time_spent_seconds } = req.body;
        
        console.log(`📝 Saving answer for attempt ${attemptId}, question ${question_id}`);
        
        // Validation
        if (!attemptId || !question_id) {
            return res.status(400).json({
                success: false,
                message: 'Attempt ID and Question ID are required'
            });
        }
        
        // Check if attempt exists
        const [attemptCheck] = await promisePool.query(
            'SELECT attempt_id FROM user_quiz_attempts WHERE attempt_id = ?',
            [attemptId]
        );
        
        if (attemptCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Attempt not found'
            });
        }
        
        // Check if answer is correct
        let isCorrect = false;
        let pointsEarned = 0;
        
        if (selected_option_id) {
            const [option] = await promisePool.query(
                'SELECT is_correct FROM quiz_options WHERE option_id = ?',
                [selected_option_id]
            );
            isCorrect = option.length > 0 && option[0].is_correct === 1;
            pointsEarned = isCorrect ? 10 : 0;
        }
        
        // Check if answer already exists
        const [existing] = await promisePool.query(
            'SELECT answer_id FROM user_quiz_answers WHERE attempt_id = ? AND question_id = ?',
            [attemptId, question_id]
        );
        
        if (existing.length > 0) {
            // Update existing answer
            await promisePool.query(
                `UPDATE user_quiz_answers 
                 SET selected_option_id = ?, 
                     user_answer = ?, 
                     is_correct = ?, 
                     points_earned = ?,
                     time_spent_seconds = ?,
                     answered_at = NOW()
                 WHERE attempt_id = ? AND question_id = ?`,
                [selected_option_id || null, 
                 user_answer || null, 
                 isCorrect, 
                 pointsEarned,
                 time_spent_seconds || 0,
                 attemptId, 
                 question_id]
            );
            console.log(`✅ Updated answer for attempt ${attemptId}, question ${question_id}`);
        } else {
            // Insert new answer with all columns
            await promisePool.query(
                `INSERT INTO user_quiz_answers 
                 (attempt_id, question_id, selected_option_id, user_answer, is_correct, points_earned, time_spent_seconds, answered_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
                [attemptId, 
                 question_id, 
                 selected_option_id || null, 
                 user_answer || null, 
                 isCorrect,
                 pointsEarned,
                 time_spent_seconds || 0]
            );
            console.log(`✅ Inserted answer for attempt ${attemptId}, question ${question_id}`);
        }
        
        res.json({
            success: true,
            is_correct: isCorrect,
            points_earned: pointsEarned
        });
        
    } catch (error) {
        console.error('❌ Error saving answer:', error);
        console.error('❌ Error code:', error.code);
        console.error('❌ SQL:', error.sql);
        
        res.status(500).json({
            success: false,
            message: error.message,
            code: error.code
        });
    }
});


// ============================================
// GET QUIZ ATTEMPT RESULTS BY ATTEMPT ID
// ============================================
app.get('/api/quiz/attempt/:attemptId/results', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        const userId = req.user.id;
        
        console.log(`📊 Fetching results for attempt ${attemptId}`);
        
        // Get attempt details
        const [attempts] = await promisePool.query(`
            SELECT 
                uqa.*,
                q.quiz_title,
                q.total_questions,
                q.passing_score
            FROM user_quiz_attempts uqa
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            WHERE uqa.attempt_id = ? AND uqa.user_id = ?
        `, [attemptId, userId]);
        
        if (attempts.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Attempt not found'
            });
        }
        
        const attempt = attempts[0];
        
        // Get questions with user answers
        const [questions] = await promisePool.query(`
            SELECT 
                qq.question_id,
                qq.question_text,
                qq.explanation,
                qa.selected_option_id,
                qa.user_answer,
                qa.is_correct,
                (
                    SELECT JSON_ARRAYAGG(
                        JSON_OBJECT(
                            'option_id', qo.option_id,
                            'option_text', qo.option_text,
                            'is_correct', qo.is_correct
                        )
                    )
                    FROM quiz_options qo
                    WHERE qo.question_id = qq.question_id
                ) as options,
                (
                    SELECT option_text 
                    FROM quiz_options 
                    WHERE question_id = qq.question_id AND is_correct = 1 
                    LIMIT 1
                ) as correct_answer_text
            FROM quiz_questions qq
            LEFT JOIN user_quiz_answers qa ON qq.question_id = qa.question_id AND qa.attempt_id = ?
            WHERE qq.quiz_id = ?
            ORDER BY qq.question_order
        `, [attemptId, attempt.quiz_id]);
        
        // Parse options JSON for each question
        const formattedQuestions = questions.map(q => {
            let options = [];
            try {
                options = q.options ? JSON.parse(q.options) : [];
            } catch (e) {
                console.log('Error parsing options:', e);
            }
            
            return {
                question_id: q.question_id,
                question_text: q.question_text,
                explanation: q.explanation,
                user_answer: q.user_answer || (q.selected_option_id ? 
                    options.find(opt => opt.option_id == q.selected_option_id)?.option_text : 'Not answered'),
                correct_answer: q.correct_answer_text,
                is_correct: q.is_correct === 1,
                options: options
            };
        });
        
        const results = {
            attempt_id: attempt.attempt_id,
            quiz_id: attempt.quiz_id,
            quiz_title: attempt.quiz_title,
            score: attempt.score,
            correct_answers: attempt.correct_answers,
            total_questions: attempt.total_questions,
            time_spent_seconds: attempt.time_spent_seconds,
            completed_at: attempt.end_time,
            questions: formattedQuestions
        };
        
        res.json({
            success: true,
            results: results
        });
        
    } catch (error) {
        console.error('❌ Error fetching attempt results:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================
// ✅ NEW: Weekly Improvement Endpoint
// ============================================
app.get('/api/progress/weekly-improvement', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get this week's activity count
        const [thisWeek] = await promisePool.query(`
            SELECT COUNT(*) as count
            FROM user_activity_log
            WHERE user_id = ? 
                AND activity_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `, [userId]);
        
        // Get last week's activity count
        const [lastWeek] = await promisePool.query(`
            SELECT COUNT(*) as count
            FROM user_activity_log
            WHERE user_id = ? 
                AND activity_timestamp >= DATE_SUB(NOW(), INTERVAL 14 DAY)
                AND activity_timestamp < DATE_SUB(NOW(), INTERVAL 7 DAY)
        `, [userId]);
        
        const thisWeekCount = thisWeek[0]?.count || 0;
        const lastWeekCount = lastWeek[0]?.count || 0;
        
        let improvement = 5; // Default
        
        if (lastWeekCount > 0) {
            improvement = Math.round(((thisWeekCount - lastWeekCount) / lastWeekCount) * 100);
        } else if (thisWeekCount > 0) {
            improvement = 10; // Positive if started this week
        }
        
        // Cap between -50% and +100%
        improvement = Math.min(100, Math.max(-50, improvement));
        
        res.json({
            success: true,
            improvement: improvement,
            this_week: thisWeekCount,
            last_week: lastWeekCount
        });
        
    } catch (error) {
        console.error('Error calculating weekly improvement:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================
// FORGOT PASSWORD ROUTES (WITHOUT EMAIL)
// ============================================

// Request password reset - generates token
app.post('/api/auth/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        
        console.log('🔑 Password reset requested for:', email);
        
        if (!email) {
            return res.status(400).json({
                success: false,
                message: 'Email is required'
            });
        }
        
        // Check if user exists
        const [users] = await promisePool.execute(
            'SELECT user_id, username, email, full_name FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            // For security, don't reveal that user doesn't exist
            return res.json({
                success: true,
                message: 'If your email exists in our system, you will receive a reset link.',
                demo_mode: true
            });
        }
        
        const user = users[0];
        
        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const tokenExpiry = new Date(Date.now() + 3600000); // 1 hour from now
        
        // Check if password_resets table exists, create if not
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'password_resets'");
        
        if (tables.length === 0) {
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS password_resets (
                    reset_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    reset_token VARCHAR(255) NOT NULL,
                    token_expiry DATETIME NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_token (reset_token),
                    INDEX idx_user (user_id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ password_resets table created');
        }
        
        // Delete any existing reset tokens for this user
        await promisePool.execute(
            'DELETE FROM password_resets WHERE user_id = ?',
            [user.user_id]
        );
        
        // Save reset token
        await promisePool.execute(
            `INSERT INTO password_resets 
             (user_id, reset_token, token_expiry, used) 
             VALUES (?, ?, ?, FALSE)`,
            [user.user_id, resetToken, tokenExpiry]
        );
        
        console.log(`✅ Reset token generated for user ${user.user_id}: ${resetToken}`);
        
        // In a real app, you would send an email here
        // For demo, we'll return the token in the response
        res.json({
            success: true,
            message: 'Password reset link generated',
            demo_mode: true,
            reset_token: resetToken,
            reset_link: `http://localhost:5000/reset-password?token=${resetToken}`,
            user: {
                id: user.user_id,
                name: user.full_name || user.username,
                email: user.email
            }
        });
        
    } catch (error) {
        console.error('❌ Forgot password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to process request',
            error: error.message
        });
    }
});

// Verify reset token
app.post('/api/auth/verify-reset-token', async (req, res) => {
    try {
        const { token } = req.body;
        
        if (!token) {
            return res.status(400).json({
                success: false,
                message: 'Token is required'
            });
        }
        
        // Check if token exists and is valid
        const [resets] = await promisePool.execute(`
            SELECT pr.*, u.user_id, u.username, u.email, u.full_name
            FROM password_resets pr
            JOIN users u ON pr.user_id = u.user_id
            WHERE pr.reset_token = ? 
              AND pr.used = FALSE 
              AND pr.token_expiry > NOW()
        `, [token]);
        
        if (resets.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }
        
        res.json({
            success: true,
            message: 'Token is valid',
            user: {
                id: resets[0].user_id,
                name: resets[0].full_name || resets[0].username,
                email: resets[0].email
            }
        });
        
    } catch (error) {
        console.error('❌ Verify token error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to verify token'
        });
    }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
    try {
        const { token, new_password, confirm_password } = req.body;
        
        if (!token || !new_password || !confirm_password) {
            return res.status(400).json({
                success: false,
                message: 'Token, new password, and confirm password are required'
            });
        }
        
        if (new_password !== confirm_password) {
            return res.status(400).json({
                success: false,
                message: 'Passwords do not match'
            });
        }
        
        if (new_password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'Password must be at least 6 characters'
            });
        }
        
        // Verify token
        const [resets] = await promisePool.execute(`
            SELECT pr.*, u.user_id
            FROM password_resets pr
            JOIN users u ON pr.user_id = u.user_id
            WHERE pr.reset_token = ? 
              AND pr.used = FALSE 
              AND pr.token_expiry > NOW()
        `, [token]);
        
        if (resets.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'Invalid or expired reset token'
            });
        }
        
        const reset = resets[0];
        
        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(new_password, salt);
        
        // Start transaction
        const connection = await promisePool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Update user password
            await connection.execute(
                'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?',
                [hashedPassword, reset.user_id]
            );
            
            // Mark token as used
            await connection.execute(
                'UPDATE password_resets SET used = TRUE WHERE reset_id = ?',
                [reset.reset_id]
            );
            
            await connection.commit();
            connection.release();
            
            console.log(`✅ Password reset successful for user ${reset.user_id}`);
            
            res.json({
                success: true,
                message: 'Password reset successful! You can now login with your new password.'
            });
            
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('❌ Reset password error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to reset password'
        });
    }
});

// Get user by email (for checking)
app.post('/api/auth/check-email', async (req, res) => {
    try {
        const { email } = req.body;
        
        const [users] = await promisePool.execute(
            'SELECT user_id FROM users WHERE email = ?',
            [email]
        );
        
        res.json({
            success: true,
            exists: users.length > 0
        });
        
    } catch (error) {
        console.error('❌ Check email error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to check email'
        });
    }
});



// Submit quiz
// Sa quiz submission endpoint
app.post('/api/quiz/:attemptId/submit', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        const { answers } = req.body;
        const userId = req.user.id;

        // Compute score
        const [questions] = await promisePool.query(
            `SELECT qq.*, qc.correct_option 
             FROM quiz_questions qq
             LEFT JOIN quiz_choices qc ON qq.question_id = qc.question_id AND qc.is_correct = 1
             WHERE qq.quiz_id = (SELECT quiz_id FROM user_quiz_attempts WHERE attempt_id = ?)`,
            [attemptId]
        );

        let correctCount = 0;
        
        // Save answers and compute score
        for (const answer of answers) {
            const question = questions.find(q => q.question_id === answer.question_id);
            const isCorrect = question && question.correct_option === answer.selected_option;
            
            if (isCorrect) correctCount++;
            
            await promisePool.query(
                `INSERT INTO user_answers (attempt_id, question_id, selected_option, is_correct)
                 VALUES (?, ?, ?, ?)`,
                [attemptId, answer.question_id, answer.selected_option, isCorrect]
            );
        }

        const totalQuestions = questions.length;
        const score = Math.round((correctCount / totalQuestions) * 100);

        // Update attempt
        await promisePool.query(
            `UPDATE user_quiz_attempts 
             SET completion_status = 'completed', 
                 score = ?,
                 end_time = NOW() 
             WHERE attempt_id = ? AND user_id = ?`,
            [score, attemptId, userId]
        );

        // Redirect to result page (not dashboard)
        res.json({
            success: true,
            score: score,
            correctCount: correctCount,
            totalQuestions: totalQuestions,
            redirectUrl: `/quiz/result/${attemptId}` // Important: direct to result page
        });

    } catch (error) {
        console.error('Submit quiz error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to submit quiz' 
        });
    }
});





// ============================================
// ✅ GET /api/user/quiz-stats - Alias for quiz stats
// ============================================
app.get('/api/user/quiz-stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Check if user has any attempts
        const [attempts] = await promisePool.query(`
            SELECT 
                COALESCE(AVG(score), 0) as avg_score,
                COALESCE(SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END), 0) as passed_count,
                COALESCE(COUNT(*), 0) as total_attempts,
                COALESCE(SUM(time_spent_seconds), 0) as total_time
            FROM user_quiz_attempts 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        const stats = attempts[0];
        
        // Calculate accuracy (passed / total * 100)
        let accuracy = 0;
        if (stats.total_attempts > 0) {
            accuracy = Math.round((stats.passed_count / stats.total_attempts) * 100);
        }
        
        // Get user rank (simplified)
        const [rankResult] = await promisePool.query(`
            SELECT COUNT(DISTINCT user_id) + 1 as user_rank
            FROM user_quiz_attempts
            WHERE score > (SELECT COALESCE(AVG(score), 0) FROM user_quiz_attempts WHERE user_id = ?)
            AND completion_status = 'completed'
        `, [userId]);
        
        const userRank = rankResult[0]?.user_rank || 1;
        
        res.json({
            success: true,
            stats: {
                avg_score: Math.round(stats.avg_score || 0),
                accuracy: accuracy,
                total_time: Math.round(stats.total_time / 60), // convert to minutes
                rank: userRank
            }
        });
        
    } catch (error) {
        console.error('❌ Error getting quiz stats:', error);
        
        // Return default values on error
        res.json({
            success: true,
            stats: {
                avg_score: 0,
                accuracy: 0,
                total_time: 0,
                rank: 1
            }
        });
    }
});


// ============================================
// ✅ GET /api/quiz/category/:categoryId/quizzes - Get quizzes by category
// ============================================
app.get('/api/quiz/category/:categoryId/quizzes', authenticateUser, async (req, res) => {
    try {
        const { categoryId } = req.params;
        const userId = req.user.id;
        
        console.log(`📥 Fetching quizzes for category ID: ${categoryId}`);
        
        // Get category info
        const [categories] = await promisePool.query(
            'SELECT category_id, category_name FROM quiz_categories WHERE category_id = ?',
            [categoryId]
        );
        
        if (categories.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }
        
        const category = categories[0];
        
        // Get quizzes for this category
        const [quizzes] = await promisePool.query(`
            SELECT 
                q.quiz_id,
                q.quiz_title,
                q.description,
                q.difficulty,
                q.duration_minutes,
                q.total_questions,
                q.passing_score,
                q.max_attempts,
                q.is_active,
                q.created_at
            FROM quizzes q
            WHERE q.category_id = ? AND (q.is_active = 1 OR q.is_active IS NULL)
            ORDER BY q.created_at DESC
        `, [categoryId]);
        
        console.log(`✅ Found ${quizzes.length} quizzes for ${category.category_name}`);
        
        // Get user progress for each quiz
        const quizzesWithProgress = [];
        
        for (const quiz of quizzes) {
            // Get user's attempts
            const [attempts] = await promisePool.query(`
                SELECT 
                    COUNT(*) as attempt_count,
                    COALESCE(MAX(score), 0) as best_score,
                    SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count
                FROM user_quiz_attempts 
                WHERE user_id = ? AND quiz_id = ? AND completion_status = 'completed'
            `, [userId, quiz.quiz_id]);
            
            // Get recent attempts for history
            const [attemptHistory] = await promisePool.query(`
                SELECT 
                    attempt_id,
                    score,
                    passed,
                    time_spent_seconds,
                    end_time as completed_at
                FROM user_quiz_attempts 
                WHERE user_id = ? AND quiz_id = ? AND completion_status = 'completed'
                ORDER BY end_time DESC
                LIMIT 3
            `, [userId, quiz.quiz_id]);
            
            quizzesWithProgress.push({
                quiz_id: quiz.quiz_id,
                quiz_title: quiz.quiz_title,
                description: quiz.description || 'Test your knowledge with this quiz',
                difficulty: quiz.difficulty || 'medium',
                duration_minutes: quiz.duration_minutes || 10,
                total_questions: quiz.total_questions || 0,
                passing_score: parseFloat(quiz.passing_score) || 70,
                max_attempts: quiz.max_attempts || 3,
                category_id: parseInt(categoryId),
                category_name: category.category_name,
                user_progress: {
                    attempts: attempts[0]?.attempt_count || 0,
                    best_score: Math.round(attempts[0]?.best_score || 0),
                    passed: (attempts[0]?.passed_count || 0) > 0,
                    can_attempt: (attempts[0]?.attempt_count || 0) < (quiz.max_attempts || 3)
                },
                user_attempts: attemptHistory.map(a => ({
                    attempt_id: a.attempt_id,
                    score: Math.round(a.score),
                    passed: a.passed === 1,
                    time_spent: a.time_spent_seconds,
                    completed_at: a.completed_at
                }))
            });
        }
        
        res.json({
            success: true,
            category: {
                id: category.category_id,
                name: category.category_name
            },
            quizzes: quizzesWithProgress
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            quizzes: [] 
        });
    }
});

// ============================================
// ✅ GET QUIZ QUESTIONS
// ============================================
// ============================================



// ============================================
// ✅ GET /api/quiz/:quizId/check-access - Check if user can access quiz
// ============================================
app.get('/api/quiz/:quizId/check-access', authenticateUser, async (req, res) => {
    try {
        const { quizId } = req.params;
        const userId = req.user.id;
        
        console.log(`🔍 Checking access for quiz ${quizId}, user ${userId}`);
        
        // Check if quiz exists
        const [quizzes] = await promisePool.query(
            'SELECT quiz_id, max_attempts FROM quizzes WHERE quiz_id = ? AND is_active = 1',
            [quizId]
        );
        
        if (quizzes.length === 0) {
            return res.json({
                success: true,
                canAccess: false,
                reason: 'Quiz not found or inactive'
            });
        }
        
        const quiz = quizzes[0];
        
        // Check attempt count using completion_status instead of status
        const [attempts] = await promisePool.query(
            'SELECT COUNT(*) as count FROM user_quiz_attempts WHERE user_id = ? AND quiz_id = ?',
            [userId, quizId]
        );
        
        const maxAttempts = quiz.max_attempts || 3;
        const attemptCount = attempts[0].count;
        
        if (attemptCount >= maxAttempts) {
            return res.json({
                success: true,
                canAccess: false,
                reason: `Maximum attempts (${maxAttempts}) reached`
            });
        }
        
        res.json({
            success: true,
            canAccess: true,
            reason: 'Access granted'
        });
        
    } catch (error) {
        console.error('❌ Error checking quiz access:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================
// ✅ POST /api/quiz/:quizId/start - Start a quiz attempt
// ============================================
app.post('/api/quiz/:quizId/start', authenticateUser, async (req, res) => {
    const connection = await promisePool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const { quizId } = req.params;
        const userId = req.user.id;
        
        console.log(`🚀 User ${userId} starting quiz ${quizId}`);
        
        // Check if quiz exists
        const [quizzes] = await connection.query(
            'SELECT quiz_id, quiz_title, max_attempts FROM quizzes WHERE quiz_id = ?',
            [quizId]
        );
        
        if (quizzes.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        const maxAttempts = quizzes[0].max_attempts || 3;
        
        // Check for abandoned attempts (older than 24 hours)
        await connection.query(
            `UPDATE user_quiz_attempts 
             SET completion_status = 'abandoned' 
             WHERE user_id = ? AND quiz_id = ? 
             AND completion_status = 'in_progress'
             AND start_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)`,
            [userId, quizId]
        );
        
        // Check for active attempt
        const [activeAttempt] = await connection.query(
            `SELECT attempt_id, attempt_number 
             FROM user_quiz_attempts 
             WHERE user_id = ? AND quiz_id = ? 
             AND completion_status = 'in_progress'
             ORDER BY start_time DESC 
             LIMIT 1`,
            [userId, quizId]
        );
        
        if (activeAttempt.length > 0) {
            await connection.commit();
            connection.release();
            
            return res.json({
                success: true,
                attempt: activeAttempt[0],
                message: 'Continuing previous attempt'
            });
        }
        
        // Get attempt number
        const [attemptCount] = await connection.query(
            'SELECT COUNT(*) as count FROM user_quiz_attempts WHERE user_id = ? AND quiz_id = ?',
            [userId, quizId]
        );
        
        const attemptNumber = attemptCount[0].count + 1;
        
        // Check max attempts
        if (attemptNumber > maxAttempts) {
            await connection.rollback();
            connection.release();
            return res.status(400).json({
                success: false,
                message: `Maximum attempts (${maxAttempts}) reached`
            });
        }
        
        // Create new attempt
        const [result] = await connection.query(
            `INSERT INTO user_quiz_attempts 
             (user_id, quiz_id, attempt_number, start_time, completion_status) 
             VALUES (?, ?, ?, NOW(), 'in_progress')`,
            [userId, quizId, attemptNumber]
        );
        
        const attemptId = result.insertId;
        
        // Get attempt details
        const [newAttempt] = await connection.query(
            'SELECT * FROM user_quiz_attempts WHERE attempt_id = ?',
            [attemptId]
        );
        
        await connection.commit();
        
        console.log(`✅ Created attempt ${attemptId} (#${attemptNumber})`);
        
        res.json({
            success: true,
            attempt: newAttempt[0]
        });
        
    } catch (error) {
        await connection.rollback();
        console.error('❌ Error starting quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    } finally {
        connection.release();
    }
});

// ============================================
// ✅ GET /api/quiz/:quizId/questions (ALTERNATIVE VERSION)
// ============================================
app.get('/api/quiz/:quizId/questions', authenticateUser, async (req, res) => {
    try {
        const { quizId } = req.params;
        
        console.log(`📚 Fetching questions for quiz ${quizId}...`);
        
        // ✅ GET QUESTIONS FIRST
        const [questions] = await promisePool.query(`
            SELECT 
                question_id,
                question_text,
                question_type,
                points
            FROM quiz_questions 
            WHERE quiz_id = ?
            ORDER BY question_order
        `, [quizId]);
        
        // ✅ GET OPTIONS FOR EACH QUESTION
        const formattedQuestions = [];
        
        for (const q of questions) {
            const [options] = await promisePool.query(`
                SELECT 
                    option_id as id,
                    option_text as text,
                    is_correct
                FROM quiz_options 
                WHERE question_id = ?
                ORDER BY option_id
            `, [q.question_id]);
            
            formattedQuestions.push({
                question_id: q.question_id,
                question_text: q.question_text,
                question_type: q.question_type,
                points: q.points,
                options: options
            });
        }
        
        res.json({
            success: true,
            questions: formattedQuestions
        });
        
    } catch (error) {
        console.error('❌ Error fetching questions:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

app.get('/api/quiz/result/:attemptId', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        const userId = req.user.id;

        const [result] = await promisePool.query(
            `SELECT uqa.*, 
                    q.quiz_title,
                    (SELECT COUNT(*) FROM quiz_questions WHERE quiz_id = uqa.quiz_id) as total_questions,
                    (SELECT COUNT(*) FROM user_answers WHERE attempt_id = uqa.attempt_id AND is_correct = 1) as correct_answers
             FROM user_quiz_attempts uqa
             JOIN quizzes q ON uqa.quiz_id = q.quiz_id
             WHERE uqa.attempt_id = ? AND uqa.user_id = ?`,
            [attemptId, userId]
        );

        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Result not found'
            });
        }

        res.json({
            success: true,
            result: result[0]
        });

    } catch (error) {
        console.error('Error fetching result:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch result'
        });
    }
});





// ============================================
// ✅ POST /api/quiz/attempt/:attemptId/complete - Complete quiz
// ============================================
app.post('/api/quiz/attempt/:attemptId/complete', authenticateUser, async (req, res) => {
    const connection = await promisePool.getConnection();
    
    try {
        await connection.beginTransaction();
        
        const { attemptId } = req.params;
        const userId = req.user.id;
        const { time_spent_seconds = 0 } = req.body;
        
        console.log(`🏁 Completing attempt ${attemptId}`);
        
        // Check attempt
        const [attempts] = await connection.query(
            'SELECT * FROM user_quiz_attempts WHERE attempt_id = ? AND user_id = ?',
            [attemptId, userId]
        );
        
        if (attempts.length === 0) {
            await connection.rollback();
            connection.release();
            return res.status(404).json({
                success: false,
                message: 'Attempt not found'
            });
        }
        
        const attempt = attempts[0];
        const quizId = attempt.quiz_id;
        
        // Get quiz details
        const [quizzes] = await connection.query(
            'SELECT passing_score FROM quizzes WHERE quiz_id = ?',
            [quizId]
        );
        
        const passingScore = quizzes[0]?.passing_score || 70;
        
        // Get total questions count
        const [questions] = await connection.query(
            'SELECT COUNT(*) as count FROM quiz_questions WHERE quiz_id = ?',
            [quizId]
        );
        
        const totalQuestions = questions[0].count;
        
        // Get all answers with their correctness
        const [answers] = await connection.query(
            `SELECT qa.*, qo.is_correct as option_correct
             FROM user_quiz_answers qa
             LEFT JOIN quiz_options qo ON qa.selected_option_id = qo.option_id
             WHERE qa.attempt_id = ?`,
            [attemptId]
        );
        
        // Calculate score
        let correctCount = 0;
        answers.forEach(a => {
            if (a.is_correct === 1 || a.option_correct === 1) correctCount++;
        });
        
        const score = totalQuestions > 0 
            ? Math.round((correctCount / totalQuestions) * 100) 
            : 0;
        
        const passed = score >= passingScore ? 1 : 0;
        
        // Update attempt
        await connection.query(
            `UPDATE user_quiz_attempts 
             SET end_time = NOW(),
                 time_spent_seconds = ?,
                 score = ?,
                 correct_answers = ?,
                 total_questions = ?,
                 completion_status = 'completed',
                 passed = ?
             WHERE attempt_id = ?`,
            [time_spent_seconds, score, correctCount, totalQuestions, passed, attemptId]
        );
        
        // Award points (10 points per correct answer)
        const pointsEarned = correctCount * 10;
        
        if (pointsEarned > 0) {
            await connection.query(
                `INSERT INTO user_points 
                 (user_id, points_type, points_amount, description, reference_id)
                 VALUES (?, 'quiz_completed', ?, ?, ?)`,
                [userId, pointsEarned, `Completed quiz with ${score}%`, quizId]
            );
        }
        
        // Update daily progress
        const today = new Date().toISOString().split('T')[0];
        
        await connection.query(
            `INSERT INTO daily_progress (user_id, progress_date, quizzes_completed, points_earned)
             VALUES (?, ?, 1, ?)
             ON DUPLICATE KEY UPDATE
                 quizzes_completed = quizzes_completed + 1,
                 points_earned = points_earned + ?`,
            [userId, today, pointsEarned, pointsEarned]
        );
        
        await connection.commit();
        
        console.log(`✅ Quiz completed! Score: ${score}%, Correct: ${correctCount}/${totalQuestions}`);
        
        res.json({
            success: true,
            results: {
                score: score,
                correct_answers: correctCount,
                total_questions: totalQuestions,
                points_earned: pointsEarned,
                passed: passed === 1
            }
        });
        
    } catch (error) {
        await connection.rollback();
        console.error('❌ Error completing quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    } finally {
        connection.release();
    }
});

// ============================================
// ✅ POST /api/quiz/update-attempt - Update attempt (direct)
// ============================================
app.post('/api/quiz/update-attempt', authenticateUser, async (req, res) => {
    try {
        const { attempt_id, time_spent_seconds, score, correct_answers, total_questions, submit_time } = req.body;
        
        console.log(`📝 Updating attempt ${attempt_id} directly...`);
        
        const [result] = await promisePool.query(
            `UPDATE user_quiz_attempts 
             SET 
                end_time = ?,
                time_spent_seconds = ?,
                score = ?,
                correct_answers = ?,
                total_questions = ?,
                completion_status = 'completed'
             WHERE attempt_id = ?`,
            [submit_time || new Date(), time_spent_seconds, score, correct_answers, total_questions, attempt_id]
        );
        
        if (result.affectedRows > 0) {
            res.json({ 
                success: true, 
                message: 'Attempt updated successfully' 
            });
        } else {
            res.status(404).json({ 
                success: false, 
                message: 'Attempt not found' 
            });
        }
        
    } catch (error) {
        console.error('❌ Error updating attempt:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});


// ============================================
// ✅ GET /api/quiz/attempt/:attemptId - Get attempt details
// ============================================
app.get('/api/quiz/attempt/:attemptId', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        
        const [attempts] = await promisePool.query(
            'SELECT * FROM user_quiz_attempts WHERE attempt_id = ?',
            [attemptId]
        );
        
        if (attempts.length > 0) {
            res.json({ 
                success: true, 
                attempt: attempts[0] 
            });
        } else {
            res.status(404).json({ 
                success: false, 
                message: 'Attempt not found' 
            });
        }
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET /api/quiz/debug/last-attempt - Debug last attempt
// ============================================
app.get('/api/quiz/debug/last-attempt', authenticateUser, async (req, res) => {
    try {
        const [attempts] = await promisePool.query(`
            SELECT attempt_id, quiz_id, score, correct_answers, 
                   total_questions, completion_status, end_time
            FROM quiz_attempts 
            WHERE user_id = ? 
            ORDER BY attempt_id DESC 
            LIMIT 1
        `, [req.user.userId]);
        
        res.json({
            success: true,
            attempt: attempts[0] || null
        });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
});


// ============================================
// ✅ GET /api/quiz/attempt/:attemptId/status - Check attempt status
// ============================================
app.get('/api/quiz/attempt/:attemptId/status', authenticateUser, async (req, res) => {
    try {
        const { attemptId } = req.params;
        
        console.log(`🔍 Checking status for attempt ${attemptId}`);
        
        // Check if attempt exists in database
        const [attempt] = await promisePool.query(
            'SELECT attempt_id, user_id, quiz_id, completion_status FROM user_quiz_attempts WHERE attempt_id = ?',
            [attemptId]
        );
        
        if (attempt.length > 0) {
            return res.json({
                success: true,
                exists: true,
                attempt: attempt[0],
                message: 'Attempt found in database'
            });
        }
        
        // Check if it's a local attempt (optional)
        return res.json({
            success: true,
            exists: false,
            message: 'Attempt not found in database'
        });
        
    } catch (error) {
        console.error('Error checking attempt status:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// ============================================
// ✅ GET /api/quiz/leaderboard/:period - Get leaderboard
// ============================================
app.get('/api/quiz/leaderboard/:period', authenticateUser, async (req, res) => {
    try {
        const { period } = req.params;
        
        let dateFilter = '';
        if (period === 'weekly') {
            dateFilter = 'AND uqa.end_time >= DATE_SUB(NOW(), INTERVAL 7 DAY)';
        } else if (period === 'monthly') {
            dateFilter = 'AND uqa.end_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)';
        }
        
        const [leaderboard] = await promisePool.query(`
            SELECT 
                u.user_id,
                u.username,
                u.full_name,
                COUNT(DISTINCT uqa.attempt_id) as quizzes_completed,
                COALESCE(AVG(uqa.score), 0) as avg_score,
                COALESCE(SUM(uqa.score), 0) as total_points,
                MAX(uqa.score) as highest_score
            FROM users u
            JOIN user_quiz_attempts uqa ON u.user_id = uqa.user_id 
                AND uqa.completion_status = 'completed'
                ${dateFilter}
            WHERE u.role = 'student' AND u.is_active = 1
            GROUP BY u.user_id
            HAVING quizzes_completed > 0
            ORDER BY total_points DESC, avg_score DESC
            LIMIT 20
        `);
        
        // Calculate rank
        const leaderboardWithRank = leaderboard.map((entry, index) => ({
            rank: index + 1,
            ...entry,
            avg_score: Math.round(entry.avg_score),
            total_points: Math.round(entry.total_points),
            highest_score: Math.round(entry.highest_score)
        }));
        
        res.json({
            success: true,
            leaderboard: leaderboardWithRank,
            period: period
        });
        
    } catch (error) {
        console.error('❌ Error fetching leaderboard:', error);
        res.status(200).json({
            success: true,
            leaderboard: [],
            period: period
        });
    }
});

// ============================================
// ✅ GET /api/leaderboard/user/position - Get user's rank position
// ============================================
app.get('/api/leaderboard/user/position', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Calculate user's total points
        const [userStats] = await promisePool.query(`
            SELECT 
                COALESCE(SUM(score), 0) as total_points,
                COUNT(*) as quizzes_completed
            FROM user_quiz_attempts 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        const totalPoints = userStats[0]?.total_points || 0;
        const quizzesCompleted = userStats[0]?.quizzes_completed || 0;
        
        if (quizzesCompleted === 0) {
            return res.json({
                success: true,
                position: {
                    rank: '--',
                    total_points: 0,
                    quizzes_completed: 0
                }
            });
        }
        
        // Count users with more points
        const [rankResult] = await promisePool.query(`
            SELECT COUNT(DISTINCT user_id) + 1 as user_rank
            FROM (
                SELECT user_id, SUM(score) as total_score
                FROM user_quiz_attempts
                WHERE completion_status = 'completed'
                GROUP BY user_id
                HAVING total_score > ?
            ) as better_users
        `, [totalPoints]);
        
        const rank = rankResult[0]?.user_rank || 1;
        
        res.json({
            success: true,
            position: {
                rank: rank,
                total_points: Math.round(totalPoints),
                quizzes_completed: quizzesCompleted
            }
        });
        
    } catch (error) {
        console.error('Error fetching user position:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});


// Helper function for initials
function getInitials(name) {
    if (!name) return 'U';
    return name
        .split(' ')
        .map(word => word.charAt(0))
        .join('')
        .toUpperCase()
        .substring(0, 2);
}


// ============================================
// ✅ GET /api/quiz/user/stats - Get user's quiz statistics
// ============================================
app.get('/api/quiz/user/stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching quiz stats for user ${userId}`);
        
        // Get all completed attempts
        const [attempts] = await promisePool.query(`
            SELECT 
                COUNT(*) as total_attempts,
                COALESCE(AVG(score), 0) as avg_score,
                SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count,
                COALESCE(SUM(time_spent_seconds), 0) as total_time_seconds,
                MAX(score) as best_score
            FROM user_quiz_attempts 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        const stats = attempts[0];
        
        // Calculate accuracy (passed / total * 100)
        let accuracy = 0;
        if (stats.total_attempts > 0) {
            accuracy = Math.round((stats.passed_count / stats.total_attempts) * 100);
        }
        
        // Format time spent
        const totalMinutes = Math.floor(stats.total_time_seconds / 60);
        const hours = Math.floor(totalMinutes / 60);
        const mins = totalMinutes % 60;
        const timeFormatted = hours > 0 ? `${hours}h ${mins}m` : `${mins}m`;
        
        // Get user rank based on total points
        const [rankResult] = await promisePool.query(`
            SELECT COUNT(DISTINCT user_id) + 1 as user_rank
            FROM (
                SELECT user_id, SUM(score) as total_points
                FROM user_quiz_attempts
                WHERE completion_status = 'completed'
                GROUP BY user_id
                HAVING total_points > (
                    SELECT COALESCE(SUM(score), 0)
                    FROM user_quiz_attempts
                    WHERE user_id = ? AND completion_status = 'completed'
                )
            ) as better_users
        `, [userId]);
        
        const userRank = rankResult[0]?.user_rank || 1;
        
        res.json({
            success: true,
            stats: {
                current_score: Math.round(stats.avg_score || 0),
                accuracy: accuracy,
                time_spent: timeFormatted,
                rank: `#${userRank}`,
                total_attempts: stats.total_attempts || 0,
                best_score: Math.round(stats.best_score || 0)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz stats:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            stats: {
                current_score: 0,
                accuracy: 0,
                time_spent: '0m',
                rank: '#--'
            }
        });
    }
});



// ============================================
// ✅ GET /api/quiz/user/points - Get user's total points
// ============================================
app.get('/api/quiz/user/points', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [points] = await promisePool.query(
            'SELECT COALESCE(SUM(points_amount), 0) as total_points FROM user_points WHERE user_id = ?',
            [userId]
        );
        
        res.json({
            success: true,
            points: {
                total_points: points[0]?.total_points || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching points:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            points: { total_points: 0 }
        });
    }
});

// Get user progress stats (for dashboard)
app.get('/api/user/progress/stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get lesson progress
        const [lessonStats] = await promisePool.query(`
            SELECT 
                COUNT(DISTINCT content_id) as lessons_completed
            FROM user_content_progress 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get quiz stats
        const [quizStats] = await promisePool.query(`
            SELECT 
                COUNT(*) as quizzes_completed,
                COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get practice stats
        const [practiceStats] = await promisePool.query(`
            SELECT 
                COUNT(*) as exercises_completed,
                COALESCE(AVG(score), 0) as avg_score
            FROM user_practice_progress 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get total time spent
        const [timeStats] = await promisePool.query(`
            SELECT 
                COALESCE(SUM(time_spent_seconds), 0) as total_seconds
            FROM (
                SELECT time_spent_seconds FROM user_content_progress WHERE user_id = ? AND time_spent_seconds IS NOT NULL
                UNION ALL
                SELECT time_spent_seconds FROM user_quiz_attempts WHERE user_id = ? AND time_spent_seconds IS NOT NULL
                UNION ALL
                SELECT time_spent_seconds FROM user_practice_progress WHERE user_id = ? AND time_spent_seconds IS NOT NULL
            ) as all_time
        `, [userId, userId, userId]);
        
        res.json({
            success: true,
            stats: {
                lessons_completed: lessonStats[0]?.lessons_completed || 0,
                quizzes_completed: quizStats[0]?.quizzes_completed || 0,
                exercises_completed: practiceStats[0]?.exercises_completed || 0,
                quiz_avg_score: Math.round(quizStats[0]?.avg_score || 0),
                practice_avg_score: Math.round(practiceStats[0]?.avg_score || 0),
                total_time_minutes: Math.round((timeStats[0]?.total_seconds || 0) / 60)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching progress stats:', error);
        res.status(200).json({
            success: true,
            stats: {
                lessons_completed: 0,
                quizzes_completed: 0,
                exercises_completed: 0,
                quiz_avg_score: 0,
                practice_avg_score: 0,
                total_time_minutes: 0
            }
        });
    }
});

// ============================================
// QUICK STATS ENDPOINT
// ============================================

app.get('/api/stats/quick', async (req, res) => {
    try {
        console.log('📊 Fetching quick stats...');
        
        const [lessonsResult] = await promisePool.execute(`
            SELECT COUNT(*) as total 
            FROM topic_content_items 
            WHERE is_active = TRUE
        `);
        
        const [subjectsResult] = await promisePool.execute(`
            SELECT COUNT(*) as total 
            FROM lessons 
            WHERE is_active = TRUE
        `);
        
        const [studentsResult] = await promisePool.execute(`
            SELECT COUNT(*) as total 
            FROM users 
            WHERE role = 'student' AND is_active = 1
        `);
        
        const [resourcesResult] = await promisePool.execute(`
            SELECT COUNT(*) as total 
            FROM topic_content_items 
            WHERE is_active = TRUE
        `);
        
        const stats = {
            totalLessons: lessonsResult[0]?.total || 0,
            totalSubjects: subjectsResult[0]?.total || 0,
            totalStudents: studentsResult[0]?.total || 0,
            totalResources: resourcesResult[0]?.total || 0
        };
        
        console.log('✅ Quick stats:', stats);
        
        res.json({
            success: true,
            stats: stats
        });
        
    } catch (error) {
        console.error('❌ Error fetching quick stats:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch quick stats',
            error: error.message
        });
    }
});
// GET all quiz categories
// ============================================
// ============================================
// ✅ GET /api/quiz/categories - PUBLIC VERSION (walang auth)
// ============================================
app.get('/api/quiz/categories', async (req, res) => {
    try {
        console.log('📥 Fetching quiz categories...');
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'quiz_categories'");
        
        if (tables.length === 0) {
            // Return default categories if table doesn't exist
            return res.json({
                success: true,
                categories: [
                    { 
                        category_id: 1, 
                        category_name: 'Mathematics', 
                        icon: 'fas fa-calculator', 
                        description: 'Math quizzes covering algebra, geometry, and more',
                        color: '#3498db'
                    },
                    { 
                        category_id: 2, 
                        category_name: 'Science', 
                        icon: 'fas fa-flask', 
                        description: 'Physics, chemistry, and biology quizzes',
                        color: '#27ae60'
                    },
                    { 
                        category_id: 3, 
                        category_name: 'English', 
                        icon: 'fas fa-book', 
                        description: 'Grammar, vocabulary, and literature',
                        color: '#e74c3c'
                    },
                    { 
                        category_id: 4, 
                        category_name: 'History', 
                        icon: 'fas fa-landmark', 
                        description: 'World history and civilizations',
                        color: '#f39c12'
                    },
                    { 
                        category_id: 5, 
                        category_name: 'Programming', 
                        icon: 'fas fa-code', 
                        description: 'Coding and computer science',
                        color: '#9b59b6'
                    }
                ]
            });
        }
        
        // Get categories from database
        const [categories] = await promisePool.query(`
            SELECT 
                category_id,
                category_name,
                icon,
                description,
                color,
                is_active,
                created_at
            FROM quiz_categories 
            WHERE is_active = 1 OR is_active IS NULL
            ORDER BY category_name
        `);
        
        console.log(`✅ Found ${categories.length} quiz categories`);
        
        // Get quiz count for each category
        for (let category of categories) {
            const [count] = await promisePool.query(`
                SELECT COUNT(*) as count FROM quizzes 
                WHERE category_id = ? AND (is_active = 1 OR is_active IS NULL)
            `, [category.category_id]);
            
            category.quiz_count = count[0]?.count || 0;
        }
        
        res.json({
            success: true,
            categories: categories
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz categories:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            categories: [] 
        });
    }
});



// ============================================
// 🔍 DEBUG: Check Quizzes in Database
// ============================================
app.get('/api/debug/quizzes', async (req, res) => {
    try {
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'quizzes'");
        
        if (tables.length === 0) {
            return res.json({
                success: false,
                message: 'Quizzes table does not exist',
                tables: []
            });
        }
        
        // Get all quizzes
        const [quizzes] = await promisePool.query(`
            SELECT 
                quiz_id,
                quiz_title,
                description,
                category_id,
                difficulty,
                total_questions,
                is_active,
                created_at
            FROM quizzes
            ORDER BY created_at DESC
        `);
        
        // Get table structure
        const [columns] = await promisePool.query("DESCRIBE quizzes");
        
        res.json({
            success: true,
            table_exists: true,
            column_count: columns.length,
            columns: columns,
            quiz_count: quizzes.length,
            quizzes: quizzes
        });
        
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});



// CREATE category (admin only)
app.post('/api/quiz/categories', authenticateAdmin, async (req, res) => {
    try {
        const { name, icon, description } = req.body;
        
        if (!name) {
            return res.status(400).json({
                success: false,
                message: 'Category name is required'
            });
        }
        
        const [result] = await promisePool.query(`
            INSERT INTO quiz_categories 
            (category_name, icon, description, created_at)
            VALUES (?, ?, ?, NOW())
        `, [name, icon || 'folder', description || null]);
        
        res.status(201).json({
            success: true,
            message: 'Category created successfully',
            category_id: result.insertId
        });
        
    } catch (error) {
        console.error('❌ Error creating category:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// UPDATE category (admin only)
app.put('/api/quiz/categories/:categoryId', authenticateAdmin, async (req, res) => {
    try {
        const { categoryId } = req.params;
        const { name, icon, description, is_active } = req.body;
        
        const [result] = await promisePool.query(`
            UPDATE quiz_categories 
            SET category_name = COALESCE(?, category_name),
                icon = COALESCE(?, icon),
                description = COALESCE(?, description),
                is_active = COALESCE(?, is_active),
                updated_at = NOW()
            WHERE category_id = ?
        `, [name, icon, description, is_active, categoryId]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Category updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating category:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// DELETE category (admin only)
app.delete('/api/quiz/categories/:categoryId', authenticateAdmin, async (req, res) => {
    try {
        const { categoryId } = req.params;
        
        // Check if category has quizzes
        const [quizzes] = await promisePool.query(
            'SELECT COUNT(*) as count FROM quizzes WHERE category_id = ?',
            [categoryId]
        );
        
        if (quizzes[0].count > 0) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete category because it has quizzes'
            });
        }
        
        const [result] = await promisePool.query(
            'DELETE FROM quiz_categories WHERE category_id = ?',
            [categoryId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Category not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Category deleted successfully'
        });
        
    } catch (error) {
        console.error('❌ Error deleting category:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});
// ===== MODULE MANAGEMENT =====

// GET all modules
app.get('/api/admin/modules', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const [modules] = await promisePool.query(`
            SELECT 
                cm.module_id,
                cm.module_name,
                cm.module_description,
                cm.module_order,
                cm.is_active,
                cm.created_at,
                l.lesson_id,
                l.lesson_name
            FROM course_modules cm
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE cm.is_active = TRUE
            ORDER BY l.lesson_order, cm.module_order
        `);
        
        res.json({
            success: true,
            modules: modules
        });
        
    } catch (error) {
        console.error('❌ Error fetching modules:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch modules',
            error: error.message
        });
    }
});

// CREATE module
app.post('/api/admin/modules', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const { lesson_id, module_name, module_description } = req.body;
        
        if (!lesson_id) {
            return res.status(400).json({
                success: false,
                message: 'Lesson ID is required'
            });
        }
        
        if (!module_name || module_name.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Module name is required'
            });
        }
        
        const [lessonCheck] = await promisePool.query(
            'SELECT lesson_id FROM lessons WHERE lesson_id = ? AND is_active = TRUE',
            [lesson_id]
        );
        
        if (lessonCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Selected lesson does not exist'
            });
        }
        
        const [orderResult] = await promisePool.query(
            'SELECT MAX(module_order) as max_order FROM course_modules WHERE lesson_id = ?',
            [lesson_id]
        );
        
        const nextOrder = (orderResult[0]?.max_order || 0) + 1;
        
        const [result] = await promisePool.query(
            `INSERT INTO course_modules 
             (lesson_id, module_name, module_description, module_order, is_active, created_at)
             VALUES (?, ?, ?, ?, TRUE, NOW())`,
            [
                parseInt(lesson_id),
                module_name.trim(),
                module_description?.trim() || null,
                nextOrder
            ]
        );
        
        const newModuleId = result.insertId;
        
        const [newModule] = await promisePool.query(`
            SELECT 
                cm.module_id,
                cm.module_name,
                cm.module_description,
                cm.module_order,
                cm.created_at,
                l.lesson_id,
                l.lesson_name
            FROM course_modules cm
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE cm.module_id = ?
        `, [newModuleId]);
        
        res.status(201).json({
            success: true,
            message: 'Module created successfully',
            module: newModule[0] || {
                module_id: newModuleId,
                module_name: module_name,
                lesson_id: lesson_id
            }
        });
        
    } catch (error) {
        console.error('❌ Error creating module:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                success: false,
                message: 'A module with this name already exists in this lesson'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Failed to create module',
            error: error.message
        });
    }
});

// UPDATE module
app.put('/api/admin/modules/:moduleId', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const { moduleId } = req.params;
        const { module_name, module_description, is_active } = req.body;
        
        const [existing] = await promisePool.query(
            'SELECT module_id FROM course_modules WHERE module_id = ?',
            [moduleId]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Module not found'
            });
        }
        
        let updateFields = [];
        let updateValues = [];
        
        if (module_name) {
            updateFields.push('module_name = ?');
            updateValues.push(module_name.trim());
        }
        
        if (module_description !== undefined) {
            updateFields.push('module_description = ?');
            updateValues.push(module_description?.trim() || null);
        }
        
        if (is_active !== undefined) {
            updateFields.push('is_active = ?');
            updateValues.push(is_active);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(moduleId);
        
        await promisePool.query(
            `UPDATE course_modules SET ${updateFields.join(', ')} WHERE module_id = ?`,
            updateValues
        );
        
        res.json({
            success: true,
            message: 'Module updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating module:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update module',
            error: error.message
        });
    }
});

// DELETE module
app.delete('/api/admin/modules/:moduleId', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin role required.'
            });
        }
        
        const { moduleId } = req.params;
        
        const [topics] = await promisePool.query(
            'SELECT COUNT(*) as count FROM module_topics WHERE module_id = ?',
            [moduleId]
        );
        
        if (topics[0].count > 0) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete module because it has topics. Delete the topics first.'
            });
        }
        
        const [result] = await promisePool.query(
            'DELETE FROM course_modules WHERE module_id = ?',
            [moduleId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Module not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Module deleted successfully'
        });
        
    } catch (error) {
        console.error('❌ Error deleting module:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to delete module',
            error: error.message
        });
    }
});

// ===== TOPIC MANAGEMENT =====

// GET all topics
app.get('/api/admin/topics', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const [topics] = await promisePool.query(`
            SELECT 
                mt.topic_id,
                mt.topic_title,
                mt.topic_description,
                mt.topic_order,
                mt.is_active,
                mt.created_at,
                cm.module_id,
                cm.module_name,
                l.lesson_id,
                l.lesson_name
            FROM module_topics mt
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE mt.is_active = TRUE
            ORDER BY l.lesson_order, cm.module_order, mt.topic_order
        `);
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('❌ Error fetching topics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch topics',
            error: error.message
        });
    }
});

// CREATE topic
app.post('/api/admin/topics', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const { module_id, topic_title, topic_description } = req.body;
        
        if (!module_id) {
            return res.status(400).json({
                success: false,
                message: 'Module ID is required'
            });
        }
        
        if (!topic_title || topic_title.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Topic title is required'
            });
        }
        
        const [moduleCheck] = await promisePool.query(
            'SELECT module_id FROM course_modules WHERE module_id = ? AND is_active = TRUE',
            [module_id]
        );
        
        if (moduleCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Selected module does not exist'
            });
        }
        
        const [orderResult] = await promisePool.query(
            'SELECT MAX(topic_order) as max_order FROM module_topics WHERE module_id = ?',
            [module_id]
        );
        
        const nextOrder = (orderResult[0]?.max_order || 0) + 1;
        
        const [result] = await promisePool.query(
            `INSERT INTO module_topics 
             (module_id, topic_title, topic_description, topic_order, is_active, created_at)
             VALUES (?, ?, ?, ?, TRUE, NOW())`,
            [
                module_id,
                topic_title.trim(),
                topic_description?.trim() || null,
                nextOrder
            ]
        );
        
        const newTopicId = result.insertId;
        
        const [newTopic] = await promisePool.query(`
            SELECT 
                mt.topic_id,
                mt.topic_title,
                mt.topic_description,
                mt.topic_order,
                mt.created_at,
                cm.module_id,
                cm.module_name,
                l.lesson_id,
                l.lesson_name
            FROM module_topics mt
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE mt.topic_id = ?
        `, [newTopicId]);
        
        res.status(201).json({
            success: true,
            message: 'Topic created successfully',
            topic: newTopic[0] || {
                topic_id: newTopicId,
                topic_title: topic_title,
                module_id: module_id
            }
        });
        
    } catch (error) {
        console.error('❌ Error creating topic:', error);
        
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
                success: false,
                message: 'A topic with this title already exists in this module'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Failed to create topic',
            error: error.message
        });
    }
});

// UPDATE topic
app.put('/api/admin/topics/:topicId', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin' && req.user.role !== 'teacher') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin or teacher role required.'
            });
        }
        
        const { topicId } = req.params;
        const { topic_title, topic_description, is_active } = req.body;
        
        const [existing] = await promisePool.query(
            'SELECT topic_id FROM module_topics WHERE topic_id = ?',
            [topicId]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Topic not found'
            });
        }
        
        let updateFields = [];
        let updateValues = [];
        
        if (topic_title) {
            updateFields.push('topic_title = ?');
            updateValues.push(topic_title.trim());
        }
        
        if (topic_description !== undefined) {
            updateFields.push('topic_description = ?');
            updateValues.push(topic_description?.trim() || null);
        }
        
        if (is_active !== undefined) {
            updateFields.push('is_active = ?');
            updateValues.push(is_active);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(topicId);
        
        await promisePool.query(
            `UPDATE module_topics SET ${updateFields.join(', ')} WHERE topic_id = ?`,
            updateValues
        );
        
        res.json({
            success: true,
            message: 'Topic updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating topic:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update topic',
            error: error.message
        });
    }
});

// DELETE topic
app.delete('/api/admin/topics/:topicId', verifyToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({
                success: false,
                message: 'Access denied. Admin role required.'
            });
        }
        
        const { topicId } = req.params;
        
        const [existing] = await promisePool.query(
            'SELECT topic_id, topic_title FROM module_topics WHERE topic_id = ?',
            [topicId]
        );
        
        if (existing.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Topic not found'
            });
        }
        
        // Hard delete
        await promisePool.query(
            'DELETE FROM topic_content_items WHERE topic_id = ?',
            [topicId]
        );
        
        const [result] = await promisePool.query(
            'DELETE FROM module_topics WHERE topic_id = ?',
            [topicId]
        );
        
        res.json({
            success: true,
            message: `Topic "${existing[0].topic_title}" deleted successfully`
        });
        
    } catch (error) {
        console.error('❌ Error deleting topic:', error);
        
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete topic because it has lessons. Delete the lessons first.'
            });
        }
        
        res.status(500).json({
            success: false,
            message: 'Failed to delete topic',
            error: error.message
        });
    }
});


// ===== PRACTICE MANAGEMENT ROUTES =====
// Add these to your server.js file

// ===== GET ALL PRACTICE EXERCISES =====
// ===== GET ALL PRACTICE EXERCISES =====
app.get('/api/admin/practice/exercises', authenticateToken, async (req, res) => {
    try {
        // Check if user is admin
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        console.log('📥 Fetching practice exercises...');

        // Check if tables exist
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'practice_exercises'");
        if (tables.length === 0) {
            return res.json({
                success: true,
                exercises: [],
                message: 'Practice tables not created yet'
            });
        }

        // Get exercises from database - using promisePool, not db
        const [exercises] = await promisePool.query(`
            SELECT 
                pe.exercise_id as id,
                pe.title,
                pe.description,
                pe.topic_id,
                pe.content_type as type,
                pe.difficulty,
                pe.points,
                pe.is_active as status,
                pe.created_at,
                mt.topic_title as category,
                (SELECT COUNT(*) FROM practice_questions pq WHERE pq.exercise_id = pe.exercise_id) as questions_count,
                COALESCE((SELECT AVG(score) FROM practice_attempts pa WHERE pa.exercise_id = pe.exercise_id), 0) as avg_score,
                (SELECT COUNT(*) FROM practice_attempts pa WHERE pa.exercise_id = pe.exercise_id) as attempts
            FROM practice_exercises pe
            LEFT JOIN module_topics mt ON pe.topic_id = mt.topic_id
            ORDER BY pe.created_at DESC
        `);

        console.log(`✅ Found ${exercises.length} practice exercises`);

        res.json({
            success: true,
            exercises: exercises
        });

    } catch (error) {
        console.error('❌ Error fetching practice exercises:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice exercises: ' + error.message 
        });
    }
});

// ===== CREATE NEW PRACTICE EXERCISE (UPDATED TO MATCH SCHEMA) =====
// ============================================
// PRACTICE EXERCISE ROUTES (Admin)
// ============================================

// CREATE new practice exercise
app.post('/api/admin/practice', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Creating practice exercise...');
        
        const {
            title,
            description,
            topic_id,
            content_type,
            difficulty,
            points,
            content_json,
            is_active,
            status
        } = req.body;

        // Validate required fields
        if (!title) {
            return res.status(400).json({ success: false, message: 'Title is required' });
        }
        if (!topic_id) {
            return res.status(400).json({ success: false, message: 'Topic ID is required' });
        }
        if (!content_type) {
            return res.status(400).json({ success: false, message: 'Content type is required' });
        }

        // Convert content_json to string if it's an object
        const contentJsonString = typeof content_json === 'object'
            ? JSON.stringify(content_json)
            : content_json;

        // Determine active status
        const activeStatus = is_active !== undefined ? is_active : (status === 'active' ? 1 : 0);

        const [result] = await promisePool.query(`
            INSERT INTO practice_exercises 
            (topic_id, title, description, content_type, difficulty, points, content_json, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [
            topic_id,
            title,
            description || null,
            content_type,
            difficulty || 'medium',
            points || 10,
            contentJsonString,
            activeStatus
        ]);

        console.log(`✅ Practice exercise created with ID: ${result.insertId}`);
        res.status(201).json({
            success: true,
            message: 'Practice exercise created successfully',
            exerciseId: result.insertId
        });

    } catch (error) {
        console.error('❌ Error creating practice exercise:', error);
        res.status(500).json({ success: false, message: 'Failed to create practice exercise: ' + error.message });
    }
});
app.post('/api/admin/practice/exercises', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        const {
            title,
            description,
            topic_id,
            content_type,  // ← This is the database column name
            difficulty,
            points,
            content_json,
            status,
            is_active
        } = req.body;

        console.log('📥 Creating practice exercise:', { 
            title, 
            topic_id, 
            content_type,
            status
        });

        // Validate required fields
        if (!title) {
            return res.status(400).json({
                success: false,
                message: 'Title is required'
            });
        }

        if (!topic_id) {
            return res.status(400).json({
                success: false,
                message: 'Topic ID is required'
            });
        }

        if (!content_type) {
            return res.status(400).json({
                success: false,
                message: 'Content type is required'
            });
        }

        // Start transaction
        const connection = await promisePool.getConnection();
        await connection.beginTransaction();

        try {
            // Convert content_json to string for storage
            const contentJsonString = JSON.stringify(content_json);

            // Insert exercise
            const [exerciseResult] = await connection.query(`
                INSERT INTO practice_exercises (
                    topic_id, 
                    title, 
                    description, 
                    content_type, 
                    difficulty, 
                    points, 
                    content_json, 
                    status,
                    is_active, 
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `, [
                topic_id, 
                title, 
                description || null, 
                content_type, 
                difficulty || 'medium', 
                points || 10, 
                contentJsonString,
                status || 'draft',
                is_active || 1
            ]);

            const exerciseId = exerciseResult.insertId;
            console.log(`✅ Exercise created with ID: ${exerciseId}`);

            await connection.commit();
            connection.release();

            res.json({
                success: true,
                message: 'Practice exercise created successfully',
                exerciseId: exerciseId
            });

        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }

    } catch (error) {
        console.error('❌ Error creating practice exercise:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to create practice exercise: ' + error.message 
        });
    }
});
// ============================================
// ADD MISSING GET /api/admin/practice ROUTE
// ============================================
app.get('/api/admin/practice', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching practice exercises for admin...');

        // Check if practice_exercises table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'practice_exercises'");
        if (tables.length === 0) {
            return res.json({ success: true, exercises: [] });
        }

        // Get exercises from database
        const [exercises] = await promisePool.query(`
            SELECT 
                pe.exercise_id as id,
                pe.title,
                pe.description,
                pe.topic_id,
                pe.content_type,
                pe.difficulty,
                pe.points,
                pe.content_json,
                pe.is_active,
                pe.created_at,
                CASE 
                    WHEN pe.is_active = 1 THEN 'active'
                    ELSE 'inactive'
                END as status
            FROM practice_exercises pe
            ORDER BY pe.created_at DESC
        `);

        // Count questions in content_json for each exercise
        const exercisesWithCount = exercises.map(ex => {
            let questionCount = 0;
            try {
                if (ex.content_json) {
                    const content = typeof ex.content_json === 'string'
                        ? JSON.parse(ex.content_json)
                        : ex.content_json;
                    questionCount = content.questions ? content.questions.length : 0;
                }
            } catch (e) {
                console.log(`⚠️ Error parsing JSON for exercise ${ex.id}`);
            }

            return {
                id: ex.id,
                title: ex.title,
                description: ex.description,
                topic_id: ex.topic_id,
                content_type: ex.content_type,
                difficulty: ex.difficulty,
                points: ex.points,
                question_count: questionCount,
                status: ex.status,
                is_active: ex.is_active,
                created_at: ex.created_at,
                attempts: 0,          // You can join with practice_attempts if needed
                avg_score: 0           // Placeholder; implement later
            };
        });

        console.log(`✅ Found ${exercisesWithCount.length} practice exercises`);
        res.json({ success: true, exercises: exercisesWithCount });

    } catch (error) {
        console.error('❌ Error fetching practice exercises:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
// ===== GET PRACTICE STATS =====
app.get('/api/admin/practice/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        console.log('📊 Fetching practice stats...');

        // Check if tables exist
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'practice_exercises'");
        if (tables.length === 0) {
            return res.json({
                success: true,
                stats: {
                    totalExercises: 0,
                    totalQuestions: 0,
                    activeExercises: 0,
                    totalAttempts: 0,
                    averageScore: 0
                }
            });
        }

        // Get total exercises
        const [totalExercises] = await promisePool.query(`
            SELECT COUNT(*) as count FROM practice_exercises
        `);

        // Get total questions
        const [totalQuestions] = await promisePool.query(`
            SELECT COUNT(*) as count FROM practice_questions
        `);

        // Get active exercises (is_active = 1)
        const [activeExercises] = await promisePool.query(`
            SELECT COUNT(*) as count FROM practice_exercises 
            WHERE is_active = 1
        `);

        // Get total attempts
        const [totalAttempts] = await promisePool.query(`
            SELECT COUNT(*) as count FROM practice_attempts
        `);

        // Get average score
        const [avgScore] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score 
            FROM practice_attempts
        `);

        const stats = {
            totalExercises: totalExercises[0].count,
            totalQuestions: totalQuestions[0].count,
            activeExercises: activeExercises[0].count,
            totalAttempts: totalAttempts[0].count,
            averageScore: Math.round(avgScore[0].avg_score)
        };

        console.log('✅ Practice stats:', stats);

        res.json({
            success: true,
            stats: stats
        });

    } catch (error) {
        console.error('❌ Error fetching practice stats:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice stats: ' + error.message 
        });
    }
});



// ===== UPDATE PRACTICE EXERCISE =====
// ===== UPDATE PRACTICE EXERCISE =====
app.put('/api/admin/practice/exercises/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        const exerciseId = req.params.id;
        const {
            title,
            description,
            topic_id,
            difficulty,
            type,
            points,
            is_active
        } = req.body;

        await promisePool.query(`
            UPDATE practice_exercises SET
                title = ?, description = ?, topic_id = ?,
                content_type = ?, difficulty = ?, points = ?,
                is_active = ?, updated_at = NOW()
            WHERE exercise_id = ?
        `, [
            title, description, topic_id, type || 'multiple_choice',
            difficulty || 'medium', points || 10, is_active ? 1 : 0, exerciseId
        ]);

        res.json({
            success: true,
            message: 'Practice exercise updated successfully'
        });

    } catch (error) {
        console.error('❌ Error updating practice exercise:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update practice exercise: ' + error.message 
        });
    }
});
app.delete('/api/admin/practice/exercises/:id', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        const exerciseId = req.params.id;

        await promisePool.query('DELETE FROM practice_exercises WHERE exercise_id = ?', [exerciseId]);

        res.json({
            success: true,
            message: 'Practice exercise deleted successfully'
        });

    } catch (error) {
        console.error('❌ Error deleting practice exercise:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete practice exercise: ' + error.message 
        });
    }
});

// ===== GET SINGLE PRACTICE EXERCISE WITH QUESTIONS =====
app.get('/api/admin/practice/exercises/:id', authenticateToken, async (req, res) => {
    try {
        const exerciseId = req.params.id;

        // Get exercise details
        const [exercises] = await db.query(`
            SELECT * FROM practice_exercises WHERE id = ?
        `, [exerciseId]);

        if (exercises.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Exercise not found'
            });
        }

        const exercise = exercises[0];

        // Get questions
        const [questions] = await db.query(`
            SELECT * FROM practice_questions 
            WHERE exercise_id = ? 
            ORDER BY order_number
        `, [exerciseId]);

        // Get options for each question
        for (const q of questions) {
            const [options] = await db.query(`
                SELECT * FROM practice_question_options 
                WHERE question_id = ?
            `, [q.id]);
            q.options = options;
        }

        exercise.questions = questions;

        res.json({
            success: true,
            exercise: exercise
        });

    } catch (error) {
        console.error('Error fetching practice exercise:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice exercise' 
        });
    }
});

// ===== GET PRACTICE STATISTICS FOR SPECIFIC EXERCISE =====
app.get('/api/admin/practice/exercises/:id/stats', authenticateToken, async (req, res) => {
    try {
        const exerciseId = req.params.id;

        // Get overall stats
        const [stats] = await db.query(`
            SELECT 
                COUNT(DISTINCT user_id) as total_students,
                COUNT(*) as total_attempts,
                AVG(score) as avg_score,
                MAX(score) as highest_score,
                MIN(score) as lowest_score,
                SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count
            FROM practice_attempts
            WHERE exercise_id = ?
        `, [exerciseId]);

        // Get question performance
        const [questionStats] = await db.query(`
            SELECT 
                q.id,
                q.question_text,
                COUNT(ua.id) as attempt_count,
                AVG(ua.is_correct) * 100 as correct_percentage
            FROM practice_questions q
            LEFT JOIN user_answers ua ON q.id = ua.question_id
            WHERE q.exercise_id = ?
            GROUP BY q.id
        `, [exerciseId]);

        res.json({
            success: true,
            stats: stats[0],
            questionStats: questionStats
        });

    } catch (error) {
        console.error('Error fetching exercise stats:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch exercise statistics' 
        });
    }
});

// ===== GET PRACTICE ANALYTICS =====
app.get('/api/admin/practice/analytics', authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Access denied. Admin only.' 
            });
        }

        // Get attempts by subject
        const [attemptsBySubject] = await db.query(`
            SELECT 
                s.subject_name,
                COUNT(pa.id) as attempt_count
            FROM practice_attempts pa
            JOIN practice_exercises pe ON pa.exercise_id = pe.id
            JOIN subjects s ON pe.subject_id = s.id
            GROUP BY s.id
        `);

        // Get performance trend (last 7 days)
        const [performanceTrend] = await db.query(`
            SELECT 
                DATE(pa.completed_at) as date,
                AVG(pa.score) as avg_score,
                COUNT(pa.id) as attempts
            FROM practice_attempts pa
            WHERE pa.completed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(pa.completed_at)
            ORDER BY date
        `);

        // Get top performing exercises
        const [topExercises] = await db.query(`
            SELECT 
                pe.title,
                COUNT(pa.id) as attempts,
                AVG(pa.score) as avg_score
            FROM practice_exercises pe
            LEFT JOIN practice_attempts pa ON pe.id = pa.exercise_id
            GROUP BY pe.id
            ORDER BY attempts DESC
            LIMIT 5
        `);

        res.json({
            success: true,
            analytics: {
                attemptsBySubject: attemptsBySubject,
                performanceTrend: performanceTrend,
                topExercises: topExercises
            }
        });

    } catch (error) {
        console.error('Error fetching practice analytics:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice analytics' 
        });
    }
});

// ============================================
// PERFORMANCE DASHBOARD ENDPOINTS
// ============================================

// Get top performers
// ===== GET TOP PERFORMERS (returns empty if no data) =====
app.get('/api/admin/performance/top-performers', authenticateAdmin, async (req, res) => {
    try {
        // Check if there's any progress data
        const [hasData] = await promisePool.query(`
            SELECT COUNT(*) as count FROM user_content_progress WHERE completion_status = 'completed'
        `);
        
        if (hasData[0].count === 0) {
            // No data yet - return empty array
            return res.json({
                success: true,
                performers: []
            });
        }
        
        // Only query if there's data
        const [performers] = await promisePool.query(`
            SELECT 
                u.user_id as id,
                u.full_name as name,
                COUNT(ucp.content_id) as lessons_completed,
                COALESCE(AVG(ucp.score), 0) as score,
                0 as progress,
                'General' as subject,
                CONCAT(SUBSTRING(u.full_name, 1, 1), COALESCE(SUBSTRING(SUBSTRING_INDEX(u.full_name, ' ', -1), 1, 1), '')) as avatar
            FROM users u
            LEFT JOIN user_content_progress ucp ON u.user_id = ucp.user_id AND ucp.completion_status = 'completed'
            WHERE u.role = 'student' AND u.is_active = 1
            GROUP BY u.user_id
            HAVING lessons_completed > 0
            ORDER BY score DESC, lessons_completed DESC
            LIMIT 10
        `);
        
        res.json({
            success: true,
            performers: performers
        });
        
    } catch (error) {
        console.error('Error:', error);
        res.json({ success: true, performers: [] });
    }
});

// ===== GET SUBJECT BREAKDOWN (returns empty if no data) =====
app.get('/api/admin/performance/subject-breakdown', authenticateAdmin, async (req, res) => {
    try {
        // Check if there's any data
        const [hasData] = await promisePool.query(`
            SELECT COUNT(*) as count FROM user_content_progress WHERE completion_status = 'completed'
        `);
        
        if (hasData[0].count === 0) {
            return res.json({
                success: true,
                subjects: []
            });
        }
        
        // Only query if there's data
        const [subjects] = await promisePool.query(`
            SELECT 
                l.lesson_name as name,
                COUNT(DISTINCT ucp.user_id) as totalStudents,
                COALESCE(AVG(ucp.score), 0) as avgScore,
                0 as completionRate,
                'N/A' as topPerformer
            FROM lessons l
            LEFT JOIN course_modules cm ON l.lesson_id = cm.lesson_id
            LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
            LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id
            WHERE l.is_active = 1
            GROUP BY l.lesson_id
            HAVING totalStudents > 0
        `);
        
        res.json({
            success: true,
            subjects: subjects
        });
        
    } catch (error) {
        console.error('Error:', error);
        res.json({ success: true, subjects: [] });
    }
});

// ===== GET PERFORMANCE STATS =====
app.get('/api/admin/performance/stats', authenticateAdmin, async (req, res) => {
    try {
        console.log('📊 Fetching performance stats...');
        
        // Check if there's any data
        const [hasData] = await promisePool.query(`
            SELECT COUNT(*) as count FROM user_content_progress WHERE completion_status = 'completed'
        `);
        
        const dataExists = hasData[0].count > 0;
        
        if (!dataExists) {
            return res.json({
                success: true,
                stats: {
                    has_data: false,
                    avg_score: 0,
                    avg_score_change: 0,
                    completion_rate: 0,
                    completion_rate_change: 0,
                    avg_time: 0,
                    avg_time_change: 0,
                    active_students: 0,
                    active_students_change: 0
                }
            });
        }
        
        // Get average score from completed lessons
        const [avgScore] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score 
            FROM user_content_progress 
            WHERE completion_status = 'completed'
        `);
        
        // Get completion rate
        const [totalStudents] = await promisePool.query(`
            SELECT COUNT(*) as count FROM users WHERE role = 'student' AND is_active = 1
        `);
        
        const [studentsWithProgress] = await promisePool.query(`
            SELECT COUNT(DISTINCT user_id) as count 
            FROM user_content_progress 
            WHERE completion_status = 'completed'
        `);
        
        const completionRate = totalStudents[0].count > 0 
            ? Math.round((studentsWithProgress[0].count * 100) / totalStudents[0].count)
            : 0;
        
        // Get average time (simplified)
        const [avgTime] = await promisePool.query(`
            SELECT COALESCE(AVG(time_spent_seconds), 0) / 60 as avg_minutes
            FROM user_content_progress 
            WHERE completion_status = 'completed' AND time_spent_seconds > 0
        `);
        
        // Get active students (completed something this week)
        const [activeThisWeek] = await promisePool.query(`
            SELECT COUNT(DISTINCT user_id) as count
            FROM user_content_progress 
            WHERE completed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `);
        
        // Get previous month data for changes (simplified)
        const [prevMonthAvg] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score
            FROM user_content_progress 
            WHERE completion_status = 'completed'
            AND completed_at >= DATE_SUB(NOW(), INTERVAL 60 DAY)
            AND completed_at < DATE_SUB(NOW(), INTERVAL 30 DAY)
        `);
        
        const avgScoreValue = Math.round(avgScore[0]?.avg_score || 0);
        const prevAvgScore = Math.round(prevMonthAvg[0]?.avg_score || 0);
        const avgScoreChange = prevAvgScore > 0 ? avgScoreValue - prevAvgScore : 0;
        
        res.json({
            success: true,
            stats: {
                has_data: true,
                avg_score: avgScoreValue,
                avg_score_change: avgScoreChange,
                completion_rate: completionRate,
                completion_rate_change: 0, // You can calculate this if needed
                avg_time: Math.round(avgTime[0]?.avg_minutes || 0),
                avg_time_change: 0,
                active_students: activeThisWeek[0]?.count || 0,
                active_students_change: 0
            }
        });
        
    } catch (error) {
        console.error('Error fetching performance stats:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});


// ============================================
// ✅ FIXED QUIZ ROUTES - MATCHES YOUR DATABASE
// ============================================

// GET all quizzes
app.get('/api/admin/quizzes', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching quizzes from database...');
        
        // Check if quizzes table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'quizzes'");
        
        if (tables.length === 0) {
            return res.json({
                success: true,
                quizzes: [],
                message: 'No quizzes table found'
            });
        }
        
        // Get quizzes with question counts and average scores
        const [quizzes] = await promisePool.query(`
            SELECT 
                q.quiz_id as id,
                q.quiz_title as title,
                q.description,
                qc.category_name as subject_name,
                q.difficulty,
                q.duration_minutes as time_limit,
                q.passing_score,
                q.is_active as status,
                q.created_at,
                COUNT(DISTINCT qq.question_id) as question_count,
                COALESCE(AVG(uqa.score), 0) as avg_score
            FROM quizzes q
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            LEFT JOIN quiz_questions qq ON q.quiz_id = qq.quiz_id
            LEFT JOIN user_quiz_attempts uqa ON q.quiz_id = uqa.quiz_id 
                AND uqa.completion_status = 'completed'
            GROUP BY q.quiz_id
            ORDER BY q.created_at DESC
        `);
        
        // Format status for frontend
        const formattedQuizzes = quizzes.map(q => ({
            ...q,
            status: q.status === 1 ? 'active' : 'draft'
        }));
        
        console.log(`✅ Found ${formattedQuizzes.length} quizzes`);
        
        res.json({
            success: true,
            quizzes: formattedQuizzes
        });
        
    } catch (error) {
        console.error('❌ Error fetching quizzes:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// GET single quiz with questions
app.get('/api/admin/quizzes/:quizId', authenticateAdmin, async (req, res) => {
    try {
        const { quizId } = req.params;
        
        const [quizzes] = await promisePool.query(`
            SELECT 
                q.*,
                qc.category_name as subject_name
            FROM quizzes q
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            WHERE q.quiz_id = ?
        `, [quizId]);
        
        if (quizzes.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        const quiz = quizzes[0];
        
        // Get questions with their options
        const [questions] = await promisePool.query(`
            SELECT 
                qq.question_id,
                qq.question_text,
                qq.question_type,
                qq.points,
                qq.question_order,
                qo.option_id,
                qo.option_text,
                qo.is_correct,
                qo.option_order
            FROM quiz_questions qq
            LEFT JOIN quiz_options qo ON qq.question_id = qo.question_id
            WHERE qq.quiz_id = ?
            ORDER BY qq.question_order, qo.option_order
        `, [quizId]);
        
        // Group options by question
        const questionMap = {};
        questions.forEach(row => {
            if (!questionMap[row.question_id]) {
                questionMap[row.question_id] = {
                    question_id: row.question_id,
                    question_text: row.question_text,
                    question_type: row.question_type,
                    points: row.points,
                    question_order: row.question_order,
                    options: []
                };
            }
            if (row.option_id) {
                questionMap[row.question_id].options.push({
                    option_id: row.option_id,
                    option_text: row.option_text,
                    is_correct: row.is_correct === 1,
                    option_order: row.option_order
                });
            }
        });
        
        quiz.questions = Object.values(questionMap).sort((a, b) => a.question_order - b.question_order);
        
        res.json({
            success: true,
            quiz
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// CREATE new quiz
app.post('/api/admin/quizzes', authenticateAdmin, async (req, res) => {
    try {
        const { 
            title, 
            description, 
            category_id,  // Use category_id instead of subject_id
            difficulty = 'medium',
            time_limit = 30,
            passing_score = 70,
            is_active = 1,  // Use is_active boolean
            questions = [] 
        } = req.body;
        
        if (!title) {
            return res.status(400).json({
                success: false,
                message: 'Quiz title is required'
            });
        }
        
        const connection = await promisePool.getConnection();
        await connection.beginTransaction();
        
        try {
            // Insert quiz
            const [quizResult] = await connection.query(`
                INSERT INTO quizzes 
                (category_id, quiz_title, description, difficulty, duration_minutes, 
                 passing_score, total_questions, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `, [
                category_id || null,
                title,
                description || null,
                difficulty,
                time_limit,
                passing_score,
                questions.length,
                is_active
            ]);
            
            const quizId = quizResult.insertId;
            
            // Insert questions and options
            for (let i = 0; i < questions.length; i++) {
                const q = questions[i];
                
                const [questionResult] = await connection.query(`
                    INSERT INTO quiz_questions 
                    (quiz_id, question_text, question_type, points, question_order)
                    VALUES (?, ?, ?, ?, ?)
                `, [
                    quizId,
                    q.question_text,
                    q.question_type || 'multiple_choice',
                    q.points || 10,
                    i + 1
                ]);
                
                const questionId = questionResult.insertId;
                
                // Insert options if provided
                if (q.options && q.options.length > 0) {
                    for (let j = 0; j < q.options.length; j++) {
                        const opt = q.options[j];
                        await connection.query(`
                            INSERT INTO quiz_options 
                            (question_id, option_text, is_correct, option_order)
                            VALUES (?, ?, ?, ?)
                        `, [
                            questionId,
                            opt.option_text,
                            opt.is_correct ? 1 : 0,
                            j + 1
                        ]);
                    }
                }
            }
            
            await connection.commit();
            
            res.status(201).json({
                success: true,
                message: 'Quiz created successfully',
                quiz_id: quizId
            });
            
        } catch (error) {
            await connection.rollback();
            throw error;
        } finally {
            connection.release();
        }
        
    } catch (error) {
        console.error('❌ Error creating quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// UPDATE quiz
app.put('/api/admin/quizzes/:quizId', authenticateAdmin, async (req, res) => {
    try {
        const { quizId } = req.params;
        const { title, description, is_active, time_limit, passing_score } = req.body;
        
        const [result] = await connection.query(`
            UPDATE quizzes 
            SET quiz_title = COALESCE(?, quiz_title),
                description = COALESCE(?, description),
                is_active = COALESCE(?, is_active),
                duration_minutes = COALESCE(?, duration_minutes),
                passing_score = COALESCE(?, passing_score),
                updated_at = NOW()
            WHERE quiz_id = ?
        `, [title, description, is_active, time_limit, passing_score, quizId]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Quiz updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// DELETE quiz
app.delete('/api/admin/quizzes/:quizId', authenticateAdmin, async (req, res) => {
    try {
        const { quizId } = req.params;
        
        const [result] = await promisePool.query(
            'DELETE FROM quizzes WHERE quiz_id = ?',
            [quizId]
        );
        
        if (result.affectedRows === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        res.json({
            success: true,
            message: 'Quiz deleted successfully'
        });
        
    } catch (error) {
        console.error('❌ Error deleting quiz:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// GET quiz statistics
app.get('/api/admin/quizzes/:quizId/stats', authenticateAdmin, async (req, res) => {
    try {
        const { quizId } = req.params;
        
        const [quiz] = await promisePool.query(
            'SELECT quiz_title as title FROM quizzes WHERE quiz_id = ?',
            [quizId]
        );
        
        if (quiz.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        // Get attempt statistics
        const [stats] = await promisePool.query(`
            SELECT 
                COUNT(*) as total_attempts,
                SUM(CASE WHEN completion_status = 'completed' AND score >= passing_score THEN 1 ELSE 0 END) as passed_count,
                SUM(CASE WHEN completion_status = 'completed' AND score < passing_score THEN 1 ELSE 0 END) as failed_count,
                COALESCE(AVG(score), 0) as average_score,
                MAX(score) as highest_score
            FROM user_quiz_attempts uqa
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            WHERE uqa.quiz_id = ?
        `, [quizId]);
        
        // Get question statistics
        const [questionStats] = await promisePool.query(`
            SELECT 
                qq.question_id,
                qq.question_text,
                COUNT(qa.answer_id) as total_answers,
                SUM(CASE WHEN qa.is_correct = 1 THEN 1 ELSE 0 END) as correct_count,
                COALESCE(AVG(CASE WHEN qa.is_correct = 1 THEN 100 ELSE 0 END), 0) as correct_percentage
            FROM quiz_questions qq
            LEFT JOIN user_quiz_answers qa ON qq.question_id = qa.question_id
            WHERE qq.quiz_id = ?
            GROUP BY qq.question_id
        `, [quizId]);
        
        res.json({
            success: true,
            stats: {
                ...stats[0],
                title: quiz[0].title,
                question_stats: questionStats
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz stats:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// GET quizzes with subjects - FIXED
app.get('/api/admin/quizzes-with-subjects', authenticateAdmin, async (req, res) => {
    try {
        console.log('📥 Fetching quizzes with subjects...');
        
        const query = `
            SELECT 
                q.quiz_id,
                q.quiz_title,
                q.description,
                q.category_id,
                q.difficulty,
                q.total_questions as question_count,
                q.is_active,
                q.created_at,
                l.lesson_name,
                l.lesson_title as subject_display_name,
                
                -- FIXED: Calculate average score correctly
                (
                    SELECT COALESCE(ROUND(AVG(score), 2), 0)
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id 
                    AND uqa.completion_status = 'completed'
                ) as avg_score,
                
                -- Count total attempts
                (
                    SELECT COUNT(*) 
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id
                ) as attempts
                
            FROM quizzes q
            LEFT JOIN module_topics mt ON q.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            ORDER BY q.created_at DESC
        `;
        
        const [quizzes] = await promisePool.query(query);
        
        console.log(`✅ Found ${quizzes.length} quizzes with subjects`);

        res.json({
            success: true,
            quizzes: quizzes
        });
        
    } catch (error) {
        console.error('❌ Error fetching quizzes with subjects:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// GET recent quiz results (for dashboard widget)
app.get('/api/admin/quizzes/recent-results', authenticateAdmin, async (req, res) => {
    try {
        console.log('📋 Fetching recent quiz results...');

        // Check if tables exist
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_quiz_attempts'");
        if (tables.length === 0) {
            return res.json({
                success: true,
                results: []
            });
        }

        const [results] = await promisePool.query(`
            SELECT 
                uqa.attempt_id,
                u.user_id,
                u.full_name as student_name,
                u.username,
                q.quiz_id,
                q.quiz_title,
                uqa.score,
                uqa.passed,
                uqa.time_spent_seconds,
                uqa.end_time as completed_at
            FROM user_quiz_attempts uqa
            JOIN users u ON uqa.user_id = u.user_id
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            WHERE uqa.completion_status = 'completed'
            ORDER BY uqa.end_time DESC
            LIMIT 10
        `);

        console.log(`✅ Found ${results.length} recent results`);

        res.json({
            success: true,
            results: results
        });

    } catch (error) {
        console.error('❌ Error fetching recent results:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch recent results: ' + error.message 
        });
    }
});

// GET top quizzes (for dashboard widget)
app.get('/api/admin/quizzes/top', authenticateAdmin, async (req, res) => {
    try {
        console.log('🏆 Fetching top quizzes...');

        const [quizzes] = await promisePool.query(`
            SELECT 
                q.quiz_id,
                q.quiz_title,
                COUNT(DISTINCT uqa.attempt_id) as attempts,
                COALESCE(AVG(uqa.score), 0) as avg_score
            FROM quizzes q
            LEFT JOIN user_quiz_attempts uqa ON q.quiz_id = uqa.quiz_id
                AND uqa.completion_status = 'completed'
            GROUP BY q.quiz_id
            HAVING attempts > 0
            ORDER BY attempts DESC, avg_score DESC
            LIMIT 5
        `);

        res.json({
            success: true,
            quizzes: quizzes
        });

    } catch (error) {
        console.error('❌ Error fetching top quizzes:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});
// ============================================
// LESSON ROUTES (STUDENT)
// ============================================

// Get ALL lessons with progress
app.get('/api/lessons-db/complete', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log('📚 Fetching all lessons with progress for user ID:', userId);
        
        const [lessons] = await promisePool.execute(`
            SELECT 
                tci.content_id,
                tci.content_title,
                tci.content_description,
                tci.content_url,
                tci.video_filename,
                tci.video_path,
                tci.video_duration_seconds,
                tci.content_type,
                tci.content_order,
                mt.topic_id,
                mt.topic_title,
                mt.topic_order,
                cm.module_id,
                cm.module_name,
                cm.module_order,
                l.lesson_id,
                l.lesson_name,
                l.lesson_order
            FROM topic_content_items tci
            JOIN module_topics mt ON tci.topic_id = mt.topic_id
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE tci.is_active = TRUE
            ORDER BY l.lesson_order, cm.module_order, mt.topic_order, tci.content_order
        `);
        
        console.log(`✅ Found ${lessons.length} lessons in database`);
        
        let progressRows = [];
        if (lessons.length > 0) {
            const contentIds = lessons.map(l => l.content_id);
            const [progress] = await promisePool.execute(
                `SELECT * FROM user_content_progress 
                WHERE user_id = ? AND content_id IN (${contentIds.map(() => '?').join(',')})`,
                [userId, ...contentIds]
            );
            progressRows = progress;
        }
        
        const progressMap = {};
        progressRows.forEach(progress => {
            progressMap[progress.content_id] = {
                completion_status: progress.completion_status,
                percentage: progress.score || 0,
                time_spent_seconds: progress.time_spent_seconds,
                last_accessed: progress.last_accessed
            };
        });
        
        const lessonsWithProgress = lessons.map(lesson => {
            const lessonProgress = progressMap[lesson.content_id] || {};
            
            return {
                ...lesson,
                progress: {
                    status: lessonProgress.completion_status || 'not_started',
                    percentage: lessonProgress.percentage || 0,
                    time_spent: lessonProgress.time_spent_seconds || 0,
                    last_accessed: lessonProgress.last_accessed
                }
            };
        });
        
        res.json({
            success: true,
            lessons: lessonsWithProgress,
            count: lessons.length
        });
        
    } catch (error) {
        console.error('❌ Get lessons error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to get lessons',
            error: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
});

// Get specific lesson content
app.get('/api/lessons-db/:contentId', verifyToken, async (req, res) => {
    try {
        const { contentId } = req.params;
        const userId = req.user.id;
        
        console.log('📖 Fetching lesson content ID:', contentId);
        
        const [lessons] = await promisePool.execute(`
            SELECT 
                tci.*,
                mt.topic_id,
                mt.topic_title,
                cm.module_id,
                cm.module_name,
                l.lesson_id,
                l.lesson_name
            FROM topic_content_items tci
            JOIN module_topics mt ON tci.topic_id = mt.topic_id
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE tci.content_id = ? AND tci.is_active = TRUE
        `, [contentId]);
        
        if (lessons.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Lesson not found'
            });
        }
        
        const lesson = lessons[0];
        
        const [progress] = await promisePool.execute(`
            SELECT * FROM user_content_progress 
            WHERE user_id = ? AND content_id = ?
        `, [userId, contentId]);
        
        const lessonProgress = progress.length > 0 ? progress[0] : null;
        
        const [adjacentLessons] = await promisePool.execute(`
            SELECT 
                prev.content_id as prev_id,
                prev.content_title as prev_title,
                next.content_id as next_id,
                next.content_title as next_title
            FROM topic_content_items current
            LEFT JOIN topic_content_items prev ON (
                prev.topic_id = current.topic_id 
                AND prev.content_order = current.content_order - 1
                AND prev.is_active = TRUE
            )
            LEFT JOIN topic_content_items next ON (
                next.topic_id = current.topic_id 
                AND next.content_order = current.content_order + 1
                AND next.is_active = TRUE
            )
            WHERE current.content_id = ?
        `, [contentId]);
        
        const adjacent = adjacentLessons[0] || {};
        
        res.json({
            success: true,
            lesson: {
                ...lesson,
                progress: lessonProgress ? {
                    status: lessonProgress.completion_status,
                    percentage: lessonProgress.score || 0,
                    time_spent_seconds: lessonProgress.time_spent_seconds,
                    last_accessed: lessonProgress.last_accessed
                } : {
                    status: 'not_started',
                    percentage: 0,
                    time_spent_seconds: 0
                },
                adjacent: {
                    previous: adjacent.prev_id ? {
                        id: adjacent.prev_id,
                        title: adjacent.prev_title
                    } : null,
                    next: adjacent.next_id ? {
                        id: adjacent.next_id,
                        title: adjacent.next_title
                    } : null
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Get lesson error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to get lesson'
        });
    }
});

// Mark lesson as complete
app.post('/api/lessons/:contentId/complete', verifyToken, async (req, res) => {
    try {
        const { contentId } = req.params;
        const userId = req.user.id;
        
        console.log('✅ Marking lesson as complete:', contentId, 'for user:', userId);
        
        const [lessonExists] = await promisePool.execute(
            'SELECT content_id, content_title, topic_id, video_duration_seconds FROM topic_content_items WHERE content_id = ? AND is_active = TRUE',
            [contentId]
        );
        
        if (lessonExists.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Lesson not found'
            });
        }
        
        const alreadyCompleted = await checkIfAlreadyCompleted(userId, contentId);
        
        if (alreadyCompleted) {
            return res.json({
                success: true,
                message: 'Lesson already marked as completed',
                already_completed: true
            });
        }
        
        const lesson = lessonExists[0];
        const videoDuration = lesson.video_duration_seconds || 300;
        
        // Update progress
        const [existingRecord] = await promisePool.execute(
            'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
            [userId, contentId]
        );
        
        if (existingRecord.length > 0) {
            await promisePool.execute(`
                UPDATE user_content_progress 
                SET completion_status = 'completed',
                    score = 100,
                    time_spent_seconds = GREATEST(time_spent_seconds, ?),
                    last_accessed = NOW(),
                    completed_at = NOW()
                WHERE user_id = ? AND content_id = ?
            `, [videoDuration, userId, contentId]);
        } else {
            await promisePool.execute(`
                INSERT INTO user_content_progress 
                (user_id, content_id, completion_status, score, time_spent_seconds, completed_at)
                VALUES (?, ?, 'completed', 100, ?, NOW())
            `, [userId, contentId, videoDuration]);
        }
        
        // Update user_progress table
        const [currentCount] = await promisePool.execute(
            'SELECT COALESCE(lessons_completed, 0) as current_count FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        const newCount = (currentCount[0]?.current_count || 0) + 1;
        
        await promisePool.execute(`
            INSERT INTO user_progress (user_id, lessons_completed, exercises_completed, quiz_score)
            VALUES (?, ?, 0, 0)
            ON DUPLICATE KEY UPDATE 
                lessons_completed = ?,
                updated_at = NOW()
        `, [userId, newCount, newCount]);
        
        // Award points
        await awardPoints(userId, 'lesson_completed', 50, `Completed lesson: ${lesson.content_title}`, contentId);
        
        // Log activity
        await logUserActivity(userId, 'lesson_completed', contentId, {
            lesson_id: contentId,
            lesson_title: lesson.content_title,
            topic_id: lesson.topic_id,
            video_duration: videoDuration
        });
        
        // Update daily progress
        const today = new Date().toISOString().split('T')[0];
        await promisePool.execute(`
            INSERT INTO daily_progress (user_id, progress_date, lessons_completed, points_earned)
            VALUES (?, ?, 1, 50)
            ON DUPLICATE KEY UPDATE 
                lessons_completed = lessons_completed + 1,
                points_earned = points_earned + 50
        `, [userId, today]);
        
        console.log(`✅ Lesson ${contentId} marked as complete for user ${userId}`);
        
        res.json({
            success: true,
            message: 'Lesson marked as completed successfully!',
            points_earned: 50,
            lesson_id: contentId,
            lesson_title: lesson.content_title,
            new_total: newCount
        });
        
    } catch (error) {
        console.error('❌ Mark lesson complete error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to mark lesson as complete'
        });
    }
});

// Update lesson progress
app.post('/api/lessons-db/:contentId/progress', verifyToken, async (req, res) => {
    try {
        const { contentId } = req.params;
        const userId = req.user.id;
        const { 
            completion_status = 'in_progress',
            percentage = 0,
            time_spent_seconds = 0
        } = req.body;
        
        console.log(`📊 Updating progress for lesson: ${contentId}, user: ${userId}`);
        
        const [contentCheck] = await promisePool.query(
            'SELECT content_id FROM topic_content_items WHERE content_id = ?',
            [contentId]
        );
        
        if (contentCheck.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Lesson content not found'
            });
        }
        
        const [existing] = await promisePool.query(
            'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
            [userId, contentId]
        );
        
        if (existing.length > 0) {
            await promisePool.query(`
                UPDATE user_content_progress 
                SET completion_status = ?,
                    score = ?,
                    time_spent_seconds = time_spent_seconds + ?,
                    last_accessed = NOW(),
                    completed_at = CASE 
                        WHEN ? = 'completed' AND completed_at IS NULL THEN NOW()
                        ELSE completed_at 
                    END
                WHERE user_id = ? AND content_id = ?
            `, [
                completion_status,
                percentage,
                time_spent_seconds,
                completion_status,
                userId,
                contentId
            ]);
        } else {
            await promisePool.query(`
                INSERT INTO user_content_progress 
                (user_id, content_id, completion_status, score, time_spent_seconds, completed_at)
                VALUES (?, ?, ?, ?, ?, ?)
            `, [
                userId,
                contentId,
                completion_status,
                percentage,
                time_spent_seconds,
                completion_status === 'completed' ? new Date() : null
            ]);
        }
        
        res.json({
            success: true,
            message: 'Progress updated',
            progress: {
                content_id: parseInt(contentId),
                completion_status: completion_status,
                percentage: percentage,
                time_spent_seconds: (existing[0]?.time_spent_seconds || 0) + time_spent_seconds
            }
        });
        
    } catch (error) {
        console.error('❌ Progress update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update progress',
            error: error.message
        });
    }
});

// ============================================
// PROGRESS SUMMARY ENDPOINTS
// ============================================



// Accurate progress summary
app.get('/api/progress/summary', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log('🎯 Getting accurate progress summary for user:', userId);
        
        const [accurateStats] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT content_id) as lessons_completed
            FROM user_content_progress 
            WHERE user_id = ? 
            AND completion_status = 'completed'
        `, [userId]);
        
        const [totalLessons] = await promisePool.execute(`
            SELECT COUNT(*) as total_lessons
            FROM topic_content_items 
            WHERE is_active = TRUE
        `);
        
        const [practiceStats] = await promisePool.execute(`
            SELECT 
                COALESCE(SUM(exercises_completed), 0) as exercises_completed
            FROM daily_progress 
            WHERE user_id = ?
        `, [userId]);
        
        const [totalPractices] = await promisePool.execute(`
            SELECT COUNT(*) as total_exercises
            FROM practice_exercises 
            WHERE is_active = TRUE
        `);
        
        const [quizStats] = await promisePool.execute(`
            SELECT 
                COALESCE(MAX(score), 0) as quiz_high_score
            FROM user_quiz_attempts 
            WHERE user_id = ? 
            AND passed = TRUE
        `, [userId]);
        
        const [timeStats] = await promisePool.execute(`
            SELECT 
                COALESCE(AVG(time_spent_seconds), 0) / 60 as avg_time_minutes
            FROM user_content_progress 
            WHERE user_id = ?
        `, [userId]);
        
        const stats = {
            lessons_completed: accurateStats[0]?.lessons_completed || 0,
            total_lessons: totalLessons[0]?.total_lessons || 1,
            exercises_completed: practiceStats[0]?.exercises_completed || 0,
            total_exercises: totalPractices[0]?.total_exercises || 5,
            quiz_high_score: quizStats[0]?.quiz_high_score || 0,
            avg_time_minutes: timeStats[0]?.avg_time_minutes || 0
        };
        
        res.json({
            success: true,
            summary: {
                lessonsCount: stats.lessons_completed,
                totalLessons: stats.total_lessons,
                exercisesCount: stats.exercises_completed,
                totalExercises: stats.total_exercises,
                quizScore: stats.quiz_high_score,
                avgTime: Math.round(stats.avg_time_minutes)
            }
        });
        
    } catch (error) {
        console.error('❌ Get progress summary error:', error.message);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to get progress summary',
            summary: {
                lessonsCount: 0,
                totalLessons: 1,
                exercisesCount: 0,
                totalExercises: 5,
                quizScore: 0,
                avgTime: 0
            }
        });
    }
});



// Get user progress
app.get('/api/user/progress', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [progress] = await promisePool.execute(
            'SELECT * FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        if (progress.length === 0) {
            await promisePool.execute(
                'INSERT INTO user_progress (user_id) VALUES (?)',
                [userId]
            );
            
            const [newProgress] = await promisePool.execute(
                'SELECT * FROM user_progress WHERE user_id = ?',
                [userId]
            );
            
            return res.json({
                success: true,
                progress: newProgress[0] || {}
            });
        }
        
        res.json({
            success: true,
            progress: progress[0]
        });
        
    } catch (error) {
        console.error('❌ Get user progress error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Failed to get user progress'
        });
    }
});




// ============================================
// USER PRACTICE ROUTES - FOR STUDENTS
// ============================================

// ============================================
// ✅ PERMANENT FIX: PRACTICE EXERCISES WITH PROPER JSON
// ============================================
app.get('/api/practice/topic/:topicId', authenticateUser, async (req, res) => {
    try {
        const { topicId } = req.params;
        const userId = req.user.id;
        
        console.log(`📝 Fetching practice for topic ${topicId}, user ${userId}`);
        
        // Get exercises from database
        const [exercises] = await promisePool.query(`
            SELECT 
                exercise_id,
                title,
                description,
                content_type,
                difficulty,
                points,
                content_json,
                is_active
            FROM practice_exercises
            WHERE topic_id = ? AND is_active = 1
            ORDER BY exercise_id
        `, [topicId]);
        
        console.log(`✅ Found ${exercises.length} exercises in database`);
        
        // ✅ PERMANENT FIX: Process each exercise to ensure valid JSON
        const processedExercises = [];
        
        for (const ex of exercises) {
            try {
                // Parse content_json - handle both string and object
                let content;
                if (typeof ex.content_json === 'string') {
                    content = JSON.parse(ex.content_json);
                } else {
                    content = ex.content_json;
                }
                
                // ✅ ENSURE COMPLETE JSON STRUCTURE
                if (!content || typeof content !== 'object') {
                    content = { questions: [] };
                }
                
                // Ensure questions array exists
                if (!content.questions || !Array.isArray(content.questions)) {
                    content.questions = [];
                }
                
                // Ensure each question has proper structure
                content.questions = content.questions.map((q, index) => {
                    // Create a complete question object
                    return {
                        id: q.id || index + 1,
                        text: q.text || q.question || `Question ${index + 1}`,
                        type: q.type || 'multiple_choice',
                        points: q.points || 10,
                        options: (q.options || []).map(opt => ({
                            text: opt.text || opt.option_text || '',
                            correct: opt.correct === true || opt.is_correct === true
                        }))
                    };
                });
                
                // If no questions, add a default question
                if (content.questions.length === 0) {
                    content.questions = [{
                        id: 1,
                        text: "Sample question",
                        type: "multiple_choice",
                        points: 10,
                        options: [
                            { text: "Option A", correct: true },
                            { text: "Option B", correct: false },
                            { text: "Option C", correct: false },
                            { text: "Option D", correct: false }
                        ]
                    }];
                }
                
                // Get user progress
                let userProgress = { status: 'not_started', score: 0 };
                try {
                    const [progress] = await promisePool.query(`
                        SELECT completion_status, score
                        FROM user_practice_progress
                        WHERE user_id = ? AND exercise_id = ?
                    `, [userId, ex.exercise_id]);
                    
                    if (progress.length > 0) {
                        userProgress = {
                            status: progress[0].completion_status || 'not_started',
                            score: progress[0].score || 0
                        };
                    }
                } catch (progressError) {
                    console.log('Progress table not found, using defaults');
                }
                
                processedExercises.push({
                    exercise_id: ex.exercise_id,
                    title: ex.title || 'Practice Exercise',
                    description: ex.description || '',
                    content_type: ex.content_type || 'multiple_choice',
                    difficulty: ex.difficulty || 'medium',
                    points: ex.points || 10,
                    content_json: content, // ✅ Send COMPLETE object
                    user_progress: userProgress
                });
                
            } catch (parseError) {
                console.error(`❌ Error parsing exercise ${ex.exercise_id}:`, parseError.message);
                
                // Provide fallback exercise
                processedExercises.push({
                    exercise_id: ex.exercise_id,
                    title: ex.title || 'Practice Exercise',
                    description: ex.description || 'Complete JSON needs fixing in database',
                    content_type: 'multiple_choice',
                    difficulty: 'medium',
                    points: 10,
                    content_json: {
                        questions: [{
                            id: 1,
                            text: "This exercise needs to be updated in the database.",
                            type: "multiple_choice",
                            points: 10,
                            options: [
                                { text: "Please contact admin", correct: true },
                                { text: "To fix this exercise", correct: false }
                            ]
                        }]
                    },
                    user_progress: { status: 'not_started', score: 0 }
                });
            }
        }
        
        // Check if practice is unlocked based on lesson progress
        let isUnlocked = true;
        let progressMessage = '';
        
        try {
            // Check topic completion
            const [topicProgress] = await promisePool.query(`
                SELECT 
                    COUNT(DISTINCT tci.content_id) as total_lessons,
                    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as completed_lessons
                FROM module_topics mt
                LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id AND tci.is_active = 1
                LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
                WHERE mt.topic_id = ?
                GROUP BY mt.topic_id
            `, [userId, topicId]);
            
            const totalLessons = topicProgress[0]?.total_lessons || 0;
            const completedLessons = topicProgress[0]?.completed_lessons || 0;
            
            // Practice is unlocked if at least one lesson is completed
            isUnlocked = completedLessons > 0;
            progressMessage = isUnlocked 
                ? `Practice unlocked! (${completedLessons}/${totalLessons} lessons completed)`
                : `Complete at least one lesson to unlock practice exercises.`;
                
        } catch (error) {
            console.log('Could not check topic progress:', error.message);
        }
        
        res.json({
            success: true,
            unlocked: isUnlocked,
            progress: {
                completed: 1,
                total: 1,
                percentage: 100,
                message: progressMessage
            },
            exercises: processedExercises
        });
        
    } catch (error) {
        console.error('❌ Error in practice endpoint:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice exercises',
            error: error.message 
        });
    }
});
// GET single practice exercise by ID
// ============================================
// GET SINGLE PRACTICE EXERCISE BY ID
// ============================================
// ============================================
// GET SINGLE PRACTICE EXERCISE BY ID - FIXED VERSION
// ============================================

// ============================================
// ✅ PERMANENT FIX: GET PRACTICE EXERCISE BY ID
// ============================================
// ============================================
// ✅ FIXED VERSION - GAGAMIT NG JSON COLUMN NANG TAMA
// ============================================
// ============================================
// ✅ PERMANENT FIX: GET SINGLE PRACTICE EXERCISE
// ============================================
app.get('/api/practice/exercises/:exerciseId', authenticateUser, async (req, res) => {
    try {
        const { exerciseId } = req.params;
        const userId = req.user.id;
        
        console.log(`📝 Fetching practice exercise ${exerciseId}`);
        
        const [exercises] = await promisePool.query(`
            SELECT 
                exercise_id,
                title,
                description,
                content_type,
                difficulty,
                points,
                content_json,
                topic_id
            FROM practice_exercises 
            WHERE exercise_id = ? AND is_active = 1
        `, [exerciseId]);
        
        if (exercises.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Exercise not found'
            });
        }
        
        const ex = exercises[0];
        
        // ✅ Parse and validate JSON
        let content;
        try {
            content = typeof ex.content_json === 'string' 
                ? JSON.parse(ex.content_json) 
                : ex.content_json;
        } catch (e) {
            console.error(`❌ Error parsing JSON for exercise ${exerciseId}:`, e.message);
            content = { questions: [] };
        }
        
        // Ensure complete structure
        if (!content.questions || !Array.isArray(content.questions)) {
            content.questions = [];
        }
        
        // Format each question
        const questions = content.questions.map((q, index) => ({
            id: q.id || index + 1,
            text: q.text || q.question || `Question ${index + 1}`,
            type: q.type || 'multiple_choice',
            points: q.points || 10,
            options: (q.options || []).map(opt => ({
                text: opt.text || opt.option_text || '',
                correct: opt.correct === true || opt.is_correct === true
            }))
        }));
        
        // Get user progress
        let userProgress = { status: 'not_started', score: 0, attempts: 0 };
        try {
            const [progress] = await promisePool.query(`
                SELECT completion_status, score, attempts
                FROM user_practice_progress
                WHERE user_id = ? AND exercise_id = ?
            `, [userId, exerciseId]);
            
            if (progress.length > 0) {
                userProgress = {
                    status: progress[0].completion_status || 'not_started',
                    score: progress[0].score || 0,
                    attempts: progress[0].attempts || 0
                };
            }
        } catch (error) {
            console.log('Progress table not found');
        }
        
        res.json({
            success: true,
            exercise: {
                exercise_id: ex.exercise_id,
                title: ex.title || 'Practice Exercise',
                description: ex.description || '',
                content_type: ex.content_type || 'multiple_choice',
                difficulty: ex.difficulty || 'medium',
                points: ex.points || 10,
                topic_id: ex.topic_id,
                questions: questions,
                question_count: questions.length,
                user_progress: userProgress
            }
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Server error' 
        });
    }
});

// ============================================
// 🔍 DEBUG ENDPOINT - I-CHECK ANG JSON STRUCTURE
// ============================================
app.get('/api/debug/practice/:exerciseId', authenticateUser, async (req, res) => {
    try {
        const { exerciseId } = req.params;
        
        const [exercises] = await promisePool.query(`
            SELECT 
                exercise_id,
                title,
                content_type,
                JSON_PRETTY(content_json) as formatted_json,
                JSON_LENGTH(content_json->'$.questions') as question_count,
                content_json->'$.questions[0]' as first_question
            FROM practice_exercises 
            WHERE exercise_id = ?
        `, [exerciseId]);
        
        if (exercises.length === 0) {
            return res.status(404).json({ success: false, message: 'Not found' });
        }
        
        res.json({
            success: true,
            debug: exercises[0]
        });
        
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// ============================================
// START PRACTICE EXERCISE - FIXED VERSION
// ============================================
app.post('/api/practice/:exerciseId/start', authenticateUser, async (req, res) => {
    try {
        const { exerciseId } = req.params;
        const userId = req.user.id;
        
        console.log(`🚀 Starting practice exercise ${exerciseId} for user ${userId}`);
        
        // Check if exercise exists
        const [exercises] = await promisePool.query(`
            SELECT exercise_id, title 
            FROM practice_exercises 
            WHERE exercise_id = ? AND is_active = 1
        `, [exerciseId]);
        
        if (exercises.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Practice exercise not found'
            });
        }
        
        // Check if user_practice_progress table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'user_practice_progress'");
        
        if (tables.length === 0) {
            // Create the table if it doesn't exist
            await promisePool.query(`
                CREATE TABLE IF NOT EXISTS user_practice_progress (
                    progress_id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT NOT NULL,
                    exercise_id INT NOT NULL,
                    completion_status ENUM('not_started', 'in_progress', 'completed') DEFAULT 'not_started',
                    score INT DEFAULT 0,
                    attempts INT DEFAULT 0,
                    time_spent_seconds INT DEFAULT 0,
                    last_attempted TIMESTAMP NULL,
                    completed_at TIMESTAMP NULL,
                    UNIQUE KEY unique_user_exercise (user_id, exercise_id),
                    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                    FOREIGN KEY (exercise_id) REFERENCES practice_exercises(exercise_id) ON DELETE CASCADE
                )
            `);
            console.log('✅ Created user_practice_progress table');
        }
        
        // Update or insert progress
        const [existing] = await promisePool.query(
            'SELECT progress_id FROM user_practice_progress WHERE user_id = ? AND exercise_id = ?',
            [userId, exerciseId]
        );
        
        if (existing.length > 0) {
            // Update existing
            await promisePool.query(`
                UPDATE user_practice_progress 
                SET attempts = attempts + 1,
                    last_attempted = NOW()
                WHERE user_id = ? AND exercise_id = ?
            `, [userId, exerciseId]);
        } else {
            // Insert new
            await promisePool.query(`
                INSERT INTO user_practice_progress 
                (user_id, exercise_id, completion_status, attempts, last_attempted)
                VALUES (?, ?, 'in_progress', 1, NOW())
            `, [userId, exerciseId]);
        }
        
        res.json({
            success: true,
            message: 'Practice exercise started',
            started_at: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('❌ Error starting practice:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to start practice exercise' 
        });
    }
});
// SUBMIT practice exercise answers
// ============================================
// ✅ UPDATE YOUR PRACTICE SUBMIT ENDPOINT
// ============================================
// Hanapin ito sa server.js
app.post('/api/practice/:exerciseId/submit', authenticateUser, async (req, res) => {
    try {
        const { exerciseId } = req.params;
        const userId = req.user.id;
        const { answers, time_spent_seconds } = req.body;
        
        console.log(`📤 Submitting practice exercise ${exerciseId} for user ${userId}`);
        console.log('📦 Full request body:', req.body);
        
        // Get exercise from database
        const [exercises] = await promisePool.query(`
            SELECT exercise_id, title, content_json, points, topic_id
            FROM practice_exercises 
            WHERE exercise_id = ? AND is_active = 1
        `, [exerciseId]);
        
        if (exercises.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Exercise not found'
            });
        }
        
        const exercise = exercises[0];
        const topicId = exercise.topic_id;
        console.log('✅ Exercise found:', exercise.title, 'Topic ID:', topicId);
        
        // Parse content_json
        let content;
        try {
            content = typeof exercise.content_json === 'string' 
                ? JSON.parse(exercise.content_json) 
                : exercise.content_json;
            console.log('✅ Content parsed, questions:', content.questions?.length || 0);
        } catch (e) {
            console.error('❌ Error parsing content_json:', e);
            content = { questions: [] };
        }
        
        // Calculate score
        let correctCount = 0;
        const totalQuestions = content.questions?.length || 0;
        
        content.questions?.forEach((question, index) => {
            const userAnswer = answers[`q${index}`];
            
            if (!userAnswer) return;
            
            // Find correct option index
            let correctOptionIndex = -1;
            
            if (question.options && Array.isArray(question.options)) {
                question.options.forEach((opt, optIndex) => {
                    if (opt.correct === true) {
                        correctOptionIndex = optIndex;
                    }
                });
            }
            
            if (userAnswer == correctOptionIndex) {
                correctCount++;
            }
        });
        
        const percentage = totalQuestions > 0 
            ? Math.round((correctCount / totalQuestions) * 100) 
            : 0;
        
        const maxPoints = exercise.points || (totalQuestions * 10);
        const pointsEarned = Math.round((percentage / 100) * maxPoints);
        const passed = percentage >= 70;
        
        console.log(`📊 Results: ${correctCount}/${totalQuestions} correct = ${percentage}%`);
        
        // ===== TRY TO SAVE TO practice_attempts TABLE =====
        try {
            // Check if practice_attempts table exists
            const [tables] = await promisePool.query("SHOW TABLES LIKE 'practice_attempts'");
            
            if (tables.length === 0) {
                console.log('⚠️ practice_attempts table does NOT exist! Creating...');
                
                await promisePool.query(`
                    CREATE TABLE IF NOT EXISTS practice_attempts (
                        attempt_id INT AUTO_INCREMENT PRIMARY KEY,
                        user_id INT NOT NULL,
                        exercise_id INT NOT NULL,
                        topic_id INT NOT NULL,
                        answers JSON,
                        score INT DEFAULT 0,
                        max_score INT DEFAULT 0,
                        percentage INT DEFAULT 0,
                        time_spent_seconds INT DEFAULT 0,
                        completion_status ENUM('in_progress', 'completed', 'failed') DEFAULT 'in_progress',
                        attempt_number INT DEFAULT 1,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        completed_at TIMESTAMP NULL,
                        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
                        FOREIGN KEY (exercise_id) REFERENCES practice_exercises(exercise_id) ON DELETE CASCADE
                    )
                `);
                console.log('✅ practice_attempts table created');
            }
            
            // Get attempt number
            const [attemptCount] = await promisePool.query(`
                SELECT COUNT(*) as count FROM practice_attempts 
                WHERE user_id = ? AND exercise_id = ?
            `, [userId, exerciseId]);
            
            const attemptNumber = (attemptCount[0]?.count || 0) + 1;
            console.log(`📝 Attempt number: ${attemptNumber}`);
            
            // Insert attempt
            const insertQuery = `
                INSERT INTO practice_attempts 
                (user_id, exercise_id, topic_id, answers, score, max_score, 
                 percentage, time_spent_seconds, completion_status, attempt_number, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `;
            
            const insertParams = [
                userId,
                exerciseId,
                topicId,
                JSON.stringify(answers),
                pointsEarned,
                maxPoints,
                percentage,
                time_spent_seconds || 0,
                passed ? 'completed' : 'failed',
                attemptNumber
            ];
            
            console.log('📝 Inserting with params:', insertParams);
            
            const [result] = await promisePool.query(insertQuery, insertParams);
            
            console.log(`✅ Practice attempt saved to database! Attempt ID: ${result.insertId}`);
            
        } catch (dbError) {
            console.error('❌❌❌ DATABASE ERROR:', dbError);
            console.error('❌ Error code:', dbError.code);
            console.error('❌ Error message:', dbError.message);
            console.error('❌ SQL:', dbError.sql);
            
            // Try fallback
            try {
                console.log('⚠️ Trying fallback to user_practice_progress...');
                await promisePool.query(`
                    INSERT INTO user_practice_progress 
                    (user_id, exercise_id, completion_status, score, attempts, time_spent_seconds, completed_at)
                    VALUES (?, ?, ?, 1, ?, ?, NOW())
                    ON DUPLICATE KEY UPDATE
                        completion_status = VALUES(completion_status),
                        score = VALUES(score),
                        attempts = attempts + 1,
                        time_spent_seconds = time_spent_seconds + VALUES(time_spent_seconds),
                        completed_at = NOW()
                `, [
                    userId,
                    exerciseId,
                    passed ? 'completed' : 'in_progress',
                    percentage,
                    time_spent_seconds || 0
                ]);
                console.log('✅ Fallback successful');
            } catch (fallbackError) {
                console.error('❌ Fallback also failed:', fallbackError);
            }
        }
        
        // Update daily progress
        try {
            const today = new Date().toISOString().split('T')[0];
            
            await promisePool.query(`
                INSERT INTO daily_progress (user_id, progress_date, exercises_completed, points_earned)
                VALUES (?, ?, 1, ?)
                ON DUPLICATE KEY UPDATE
                    exercises_completed = exercises_completed + 1,
                    points_earned = points_earned + ?
            `, [userId, today, pointsEarned, pointsEarned]);
        } catch (dailyError) {
            console.log('Daily progress update error:', dailyError.message);
        }
        
        res.json({
            success: true,
            completed: passed,
            score: pointsEarned,
            max_score: maxPoints,
            percentage: percentage,
            correct: correctCount,
            total: totalQuestions,
            points_earned: pointsEarned,
            message: passed ? '🎉 Great job!' : '💪 Keep practicing!'
        });
        
    } catch (error) {
        console.error('❌❌❌ FATAL ERROR:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to submit practice',
            error: error.message
        });
    }
});

// GET user's practice statistics
app.get('/api/practice/user/stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching practice stats for user ${userId}`);
        
        const [stats] = await promisePool.query(`
            SELECT 
                COUNT(DISTINCT CASE WHEN completion_status = 'completed' THEN exercise_id END) as completed_exercises,
                COUNT(DISTINCT exercise_id) as total_attempted,
                COALESCE(AVG(score), 0) as average_score,
                COALESCE(SUM(attempts), 0) as total_attempts,
                COALESCE(SUM(time_spent_seconds), 0) as total_time_seconds
            FROM user_practice_progress
            WHERE user_id = ?
        `, [userId]);
        
        // Get overall exercise count
        const [totalExercises] = await promisePool.query(`
            SELECT COUNT(*) as total FROM practice_exercises WHERE is_active = 1
        `);
        
        res.json({
            success: true,
            stats: {
                completed: stats[0]?.completed_exercises || 0,
                total_exercises: totalExercises[0]?.total || 0,
                average_score: Math.round(stats[0]?.average_score || 0),
                total_attempts: stats[0]?.total_attempts || 0,
                total_time_minutes: Math.round((stats[0]?.total_time_seconds || 0) / 60)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching practice stats:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch practice statistics' 
        });
    }
});


// ============================================
// TOPICS PROGRESS ENDPOINT - GET ALL TOPICS WITH USER PROGRESS
// ============================================
// ============================================
// FIXED: PRACTICE TOPIC ENDPOINT - WITH PROPER ERROR CHECKING
// ============================================

// Get topics progress
app.get('/api/topics/progress', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [topics] = await promisePool.query(`
            SELECT 
                mt.topic_id,
                mt.topic_title,
                mt.topic_description,
                cm.module_id,
                cm.module_name,
                COUNT(DISTINCT tci.content_id) as total_lessons,
                COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as lessons_completed
            FROM module_topics mt
            JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id AND tci.is_active = 1
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
            GROUP BY mt.topic_id
            ORDER BY mt.topic_id
        `, [userId]);
        
        const topicsWithProgress = topics.map(topic => ({
            topic_id: topic.topic_id || 0,
            topic_title: topic.topic_title || 'Unknown Topic',
            topic_description: topic.topic_description || '',
            module_id: topic.module_id || 0,
            module_name: topic.module_name || 'Unknown Module',
            total_lessons: topic.total_lessons || 1,
            lessons_completed: topic.lessons_completed || 0,
            lesson_progress_percentage: topic.total_lessons > 0 
                ? Math.round((topic.lessons_completed / topic.total_lessons) * 100) 
                : 0,
            practice_unlocked: (topic.lessons_completed || 0) > 0
        }));
        
        res.json({
            success: true,
            topics: topicsWithProgress
        });
        
    } catch (error) {
        console.error('❌ Error fetching topics progress:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch topics progress',
            error: error.message 
        });
    }
});

// ============================================
// ✅ ADD THIS TO YOUR server.js - PRACTICE ATTEMPTS ENDPOINT
// ============================================
// Get practice attempts
app.get('/api/progress/practice-attempts', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Check if practice_attempts table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'practice_attempts'");
        
        if (tables.length === 0) {
            return res.json({
                success: true,
                attempts: []
            });
        }
        
        const [attempts] = await promisePool.query(`
            SELECT 
                pa.*,
                pe.title as exercise_title,
                pe.difficulty,
                t.topic_title
            FROM practice_attempts pa
            LEFT JOIN practice_exercises pe ON pa.exercise_id = pe.exercise_id
            LEFT JOIN module_topics t ON pa.topic_id = t.topic_id
            WHERE pa.user_id = ?
            ORDER BY pa.created_at DESC
        `, [userId]);
        
        res.json({
            success: true,
            attempts: attempts
        });
        
    } catch (error) {
        console.error('❌ Error fetching practice attempts:', error);
        res.json({ 
            success: true, 
            attempts: []
        });
    }
});


// ============================================
// PROGRESS DASHBOARD ENDPOINTS - ADD THESE
// ============================================

// Get today's learning stats
app.get('/api/progress/today-stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching today's stats for user ${userId}`);
        
        // Get start and end of today
        const now = new Date();
        const startOfDay = new Date(now);
        startOfDay.setHours(0, 0, 0, 0);
        const endOfDay = new Date(now);
        endOfDay.setHours(23, 59, 59, 999);
        
        // Get today's practice attempts
        let exercisesToday = 0;
        let totalAccuracy = 0;
        let accuracyCount = 0;
        let totalSeconds = 0;
        
        try {
            const [attempts] = await promisePool.query(`
                SELECT * FROM practice_attempts 
                WHERE user_id = ? 
                AND created_at BETWEEN ? AND ?
            `, [userId, startOfDay, endOfDay]);
            
            exercisesToday = attempts.length;
            
            attempts.forEach(a => {
                if (a.percentage) {
                    totalAccuracy += a.percentage;
                    accuracyCount++;
                }
                if (a.time_spent_seconds) {
                    totalSeconds += a.time_spent_seconds;
                }
            });
        } catch (e) {
            console.log('No practice_attempts table:', e.message);
        }
        
        // Get today's lesson progress
        try {
            const [lessonProgress] = await promisePool.query(`
                SELECT time_spent_seconds, completed_at 
                FROM user_content_progress 
                WHERE user_id = ? 
                AND last_accessed BETWEEN ? AND ?
            `, [userId, startOfDay, endOfDay]);
            
            lessonProgress.forEach(p => {
                if (p.time_spent_seconds) {
                    totalSeconds += p.time_spent_seconds;
                }
            });
        } catch (e) {
            console.log('No lesson progress:', e.message);
        }
        
        // Cap total seconds to reasonable amount (12 hours max)
        if (totalSeconds > 43200) totalSeconds = 43200;
        
        const accuracyRate = accuracyCount > 0 ? Math.round(totalAccuracy / accuracyCount) : 0;
        
        res.json({
            success: true,
            stats: {
                totalLearningTime: totalSeconds,
                accuracyRate: accuracyRate,
                exercisesCompleted: exercisesToday,
                totalExercises: 5,
                displayExercises: `${exercisesToday}/5`
            }
        });
        
    } catch (error) {
        console.error('❌ Error in today-stats:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get daily progress
app.get('/api/progress/daily', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const today = new Date().toISOString().split('T')[0];
        
        // Try to get from daily_progress table
        const [daily] = await promisePool.query(
            'SELECT * FROM daily_progress WHERE user_id = ? AND progress_date = ?',
            [userId, today]
        );
        
        if (daily.length > 0) {
            return res.json({
                success: true,
                progress: daily[0]
            });
        }
        
        // Calculate from other tables
        const startOfDay = new Date();
        startOfDay.setHours(0, 0, 0, 0);
        const endOfDay = new Date();
        endOfDay.setHours(23, 59, 59, 999);
        
        // Count today's practice attempts
        let exercisesToday = 0;
        try {
            const [practice] = await promisePool.query(
                'SELECT COUNT(*) as count FROM practice_attempts WHERE user_id = ? AND created_at BETWEEN ? AND ?',
                [userId, startOfDay, endOfDay]
            );
            exercisesToday = practice[0]?.count || 0;
        } catch (e) {}
        
        // Count today's lesson completions
        let lessonsToday = 0;
        try {
            const [lessons] = await promisePool.query(
                'SELECT COUNT(*) as count FROM user_content_progress WHERE user_id = ? AND completion_status = "completed" AND DATE(completed_at) = CURDATE()',
                [userId]
            );
            lessonsToday = lessons[0]?.count || 0;
        } catch (e) {}
        
        // Count today's quiz completions
        let quizzesToday = 0;
        try {
            const [quizzes] = await promisePool.query(
                'SELECT COUNT(*) as count FROM user_quiz_attempts WHERE user_id = ? AND completion_status = "completed" AND DATE(end_time) = CURDATE()',
                [userId]
            );
            quizzesToday = quizzes[0]?.count || 0;
        } catch (e) {}
        
        const defaultProgress = {
            user_id: userId,
            progress_date: today,
            lessons_completed: lessonsToday,
            exercises_completed: exercisesToday,
            quizzes_completed: quizzesToday,
            points_earned: 0,
            time_spent_minutes: 0,
            streak_maintained: 0
        };
        
        res.json({
            success: true,
            progress: defaultProgress
        });
        
    } catch (error) {
        console.error('❌ Error in daily progress:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Get cumulative progress
app.get('/api/progress/cumulative', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get total lessons completed
        let lessonsCompleted = 0;
        try {
            const [lessons] = await promisePool.query(
                'SELECT COUNT(*) as count FROM user_content_progress WHERE user_id = ? AND completion_status = "completed"',
                [userId]
            );
            lessonsCompleted = lessons[0]?.count || 0;
        } catch (e) {}
        
        // Get total exercises completed
        let exercisesCompleted = 0;
        try {
            const [exercises] = await promisePool.query(
                'SELECT COUNT(*) as count FROM practice_attempts WHERE user_id = ?',
                [userId]
            );
            exercisesCompleted = exercises[0]?.count || 0;
        } catch (e) {}
        
        // Get total points
        let totalPoints = 0;
        try {
            const [points] = await promisePool.query(
                'SELECT COALESCE(SUM(points_amount), 0) as total FROM user_points WHERE user_id = ?',
                [userId]
            );
            totalPoints = points[0]?.total || 0;
        } catch (e) {}
        
        // Get total time
        let totalSeconds = 0;
        try {
            const [time] = await promisePool.query(
                'SELECT COALESCE(SUM(time_spent_seconds), 0) as total FROM user_content_progress WHERE user_id = ?',
                [userId]
            );
            totalSeconds = time[0]?.total || 0;
        } catch (e) {}
        
        // Calculate weekly time (last 7 days)
        let weeklySeconds = 0;
        const sevenDaysAgo = new Date();
        sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
        
        try {
            const [weekly] = await promisePool.query(
                'SELECT COALESCE(SUM(time_spent_seconds), 0) as total FROM user_content_progress WHERE user_id = ? AND last_accessed >= ?',
                [userId, sevenDaysAgo]
            );
            weeklySeconds = weekly[0]?.total || 0;
        } catch (e) {}
        
        res.json({
            success: true,
            progress: {
                total_lessons_completed: lessonsCompleted,
                exercises_completed: exercisesCompleted,
                total_quizzes_completed: 0,
                total_points_earned: totalPoints,
                total_time_spent_minutes: Math.round(totalSeconds / 60),
                weekly_time_spent: Math.round(weeklySeconds / 60),
                avg_display_time: Math.round((weeklySeconds / 7) / 60) || 5,
                streak_days: 1
            }
        });
        
    } catch (error) {
        console.error('❌ Error in cumulative progress:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// Update daily progress
app.post('/api/progress/update-daily', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { lessons_completed, exercises_completed, quizzes_completed, time_spent_minutes } = req.body;
        
        const today = new Date().toISOString().split('T')[0];
        
        // Check if entry exists
        const [existing] = await promisePool.query(
            'SELECT * FROM daily_progress WHERE user_id = ? AND progress_date = ?',
            [userId, today]
        );
        
        if (existing.length > 0) {
            // Update existing
            const updates = [];
            const values = [];
            
            if (lessons_completed) {
                updates.push('lessons_completed = lessons_completed + ?');
                values.push(lessons_completed);
            }
            if (exercises_completed) {
                updates.push('exercises_completed = exercises_completed + ?');
                values.push(exercises_completed);
            }
            if (quizzes_completed) {
                updates.push('quizzes_completed = quizzes_completed + ?');
                values.push(quizzes_completed);
            }
            if (time_spent_minutes) {
                updates.push('time_spent_minutes = time_spent_minutes + ?');
                values.push(time_spent_minutes);
            }
            
            if (updates.length === 0) {
                return res.json({ success: true });
            }
            
            values.push(userId, today);
            
            await promisePool.query(
                `UPDATE daily_progress SET ${updates.join(', ')} WHERE user_id = ? AND progress_date = ?`,
                values
            );
        } else {
            // Insert new
            await promisePool.query(
                `INSERT INTO daily_progress 
                 (user_id, progress_date, lessons_completed, exercises_completed, quizzes_completed, time_spent_minutes)
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [
                    userId,
                    today,
                    lessons_completed || 0,
                    exercises_completed || 0,
                    quizzes_completed || 0,
                    time_spent_minutes || 0
                ]
            );
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('❌ Error updating daily progress:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});




// GET /api/auth/me
app.get('/api/auth/me', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [users] = await promisePool.query(`
            SELECT 
                user_id as id,
                username,
                email,
                full_name,
                role,
                created_at as joined_date,
                last_login
            FROM users 
            WHERE user_id = ?
        `, [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: users[0]
        });
        
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch user'
        });
    }
});


// ============================================
// PROGRESS CHART DATA - CONNECT TO MYSQL DATABASE
// ============================================
// ============================================
// ✅ ADD TO server.js - SESSION ENDPOINTS
// ============================================

// Create session
app.post('/api/user/sessions/create', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // End any active sessions
        await promisePool.query(`
            UPDATE user_sessions 
            SET is_active = FALSE, 
                logout_time = NOW(),
                total_duration_seconds = TIMESTAMPDIFF(SECOND, login_time, NOW())
            WHERE user_id = ? AND is_active = TRUE
        `, [userId]);
        
        // Create new session
        const [result] = await promisePool.query(`
            INSERT INTO user_sessions (user_id, login_time, is_active)
            VALUES (?, NOW(), TRUE)
        `, [userId]);
        
        res.json({
            success: true,
            session_id: result.insertId
        });
        
    } catch (error) {
        console.error('Error creating session:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// End session
app.post('/api/user/sessions/end', authenticateUser, async (req, res) => {
    try {
        const { session_id } = req.body;
        const userId = req.user.id;
        
        const [result] = await promisePool.query(`
            UPDATE user_sessions 
            SET logout_time = NOW(),
                total_duration_seconds = TIMESTAMPDIFF(SECOND, login_time, NOW()),
                is_active = FALSE
            WHERE session_id = ? AND user_id = ?
        `, [session_id, userId]);
        
        const [session] = await promisePool.query(`
            SELECT total_duration_seconds FROM user_sessions WHERE session_id = ?
        `, [session_id]);
        
        res.json({
            success: true,
            duration_seconds: session[0]?.total_duration_seconds || 0
        });
        
    } catch (error) {
        console.error('Error ending session:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});

// Get today's total session time
app.get('/api/user/sessions/today', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [sessions] = await promisePool.query(`
            SELECT 
                SUM(total_duration_seconds) as total_seconds
            FROM user_sessions 
            WHERE user_id = ? 
            AND DATE(login_time) = CURDATE()
        `, [userId]);
        
        res.json({
            success: true,
            total_seconds: sessions[0]?.total_seconds || 0
        });
        
    } catch (error) {
        console.error('Error getting today\'s sessions:', error);
        res.status(500).json({ success: false, message: error.message });
    }
});
/**
 * GET PROGRESS CHART DATA
 * Returns formatted data for the progress chart including:
 * - Labels (dates for the last 14 days)
 * - Lessons completed per day
 * - Exercises completed per day
 * - Points earned per day
 */
// Get progress chart data
app.get('/api/progress/chart-data', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { days = 14 } = req.query;
        
        console.log(`📊 Fetching chart data for user ${userId} (last ${days} days)`);
        
        // Generate date labels for the last N days
        const labels = [];
        const today = new Date();
        
        for (let i = days - 1; i >= 0; i--) {
            const date = new Date(today);
            date.setDate(date.getDate() - i);
            const month = date.toLocaleString('default', { month: 'short' });
            const day = date.getDate();
            labels.push(`${month} ${day}`);
        }
        
        // Initialize arrays with zeros
        const lessonsData = new Array(days).fill(0);
        const exercisesData = new Array(days).fill(0);
        const pointsData = new Array(days).fill(0);
        
        // Try to get data from daily_progress table
        try {
            const [tables] = await promisePool.query("SHOW TABLES LIKE 'daily_progress'");
            
            if (tables.length > 0) {
                const [dailyProgress] = await promisePool.query(`
                    SELECT 
                        progress_date,
                        lessons_completed,
                        exercises_completed,
                        points_earned
                    FROM daily_progress 
                    WHERE user_id = ? 
                    AND progress_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
                    ORDER BY progress_date ASC
                `, [userId, days]);
                
                dailyProgress.forEach(day => {
                    const dateStr = new Date(day.progress_date).toLocaleDateString('en-US', { 
                        month: 'short', 
                        day: 'numeric' 
                    });
                    
                    const index = labels.findIndex(label => label === dateStr);
                    if (index !== -1) {
                        lessonsData[index] = day.lessons_completed || 0;
                        exercisesData[index] = day.exercises_completed || 0;
                        pointsData[index] = day.points_earned || 0;
                    }
                });
            }
        } catch (error) {
            console.log('⚠️ Error fetching daily progress:', error.message);
        }
        
        res.json({
            success: true,
            chartData: {
                labels: labels,
                datasets: [
                    {
                        label: 'Lessons',
                        data: lessonsData,
                        borderColor: '#7a0000',
                        backgroundColor: 'rgba(122, 0, 0, 0.1)'
                    },
                    {
                        label: 'Exercises',
                        data: exercisesData,
                        borderColor: '#27ae60',
                        backgroundColor: 'rgba(39, 174, 96, 0.1)'
                    },
                    {
                        label: 'Points',
                        data: pointsData,
                        borderColor: '#f39c12',
                        backgroundColor: 'rgba(243, 156, 18, 0.1)'
                    }
                ]
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching chart data:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch chart data',
            error: error.message
        });
    }
});

// ============================================
// MISSING PROGRESS DASHBOARD ENDPOINTS
// ============================================

// Get topics progress with mastery data
app.get('/api/progress/topic-mastery', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📊 Fetching topic mastery for user ${userId}`);
        
        // Get all topics with progress data
        const [topics] = await promisePool.query(`
            SELECT 
                mt.topic_id,
                mt.topic_title,
                mt.topic_description,
                cm.module_id,
                cm.module_name,
                l.lesson_id,
                l.lesson_name,
                COUNT(DISTINCT tci.content_id) as total_lessons,
                COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as completed_lessons,
                COALESCE(AVG(ucp.score), 0) as avg_score,
                MAX(ucp.completed_at) as last_practiced
            FROM module_topics mt
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id AND tci.is_active = 1
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
            GROUP BY mt.topic_id
            ORDER BY l.lesson_order, cm.module_order, mt.topic_order
        `, [userId]);
        
        // Calculate mastery level for each topic
        const masteryData = topics.map(topic => {
            const completionRate = topic.total_lessons > 0 
                ? (topic.completed_lessons / topic.total_lessons) * 100 
                : 0;
            
            let masteryLevel = 'Beginner';
            if (completionRate >= 80 && topic.avg_score >= 80) {
                masteryLevel = 'Expert';
            } else if (completionRate >= 60 && topic.avg_score >= 70) {
                masteryLevel = 'Advanced';
            } else if (completionRate >= 40 && topic.avg_score >= 60) {
                masteryLevel = 'Intermediate';
            }
            
            return {
                topic_id: topic.topic_id,
                topic_title: topic.topic_title,
                topic_description: topic.topic_description,
                module_name: topic.module_name,
                lesson_name: topic.lesson_name,
                completion_rate: Math.round(completionRate),
                accuracy_rate: Math.round(topic.avg_score || 0),
                mastery_level: masteryLevel,
                last_practiced: topic.last_practiced,
                total_lessons: topic.total_lessons || 0,
                completed_lessons: topic.completed_lessons || 0
            };
        });
        
        res.json({
            success: true,
            mastery: masteryData
        });
        
    } catch (error) {
        console.error('❌ Error fetching topic mastery:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get performance analytics
app.get('/api/progress/performance-analytics', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        console.log(`📈 Fetching performance analytics for user ${userId}`);
        
        // Get weekly performance trend (last 7 days)
        const [weeklyTrend] = await promisePool.query(`
            SELECT 
                DATE(activity_timestamp) as date,
                COUNT(*) as activity_count,
                SUM(CASE WHEN activity_type LIKE '%_completed' THEN 1 ELSE 0 END) as completions
            FROM user_activity_log
            WHERE user_id = ? 
                AND activity_timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)
            GROUP BY DATE(activity_timestamp)
            ORDER BY date
        `, [userId]);
        
        // Calculate improvement percentage
        let weeklyImprovement = 0;
        if (weeklyTrend.length >= 2) {
            const firstHalf = weeklyTrend.slice(0, 3).reduce((sum, d) => sum + d.activity_count, 0);
            const secondHalf = weeklyTrend.slice(-3).reduce((sum, d) => sum + d.activity_count, 0);
            if (firstHalf > 0) {
                weeklyImprovement = Math.round(((secondHalf - firstHalf) / firstHalf) * 100);
            }
        }
        
        // Get average quiz score
        const [quizAvg] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get average practice accuracy
        const [practiceAccuracy] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score
            FROM practice_attempts
            WHERE user_id = ?
        `, [userId]);
        
        // Get average time per activity
        const [avgTime] = await promisePool.query(`
            SELECT COALESCE(AVG(time_spent_seconds), 0) / 60 as avg_minutes
            FROM user_content_progress
            WHERE user_id = ? AND time_spent_seconds > 0
        `, [userId]);
        
        // Get current streak (consecutive days with activity)
        const [streak] = await promisePool.query(`
            WITH RECURSIVE dates AS (
                SELECT DISTINCT DATE(activity_timestamp) as activity_date
                FROM user_activity_log
                WHERE user_id = ?
                ORDER BY activity_date DESC
            )
            SELECT COUNT(*) as current_streak
            FROM dates
            WHERE activity_date >= CURDATE() - INTERVAL 7 DAY
        `, [userId]);
        
        res.json({
            success: true,
            analytics: {
                weekly_improvement: weeklyImprovement,
                practice_accuracy: Math.round(practiceAccuracy[0]?.avg_score || 0),
                avg_time_per_activity: Math.round(avgTime[0]?.avg_minutes || 0),
                current_streak: streak[0]?.current_streak || 0,
                quiz_avg_score: Math.round(quizAvg[0]?.avg_score || 0)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching performance analytics:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get achievement timeline
app.get('/api/progress/achievements', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { limit = 10 } = req.query;
        
        console.log(`🏆 Fetching achievements for user ${userId}`);
        
        // Get badges earned
        const [badges] = await promisePool.query(`
            SELECT 
                'badge_earned' as activity_type,
                b.badge_name as achievement_name,
                b.description,
                b.icon,
                b.color,
                ub.awarded_at as created_at
            FROM user_badges ub
            JOIN badges b ON ub.badge_id = b.badge_id
            WHERE ub.user_id = ?
            ORDER BY ub.awarded_at DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        // Get completed lessons as achievements
        const [lessons] = await promisePool.query(`
            SELECT 
                'lesson_completed' as activity_type,
                tci.content_title as achievement_name,
                tci.content_description as description,
                'fas fa-check-circle' as icon,
                '#27ae60' as color,
                ucp.completed_at as created_at
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE ucp.user_id = ? AND ucp.completion_status = 'completed'
            ORDER BY ucp.completed_at DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        // Get completed quizzes as achievements
        const [quizzes] = await promisePool.query(`
            SELECT 
                'quiz_completed' as activity_type,
                q.quiz_title as achievement_name,
                CONCAT('Score: ', uqa.score, '%') as description,
                'fas fa-question-circle' as icon,
                '#f39c12' as color,
                uqa.end_time as created_at
            FROM user_quiz_attempts uqa
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            WHERE uqa.user_id = ? AND uqa.completion_status = 'completed'
            ORDER BY uqa.end_time DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        // Get completed practice as achievements
        const [practice] = await promisePool.query(`
            SELECT 
                'practice_completed' as activity_type,
                pe.title as achievement_name,
                CONCAT('Score: ', pa.score, '/', pa.max_score) as description,
                'fas fa-pencil-alt' as icon,
                '#3498db' as color,
                pa.completed_at as created_at
            FROM practice_attempts pa
            JOIN practice_exercises pe ON pa.exercise_id = pe.exercise_id
            WHERE pa.user_id = ? AND pa.completion_status = 'completed'
            ORDER BY pa.completed_at DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        // Combine all achievements and sort by date
        let allAchievements = [...badges, ...lessons, ...quizzes, ...practice];
        
        // Sort by created_at (most recent first)
        allAchievements.sort((a, b) => {
            const dateA = a.created_at ? new Date(a.created_at) : new Date(0);
            const dateB = b.created_at ? new Date(b.created_at) : new Date(0);
            return dateB - dateA;
        });
        
        // Limit the combined list
        allAchievements = allAchievements.slice(0, parseInt(limit));
        
        res.json({
            success: true,
            achievements: allAchievements
        });
        
    } catch (error) {
        console.error('❌ Error fetching achievements:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get activity feed
app.get('/api/dashboard/activity-feed', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { limit = 10 } = req.query;
        
        console.log(`📋 Fetching activity feed for user ${userId}`);
        
        const [activities] = await promisePool.query(`
            SELECT 
                activity_id,
                activity_type,
                related_id,
                details,
                activity_timestamp,
                CASE 
                    WHEN activity_type = 'lesson_completed' THEN 10
                    WHEN activity_type = 'practice_completed' THEN 5
                    WHEN activity_type = 'quiz_completed' THEN 20
                    ELSE 0
                END as points_earned
            FROM user_activity_log
            WHERE user_id = ?
            ORDER BY activity_timestamp DESC
            LIMIT ?
        `, [userId, parseInt(limit)]);
        
        // Format activities for display
        const formattedActivities = activities.map(activity => {
            let details = {};
            try {
                details = activity.details ? JSON.parse(activity.details) : {};
            } catch (e) {
                details = {};
            }
            
            return {
                id: activity.activity_id,
                activity_type: activity.activity_type,
                details: details,
                points_earned: activity.points_earned || 0,
                activity_timestamp: activity.activity_timestamp,
                item_name: details.item_name || null
            };
        });
        
        res.json({
            success: true,
            activities: formattedActivities
        });
        
    } catch (error) {
        console.error('❌ Error fetching activity feed:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get weekly progress
app.get('/api/progress/weekly', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [weekly] = await promisePool.query(`
            SELECT 
                COALESCE(SUM(lessons_completed), 0) as total_lessons,
                COALESCE(SUM(exercises_completed), 0) as total_exercises,
                COALESCE(SUM(quizzes_completed), 0) as total_quizzes,
                COALESCE(SUM(points_earned), 0) as total_points,
                COALESCE(SUM(time_spent_minutes), 0) as total_minutes
            FROM daily_progress
            WHERE user_id = ? 
                AND progress_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        `, [userId]);
        
        res.json({
            success: true,
            progress: weekly[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching weekly progress:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get monthly progress
app.get('/api/progress/monthly', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [monthly] = await promisePool.query(`
            SELECT 
                COALESCE(SUM(lessons_completed), 0) as total_lessons,
                COALESCE(SUM(exercises_completed), 0) as total_exercises,
                COALESCE(SUM(quizzes_completed), 0) as total_quizzes,
                COALESCE(SUM(points_earned), 0) as total_points,
                COALESCE(SUM(time_spent_minutes), 0) as total_minutes
            FROM daily_progress
            WHERE user_id = ? 
                AND progress_date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
        `, [userId]);
        
        res.json({
            success: true,
            progress: monthly[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching monthly progress:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get learning goals
app.get('/api/progress/goals', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Check if table exists
        const [tables] = await promisePool.query("SHOW TABLES LIKE 'learning_goals'");
        
        if (tables.length === 0) {
            return res.json({
                success: true,
                goals: []
            });
        }
        
        const [goals] = await promisePool.query(`
            SELECT 
                goal_id,
                goal_title,
                goal_description,
                goal_type,
                target_value,
                current_value,
                unit_type,
                status,
                progress_percentage,
                start_date,
                end_date
            FROM learning_goals
            WHERE user_id = ?
            ORDER BY created_at DESC
        `, [userId]);
        
        res.json({
            success: true,
            goals: goals
        });
        
    } catch (error) {
        console.error('❌ Error fetching goals:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get module progress
app.get('/api/progress/modules', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [modules] = await promisePool.query(`
            SELECT 
                cm.module_id,
                cm.module_name,
                cm.module_description,
                cm.module_order,
                COUNT(DISTINCT tci.content_id) as total_lessons,
                COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as completed_lessons,
                COALESCE(AVG(ucp.score), 0) as average_score,
                COALESCE(SUM(ucp.time_spent_seconds), 0) as total_time_seconds
            FROM course_modules cm
            LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
            LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id AND tci.is_active = 1
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
            WHERE cm.is_active = 1
            GROUP BY cm.module_id
            ORDER BY cm.module_order
        `, [userId]);
        
        const moduleProgress = modules.map(m => ({
            module_id: m.module_id,
            module_name: m.module_name,
            module_description: m.module_description,
            total_lessons: m.total_lessons || 0,
            lessons_completed: m.completed_lessons || 0,
            average_score: Math.round(m.average_score || 0),
            time_spent_minutes: Math.round((m.total_time_seconds || 0) / 60),
            progress_percentage: m.total_lessons > 0 
                ? Math.round((m.completed_lessons / m.total_lessons) * 100) 
                : 0
        }));
        
        res.json({
            success: true,
            progress: moduleProgress
        });
        
    } catch (error) {
        console.error('❌ Error fetching module progress:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get progress trends
app.get('/api/progress/trends', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { days = 30 } = req.query;
        
        const [trends] = await promisePool.query(`
            SELECT 
                progress_date as activity_date,
                lessons_completed,
                exercises_completed,
                quizzes_completed,
                points_earned
            FROM daily_progress
            WHERE user_id = ? 
                AND progress_date >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
            ORDER BY progress_date ASC
        `, [userId, parseInt(days)]);
        
        res.json({
            success: true,
            trends: trends
        });
        
    } catch (error) {
        console.error('❌ Error fetching trends:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get dashboard stats
app.get('/api/progress/dashboard-stats', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get total lessons completed
        const [lessons] = await promisePool.query(`
            SELECT COUNT(*) as count
            FROM user_content_progress
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get total practice completed
        const [practice] = await promisePool.query(`
            SELECT COUNT(*) as count
            FROM practice_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get total quizzes completed
        const [quizzes] = await promisePool.query(`
            SELECT COUNT(*) as count
            FROM user_quiz_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get total points
        const [points] = await promisePool.query(`
            SELECT COALESCE(SUM(points_amount), 0) as total
            FROM user_points
            WHERE user_id = ?
        `, [userId]);
        
        // Get average score
        const [avgScore] = await promisePool.query(`
            SELECT COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        res.json({
            success: true,
            stats: {
                total_lessons: lessons[0]?.count || 0,
                total_practice: practice[0]?.count || 0,
                total_quizzes: quizzes[0]?.count || 0,
                total_points: points[0]?.total || 0,
                average_score: Math.round(avgScore[0]?.avg_score || 0)
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching dashboard stats:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get all lessons with progress
app.get('/api/progress/lessons', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [progress] = await promisePool.query(`
            SELECT 
                ucp.content_id,
                ucp.completion_status,
                ucp.score as percentage,
                ucp.time_spent_seconds,
                ucp.last_accessed,
                ucp.completed_at,
                tci.content_title,
                tci.content_description,
                tci.content_type
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE ucp.user_id = ?
            ORDER BY ucp.last_accessed DESC
        `, [userId]);
        
        res.json({
            success: true,
            progress: progress
        });
        
    } catch (error) {
        console.error('❌ Error fetching lesson progress:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get practice analytics
app.get('/api/progress/practice-analytics', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [stats] = await promisePool.query(`
            SELECT 
                COALESCE(AVG(score), 0) as average_score,
                COALESCE(SUM(time_spent_seconds), 0) as total_time_seconds,
                COUNT(*) as total_attempts
            FROM practice_attempts
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        const average_score = Math.round(stats[0]?.average_score || 0);
        const total_time_minutes = Math.round((stats[0]?.total_time_seconds || 0) / 60);
        
        res.json({
            success: true,
            stats: {
                average_score: average_score,
                average_time_minutes: total_time_minutes > 0 ? Math.round(total_time_minutes / (stats[0]?.total_attempts || 1)) : 0,
                total_attempts: stats[0]?.total_attempts || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching practice analytics:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Create learning goal
app.post('/api/progress/create-goal', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { goal_title, goal_description, goal_type, target_value, unit_type, end_date } = req.body;
        
        // Check if table exists, create if not
        await promisePool.query(`
            CREATE TABLE IF NOT EXISTS learning_goals (
                goal_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                goal_title VARCHAR(255) NOT NULL,
                goal_description TEXT,
                goal_type ENUM('daily', 'weekly', 'monthly', 'custom') DEFAULT 'weekly',
                target_value INT NOT NULL,
                current_value INT DEFAULT 0,
                unit_type VARCHAR(50) DEFAULT 'lessons',
                progress_percentage INT DEFAULT 0,
                status ENUM('active', 'completed', 'paused', 'failed') DEFAULT 'active',
                start_date DATE,
                end_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
            )
        `);
        
        const [result] = await promisePool.query(`
            INSERT INTO learning_goals 
            (user_id, goal_title, goal_description, goal_type, target_value, unit_type, end_date, start_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, CURDATE())
        `, [userId, goal_title, goal_description, goal_type, target_value, unit_type, end_date]);
        
        res.status(201).json({
            success: true,
            message: 'Goal created successfully',
            goal: {
                goal_id: result.insertId,
                goal_title,
                goal_description,
                goal_type,
                target_value,
                unit_type,
                current_value: 0,
                progress_percentage: 0,
                status: 'active',
                end_date
            }
        });
        
    } catch (error) {
        console.error('❌ Error creating goal:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Update goal progress
app.post('/api/progress/update-goal-progress', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { goal_id, current_value } = req.body;
        
        // Get goal details
        const [goals] = await promisePool.query(
            'SELECT * FROM learning_goals WHERE goal_id = ? AND user_id = ?',
            [goal_id, userId]
        );
        
        if (goals.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Goal not found'
            });
        }
        
        const goal = goals[0];
        const progress_percentage = Math.min(100, Math.round((current_value / goal.target_value) * 100));
        const status = progress_percentage >= 100 ? 'completed' : 'active';
        
        await promisePool.query(`
            UPDATE learning_goals 
            SET current_value = ?, progress_percentage = ?, status = ?
            WHERE goal_id = ? AND user_id = ?
        `, [current_value, progress_percentage, status, goal_id, userId]);
        
        res.json({
            success: true,
            message: 'Goal progress updated'
        });
        
    } catch (error) {
        console.error('❌ Error updating goal:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Complete learning goal
app.post('/api/progress/complete-goal', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { goal_id } = req.body;
        
        await promisePool.query(`
            UPDATE learning_goals 
            SET status = 'completed', 
                progress_percentage = 100,
                current_value = target_value
            WHERE goal_id = ? AND user_id = ?
        `, [goal_id, userId]);
        
        res.json({
            success: true,
            message: 'Goal completed successfully'
        });
        
    } catch (error) {
        console.error('❌ Error completing goal:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// Get progress dashboard summary
app.get('/api/progress/dashboard-summary', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Get overall stats
        const [overallStats] = await promisePool.query(`
            SELECT 
                COALESCE(SUM(CASE WHEN activity_type = 'lesson_completed' THEN 1 ELSE 0 END), 0) as total_lessons,
                COALESCE(SUM(CASE WHEN activity_type = 'practice_completed' THEN 1 ELSE 0 END), 0) as total_exercises,
                COALESCE(SUM(CASE WHEN activity_type = 'quiz_completed' THEN 1 ELSE 0 END), 0) as total_quizzes,
                COUNT(DISTINCT DATE(activity_timestamp)) as active_days
            FROM user_activity_log 
            WHERE user_id = ?
        `, [userId]);
        
        // Get total points
        const [pointsStats] = await promisePool.query(`
            SELECT COALESCE(SUM(points_amount), 0) as total_points
            FROM user_points 
            WHERE user_id = ?
        `, [userId]);
        
        // Get average scores
        const [avgScores] = await promisePool.query(`
            SELECT 
                COALESCE(AVG(score), 0) as avg_quiz_score
            FROM user_quiz_attempts 
            WHERE user_id = ? AND completion_status = 'completed'
        `, [userId]);
        
        // Get streak data
        const [streakData] = await promisePool.query(`
            SELECT COUNT(*) as current_streak
            FROM daily_progress 
            WHERE user_id = ? 
            AND progress_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
            AND (lessons_completed > 0 OR exercises_completed > 0 OR quizzes_completed > 0)
        `, [userId]);
        
        res.json({
            success: true,
            dashboard: {
                welcomeTitle: `Your Learning Progress`,
                lastUpdated: `Last updated: ${new Date().toLocaleDateString()}`,
                overallProgress: {
                    percentage: Math.min(100, Math.round((overallStats[0]?.total_lessons / 20) * 100)),
                    barWidth: `${Math.min(100, Math.round((overallStats[0]?.total_lessons / 20) * 100))}%`,
                    barClass: 'progress-good'
                },
                totalPoints: {
                    current: pointsStats[0]?.total_points || 0,
                    change: `+${Math.round((pointsStats[0]?.total_points || 0) / 30)} this week`
                },
                timeInvested: {
                    total: `${Math.floor(overallStats[0]?.active_days * 30 / 60)}h`,
                    change: `${overallStats[0]?.active_days} days active`
                },
                badgesEarned: {
                    display: `${overallStats[0]?.total_lessons > 0 ? 1 : 0}/5`,
                    change: '+0 this month'
                },
                stats: {
                    total_lessons: overallStats[0]?.total_lessons || 0,
                    total_exercises: overallStats[0]?.total_exercises || 0,
                    total_quizzes: overallStats[0]?.total_quizzes || 0,
                    avg_score: Math.round(avgScores[0]?.avg_quiz_score || 0),
                    current_streak: streakData[0]?.current_streak || 0,
                    total_points: pointsStats[0]?.total_points || 0
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching dashboard summary:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});








// ============================================
// 📅 WEEKLY RESET ENDPOINT
// ============================================
app.post('/api/progress/reset-weekly-avg', authenticateToken, async (req, res) => {
    const connection = await mysql.createConnection(dbConfig);
    
    try {
        const userId = req.user.id;
        
        // Start transaction
        await connection.beginTransaction();
        
        // Archive weekly data before reset
        await connection.execute(
            `INSERT INTO weekly_performance_archive 
             (user_id, week_start, week_end, total_time, avg_time, lessons_completed, exercises_completed)
             SELECT ?, DATE_SUB(CURDATE(), INTERVAL DAYOFWEEK(CURDATE())-1 DAY),
             CURDATE(), SUM(time_spent_seconds), AVG(time_spent_seconds), 
             SUM(CASE WHEN completion_status = 'completed' THEN 1 ELSE 0 END), 0
             FROM user_content_progress 
             WHERE user_id = ? AND last_accessed >= DATE_SUB(CURDATE(), INTERVAL DAYOFWEEK(CURDATE())-1 DAY)`,
            [userId, userId]
        );
        
        // Reset weekly average in user_stats
        await connection.execute(
            `UPDATE user_stats 
             SET weekly_avg_time = 0,
                 weekly_total_time = 0,
                 last_weekly_reset = NOW()
             WHERE user_id = ?`,
            [userId]
        );
        
        await connection.commit();
        
        res.json({ 
            success: true, 
            message: 'Weekly average reset successfully' 
        });
        
    } catch (error) {
        await connection.rollback();
        console.error('Weekly reset error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to reset weekly average' 
        });
    } finally {
        await connection.end();
    }
});
/**
 * RECORD ACTIVITY - Saves any user activity to database
 */
// Record activity
app.post('/api/progress/record-activity', authenticateUser, async (req, res) => {
    try {
        const userId = req.user.id;
        const { activity_type, item_id, item_name, time_spent = 0, points_earned = 0, details = {} } = req.body;
        
        // Insert into activity log
        const detailsJson = JSON.stringify({ ...details, item_name, time_spent });
        
        await promisePool.query(`
            INSERT INTO user_activity_log 
            (user_id, activity_type, related_id, details, activity_timestamp)
            VALUES (?, ?, ?, ?, NOW())
        `, [userId, activity_type, item_id || null, detailsJson]);
        
        // Update daily progress if activity is completion
        if (activity_type.includes('_completed')) {
            const today = new Date().toISOString().split('T')[0];
            
            const [existing] = await promisePool.query(
                'SELECT * FROM daily_progress WHERE user_id = ? AND progress_date = ?',
                [userId, today]
            );
            
            let updateFields = [];
            
            if (activity_type === 'lesson_completed') {
                updateFields.push('lessons_completed = lessons_completed + 1');
            } else if (activity_type === 'practice_completed') {
                updateFields.push('exercises_completed = exercises_completed + 1');
            } else if (activity_type === 'quiz_completed') {
                updateFields.push('quizzes_completed = quizzes_completed + 1');
            }
            
            if (points_earned > 0) {
                updateFields.push('points_earned = points_earned + ?');
            }
            
            if (time_spent > 0) {
                updateFields.push('time_spent_minutes = time_spent_minutes + ?');
            }
            
            if (existing.length > 0) {
                await promisePool.query(`
                    UPDATE daily_progress 
                    SET ${updateFields.join(', ')}
                    WHERE user_id = ? AND progress_date = ?
                `, [points_earned, Math.round(time_spent / 60), userId, today]);
            } else {
                await promisePool.query(`
                    INSERT INTO daily_progress 
                    (user_id, progress_date, lessons_completed, exercises_completed, 
                     quizzes_completed, points_earned, time_spent_minutes)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [
                    userId,
                    today,
                    activity_type === 'lesson_completed' ? 1 : 0,
                    activity_type === 'practice_completed' ? 1 : 0,
                    activity_type === 'quiz_completed' ? 1 : 0,
                    points_earned,
                    Math.round(time_spent / 60)
                ]);
            }
            
            // Award points if applicable
            if (points_earned > 0) {
                await promisePool.query(`
                    INSERT INTO user_points 
                    (user_id, points_type, points_amount, description, reference_id)
                    VALUES (?, ?, ?, ?, ?)
                `, [
                    userId,
                    activity_type,
                    points_earned,
                    `Completed ${item_name || activity_type}`,
                    item_id || null
                ]);
            }
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('❌ Error recording activity:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ============================================
// HEALTH CHECK
// ============================================

app.get('/api/health', async (req, res) => {
    try {
        const [dbCheck] = await promisePool.execute('SELECT 1 as db_status');
        
        res.json({
            success: true,
            message: 'PolyLearn API is running',
            timestamp: new Date().toISOString(),
            database: dbCheck[0].db_status === 1 ? 'Connected' : 'Error',
            version: '3.0.0 (NEW SERVER + ADMIN ROUTES)',
            features: {
                admin: '✅ Complete (Lessons, Modules, Topics, Video Upload)',
                progress_tracking: '✅ Complete (Points, Badges, Daily Progress)',
                quiz_system: '✅ Complete',
                leaderboard: '✅ Complete',
                analytics: '✅ Complete'
            }
        });
    } catch (error) {
        res.json({
            success: true,
            message: 'PolyLearn API is running (Database Error)',
            timestamp: new Date().toISOString(),
            database: 'Not connected',
            error: error.message
        });
    }
});



// ============================================
// ✅ TEACHER ROUTES - COMPLETE FUNCTIONALITIES
// ============================================

// ===== AUTHENTICATE TEACHER MIDDLEWARE =====
const authenticateTeacher = async (req, res, next) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({ 
                success: false, 
                message: 'Access token required' 
            });
        }
        
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
        
        // Check if user is teacher or admin
        const [users] = await promisePool.execute(
            'SELECT user_id, role FROM users WHERE user_id = ?',
            [decoded.userId || decoded.id]
        );
        
        if (users.length === 0) {
            return res.status(403).json({ 
                success: false, 
                message: 'User not found' 
            });
        }
        
        const user = users[0];
        
        // Allow both teachers and admins
        if (user.role !== 'teacher' && user.role !== 'admin') {
            return res.status(403).json({ 
                success: false, 
                message: 'Teacher access required' 
            });
        }
        
        req.user = {
            id: user.user_id,
            role: user.role
        };
        
        next();
        
    } catch (error) {
        console.error('❌ Auth error:', error);
        return res.status(403).json({ 
            success: false, 
            message: 'Invalid or expired token' 
        });
    }
};

// ============================================
// ✅ TEACHER DASHBOARD STATS
// ============================================
app.get('/api/teacher/dashboard/stats', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                stats: {
                    total_lessons: 0,
                    published: 0,
                    draft: 0,
                    needs_review: 0,
                    avg_completion: 0,
                    total_students: 0,
                    avg_grade: 0,
                    pending_reviews: 0,
                    total_resources: 0
                }
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [lessonsResult] = await promisePool.execute(`
            SELECT 
                COUNT(*) as total_lessons,
                COALESCE(SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END), 0) as published,
                COALESCE(SUM(CASE WHEN is_active = 0 OR is_active IS NULL THEN 1 ELSE 0 END), 0) as draft,
                COALESCE(SUM(CASE WHEN content_type IN ('video', 'pdf', 'interactive') THEN 1 ELSE 0 END), 0) as total_resources
            FROM topic_content_items 
            WHERE (created_by = ? OR teacher_id = ?)
        `, [userId, teacherId]);
        
        const [completionResult] = await promisePool.execute(`
            SELECT 
                COALESCE(AVG(ucp.score), 0) as avg_completion
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.created_by = ? OR tci.teacher_id = ?)
            AND ucp.completion_status = 'completed'
        `, [userId, teacherId]);
        
        const [studentsResult] = await promisePool.execute(`
            SELECT COUNT(DISTINCT ucp.user_id) as total_students
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.created_by = ? OR tci.teacher_id = ?)
            AND ucp.completion_status = 'completed'
        `, [userId, teacherId]);
        
        const [pendingResult] = await promisePool.execute(`
            SELECT COUNT(*) as pending_reviews
            FROM feedback f
            WHERE f.teacher_id = ? AND f.status = 'new'
        `, [teacherId]);
        
        const avgCompletion = Math.round(completionResult[0]?.avg_completion || 0);
        
        res.json({
            success: true,
            stats: {
                total_lessons: lessonsResult[0]?.total_lessons || 0,
                published: lessonsResult[0]?.published || 0,
                draft: lessonsResult[0]?.draft || 0,
                needs_review: 0,
                avg_completion: avgCompletion,
                total_students: studentsResult[0]?.total_students || 0,
                avg_grade: avgCompletion,
                pending_reviews: pendingResult[0]?.pending_reviews || 0,
                total_resources: lessonsResult[0]?.total_resources || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Teacher dashboard stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET TEACHER'S STUDENTS
// ============================================
app.get('/api/teacher/students', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                students: [],
                teacher: null,
                subject_counts: { polynomial: 0, factorial: 0, mdas: 0 }
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [students] = await promisePool.execute(`
            SELECT 
                u.user_id as id,
                u.full_name as name,
                u.email,
                u.last_login as last_active,
                u.created_at as joined_date,
                (
                    SELECT COUNT(*) 
                    FROM user_content_progress ucp 
                    WHERE ucp.user_id = u.user_id 
                    AND ucp.completion_status = 'completed'
                    AND ucp.content_id IN (
                        SELECT content_id FROM topic_content_items 
                        WHERE created_by = ? OR teacher_id IN (?, ?) OR is_public = 1
                    )
                ) as lessons_completed,
                (
                    SELECT COALESCE(AVG(score), 0)
                    FROM user_quiz_attempts uqa
                    WHERE uqa.user_id = u.user_id 
                    AND uqa.completion_status = 'completed'
                ) as avg_score
            FROM users u
            WHERE u.user_id IN (
                SELECT DISTINCT ucp.user_id
                FROM user_content_progress ucp
                JOIN topic_content_items tci ON ucp.content_id = tci.content_id
                WHERE (tci.created_by = ? OR tci.teacher_id IN (?, ?) OR tci.is_public = 1)
            )
            AND u.role = 'student'
            AND u.is_active = 1
            ORDER BY u.full_name
        `, [userId, userId, teacherId, userId, userId, teacherId]);
        
        const formattedStudents = students.map(s => ({
            ...s,
            avatar: getInitialsFromName(s.name),
            last_active: s.last_active ? getTimeAgo(s.last_active) : 'Never'
        }));
        
        res.json({
            success: true,
            students: formattedStudents,
            total: formattedStudents.length
        });
        
    } catch (error) {
        console.error('❌ Teacher students error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET TEACHER'S LESSONS
// ============================================
app.get('/api/teacher/lessons', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                lessons: []
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [lessons] = await promisePool.execute(`
            SELECT 
                tci.content_id,
                tci.content_title,
                tci.content_description,
                tci.content_type,
                tci.content_url,
                tci.video_filename,
                tci.is_active,
                tci.created_at,
                tci.created_by,
                tci.teacher_id,
                tci.is_public,
                tci.topic_id,
                mt.topic_title,
                cm.module_name,
                l.lesson_name,
                l.lesson_id,
                creator.full_name as creator_name,
                creator.role as creator_role,
                (
                    SELECT COUNT(*) 
                    FROM user_content_progress ucp 
                    WHERE ucp.content_id = tci.content_id 
                    AND ucp.completion_status = 'completed'
                ) as completions,
                (
                    SELECT COUNT(DISTINCT ucp.user_id)
                    FROM user_content_progress ucp 
                    WHERE ucp.content_id = tci.content_id
                ) as unique_students,
                (
                    SELECT COALESCE(AVG(ucp.score), 0)
                    FROM user_content_progress ucp 
                    WHERE ucp.content_id = tci.content_id 
                    AND ucp.completion_status = 'completed'
                ) as avg_score
            FROM topic_content_items tci
            LEFT JOIN module_topics mt ON tci.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users creator ON tci.created_by = creator.user_id
            WHERE 
                tci.teacher_id = ?  
                OR tci.teacher_id = ?  
                OR tci.created_by = ?
            ORDER BY tci.created_at DESC
        `, [userId, teacherId, userId]);
        
        const formattedLessons = lessons.map(lesson => ({
            content_id: lesson.content_id,
            content_title: lesson.content_title,
            content_description: lesson.content_description,
            content_type: lesson.content_type,
            content_url: lesson.content_url,
            video_filename: lesson.video_filename,
            is_active: lesson.is_active,
            created_at: lesson.created_at,
            lesson_name: lesson.lesson_name || 'General',
            creator_name: lesson.creator_name,
            creator_role: lesson.creator_role,
            is_from_admin: lesson.creator_role === 'admin',
            is_own: lesson.created_by === userId,
            completions: lesson.completions || 0,
            unique_students: lesson.unique_students || 0,
            avg_score: Math.round(lesson.avg_score || 0)
        }));
        
        res.json({
            success: true,
            lessons: formattedLessons
        });
        
    } catch (error) {
        console.error('❌ Teacher lessons error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET SINGLE LESSON DETAILS
// ============================================
app.get('/api/teacher/lessons/:lessonId', authenticateTeacher, async (req, res) => {
    try {
        const { lessonId } = req.params;
        const userId = req.user.id;
        
        const [lessons] = await promisePool.execute(`
            SELECT 
                tci.*,
                mt.topic_title,
                cm.module_name,
                l.lesson_name,
                l.lesson_title as subject_name,
                creator.full_name as creator_name,
                creator.role as creator_role,
                teacher_user.full_name as teacher_name
            FROM topic_content_items tci
            LEFT JOIN module_topics mt ON tci.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users creator ON tci.created_by = creator.user_id
            LEFT JOIN users teacher_user ON tci.teacher_id = teacher_user.user_id
            WHERE tci.content_id = ?
        `, [lessonId]);
        
        if (lessons.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Lesson not found'
            });
        }
        
        const lesson = lessons[0];
        
        const hasAccess = lesson.created_by === userId || 
                         lesson.teacher_id === userId || 
                         lesson.is_public === 1;
        
        if (!hasAccess) {
            return res.status(403).json({
                success: false,
                message: 'You do not have access to this lesson'
            });
        }
        
        const [progress] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT user_id) as total_students,
                COUNT(*) as total_attempts,
                SUM(CASE WHEN completion_status = 'completed' THEN 1 ELSE 0 END) as completions,
                COALESCE(AVG(score), 0) as avg_score,
                COALESCE(AVG(time_spent_seconds), 0) as avg_time_seconds
            FROM user_content_progress
            WHERE content_id = ?
        `, [lessonId]);
        
        const [recentActivity] = await promisePool.execute(`
            SELECT 
                ucp.progress_id,
                ucp.user_id,
                u.full_name as student_name,
                ucp.completion_status,
                ucp.score,
                ucp.time_spent_seconds,
                ucp.last_accessed,
                ucp.completed_at
            FROM user_content_progress ucp
            JOIN users u ON ucp.user_id = u.user_id
            WHERE ucp.content_id = ?
            ORDER BY ucp.last_accessed DESC
            LIMIT 10
        `, [lessonId]);
        
        res.json({
            success: true,
            lesson: {
                id: lesson.content_id,
                title: lesson.content_title,
                description: lesson.content_description,
                type: lesson.content_type,
                subject: {
                    id: lesson.lesson_id,
                    name: lesson.subject_name || lesson.lesson_name,
                    topic: lesson.topic_title,
                    module: lesson.module_name
                },
                status: lesson.is_active === 1 ? 'active' : 'inactive',
                is_required: lesson.is_required === 1,
                is_public: lesson.is_public === 1,
                created_at: lesson.created_at,
                created_by: lesson.created_by,
                creator: {
                    name: lesson.creator_name,
                    role: lesson.creator_role
                },
                teacher: lesson.teacher_name,
                content: {
                    url: lesson.content_url,
                    video_filename: lesson.video_filename,
                    duration_seconds: lesson.video_duration_seconds
                },
                stats: progress[0] || {
                    total_students: 0,
                    total_attempts: 0,
                    completions: 0,
                    avg_score: 0,
                    avg_time_seconds: 0
                },
                recent_activity: recentActivity.map(a => ({
                    ...a,
                    time_spent_minutes: Math.round(a.time_spent_seconds / 60)
                }))
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching lesson details:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ CREATE TEACHER LESSON (WITH VIDEO UPLOAD)
// ============================================
app.post('/api/teacher/lessons/create', 
    authenticateTeacher,
    upload.single('video_file'),
    async (req, res) => {
        try {
            const userId = req.user.id;
            
            const { 
                title, 
                description, 
                topic_id,
                content_type, 
                youtube_url,
                text_content,
                lesson_id,
                lesson_name,
                module_id,
                module_name,
                topic_name
            } = req.body;
            
            const videoFile = req.file;
            
            if (!title) {
                return res.status(400).json({
                    success: false,
                    message: 'Title is required'
                });
            }
            
            if (!topic_id) {
                return res.status(400).json({
                    success: false,
                    message: 'Topic ID is required'
                });
            }
            
            const [teacher] = await promisePool.execute(`
                SELECT teacher_id FROM teachers WHERE user_id = ?
            `, [userId]);
            
            let teacherId = userId;
            if (teacher.length > 0) {
                teacherId = teacher[0].teacher_id;
            }
            
            let contentUrl = null;
            let videoFilename = null;
            
            if (youtube_url) {
                contentUrl = youtube_url;
            } else if (videoFile) {
                videoFilename = videoFile.filename;
                contentUrl = `/videos/${videoFile.filename}`;
            } else if (content_type === 'text' && text_content) {
                contentUrl = text_content;
            }
            
            const [orderResult] = await promisePool.execute(
                'SELECT MAX(content_order) as max_order FROM topic_content_items WHERE topic_id = ?',
                [topic_id]
            );
            const nextOrder = (orderResult[0]?.max_order || 0) + 1;
            
            const [result] = await promisePool.execute(`
                INSERT INTO topic_content_items 
                (topic_id, created_by, teacher_id, content_type, content_title, 
                 content_description, content_url, video_filename, content_order, is_active, is_public)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)
            `, [
                topic_id,
                userId,
                teacherId,
                content_type || 'text',
                title,
                description || null,
                contentUrl,
                videoFilename,
                nextOrder
            ]);
            
            // ===== ADD THIS: Get complete structure info =====
            const [structureInfo] = await promisePool.execute(`
                SELECT 
                    l.lesson_id,
                    l.lesson_name,
                    cm.module_id,
                    cm.module_name,
                    mt.topic_id,
                    mt.topic_title
                FROM lessons l
                LEFT JOIN course_modules cm ON l.lesson_id = cm.lesson_id
                LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
                WHERE mt.topic_id = ?
            `, [topic_id]);
            
            const structure = structureInfo.length > 0 ? structureInfo[0] : {
                lesson_id: lesson_id,
                lesson_name: lesson_name,
                module_id: module_id,
                module_name: module_name,
                topic_id: topic_id,
                topic_title: topic_name
            };
            
            res.status(201).json({
                success: true,
                message: 'Lesson created successfully',
                lesson_id: result.insertId,
                structure: {
                    lesson: { 
                        id: structure.lesson_id, 
                        name: structure.lesson_name 
                    },
                    module: { 
                        id: structure.module_id, 
                        name: structure.module_name 
                    },
                    topic: { 
                        id: structure.topic_id, 
                        name: structure.topic_title 
                    }
                }
            });
            
        } catch (error) {
            console.error('❌ Create teacher lesson error:', error);
            res.status(500).json({ 
                success: false, 
                message: error.message 
            });
        }
    }
);

// ============================================
// ✅ UPDATE TEACHER LESSON
// ============================================
app.put('/api/teacher/lessons/:lessonId', authenticateTeacher, upload.single('video_file'), async (req, res) => {
    try {
        const userId = req.user.id;
        const { lessonId } = req.params;
        const { 
            title, 
            description, 
            subject,
            content_type,
            youtube_url,
            text_content,
            is_active 
        } = req.body;
        
        const videoFile = req.file;
        
        const [check] = await promisePool.execute(`
            SELECT content_id, created_by, teacher_id 
            FROM topic_content_items 
            WHERE content_id = ? AND (created_by = ? OR teacher_id = ?)
        `, [lessonId, userId, userId]);
        
        if (check.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to edit this lesson'
            });
        }
        
        let updateFields = [];
        let updateValues = [];
        
        if (title) {
            updateFields.push('content_title = ?');
            updateValues.push(title);
        }
        
        if (description !== undefined) {
            updateFields.push('content_description = ?');
            updateValues.push(description);
        }
        
        if (is_active !== undefined) {
            updateFields.push('is_active = ?');
            updateValues.push(is_active ? 1 : 0);
        }
        
        if (youtube_url) {
            updateFields.push('content_url = ?');
            updateValues.push(youtube_url);
            updateFields.push('content_type = ?');
            updateValues.push('video');
        } else if (videoFile) {
            updateFields.push('video_filename = ?');
            updateValues.push(videoFile.filename);
            updateFields.push('content_url = ?');
            updateValues.push(`/videos/${videoFile.filename}`);
            updateFields.push('content_type = ?');
            updateValues.push('video');
        } else if (text_content) {
            updateFields.push('content_url = ?');
            updateValues.push(text_content);
            updateFields.push('content_type = ?');
            updateValues.push('text');
        }
        
        if (subject) {
            let topic_id = 1;
            if (subject === 'polynomial') topic_id = 2;
            else if (subject === 'factorial') topic_id = 1;
            else if (subject === 'mdas') topic_id = 3;
            
            updateFields.push('topic_id = ?');
            updateValues.push(topic_id);
        }
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(lessonId);
        
        await promisePool.execute(
            `UPDATE topic_content_items SET ${updateFields.join(', ')} WHERE content_id = ?`,
            updateValues
        );
        
        res.json({
            success: true,
            message: 'Lesson updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Update lesson error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ DELETE TEACHER LESSON
// ============================================
app.delete('/api/teacher/lessons/:lessonId', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const { lessonId } = req.params;
        
        const [check] = await promisePool.execute(`
            SELECT content_id, content_title, created_by 
            FROM topic_content_items 
            WHERE content_id = ? AND (created_by = ? OR teacher_id = ?)
        `, [lessonId, userId, userId]);
        
        if (check.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'You do not have permission to delete this lesson'
            });
        }
        
        const lesson = check[0];
        
        await promisePool.execute(
            'DELETE FROM user_content_progress WHERE content_id = ?',
            [lessonId]
        );
        
        await promisePool.execute(
            'DELETE FROM topic_content_items WHERE content_id = ?',
            [lessonId]
        );
        
        res.json({
            success: true,
            message: `Lesson "${lesson.content_title}" deleted successfully`
        });
        
    } catch (error) {
        console.error('❌ Delete lesson error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET TEACHER'S FEEDBACK
// ============================================
app.get('/api/teacher/my-feedback', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                feedback: [],
                total: 0
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [feedback] = await promisePool.execute(`
            SELECT 
                f.feedback_id as id,
                f.feedback_type as type,
                f.feedback_message as message,
                f.rating,
                f.status,
                f.created_at as date,
                f.related_id,
                u.user_id,
                u.full_name as student_name,
                u.username,
                u.email,
                tci.content_title as lesson_title,
                tci.content_id
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
            LEFT JOIN topic_content_items tci ON f.related_id = tci.content_id
            WHERE f.teacher_id = ?
            ORDER BY f.created_at DESC
        `, [teacherId]);
        
        const formattedFeedback = feedback.map(f => ({
            id: f.id,
            type: f.type,
            message: f.message,
            rating: f.rating,
            status: f.status,
            date: f.date,
            student: {
                id: f.user_id,
                name: f.student_name || 'Anonymous',
                username: f.username,
                email: f.email,
                avatar: getInitialsFromName(f.student_name || 'Anonymous')
            },
            lesson: f.lesson_title ? {
                id: f.related_id,
                title: f.lesson_title
            } : null,
            time_ago: getTimeAgo(f.date),
            status_badge: getStatusBadge(f.status),
            type_icon: getTypeIcon(f.type)
        }));
        
        res.json({
            success: true,
            feedback: formattedFeedback,
            total: formattedFeedback.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching teacher feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET SINGLE FEEDBACK DETAILS
// ============================================
app.get('/api/teacher/feedback/:feedbackId', authenticateTeacher, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Teacher not found'
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [feedback] = await promisePool.execute(`
            SELECT 
                f.feedback_id as id,
                f.feedback_type as type,
                f.feedback_message as message,
                f.rating,
                f.status,
                f.created_at,
                f.reviewed_at,
                f.resolved_at,
                f.admin_notes as admin_response,
                f.user_agent,
                f.ip_address,
                f.page_url,
                u.user_id as student_id,
                u.full_name as student_name,
                u.email as student_email,
                u.username as student_username,
                tci.content_id as lesson_id,
                tci.content_title as lesson_title
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
            LEFT JOIN topic_content_items tci ON f.related_id = tci.content_id
            WHERE f.feedback_id = ? AND f.teacher_id = ?
        `, [feedbackId, teacherId]);
        
        if (feedback.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Feedback not found'
            });
        }
        
        const fb = feedback[0];
        
        res.json({
            success: true,
            feedback: {
                id: fb.id,
                type: fb.type,
                message: fb.message,
                rating: fb.rating,
                status: fb.status,
                created_at: fb.created_at,
                reviewed_at: fb.reviewed_at,
                resolved_at: fb.resolved_at,
                admin_response: fb.admin_response,
                user_agent: fb.user_agent,
                ip_address: fb.ip_address,
                page_url: fb.page_url,
                student_id: fb.student_id,
                student_name: fb.student_name || 'Anonymous',
                student_email: fb.student_email,
                student_username: fb.student_username,
                lesson_id: fb.lesson_id,
                lesson_title: fb.lesson_title
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching feedback details:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ MARK FEEDBACK AS RESOLVED
// ============================================
app.post('/api/teacher/feedback/:feedbackId/resolve', authenticateTeacher, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        const userId = req.user.id;
        
        const [feedback] = await promisePool.execute(`
            SELECT f.feedback_id, f.teacher_id, t.user_id 
            FROM feedback f
            JOIN teachers t ON f.teacher_id = t.teacher_id
            WHERE f.feedback_id = ?
        `, [feedbackId]);
        
        if (feedback.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Feedback not found'
            });
        }
        
        if (feedback[0].user_id !== userId) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized'
            });
        }
        
        await promisePool.execute(`
            UPDATE feedback 
            SET status = 'resolved', 
                resolved_at = NOW() 
            WHERE feedback_id = ?
        `, [feedbackId]);
        
        res.json({
            success: true,
            message: 'Feedback marked as resolved'
        });
        
    } catch (error) {
        console.error('❌ Error resolving feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ REPLY TO FEEDBACK
// ============================================
app.post('/api/teacher/feedback/:feedbackId/reply', authenticateTeacher, async (req, res) => {
    try {
        const { feedbackId } = req.params;
        const userId = req.user.id;
        const { reply } = req.body;
        
        if (!reply || reply.trim() === '') {
            return res.status(400).json({
                success: false,
                message: 'Reply is required'
            });
        }
        
        const [feedback] = await promisePool.execute(`
            SELECT f.feedback_id, f.teacher_id, t.user_id 
            FROM feedback f
            JOIN teachers t ON f.teacher_id = t.teacher_id
            WHERE f.feedback_id = ?
        `, [feedbackId]);
        
        if (feedback.length === 0 || feedback[0].user_id !== userId) {
            return res.status(403).json({
                success: false,
                message: 'Not authorized'
            });
        }
        
        await promisePool.execute(`
            UPDATE feedback 
            SET admin_notes = CONCAT(COALESCE(admin_notes, ''), '\n\nTeacher Reply: ', ?),
                status = 'reviewed',
                reviewed_at = NOW()
            WHERE feedback_id = ?
        `, [reply, feedbackId]);
        
        res.json({
            success: true,
            message: 'Reply sent successfully'
        });
        
    } catch (error) {
        console.error('❌ Error replying to feedback:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER PROFILE
// ============================================
app.get('/api/teacher/profile', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [profile] = await promisePool.execute(`
            SELECT 
                t.teacher_id,
                t.user_id,
                t.department,
                t.qualification,
                t.years_experience,
                t.bio,
                t.rating,
                t.total_students,
                t.total_lessons,
                t.specialization,
                t.available_hours,
                t.created_at as teacher_since,
                t.updated_at,
                u.username,
                u.email,
                u.full_name,
                u.role,
                u.created_at as joined_date,
                u.last_login,
                u.is_active
            FROM teachers t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.user_id = ?
        `, [userId]);
        
        if (profile.length === 0) {
            const [user] = await promisePool.execute(`
                SELECT 
                    user_id,
                    username,
                    email,
                    full_name,
                    role,
                    created_at as joined_date,
                    last_login,
                    is_active
                FROM users 
                WHERE user_id = ?
            `, [userId]);
            
            return res.json({
                success: true,
                profile: {
                    ...user[0],
                    department: 'Not set',
                    qualification: 'Not set',
                    years_experience: 0,
                    bio: '',
                    specialization: null,
                    available_hours: null,
                    teacher_since: null
                }
            });
        }
        
        const [stats] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT tci.content_id) as total_lessons_created,
                COUNT(DISTINCT CASE WHEN tci.is_active = 1 THEN tci.content_id END) as active_lessons,
                COUNT(DISTINCT ucp.user_id) as total_students_taught,
                COALESCE(AVG(ucp.score), 0) as avg_student_score,
                (SELECT COUNT(*) FROM quizzes WHERE created_by = ?) as total_quizzes_created,
                (SELECT COUNT(*) FROM practice_exercises WHERE created_by = ?) as total_practice_created,
                (SELECT COUNT(*) FROM feedback WHERE teacher_id = (SELECT teacher_id FROM teachers WHERE user_id = ?)) as total_feedback,
                (SELECT COALESCE(AVG(rating), 0) FROM feedback 
                 WHERE teacher_id = (SELECT teacher_id FROM teachers WHERE user_id = ?) 
                 AND rating IS NOT NULL) as avg_rating
            FROM topic_content_items tci
            LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id
            WHERE (tci.created_by = ? OR tci.teacher_id = ?)
        `, [userId, userId, userId, userId, userId, userId]);
        
        const [recentActivity] = await promisePool.execute(`
            (SELECT 
                'lesson' as type,
                tci.content_title as title,
                ucp.completed_at as date,
                ucp.score
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.created_by = ? OR tci.teacher_id = ?)
            AND ucp.completion_status = 'completed'
            ORDER BY ucp.completed_at DESC
            LIMIT 5)
            
            UNION ALL
            
            (SELECT 
                'quiz' as type,
                q.quiz_title as title,
                uqa.end_time as date,
                uqa.score
            FROM user_quiz_attempts uqa
            JOIN quizzes q ON uqa.quiz_id = q.quiz_id
            WHERE q.created_by = ?
            AND uqa.completion_status = 'completed'
            ORDER BY uqa.end_time DESC
            LIMIT 5)
            
            ORDER BY date DESC
            LIMIT 10
        `, [userId, userId, userId]);
        
        const [subjects] = await promisePool.execute(`
            SELECT 
                l.lesson_name,
                l.lesson_title,
                COUNT(DISTINCT tci.content_id) as lesson_count,
                COUNT(DISTINCT CASE WHEN tci.content_type = 'video' THEN tci.content_id END) as video_count,
                COUNT(DISTINCT CASE WHEN tci.content_type = 'pdf' THEN tci.content_id END) as pdf_count
            FROM lessons l
            LEFT JOIN course_modules cm ON l.lesson_id = cm.lesson_id
            LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
            LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id 
                AND (tci.created_by = ? OR tci.teacher_id = ?)
            WHERE l.is_active = TRUE
            GROUP BY l.lesson_id
            HAVING lesson_count > 0
        `, [userId, userId]);
        
        const [badges] = await promisePool.execute(`
            SELECT 
                b.badge_id,
                b.badge_name,
                b.description,
                b.icon,
                b.color,
                b.points_awarded,
                ub.awarded_at
            FROM badges b
            LEFT JOIN user_badges ub ON b.badge_id = ub.badge_id AND ub.user_id = ?
            WHERE b.is_active = TRUE
            ORDER BY ub.awarded_at DESC
            LIMIT 6
        `, [userId]);
        
        res.json({
            success: true,
            profile: profile[0],
            stats: stats[0] || {
                total_lessons_created: 0,
                active_lessons: 0,
                total_students_taught: 0,
                avg_student_score: 0,
                total_quizzes_created: 0,
                total_practice_created: 0,
                total_feedback: 0,
                avg_rating: 0
            },
            recent_activity: recentActivity || [],
            subjects: subjects || [],
            badges: badges || []
        });
        
    } catch (error) {
        console.error('❌ Error fetching teacher profile:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ UPDATE TEACHER PROFILE
// ============================================
app.put('/api/teacher/profile/update', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const {
            full_name,
            email,
            department,
            qualification,
            years_experience,
            bio,
            specialization,
            available_hours,
            phone,
            education
        } = req.body;
        
        const connection = await promisePool.getConnection();
        await connection.beginTransaction();
        
        try {
            if (full_name || email) {
                const userUpdates = [];
                const userValues = [];
                
                if (full_name) {
                    userUpdates.push('full_name = ?');
                    userValues.push(full_name);
                }
                
                if (email) {
                    const [existing] = await connection.execute(
                        'SELECT user_id FROM users WHERE email = ? AND user_id != ?',
                        [email, userId]
                    );
                    
                    if (existing.length > 0) {
                        throw new Error('Email already in use');
                    }
                    
                    userUpdates.push('email = ?');
                    userValues.push(email);
                }
                
                if (userUpdates.length > 0) {
                    userValues.push(userId);
                    await connection.execute(
                        `UPDATE users SET ${userUpdates.join(', ')} WHERE user_id = ?`,
                        userValues
                    );
                }
            }
            
            const [teacher] = await connection.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [userId]
            );
            
            if (teacher.length === 0) {
                await connection.execute(`
                    INSERT INTO teachers (
                        user_id, department, qualification, years_experience, 
                        bio, specialization, available_hours
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                `, [
                    userId,
                    department || 'Mathematics',
                    qualification || 'Licensed Professional Teacher',
                    years_experience || 0,
                    bio || '',
                    specialization || null,
                    available_hours || null
                ]);
            } else {
                const teacherUpdates = [];
                const teacherValues = [];
                
                if (department !== undefined) {
                    teacherUpdates.push('department = ?');
                    teacherValues.push(department);
                }
                
                if (qualification !== undefined) {
                    teacherUpdates.push('qualification = ?');
                    teacherValues.push(qualification);
                }
                
                if (years_experience !== undefined) {
                    teacherUpdates.push('years_experience = ?');
                    teacherValues.push(years_experience);
                }
                
                if (bio !== undefined) {
                    teacherUpdates.push('bio = ?');
                    teacherValues.push(bio);
                }
                
                if (specialization !== undefined) {
                    teacherUpdates.push('specialization = ?');
                    teacherValues.push(specialization);
                }
                
                if (available_hours !== undefined) {
                    teacherUpdates.push('available_hours = ?');
                    teacherValues.push(available_hours);
                }
                
                if (teacherUpdates.length > 0) {
                    teacherValues.push(userId);
                    await connection.execute(
                        `UPDATE teachers SET ${teacherUpdates.join(', ')} WHERE user_id = ?`,
                        teacherValues
                    );
                }
            }
            
            await connection.commit();
            connection.release();
            
            const [updated] = await promisePool.execute(`
                SELECT 
                    t.*,
                    u.username,
                    u.email,
                    u.full_name
                FROM teachers t
                JOIN users u ON t.user_id = u.user_id
                WHERE t.user_id = ?
            `, [userId]);
            
            res.json({
                success: true,
                message: 'Profile updated successfully',
                profile: updated[0] || { user_id: userId }
            });
            
        } catch (error) {
            await connection.rollback();
            connection.release();
            throw error;
        }
        
    } catch (error) {
        console.error('❌ Error updating teacher profile:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ CHANGE TEACHER PASSWORD
// ============================================
app.post('/api/teacher/profile/change-password', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const { current_password, new_password } = req.body;
        
        if (!current_password || !new_password) {
            return res.status(400).json({
                success: false,
                message: 'Current password and new password are required'
            });
        }
        
        if (new_password.length < 6) {
            return res.status(400).json({
                success: false,
                message: 'New password must be at least 6 characters'
            });
        }
        
        const [user] = await promisePool.execute(
            'SELECT password_hash FROM users WHERE user_id = ?',
            [userId]
        );
        
        if (user.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const isValid = await bcrypt.compare(current_password, user[0].password_hash);
        if (!isValid) {
            return res.status(401).json({
                success: false,
                message: 'Current password is incorrect'
            });
        }
        
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(new_password, salt);
        
        await promisePool.execute(
            'UPDATE users SET password_hash = ?, updated_at = NOW() WHERE user_id = ?',
            [hashedPassword, userId]
        );
        
        res.json({
            success: true,
            message: 'Password changed successfully'
        });
        
    } catch (error) {
        console.error('❌ Error changing password:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER NOTIFICATION SETTINGS
// ============================================
app.get('/api/teacher/settings/notifications', authenticateTeacher, async (req, res) => {
    try {
        res.json({
            success: true,
            settings: {
                email_notifications: true,
                assignment_submissions: true,
                student_questions: true,
                grade_updates: true,
                system_announcements: true,
                digest_time: '09:00'
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching notification settings:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ UPDATE TEACHER NOTIFICATION SETTINGS
// ============================================
app.post('/api/teacher/settings/notifications', authenticateTeacher, async (req, res) => {
    try {
        const settings = req.body;
        console.log('📧 Updating notification settings:', settings);
        
        res.json({
            success: true,
            message: 'Notification settings updated'
        });
        
    } catch (error) {
        console.error('❌ Error updating notification settings:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER PRIVACY SETTINGS
// ============================================
app.get('/api/teacher/settings/privacy', authenticateTeacher, async (req, res) => {
    try {
        res.json({
            success: true,
            settings: {
                show_profile_to_students: true,
                allow_contact: true,
                share_lessons: false,
                collect_usage_data: true
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching privacy settings:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ UPDATE TEACHER PRIVACY SETTINGS
// ============================================
app.post('/api/teacher/settings/privacy', authenticateTeacher, async (req, res) => {
    try {
        const settings = req.body;
        console.log('🔒 Updating privacy settings:', settings);
        
        res.json({
            success: true,
            message: 'Privacy settings updated'
        });
        
    } catch (error) {
        console.error('❌ Error updating privacy settings:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER APPEARANCE SETTINGS
// ============================================
app.get('/api/teacher/settings/appearance', authenticateTeacher, async (req, res) => {
    try {
        res.json({
            success: true,
            settings: {
                theme: 'light',
                font_size: 'medium',
                density: 'normal'
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching appearance settings:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER OVERVIEW STATS
// ============================================
app.get('/api/teacher/stats/overview', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [stats] = await promisePool.execute(`
            SELECT 
                (SELECT COUNT(*) FROM topic_content_items WHERE created_by = ? OR teacher_id = ?) as total_lessons,
                (SELECT COUNT(DISTINCT user_id) FROM user_content_progress ucp 
                 JOIN topic_content_items tci ON ucp.content_id = tci.content_id 
                 WHERE (tci.created_by = ? OR tci.teacher_id = ?)) as total_students,
                (SELECT COUNT(*) FROM quizzes WHERE created_by = ? OR assigned_teacher_id = ?) as total_quizzes,
                (SELECT COUNT(*) FROM practice_exercises WHERE created_by = ?) as total_practice,
                (SELECT COUNT(*) FROM feedback WHERE teacher_id = (SELECT teacher_id FROM teachers WHERE user_id = ?)) as total_feedback
        `, [userId, userId, userId, userId, userId, userId, userId, userId]);
        
        res.json({
            success: true,
            stats: stats[0] || {
                total_lessons: 0,
                total_students: 0,
                total_quizzes: 0,
                total_practice: 0,
                total_feedback: 0
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching overview stats:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER PRACTICE MATERIALS
// ============================================
app.get('/api/teacher/practice', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                practice: [],
                message: 'Teacher record not found'
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [practice] = await promisePool.execute(`
            SELECT 
                pe.exercise_id as id,
                pe.title,
                pe.description,
                pe.difficulty,
                pe.content_type as type,
                pe.points,
                pe.content_json,
                pe.is_active as status,
                pe.created_at,
                pe.created_by,
                pe.is_public,
                mt.topic_title as topic_name,
                l.lesson_name as subject,
                u.full_name as creator_name,
                u.role as creator_role,
                (
                    SELECT COUNT(*) 
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id
                ) as total_attempts,
                (
                    SELECT COUNT(DISTINCT upp.user_id)
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id
                ) as unique_students,
                (
                    SELECT COALESCE(ROUND(AVG(upp.score), 2), 0)
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id 
                    AND upp.completion_status = 'completed'
                ) as avg_score,
                (
                    SELECT COUNT(*) 
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id 
                    AND upp.completion_status = 'completed'
                ) as completions,
                (
                    SELECT MAX(upp.score)
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id 
                    AND upp.completion_status = 'completed'
                ) as highest_score,
                (
                    SELECT MIN(upp.score)
                    FROM user_practice_progress upp 
                    WHERE upp.exercise_id = pe.exercise_id 
                    AND upp.completion_status = 'completed'
                ) as lowest_score
            FROM practice_exercises pe
            LEFT JOIN module_topics mt ON pe.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users u ON pe.created_by = u.user_id
            WHERE 
                pe.created_by = ?
                OR pe.is_public = 1
                OR pe.created_by IN (
                    SELECT user_id FROM users WHERE role = 'teacher'
                )
            ORDER BY 
                CASE 
                    WHEN pe.created_by = ? THEN 1
                    ELSE 2
                END,
                pe.created_at DESC
        `, [userId, userId]);
        
        const formattedPractice = practice.map(p => {
            let questionCount = 0;
            let parsedContent = { questions: [] };
            
            try {
                if (p.content_json) {
                    parsedContent = typeof p.content_json === 'string' 
                        ? JSON.parse(p.content_json) 
                        : p.content_json;
                    questionCount = parsedContent.questions ? parsedContent.questions.length : 0;
                }
            } catch (e) {
                console.log(`Error parsing content_json for practice ${p.id}:`, e.message);
            }
            
            let source = 'public';
            let sourceLabel = 'Public';
            let sourceColor = '#666';
            
            if (p.created_by === userId) {
                source = 'own';
                sourceLabel = 'My Practice';
                sourceColor = '#4CAF50';
            }
            
            const passCount = p.completions || 0;
            const passRate = p.total_attempts > 0 
                ? Math.round((passCount / p.total_attempts) * 100) 
                : 0;
            
            return {
                id: p.id,
                title: p.title,
                description: p.description,
                subject: p.subject || 'General',
                topic: p.topic_name || 'General',
                difficulty: p.difficulty || 'medium',
                type: p.type || 'multiple_choice',
                points: p.points || 10,
                question_count: questionCount,
                status: p.status === 1 ? 'active' : 'inactive',
                created_at: p.created_at,
                stats: {
                    total_attempts: p.total_attempts || 0,
                    unique_students: p.unique_students || 0,
                    avg_score: Math.round(p.avg_score || 0),
                    highest_score: Math.round(p.highest_score || 0),
                    lowest_score: Math.round(p.lowest_score || 0),
                    completions: p.completions || 0,
                    pass_rate: passRate
                },
                source: {
                    type: source,
                    label: sourceLabel,
                    color: sourceColor,
                    creator: p.creator_name || (p.creator_role === 'admin' ? 'Admin' : 'Unknown')
                },
                content: parsedContent,
                is_editable: p.created_by === userId,
                is_deletable: p.created_by === userId
            };
        });
        
        const stats = {
            total_practice: formattedPractice.length,
            active_practice: formattedPractice.filter(p => p.status === 'active').length,
            own_practice: formattedPractice.filter(p => p.source.type === 'own').length,
            public_practice: formattedPractice.filter(p => p.source.type === 'public').length,
            total_attempts: formattedPractice.reduce((sum, p) => sum + (p.stats.total_attempts || 0), 0),
            avg_score_all: formattedPractice.length > 0 
                ? Math.round(formattedPractice.reduce((sum, p) => sum + (p.stats.avg_score || 0), 0) / formattedPractice.length)
                : 0,
            total_completions: formattedPractice.reduce((sum, p) => sum + (p.stats.completions || 0), 0)
        };
        
        res.json({
            success: true,
            practice: formattedPractice,
            total: formattedPractice.length,
            stats: stats
        });
        
    } catch (error) {
        console.error('❌ Error fetching teacher practice:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET SINGLE PRACTICE MATERIAL
// ============================================
app.get('/api/teacher/practice/:practiceId', authenticateTeacher, async (req, res) => {
    try {
        const { practiceId } = req.params;
        const userId = req.user.id;
        
        const [practice] = await promisePool.execute(`
            SELECT 
                pe.*,
                mt.topic_title as topic_name,
                l.lesson_name as subject,
                u.full_name as creator_name,
                u.role as creator_role
            FROM practice_exercises pe
            LEFT JOIN module_topics mt ON pe.topic_id = mt.topic_id
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users u ON pe.created_by = u.user_id
            WHERE pe.exercise_id = ?
        `, [practiceId]);
        
        if (practice.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Practice material not found'
            });
        }
        
        const p = practice[0];
        
        const hasAccess = p.created_by === userId || p.is_public === 1;
        
        if (!hasAccess) {
            return res.status(403).json({
                success: false,
                message: 'You do not have access to this practice material'
            });
        }
        
        let parsedContent = { questions: [] };
        try {
            if (p.content_json) {
                parsedContent = typeof p.content_json === 'string' 
                    ? JSON.parse(p.content_json) 
                    : p.content_json;
            }
        } catch (e) {
            console.log('Error parsing content_json:', e);
        }
        
        const [progress] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT user_id) as total_students,
                COUNT(*) as total_attempts,
                SUM(CASE WHEN completion_status = 'completed' THEN 1 ELSE 0 END) as completions,
                COALESCE(AVG(score), 0) as avg_score,
                MAX(score) as highest_score,
                MIN(score) as lowest_score,
                COALESCE(AVG(time_spent_seconds), 0) as avg_time_seconds
            FROM user_practice_progress
            WHERE exercise_id = ?
        `, [practiceId]);
        
        const [recentAttempts] = await promisePool.execute(`
            SELECT 
                upp.progress_id,
                upp.user_id,
                u.full_name as student_name,
                upp.score,
                upp.completion_status,
                upp.attempts,
                upp.time_spent_seconds,
                upp.last_attempted as attempted_at,
                upp.completed_at
            FROM user_practice_progress upp
            JOIN users u ON upp.user_id = u.user_id
            WHERE upp.exercise_id = ?
            ORDER BY upp.last_attempted DESC
            LIMIT 10
        `, [practiceId]);
        
        res.json({
            success: true,
            practice: {
                id: p.exercise_id,
                title: p.title,
                description: p.description,
                topic_id: p.topic_id,
                topic_name: p.topic_name,
                subject: p.subject,
                difficulty: p.difficulty,
                content_type: p.content_type,
                points: p.points,
                status: p.is_active === 1 ? 'active' : 'inactive',
                created_at: p.created_at,
                created_by: p.created_by,
                creator: {
                    name: p.creator_name,
                    role: p.creator_role
                },
                content: parsedContent,
                question_count: parsedContent.questions?.length || 0,
                stats: progress[0] || {
                    total_students: 0,
                    total_attempts: 0,
                    completions: 0,
                    avg_score: 0,
                    highest_score: 0,
                    lowest_score: 0,
                    avg_time_seconds: 0
                },
                recent_attempts: recentAttempts.map(a => ({
                    ...a,
                    time_spent_minutes: Math.round(a.time_spent_seconds / 60),
                    score_percent: Math.round(a.score)
                }))
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching practice details:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ CREATE NEW PRACTICE MATERIAL
// ============================================
app.post('/api/teacher/practice/create', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const practiceData = req.body;
        
        if (!practiceData.title) {
            return res.status(400).json({
                success: false,
                message: 'Title is required'
            });
        }
        
        if (!practiceData.topic_id) {
            return res.status(400).json({
                success: false,
                message: 'Topic is required'
            });
        }
        
        if (!practiceData.content_json || !practiceData.content_json.questions) {
            return res.status(400).json({
                success: false,
                message: 'Questions are required'
            });
        }
        
        const [result] = await promisePool.execute(`
            INSERT INTO practice_exercises (
                topic_id,
                created_by,
                title,
                description,
                difficulty,
                content_type,
                points,
                content_json,
                is_active,
                is_public,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
        `, [
            practiceData.topic_id,
            userId,
            practiceData.title,
            practiceData.description || '',
            practiceData.difficulty || 'medium',
            practiceData.content_type || 'multiple_choice',
            practiceData.points || 10,
            JSON.stringify(practiceData.content_json),
            practiceData.is_active !== undefined ? practiceData.is_active : 1,
            0
        ]);
        
        const newPracticeId = result.insertId;
        
        const [newPractice] = await promisePool.execute(`
            SELECT 
                pe.*,
                mt.topic_title as topic_name
            FROM practice_exercises pe
            LEFT JOIN module_topics mt ON pe.topic_id = mt.topic_id
            WHERE pe.exercise_id = ?
        `, [newPracticeId]);
        
        res.status(201).json({
            success: true,
            message: 'Practice material created successfully',
            practice_id: newPracticeId,
            practice: newPractice[0]
        });
        
    } catch (error) {
        console.error('❌ Error creating practice material:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ UPDATE PRACTICE MATERIAL
// ============================================
app.put('/api/teacher/practice/:practiceId', authenticateTeacher, async (req, res) => {
    try {
        const { practiceId } = req.params;
        const userId = req.user.id;
        const updates = req.body;
        
        const [practice] = await promisePool.execute(
            'SELECT created_by FROM practice_exercises WHERE exercise_id = ?',
            [practiceId]
        );
        
        if (practice.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Practice material not found'
            });
        }
        
        if (practice[0].created_by !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only edit your own practice materials'
            });
        }
        
        const updateFields = [];
        const updateValues = [];
        
        const allowedFields = ['title', 'description', 'difficulty', 'content_type', 'points', 'content_json', 'is_active'];
        
        allowedFields.forEach(field => {
            if (updates[field] !== undefined) {
                if (field === 'content_json') {
                    updateFields.push(`${field} = ?`);
                    updateValues.push(JSON.stringify(updates[field]));
                } else {
                    updateFields.push(`${field} = ?`);
                    updateValues.push(updates[field]);
                }
            }
        });
        
        if (updateFields.length === 0) {
            return res.status(400).json({
                success: false,
                message: 'No fields to update'
            });
        }
        
        updateFields.push('updated_at = NOW()');
        updateValues.push(practiceId);
        
        await promisePool.execute(
            `UPDATE practice_exercises SET ${updateFields.join(', ')} WHERE exercise_id = ?`,
            updateValues
        );
        
        res.json({
            success: true,
            message: 'Practice material updated successfully'
        });
        
    } catch (error) {
        console.error('❌ Error updating practice material:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ DELETE PRACTICE MATERIAL
// ============================================
app.delete('/api/teacher/practice/:practiceId', authenticateTeacher, async (req, res) => {
    try {
        const { practiceId } = req.params;
        const userId = req.user.id;
        
        const [practice] = await promisePool.execute(
            'SELECT created_by, title FROM practice_exercises WHERE exercise_id = ?',
            [practiceId]
        );
        
        if (practice.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Practice material not found'
            });
        }
        
        if (practice[0].created_by !== userId) {
            return res.status(403).json({
                success: false,
                message: 'You can only delete your own practice materials'
            });
        }
        
        await promisePool.execute(
            'DELETE FROM user_practice_progress WHERE exercise_id = ?',
            [practiceId]
        );
        
        await promisePool.execute(
            'DELETE FROM practice_exercises WHERE exercise_id = ?',
            [practiceId]
        );
        
        res.json({
            success: true,
            message: `Practice material "${practice[0].title}" deleted successfully`
        });
        
    } catch (error) {
        console.error('❌ Error deleting practice material:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER PRACTICE STATS OVERVIEW
// ============================================
app.get('/api/teacher/practice/stats/overview', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [stats] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT pe.exercise_id) as total_practice,
                SUM(CASE WHEN pe.is_active = 1 THEN 1 ELSE 0 END) as active_practice,
                COUNT(DISTINCT upp.user_id) as total_students,
                COUNT(DISTINCT upp.progress_id) as total_attempts,
                SUM(CASE WHEN upp.completion_status = 'completed' THEN 1 ELSE 0 END) as total_completions,
                COALESCE(AVG(upp.score), 0) as avg_score,
                COALESCE(AVG(upp.time_spent_seconds), 0) as avg_time_seconds
            FROM practice_exercises pe
            LEFT JOIN user_practice_progress upp ON pe.exercise_id = upp.exercise_id
            WHERE pe.created_by = ?
        `, [userId]);
        
        const [byDifficulty] = await promisePool.execute(`
            SELECT 
                pe.difficulty,
                COUNT(*) as count,
                COALESCE(AVG(upp.score), 0) as avg_score
            FROM practice_exercises pe
            LEFT JOIN user_practice_progress upp ON pe.exercise_id = upp.exercise_id
            WHERE pe.created_by = ?
            GROUP BY pe.difficulty
        `, [userId]);
        
        res.json({
            success: true,
            stats: stats[0] || {
                total_practice: 0,
                active_practice: 0,
                total_students: 0,
                total_attempts: 0,
                total_completions: 0,
                avg_score: 0,
                avg_time_seconds: 0
            },
            by_difficulty: byDifficulty || []
        });
        
    } catch (error) {
        console.error('❌ Error fetching practice stats:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER QUIZZES
// ============================================
app.get('/api/teacher/quizzes', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                quizzes: [],
                message: 'Teacher record not found'
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [quizzes] = await promisePool.execute(`
            SELECT 
                q.quiz_id as id,
                q.quiz_title as title,
                q.description,
                q.difficulty,
                q.duration_minutes as time_limit,
                q.passing_score,
                q.total_questions as question_count,
                q.is_active as status,
                q.created_at,
                q.created_by,
                q.assigned_teacher_id,
                q.is_public,
                qc.category_name as subject,
                u.full_name as creator_name,
                u.role as creator_role,
                (
                    SELECT COUNT(*) 
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id
                ) as total_attempts,
                (
                    SELECT COUNT(DISTINCT uqa.user_id)
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id
                ) as unique_students,
                (
                    SELECT COALESCE(ROUND(AVG(score), 2), 0)
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id 
                    AND uqa.completion_status = 'completed'
                ) as avg_score,
                (
                    SELECT MAX(score)
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id 
                    AND uqa.completion_status = 'completed'
                ) as highest_score,
                (
                    SELECT MIN(score)
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id 
                    AND uqa.completion_status = 'completed'
                ) as lowest_score,
                (
                    SELECT COUNT(*) 
                    FROM user_quiz_attempts uqa 
                    WHERE uqa.quiz_id = q.quiz_id 
                    AND uqa.completion_status = 'completed'
                    AND uqa.passed = 1
                ) as passed_count
            FROM quizzes q
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            LEFT JOIN users u ON q.created_by = u.user_id
            WHERE 
                q.created_by = ?
                OR q.assigned_teacher_id = ?
                OR (q.is_public = 1 AND q.created_by IN (
                    SELECT user_id FROM users WHERE role = 'admin'
                ))
            ORDER BY 
                CASE 
                    WHEN q.created_by = ? THEN 1
                    WHEN q.assigned_teacher_id = ? THEN 2
                    ELSE 3
                END,
                q.created_at DESC
        `, [userId, userId, userId, userId]);
        
        const formattedQuizzes = quizzes.map(quiz => {
            let source = 'public';
            let sourceLabel = 'Public';
            let sourceColor = '#666';
            
            if (quiz.created_by === userId) {
                source = 'own';
                sourceLabel = 'My Quiz';
                sourceColor = '#4CAF50';
            } else if (quiz.assigned_teacher_id === userId) {
                source = 'assigned';
                sourceLabel = 'Assigned by Admin';
                sourceColor = '#7a0000';
            }
            
            const passRate = quiz.total_attempts > 0 
                ? Math.round((quiz.passed_count / quiz.total_attempts) * 100) 
                : 0;
            
            return {
                id: quiz.id,
                title: quiz.title,
                description: quiz.description,
                subject: quiz.subject || 'General',
                difficulty: quiz.difficulty || 'medium',
                time_limit: quiz.time_limit || 30,
                passing_score: quiz.passing_score || 70,
                question_count: quiz.question_count || 0,
                status: quiz.status === 1 ? 'active' : 'draft',
                created_at: quiz.created_at,
                stats: {
                    total_attempts: quiz.total_attempts || 0,
                    unique_students: quiz.unique_students || 0,
                    avg_score: Math.round(quiz.avg_score || 0),
                    highest_score: Math.round(quiz.highest_score || 0),
                    lowest_score: Math.round(quiz.lowest_score || 0),
                    pass_rate: passRate
                },
                source: {
                    type: source,
                    label: sourceLabel,
                    color: sourceColor,
                    creator: quiz.creator_name || (quiz.creator_role === 'admin' ? 'Admin' : 'Unknown')
                },
                is_editable: quiz.created_by === userId,
                is_deletable: quiz.created_by === userId
            };
        });
        
        res.json({
            success: true,
            quizzes: formattedQuizzes,
            total: formattedQuizzes.length,
            stats: {
                total_quizzes: formattedQuizzes.length,
                active_quizzes: formattedQuizzes.filter(q => q.status === 'active').length,
                draft_quizzes: formattedQuizzes.filter(q => q.status === 'draft').length,
                own_quizzes: formattedQuizzes.filter(q => q.source.type === 'own').length,
                assigned_quizzes: formattedQuizzes.filter(q => q.source.type === 'assigned').length,
                public_quizzes: formattedQuizzes.filter(q => q.source.type === 'public').length,
                total_attempts: formattedQuizzes.reduce((sum, q) => sum + (q.stats.total_attempts || 0), 0),
                avg_score_all: formattedQuizzes.length > 0 
                    ? Math.round(formattedQuizzes.reduce((sum, q) => sum + (q.stats.avg_score || 0), 0) / formattedQuizzes.length)
                    : 0
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching teacher quizzes:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET SINGLE QUIZ DETAILS
// ============================================
app.get('/api/teacher/quizzes/:quizId', authenticateTeacher, async (req, res) => {
    try {
        const { quizId } = req.params;
        const userId = req.user.id;
        
        const [accessCheck] = await promisePool.execute(`
            SELECT quiz_id FROM quizzes 
            WHERE quiz_id = ? 
            AND (created_by = ? OR assigned_teacher_id = ? OR is_public = 1)
        `, [quizId, userId, userId]);
        
        if (accessCheck.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'You do not have access to this quiz'
            });
        }
        
        const [quizzes] = await promisePool.execute(`
            SELECT 
                q.*,
                qc.category_name as subject,
                u.full_name as creator_name,
                u.role as creator_role,
                creator2.full_name as assigned_teacher_name
            FROM quizzes q
            LEFT JOIN quiz_categories qc ON q.category_id = qc.category_id
            LEFT JOIN users u ON q.created_by = u.user_id
            LEFT JOIN users creator2 ON q.assigned_teacher_id = creator2.user_id
            WHERE q.quiz_id = ?
        `, [quizId]);
        
        if (quizzes.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        const quiz = quizzes[0];
        
        const [questions] = await promisePool.execute(`
            SELECT 
                qq.question_id,
                qq.question_text,
                qq.question_type,
                qq.points,
                qq.question_order,
                qq.explanation,
                (
                    SELECT JSON_ARRAYAGG(
                        JSON_OBJECT(
                            'option_id', qo.option_id,
                            'option_text', qo.option_text,
                            'is_correct', qo.is_correct,
                            'option_order', qo.option_order
                        )
                    )
                    FROM quiz_options qo
                    WHERE qo.question_id = qq.question_id
                    ORDER BY qo.option_order
                ) as options
            FROM quiz_questions qq
            WHERE qq.quiz_id = ?
            ORDER BY qq.question_order
        `, [quizId]);
        
        const formattedQuestions = questions.map(q => {
            let options = [];
            try {
                options = q.options ? JSON.parse(q.options) : [];
            } catch (e) {
                console.log(`Error parsing options for question ${q.question_id}:`, e);
                options = [];
            }
            return {
                ...q,
                options: options
            };
        });
        
        const [recentAttempts] = await promisePool.execute(`
            SELECT 
                uqa.attempt_id,
                uqa.user_id,
                u.full_name as student_name,
                uqa.score,
                uqa.passed,
                uqa.time_spent_seconds,
                uqa.end_time as completed_at,
                uqa.attempt_number
            FROM user_quiz_attempts uqa
            JOIN users u ON uqa.user_id = u.user_id
            WHERE uqa.quiz_id = ? AND uqa.completion_status = 'completed'
            ORDER BY uqa.end_time DESC
            LIMIT 10
        `, [quizId]);
        
        const [totalAttempts] = await promisePool.execute(`
            SELECT COUNT(*) as count
            FROM user_quiz_attempts
            WHERE quiz_id = ? AND completion_status = 'completed'
        `, [quizId]);
        
        res.json({
            success: true,
            quiz: {
                id: quiz.quiz_id,
                title: quiz.quiz_title,
                description: quiz.description,
                subject: quiz.subject || 'General',
                difficulty: quiz.difficulty,
                time_limit: quiz.duration_minutes,
                passing_score: quiz.passing_score,
                question_count: quiz.total_questions,
                status: quiz.is_active === 1 ? 'active' : 'draft',
                created_at: quiz.created_at,
                created_by: quiz.created_by,
                assigned_to: quiz.assigned_teacher_id,
                is_public: quiz.is_public === 1,
                creator: {
                    name: quiz.creator_name,
                    role: quiz.creator_role
                },
                assigned_teacher: quiz.assigned_teacher_name,
                questions: formattedQuestions,
                recent_attempts: recentAttempts.map(a => ({
                    ...a,
                    time_spent_minutes: Math.round(a.time_spent_seconds / 60),
                    score_percent: Math.round(a.score)
                })),
                stats: {
                    total_attempts: totalAttempts[0].count || 0,
                    recent_count: recentAttempts.length
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz details:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET QUIZ STATISTICS
// ============================================
app.get('/api/teacher/quizzes/:quizId/stats', authenticateTeacher, async (req, res) => {
    try {
        const { quizId } = req.params;
        const userId = req.user.id;
        
        const [quiz] = await promisePool.execute(`
            SELECT quiz_id FROM quizzes 
            WHERE quiz_id = ? AND (created_by = ? OR assigned_teacher_id = ?)
        `, [quizId, userId, userId]);
        
        if (quiz.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Access denied'
            });
        }
        
        const [overall] = await promisePool.execute(`
            SELECT 
                COUNT(*) as total_attempts,
                COUNT(DISTINCT user_id) as unique_students,
                COALESCE(AVG(score), 0) as avg_score,
                MAX(score) as highest_score,
                MIN(score) as lowest_score,
                SUM(CASE WHEN passed = 1 THEN 1 ELSE 0 END) as passed_count,
                COALESCE(AVG(time_spent_seconds), 0) as avg_time_seconds
            FROM user_quiz_attempts
            WHERE quiz_id = ? AND completion_status = 'completed'
        `, [quizId]);
        
        const [distribution] = await promisePool.execute(`
            SELECT 
                SUM(CASE WHEN score >= 90 THEN 1 ELSE 0 END) as range_90_100,
                SUM(CASE WHEN score >= 80 AND score < 90 THEN 1 ELSE 0 END) as range_80_89,
                SUM(CASE WHEN score >= 70 AND score < 80 THEN 1 ELSE 0 END) as range_70_79,
                SUM(CASE WHEN score >= 60 AND score < 70 THEN 1 ELSE 0 END) as range_60_69,
                SUM(CASE WHEN score < 60 THEN 1 ELSE 0 END) as range_below_60
            FROM user_quiz_attempts
            WHERE quiz_id = ? AND completion_status = 'completed'
        `, [quizId]);
        
        const [daily] = await promisePool.execute(`
            SELECT 
                DATE(end_time) as date,
                COUNT(*) as attempts,
                COALESCE(AVG(score), 0) as avg_score
            FROM user_quiz_attempts
            WHERE quiz_id = ? 
                AND completion_status = 'completed'
                AND end_time >= DATE_SUB(NOW(), INTERVAL 30 DAY)
            GROUP BY DATE(end_time)
            ORDER BY date
        `, [quizId]);
        
        res.json({
            success: true,
            stats: {
                overall: {
                    total_attempts: overall[0].total_attempts || 0,
                    unique_students: overall[0].unique_students || 0,
                    avg_score: Math.round(overall[0].avg_score || 0),
                    highest_score: Math.round(overall[0].highest_score || 0),
                    lowest_score: Math.round(overall[0].lowest_score || 0),
                    pass_rate: overall[0].total_attempts > 0 
                        ? Math.round((overall[0].passed_count / overall[0].total_attempts) * 100)
                        : 0,
                    avg_time_minutes: Math.round(overall[0].avg_time_seconds / 60)
                },
                distribution: {
                    '90-100%': parseInt(distribution[0].range_90_100) || 0,
                    '80-89%': parseInt(distribution[0].range_80_89) || 0,
                    '70-79%': parseInt(distribution[0].range_70_79) || 0,
                    '60-69%': parseInt(distribution[0].range_60_69) || 0,
                    'Below 60%': parseInt(distribution[0].range_below_60) || 0
                },
                daily: daily.map(d => ({
                    date: d.date,
                    attempts: d.attempts,
                    avg_score: Math.round(d.avg_score)
                }))
            }
        });
        
    } catch (error) {
        console.error('❌ Error fetching quiz stats:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER PERFORMANCE STATS
// ============================================
app.get('/api/teacher/performance/stats', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                stats: {
                    avg_score: 0,
                    completion_rate: 0,
                    avg_time_minutes: 0,
                    active_students: 0
                }
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [avgScore] = await promisePool.execute(`
            SELECT COALESCE(AVG(ucp.score), 0) as avg_score
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
            AND ucp.completion_status = 'completed'
        `, [userId, userId]);
        
        const [completion] = await promisePool.execute(`
            SELECT 
                COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN ucp.user_id END) as completed_students,
                COUNT(DISTINCT ucp.user_id) as total_students
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
        `, [userId, userId]);
        
        const completionRate = completion[0].total_students > 0 
            ? Math.round((completion[0].completed_students / completion[0].total_students) * 100)
            : 0;
        
        const [avgTime] = await promisePool.execute(`
            SELECT COALESCE(AVG(time_spent_seconds), 0) / 60 as avg_time_minutes
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
            AND time_spent_seconds > 0
        `, [userId, userId]);
        
        const [active] = await promisePool.execute(`
            SELECT COUNT(DISTINCT ucp.user_id) as active_students
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
            AND ucp.last_accessed >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        `, [userId, userId]);
        
        res.json({
            success: true,
            stats: {
                avg_score: Math.round(avgScore[0].avg_score),
                completion_rate: completionRate,
                avg_time_minutes: Math.round(avgTime[0].avg_time_minutes),
                active_students: active[0].active_students || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Teacher performance stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER TOP PERFORMERS
// ============================================
app.get('/api/teacher/performance/top-performers', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const subject = req.query.subject || 'all';
        
        let query = `
            SELECT 
                u.user_id as id,
                u.full_name as name,
                u.email,
                COALESCE(AVG(ucp.score), 0) as score,
                COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN ucp.content_id END) as lessons_completed,
                (
                    SELECT COUNT(*) 
                    FROM user_quiz_attempts uqa
                    JOIN quizzes q ON uqa.quiz_id = q.quiz_id
                    WHERE uqa.user_id = u.user_id 
                    AND q.created_by = ?
                    AND uqa.passed = 1
                ) as quizzes_passed,
                l.lesson_name as subject
            FROM users u
            JOIN user_content_progress ucp ON u.user_id = ucp.user_id
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            JOIN module_topics mt ON tci.topic_id = mt.topic_id
            JOIN course_modules cm ON mt.module_id = cm.module_id
            JOIN lessons l ON cm.lesson_id = l.lesson_id
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
            AND u.role = 'student'
        `;
        
        const params = [userId, userId, userId];
        
        if (subject !== 'all') {
            query += ` AND l.lesson_name = ?`;
            params.push(subject);
        }
        
        query += ` GROUP BY u.user_id HAVING lessons_completed > 0 ORDER BY score DESC LIMIT 10`;
        
        const [performers] = await promisePool.execute(query, params);
        
        const performersWithProgress = performers.map(p => ({
            ...p,
            progress: Math.min(100, Math.round((p.lessons_completed / 10) * 100))
        }));
        
        res.json({
            success: true,
            performers: performersWithProgress
        });
        
    } catch (error) {
        console.error('❌ Teacher top performers error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            performers: []
        });
    }
});

// ============================================
// ✅ GET TEACHER PERFORMANCE TREND
// ============================================
app.get('/api/teacher/performance/trend', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const timeRange = req.query.range || 'month';
        
        let weeks = 4;
        let interval = 'WEEK';
        
        switch(timeRange) {
            case 'week':
                weeks = 7;
                interval = 'DAY';
                break;
            case 'month':
                weeks = 4;
                interval = 'WEEK';
                break;
            case 'quarter':
                weeks = 12;
                interval = 'WEEK';
                break;
            default:
                weeks = 4;
                interval = 'WEEK';
        }
        
        const labels = [];
        const avgScores = [];
        const completionRates = [];
        
        for (let i = weeks - 1; i >= 0; i--) {
            let startDate, endDate;
            let label;
            
            const now = new Date();
            
            if (timeRange === 'week') {
                const date = new Date();
                date.setDate(date.getDate() - i);
                startDate = new Date(date);
                startDate.setHours(0, 0, 0, 0);
                endDate = new Date(date);
                endDate.setHours(23, 59, 59, 999);
                label = date.toLocaleDateString('en-US', { weekday: 'short' });
            } else {
                startDate = new Date();
                startDate.setDate(startDate.getDate() - (i * 7) - 7);
                endDate = new Date();
                endDate.setDate(endDate.getDate() - (i * 7));
                label = `Week ${weeks - i}`;
            }
            
            labels.push(label);
            
            const [avgScoreResult] = await promisePool.execute(`
                SELECT COALESCE(AVG(ucp.score), 0) as avg_score
                FROM user_content_progress ucp
                JOIN topic_content_items tci ON ucp.content_id = tci.content_id
                WHERE (tci.teacher_id = ? OR tci.created_by = ?)
                AND ucp.completion_status = 'completed'
                AND ucp.completed_at BETWEEN ? AND ?
            `, [userId, userId, startDate, endDate]);
            
            avgScores.push(Math.round(avgScoreResult[0].avg_score));
            
            const [totalStudents] = await promisePool.execute(`
                SELECT COUNT(DISTINCT ucp.user_id) as student_count
                FROM user_content_progress ucp
                JOIN topic_content_items tci ON ucp.content_id = tci.content_id
                WHERE (tci.teacher_id = ? OR tci.created_by = ?)
                AND ucp.completion_status = 'completed'
                AND ucp.completed_at BETWEEN ? AND ?
            `, [userId, userId, startDate, endDate]);
            
            completionRates.push(Math.min(100, avgScoreResult[0].avg_score));
        }
        
        res.json({
            success: true,
            trend: {
                labels: labels,
                avg_scores: avgScores,
                completion_rates: completionRates
            }
        });
        
    } catch (error) {
        console.error('❌ Teacher performance trend error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET TEACHER SCORE DISTRIBUTION
// ============================================
app.get('/api/teacher/performance/score-distribution', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const filter = req.query.filter || 'all';
        
        let joinClause = '';
        let whereClause = "WHERE ucp.completion_status = 'completed'";
        
        if (filter !== 'all') {
            joinClause = `
                JOIN topic_content_items tci ON ucp.content_id = tci.content_id
                JOIN module_topics mt ON tci.topic_id = mt.topic_id
                JOIN course_modules cm ON mt.module_id = cm.module_id
                JOIN lessons l ON cm.lesson_id = l.lesson_id
            `;
            whereClause += ` AND l.lesson_name = ?`;
        }
        
        const query = `
            SELECT 
                SUM(CASE WHEN ucp.score >= 90 THEN 1 ELSE 0 END) as range_90_100,
                SUM(CASE WHEN ucp.score >= 80 AND ucp.score < 90 THEN 1 ELSE 0 END) as range_80_89,
                SUM(CASE WHEN ucp.score >= 70 AND ucp.score < 80 THEN 1 ELSE 0 END) as range_70_79,
                SUM(CASE WHEN ucp.score >= 60 AND ucp.score < 70 THEN 1 ELSE 0 END) as range_60_69,
                SUM(CASE WHEN ucp.score < 60 THEN 1 ELSE 0 END) as range_below_60,
                COUNT(*) as total
            FROM user_content_progress ucp
            JOIN topic_content_items tci ON ucp.content_id = tci.content_id
            ${joinClause}
            WHERE (tci.teacher_id = ? OR tci.created_by = ?)
            AND ucp.completion_status = 'completed'
        `;
        
        const params = [userId, userId];
        if (filter !== 'all') {
            params.push(filter);
        }
        
        const [result] = await promisePool.execute(query, params);
        
        const distribution = {
            '90-100%': parseInt(result[0].range_90_100) || 0,
            '80-89%': parseInt(result[0].range_80_89) || 0,
            '70-79%': parseInt(result[0].range_70_79) || 0,
            '60-69%': parseInt(result[0].range_60_69) || 0,
            'Below 60%': parseInt(result[0].range_below_60) || 0,
            total: parseInt(result[0].total) || 0
        };
        
        res.json({
            success: true,
            distribution: distribution
        });
        
    } catch (error) {
        console.error('❌ Teacher score distribution error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ============================================
// ✅ GET TEACHER'S PENDING REVIEWS
// ============================================
app.get('/api/teacher/pending-reviews', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                pending_reviews: [],
                total: 0
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [feedback] = await promisePool.execute(`
            SELECT 
                f.feedback_id as id,
                f.feedback_type as type,
                f.feedback_message as message,
                f.rating,
                f.status,
                f.created_at as date,
                u.full_name as student_name,
                u.user_id,
                tci.content_title as lesson_title
            FROM feedback f
            LEFT JOIN users u ON f.user_id = u.user_id
            LEFT JOIN topic_content_items tci ON f.related_id = tci.content_id
            WHERE f.teacher_id = ? AND f.status = 'new'
            ORDER BY f.created_at DESC
            LIMIT 20
        `, [teacherId]);
        
        const formatted = feedback.map(f => ({
            ...f,
            time_ago: getTimeAgo(f.date),
            student_avatar: getInitialsFromName(f.student_name || 'Anonymous'),
            type_icon: getTypeIcon(f.type),
            type_color: getTypeColor(f.type)
        }));
        
        res.json({
            success: true,
            pending_reviews: formatted,
            total: formatted.length
        });
        
    } catch (error) {
        console.error('❌ Error fetching pending reviews:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET PENDING REVIEWS COUNT
// ============================================
app.get('/api/teacher/pending-reviews-count', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.json({
                success: true,
                pending_count: 0
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        const [result] = await promisePool.execute(`
            SELECT COUNT(*) as count
            FROM feedback
            WHERE teacher_id = ? AND status = 'new'
        `, [teacherId]);
        
        res.json({
            success: true,
            pending_count: result[0].count || 0
        });
        
    } catch (error) {
        console.error('❌ Error fetching pending count:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER TOPICS
// ============================================
// ===== SIMPLIFIED GET TEACHER TOPICS =====
app.get('/api/teacher/topics', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Simple query - get all topics
        const [topics] = await promisePool.execute(`
            SELECT 
                mt.topic_id as id,
                mt.topic_title as name,
                mt.topic_description as description,
                mt.module_id,
                cm.module_name,
                cm.lesson_id,
                l.lesson_name
            FROM module_topics mt
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            ORDER BY l.lesson_name, cm.module_order, mt.topic_order
        `);
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});

// ===== SIMPLIFIED GET TEACHER MODULES =====
app.get('/api/teacher/modules', authenticateTeacher, async (req, res) => {
    try {
        const [modules] = await promisePool.execute(`
            SELECT 
                cm.module_id as id,
                cm.module_name as name,
                cm.module_description as description,
                cm.lesson_id,
                l.lesson_name
            FROM course_modules cm
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            ORDER BY l.lesson_name, cm.module_order
        `);
        
        res.json({
            success: true,
            modules: modules
        });
        
    } catch (error) {
        console.error('❌ Error:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message 
        });
    }
});
app.get('/api/teacher/topics', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        
        // Test database connection first
        const [test] = await promisePool.execute('SELECT 1');
        console.log('✅ Database connected');
        
        // Test if tables exist
        const [tables] = await promisePool.execute(`
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = DATABASE()
        `);
        console.log('📊 Tables:', tables.map(t => t.TABLE_NAME));
        
        // Try to get topics
        const [topics] = await promisePool.execute(`
            SELECT * FROM module_topics LIMIT 5
        `);
        
        res.json({
            success: true,
            topics: topics,
            debug: {
                tables: tables.map(t => t.TABLE_NAME)
            }
        });
        
    } catch (error) {
        console.error('❌ DETAILED ERROR:', error);
        res.status(500).json({ 
            success: false, 
            message: error.message,
            sqlMessage: error.sqlMessage,
            sqlState: error.sqlState,
            code: error.code
        });
    }
});
// ============================================
// ✅ GET MODULES BY LESSON ID
// ============================================
app.get('/api/admin/modules', authenticateTeacher, async (req, res) => {
    try {
        const { lesson_id } = req.query;
        
        let query = `
            SELECT 
                module_id as id,
                module_name as name,
                module_description as description,
                lesson_id
            FROM course_modules
            WHERE is_active = TRUE
        `;
        
        const params = [];
        
        if (lesson_id) {
            query += ` AND lesson_id = ?`;
            params.push(lesson_id);
        }
        
        query += ` ORDER BY module_order`;
        
        const [modules] = await promisePool.execute(query, params);
        
        res.json({
            success: true,
            modules: modules
        });
        
    } catch (error) {
        console.error('❌ Error fetching modules:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TOPICS BY MODULE ID
// ============================================
app.get('/api/admin/topics', authenticateTeacher, async (req, res) => {
    try {
        const { module_id } = req.query;
        
        let query = `
            SELECT 
                topic_id as id,
                topic_title as name,
                topic_description as description,
                module_id
            FROM module_topics
            WHERE is_active = TRUE
        `;
        
        const params = [];
        
        if (module_id) {
            query += ` AND module_id = ?`;
            params.push(module_id);
        }
        
        query += ` ORDER BY topic_order`;
        
        const [topics] = await promisePool.execute(query, params);
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('❌ Error fetching topics:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ GET TEACHER BY ID
// ============================================
app.get('/api/teachers/:teacherId', authenticateUser, async (req, res) => {
    try {
        const { teacherId } = req.params;
        
        const [teachers] = await promisePool.execute(`
            SELECT 
                t.teacher_id,
                t.user_id,
                t.department,
                t.qualification,
                t.years_experience,
                t.bio,
                t.rating,
                t.total_students,
                t.total_lessons,
                t.specialization,
                t.available_hours,
                t.created_at,
                t.updated_at,
                u.username,
                u.email,
                u.full_name,
                u.role
            FROM teachers t
            JOIN users u ON t.user_id = u.user_id
            WHERE t.user_id = ?
        `, [teacherId]);
        
        if (teachers.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Teacher not found'
            });
        }
        
        res.json({
            success: true,
            teacher: teachers[0]
        });
        
    } catch (error) {
        console.error('❌ Error fetching teacher:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// ============================================
// ✅ CREATE TEACHER QUIZ
// ============================================
app.post('/api/teacher/quizzes/create', authenticateTeacher, async (req, res) => {
    const connection = await promisePool.getConnection();
    
    try {
        const { 
            category_id, 
            title, 
            description, 
            difficulty = 'medium',
            time_limit = 30,
            passing_score = 70,
            status = 'draft',
            questions = [],
            topic_id = null
        } = req.body;

        const userId = req.user.id;
        
        if (!title) {
            connection.release();
            return res.status(400).json({
                success: false,
                message: 'Quiz title is required'
            });
        }
        
        if (!category_id) {
            connection.release();
            return res.status(400).json({
                success: false,
                message: 'Category ID is required'
            });
        }

        if (!questions || questions.length === 0) {
            connection.release();
            return res.status(400).json({
                success: false,
                message: 'At least one question is required'
            });
        }

        await connection.beginTransaction();

        const [quizResult] = await connection.query(`
            INSERT INTO quizzes 
            (category_id, topic_id, quiz_title, description, difficulty, duration_minutes, 
             passing_score, total_questions, is_active, created_at, created_by, is_public)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?, ?)
        `, [
            category_id,
            topic_id,
            title,
            description || null,
            difficulty,
            time_limit,
            passing_score,
            questions.length,
            status === 'active' ? 1 : 0,
            userId,
            0
        ]);

        const newQuizId = quizResult.insertId;

        for (let i = 0; i < questions.length; i++) {
            const q = questions[i];
            
            const [questionResult] = await connection.query(`
                INSERT INTO quiz_questions 
                (quiz_id, question_text, question_type, points, question_order)
                VALUES (?, ?, ?, ?, ?)
            `, [
                newQuizId,
                q.question_text,
                q.question_type || 'multiple_choice',
                q.points || 10,
                i + 1
            ]);

            const newQuestionId = questionResult.insertId;

            if (q.options && q.options.length > 0) {
                for (let j = 0; j < q.options.length; j++) {
                    const opt = q.options[j];
                    await connection.query(`
                        INSERT INTO quiz_options 
                        (question_id, option_text, is_correct, option_order)
                        VALUES (?, ?, ?, ?)
                    `, [
                        newQuestionId,
                        opt.option_text,
                        opt.is_correct ? 1 : 0,
                        j + 1
                    ]);
                }
            }
        }

        await connection.commit();
        connection.release();

        res.status(201).json({
            success: true,
            message: 'Quiz created successfully',
            quiz_id: newQuizId
        });

    } catch (error) {
        await connection.rollback();
        connection.release();
        console.error('❌ Error in quiz operation:', error);
        
        res.status(500).json({ 
            success: false, 
            message: 'Failed to save quiz: ' + error.message 
        });
    }
});

// ============================================
// ✅ HELPER FUNCTIONS
// ============================================
function getInitialsFromName(name) {
    if (!name) return 'U';
    return name
        .split(' ')
        .map(word => word.charAt(0))
        .join('')
        .toUpperCase()
        .substring(0, 2);
}

function getTimeAgo(dateString) {
    if (!dateString) return 'Recently';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min ago`;
    if (diffHours < 24) return `${diffHours} hour ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return date.toLocaleDateString();
}

function getStatusBadge(status) {
    const badges = {
        'new': '<span class="badge badge-warning">New</span>',
        'reviewed': '<span class="badge badge-info">Reviewed</span>',
        'resolved': '<span class="badge badge-success">Resolved</span>',
        'closed': '<span class="badge badge-secondary">Closed</span>'
    };
    return badges[status] || '<span class="badge">Unknown</span>';
}

function getTypeIcon(type) {
    const icons = {
        'suggestion': 'fa-lightbulb',
        'bug': 'fa-bug',
        'praise': 'fa-heart',
        'question': 'fa-question-circle',
        'complaint': 'fa-exclamation-triangle',
        'rating': 'fa-star',
        'other': 'fa-comment'
    };
    return icons[type] || 'fa-comment';
}

function getTypeColor(type) {
    const colors = {
        'suggestion': '#FFC107',
        'bug': '#f44336',
        'praise': '#4CAF50',
        'question': '#2196F3',
        'complaint': '#FF9800',
        'rating': '#9C27B0',
        'other': '#9E9E9E'
    };
    return colors[type] || '#9E9E9E';
}

// ============================================
// ✅ END OF TEACHER ROUTES
// ============================================







// ============================================
// ERROR HANDLING
// ============================================

app.use((req, res) => {
    res.status(404).json({
        success: false,
        message: 'Route not found'
    });
});

app.use((err, req, res, next) => {
    console.error('❌ Server error:', err.stack);
    res.status(500).json({
        success: false,
        message: 'Internal server error',
        error: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// ============================================
// START SERVER
// ============================================

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log('🚀 ===========================================');
    console.log('🚀 PolyLearn Backend Server Started!');
    console.log('🚀 ===========================================');
    console.log(`🌐 URL: http://localhost:${PORT}`);
    console.log(`📊 Mode: NEW SERVER + ADMIN ROUTES`);
    console.log(`✅ Admin Routes: IMPORTED FROM OLD SERVER`);
    console.log(`✅ Progress Tracking: FULLY INTEGRATED`);
    console.log(`✅ Video Upload: WORKING`);
    console.log('=============================================');
    console.log(`🔐 Auth: http://localhost:${PORT}/api/auth/login`);
    console.log(`📚 Admin Lessons: http://localhost:${PORT}/api/admin/lessons`);
    console.log(`📁 Admin Structure: http://localhost:${PORT}/api/admin/structure`);
    console.log(`📦 Admin Modules: http://localhost:${PORT}/api/admin/modules`);
    console.log(`📝 Admin Topics: http://localhost:${PORT}/api/admin/topics`);
    console.log(`👥 Admin Users: http://localhost:${PORT}/api/admin/users`);
    console.log(`💬 Admin Feedback: http://localhost:${PORT}/api/admin/feedback`);
    console.log(`🎬 Student Lessons: http://localhost:${PORT}/api/lessons-db/complete`);
    console.log(`📊 Progress: http://localhost:${PORT}/api/progress/summary`);
    console.log(`🧪 Health: http://localhost:${PORT}/api/health`);
    console.log('=============================================');
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
    console.error('❌ Unhandled Promise Rejection:', err);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err);
});

// ===== TEACHER MODULES & TOPICS ROUTES =====

// GET /api/teacher/modules?lesson_id=xxx - Get modules for specific lesson
// ===== GET TEACHER MODULES =====
// GET modules for teacher (with optional lesson filter)
app.get('/api/teacher/modules', authenticateTeacher, async (req, res) => {
    try {
        const userId = req.user.id;
        const { lesson_id } = req.query;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        const teacherId = teacher.length > 0 ? teacher[0].teacher_id : null;
        
        let query = `
            SELECT DISTINCT 
                cm.module_id as id,
                cm.module_name as name,
                cm.module_description as description,
                cm.lesson_id,
                l.lesson_name,
                cm.created_by,
                creator.full_name as creator_name,
                creator.role as creator_role
            FROM course_modules cm
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users creator ON cm.created_by = creator.user_id
            WHERE 1=1
        `;
        
        const params = [];
        
        if (lesson_id) {
            query += ` AND cm.lesson_id = ?`;
            params.push(lesson_id);
        }
        
        // Filter by teacher access
        query += ` AND (
            cm.created_by = ? 
            OR cm.module_id IN (
                SELECT DISTINCT mt.module_id 
                FROM module_topics mt
                JOIN topic_content_items tci ON mt.topic_id = tci.topic_id
                WHERE tci.teacher_id = ? OR tci.created_by = ?
            )
        )`;
        
        params.push(userId, teacherId, userId);
        
        query += ` ORDER BY l.lesson_name, cm.module_order`;
        
        const [modules] = await promisePool.execute(query, params);
        
        res.json({
            success: true,
            modules: modules
        });
        
    } catch (error) {
        console.error('❌ Error fetching modules:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});


// GET /api/teacher/topics - Get all topics for teacher's modules
// GET /api/teacher/topics?module_id=xxx - Get topics for specific module
app.get('/api/teacher/topics', authenticateToken, async (req, res) => {
    try {
        const { module_id } = req.query;
        const teacherId = req.user.id;
        
        let query = `
            SELECT t.*, m.name as module_name 
            FROM topics t
            JOIN modules m ON t.module_id = m.id
            JOIN lessons l ON m.lesson_id = l.id
            WHERE (l.created_by = ? OR t.created_by = 'admin')
        `;
        let params = [teacherId];
        
        if (module_id) {
            query += ' AND t.module_id = ?';
            params.push(module_id);
        }
        
        query += ' ORDER BY t.topic_order';
        
        const [topics] = await db.query(query, params);
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('Error fetching topics:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch topics'
        });
    }
});
// POST /api/teacher/modules/create - Create new module
app.post('/api/teacher/modules/create', authenticateTeacher, async (req, res) => {
    try {
        const { name, description, lesson_id, lesson_name } = req.body;
        const userId = req.user.id;
        
        if (!name || !lesson_id) {
            return res.status(400).json({
                success: false,
                message: 'Module name and lesson ID are required'
            });
        }
        
        // Get teacher_id
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        if (teacher.length === 0) {
            return res.status(403).json({
                success: false,
                message: 'Teacher not found'
            });
        }
        
        const teacherId = teacher[0].teacher_id;
        
        // Get max module order
        const [maxOrder] = await promisePool.execute(`
            SELECT COALESCE(MAX(module_order), 0) + 1 as next_order
            FROM course_modules
            WHERE lesson_id = ?
        `, [lesson_id]);
        
        const moduleOrder = maxOrder[0].next_order;
        
        // Insert new module
        const [result] = await promisePool.execute(`
            INSERT INTO course_modules (
                module_name, 
                module_description, 
                lesson_id, 
                module_order,
                created_by
            ) VALUES (?, ?, ?, ?, ?)
        `, [name, description || null, lesson_id, moduleOrder, userId]);
        
        const newModule = {
            id: result.insertId,
            name: name,
            description: description,
            lesson_id: lesson_id,
            lesson_name: lesson_name,
            module_order: moduleOrder,
            created_by: userId,
            creator_name: req.user.full_name,
            creator_role: 'teacher'
        };
        
        res.json({
            success: true,
            message: 'Module created successfully',
            module: newModule,
            module_id: result.insertId
        });
        
    } catch (error) {
        console.error('❌ Error creating module:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// POST /api/teacher/topics/create - Create new topic
// CREATE new topic
app.post('/api/teacher/topics/create', authenticateTeacher, async (req, res) => {
    try {
        const { name, description, module_id, module_name } = req.body;
        const userId = req.user.id;
        
        if (!name || !module_id) {
            return res.status(400).json({
                success: false,
                message: 'Topic name and module ID are required'
            });
        }
        
        // Get next topic order
        const [orderResult] = await promisePool.execute(`
            SELECT COALESCE(MAX(topic_order), 0) + 1 as next_order
            FROM module_topics
            WHERE module_id = ?
        `, [module_id]);
        
        const topicOrder = orderResult[0].next_order;
        
        // Insert new topic
        const [result] = await promisePool.execute(`
            INSERT INTO module_topics (
                topic_title,
                topic_description,
                module_id,
                topic_order,
                created_by
            ) VALUES (?, ?, ?, ?, ?)
        `, [name, description || null, module_id, topicOrder, userId]);
        
        const newTopic = {
            id: result.insertId,
            name: name,
            description: description,
            module_id: module_id,
            module_name: module_name,
            topic_order: topicOrder,
            created_by: userId,
            creator_name: req.user.full_name,
            creator_role: 'teacher',
            content_count: 0
        };
        
        res.json({
            success: true,
            message: 'Topic created successfully',
            topic: newTopic,
            topic_id: result.insertId
        });
        
    } catch (error) {
        console.error('❌ Error creating topic:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ===== GET MODULES BY LESSON =====
app.get('/api/teacher/modules/by-lesson/:lessonId', authenticateTeacher, async (req, res) => {
    try {
        const { lessonId } = req.params;
        const userId = req.user.id;
        
        const [teacher] = await promisePool.execute(`
            SELECT teacher_id FROM teachers WHERE user_id = ?
        `, [userId]);
        
        const teacherId = teacher.length > 0 ? teacher[0].teacher_id : null;
        
        const [modules] = await promisePool.execute(`
            SELECT 
                cm.module_id as id,
                cm.module_name as name,
                cm.module_description as description,
                cm.lesson_id,
                cm.module_order,
                cm.created_by,
                l.lesson_name,
                creator.full_name as creator_name,
                creator.role as creator_role,
                CASE 
                    WHEN cm.created_by = ? THEN 'teacher'
                    WHEN cm.created_by IN (SELECT user_id FROM users WHERE role = 'admin') THEN 'admin'
                    ELSE 'system'
                END as source
            FROM course_modules cm
            LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
            LEFT JOIN users creator ON cm.created_by = creator.user_id
            WHERE cm.lesson_id = ?
            ORDER BY cm.module_order
        `, [userId, lessonId]);
        
        res.json({
            success: true,
            modules: modules
        });
        
    } catch (error) {
        console.error('❌ Error fetching modules by lesson:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ===== GET TOPICS BY MODULE =====
app.get('/api/teacher/topics/by-module/:moduleId', authenticateTeacher, async (req, res) => {
    try {
        const { moduleId } = req.params;
        const userId = req.user.id;
        
        const [topics] = await promisePool.execute(`
            SELECT 
                mt.topic_id as id,
                mt.topic_title as name,
                mt.topic_description as description,
                mt.module_id,
                mt.topic_order,
                mt.created_by,
                cm.module_name,
                creator.full_name as creator_name,
                creator.role as creator_role,
                (
                    SELECT COUNT(*) 
                    FROM topic_content_items tci 
                    WHERE tci.topic_id = mt.topic_id
                ) as content_count
            FROM module_topics mt
            LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
            LEFT JOIN users creator ON mt.created_by = creator.user_id
            WHERE mt.module_id = ?
            ORDER BY mt.topic_order
        `, [moduleId]);
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('❌ Error fetching topics by module:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});
// ============================================
// ADD THESE HELPER FUNCTIONS AT THE END
// ============================================

function formatActivityDescription(activity, details) {
    const type = activity.activity_type;
    const userName = activity.user_name || activity.username || 'A user';
    
    switch(type) {
        case 'login':
            return `${userName} logged in`;
        case 'logout':
            return `${userName} logged out`;
        case 'lesson_completed':
            return `${userName} completed a lesson${details.lesson_title ? ': ' + details.lesson_title : ''}`;
        case 'practice_completed':
            return `${userName} completed a practice exercise${details.exercise_title ? ': ' + details.exercise_title : ''}`;
        case 'quiz_completed':
            const score = details.score ? ` with ${details.score}%` : '';
            return `${userName} completed a quiz${score}`;
        case 'quiz_started':
            return `${userName} started a quiz${details.quiz_title ? ': ' + details.quiz_title : ''}`;
        case 'feedback_submitted':
            return `${userName} submitted feedback`;
        case 'points_earned':
            return `${userName} earned ${activity.points_earned || 0} points`;
        case 'tool_used':
            return `${userName} used ${details.tool || 'a tool'}`;
        case 'graph_saved':
            return `${userName} saved a graph`;
        case 'note_saved':
            return `${userName} saved a note`;
        case 'timer_session':
            return `${userName} completed a timer session`;
        default:
            return `${userName} performed ${type.replace(/_/g, ' ')}`;
    }
}

function getActivityIcon(activityType) {
    const icons = {
        'login': 'fa-sign-in-alt',
        'logout': 'fa-sign-out-alt',
        'lesson_completed': 'fa-check-circle',
        'lesson_started': 'fa-play',
        'practice_completed': 'fa-dumbbell',
        'quiz_completed': 'fa-question-circle',
        'quiz_started': 'fa-hourglass-start',
        'feedback_submitted': 'fa-comment',
        'points_earned': 'fa-coins',
        'tool_used': 'fa-tools',
        'graph_saved': 'fa-chart-line',
        'note_saved': 'fa-sticky-note',
        'timer_session': 'fa-clock'
    };
    
    return icons[activityType] || 'fa-circle';
}

function getActivityColor(activityType) {
    const colors = {
        'login': '#4CAF50',
        'logout': '#f44336',
        'lesson_completed': '#2196F3',
        'practice_completed': '#9C27B0',
        'quiz_completed': '#FF9800',
        'quiz_started': '#FFC107',
        'feedback_submitted': '#E91E63',
        'points_earned': '#FFD700',
        'tool_used': '#607D8B',
        'graph_saved': '#3F51B5',
        'note_saved': '#009688',
        'timer_session': '#795548'
    };
    
    return colors[activityType] || '#9E9E9E';
}

function getTimeAgo(timestamp) {
    if (!timestamp) return 'Recently';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins} min${diffMins > 1 ? 's' : ''} ago`;
    if (diffHours < 24) return `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    if (diffDays === 1) return 'Yesterday';
    if (diffDays < 7) return `${diffDays} days ago`;
    
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}

// ===== DEBUG ENDPOINT - CHECK DATABASE CONTENTS =====
app.get('/api/debug/database', async (req, res) => {
    try {
        console.log('🔍 DEBUG: Checking database contents...');
        
        // Check lessons table
        const [lessons] = await promisePool.execute('SELECT * FROM lessons');
        
        // Check users table (students)
        const [users] = await promisePool.execute('SELECT user_id, username, email, role, is_active FROM users');
        
        // Check topic_content_items
        const [contentItems] = await promisePool.execute('SELECT * FROM topic_content_items LIMIT 10');
        
        res.json({
            success: true,
            debug: {
                lessons: lessons,
                users: users,
                content_items: contentItems,
                counts: {
                    lessons: lessons.length,
                    users: users.length,
                    content_items: contentItems.length
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Debug error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// I-add ito sa server.js (temporary)
app.get('/api/practice/test/:topicId', verifyToken, async (req, res) => {
  try {
    const { topicId } = req.params;
    
    // Diretsong query lang muna
    const [exercises] = await promisePool.query(
      'SELECT * FROM practice_exercises WHERE topic_id = ?',
      [topicId]
    );
    
    console.log(`📊 Test query found ${exercises.length} exercises`);
    
    res.json({
      success: true,
      exercises: exercises,
      count: exercises.length
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ===== DEBUG ENDPOINT - CHECK DATABASE CONTENTS =====
app.get('/api/debug/database', async (req, res) => {
    try {
        console.log('🔍 DEBUG: Checking database contents...');
        
        // Check lessons table
        const [lessons] = await promisePool.execute('SELECT * FROM lessons');
        
        // Check users table (students)
        const [users] = await promisePool.execute('SELECT user_id, username, email, role, is_active FROM users');
        
        // Check topic_content_items
        const [contentItems] = await promisePool.execute('SELECT * FROM topic_content_items LIMIT 10');
        
        res.json({
            success: true,
            debug: {
                lessons: lessons,
                users: users,
                content_items: contentItems,
                counts: {
                    lessons: lessons.length,
                    users: users.length,
                    content_items: contentItems.length
                }
            }
        });
        
    } catch (error) {
        console.error('❌ Debug error:', error);
        res.status(500).json({
            success: false,
            message: error.message
        });
    }
});

// I-add ito sa server.js (temporary)
app.get('/api/practice/test/:topicId', verifyToken, async (req, res) => {
  try {
    const { topicId } = req.params;
    
    // Diretsong query lang muna
    const [exercises] = await promisePool.query(
      'SELECT * FROM practice_exercises WHERE topic_id = ?',
      [topicId]
    );
    
    console.log(`📊 Test query found ${exercises.length} exercises`);
    
    res.json({
      success: true,
      exercises: exercises,
      count: exercises.length
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});