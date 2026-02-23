// authRoutes.js - Updated version
const express = require('express');
const bcrypt = require('bcryptjs');
const router = express.Router();
const { pool, generateToken, verifyToken } = require('../server');

// POST /api/auth/logout
router.post('/logout', (req, res) => {
    res.json({
        success: true,
        message: 'Logout successful'
    });
});

// GET /api/auth/me - Get current user (protected route)
router.get('/me', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        
        const [result] = await pool.promise().query(
            `SELECT u.*, p.* FROM users u 
             LEFT JOIN user_progress p ON u.user_id = p.user_id 
             WHERE u.user_id = ?`,
            [userId]
        );
        
        if (result.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        const userData = result[0];
        
        res.json({
            success: true,
            user: {
                id: userData.user_id,
                username: userData.username,
                email: userData.email,
                full_name: userData.full_name || userData.username,
                role: userData.role || 'student',
                lessons_completed: userData.lessons_completed || 0,
                exercises_completed: userData.exercises_completed || 0,
                quiz_score: userData.quiz_score || 0,
                average_time: userData.average_time || 0,
                streak_days: userData.streak_days || 0,
                achievements: userData.achievements || 0,
                accuracy_rate: userData.accuracy_rate || 0
            }
        });
        
    } catch (error) {
        console.error('❌ Get user error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});
router.post('/login', authController.login);
router.post('/register', authController.register);
module.exports = router;