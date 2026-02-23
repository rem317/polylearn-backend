const express = require('express');
const router = express.Router();
const { pool, verifyToken } = require('../server');

// POST /api/feedback - Submit feedback
router.post('/feedback', verifyToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const { feedback_type, message, rating, page_url } = req.body;
        
        if (!message || !feedback_type) {
            return res.status(400).json({
                success: false,
                message: 'Feedback type and message are required'
            });
        }
        
        await pool.promise().query(
            `INSERT INTO feedback 
             (user_id, feedback_type, message, rating, page_url, created_at)
             VALUES (?, ?, ?, ?, ?, NOW())`,
            [userId, feedback_type, message, rating || 5, page_url || null]
        );
        
        res.json({
            success: true,
            message: 'Thank you for your feedback!'
        });
        
    } catch (error) {
        console.error('❌ Submit feedback error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// GET /api/feedback (admin only - optional)
router.get('/feedback', verifyToken, async (req, res) => {
    try {
        // Simple admin check (you might want to implement proper admin roles)
        const [user] = await pool.promise().query(
            'SELECT is_admin FROM users WHERE user_id = ?',
            [req.user.id]
        );
        
        if (user.length === 0 || !user[0].is_admin) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized'
            });
        }
        
        const [feedback] = await pool.promise().query(
            `SELECT f.*, u.username, u.email 
             FROM feedback f
             JOIN users u ON f.user_id = u.user_id
             ORDER BY f.created_at DESC`
        );
        
        res.json({
            success: true,
            feedback: feedback
        });
        
    } catch (error) {
        console.error('❌ Get feedback error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

module.exports = router;