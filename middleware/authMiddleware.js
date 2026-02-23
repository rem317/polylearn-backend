const jwt = require('jsonwebtoken');
const { pool } = require('../server');

const verifyToken = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({
            success: false,
            message: 'No token provided'
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'demo_secret');
        
        // Verify user still exists in database
        const [users] = await pool.promise().query(
            'SELECT user_id FROM users WHERE user_id = ?',
            [decoded.id]
        );
        
        if (users.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'User no longer exists'
            });
        }
        
        req.user = { id: decoded.id };
        next();
    } catch (error) {
        return res.status(401).json({
            success: false,
            message: 'Invalid token'
        });
    }
};

module.exports = verifyToken;