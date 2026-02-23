const express = require('express');
const router = express.Router();
const { pool, verifyToken } = require('../server');
const { checkRole } = require('../server');

// Apply middleware to all admin routes
router.use(verifyToken);
router.use(checkRole(['admin']));

// Admin dashboard stats
router.get('/dashboard/stats', async (req, res) => {
    try {
        // Get total users
        const [users] = await pool.execute('SELECT COUNT(*) as total FROM users');
        
        // Get users by role
        const [roleStats] = await pool.execute(
            'SELECT role, COUNT(*) as count FROM users GROUP BY role'
        );
        
        // Get recent signups
        const [recentUsers] = await pool.execute(
            'SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC LIMIT 5'
        );
        
        res.json({
            success: true,
            stats: {
                totalUsers: users[0].total,
                roleStats: roleStats,
                recentUsers: recentUsers
            }
        });
    } catch (error) {
        console.error('Admin stats error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch admin stats' 
        });
    }
});

// Get all users
router.get('/users', async (req, res) => {
    try {
        const [users] = await pool.execute(
            'SELECT id, username, email, role, created_at, last_login FROM users ORDER BY created_at DESC'
        );
        
        res.json({
            success: true,
            users
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch users' 
        });
    }
});

// Update user role
router.put('/users/:id/role', async (req, res) => {
    try {
        const { id } = req.params;
        const { role } = req.body;
        
        const validRoles = ['student', 'teacher', 'admin'];
        if (!validRoles.includes(role)) {
            return res.status(400).json({
                success: false,
                message: 'Invalid role'
            });
        }
        
        await pool.execute(
            'UPDATE users SET role = ? WHERE id = ?',
            [role, id]
        );
        
        res.json({
            success: true,
            message: 'User role updated successfully'
        });
    } catch (error) {
        console.error('Update role error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to update user role' 
        });
    }
});

// Delete user
router.delete('/users/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // Don't allow deleting yourself
        if (req.user.id == id) {
            return res.status(400).json({
                success: false,
                message: 'Cannot delete your own account'
            });
        }
        
        await pool.execute('DELETE FROM users WHERE id = ?', [id]);
        
        res.json({
            success: true,
            message: 'User deleted successfully'
        });
    } catch (error) {
        console.error('Delete user error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to delete user' 
        });
    }
});

// System logs
router.get('/logs', async (req, res) => {
    try {
        const [logs] = await pool.execute(`
            SELECT * FROM system_logs 
            ORDER BY created_at DESC 
            LIMIT 100
        `);
        
        res.json({
            success: true,
            logs
        });
    } catch (error) {
        console.error('Get logs error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Failed to fetch logs' 
        });
    }
});
// Admin/Teacher routes
router.post('/admin/upload-content', auth.verifyToken, auth.verifyAdmin, teacherController.uploadLessonContent);
module.exports = router;