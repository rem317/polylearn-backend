const express = require('express');
const router = express.Router();
const { pool, verifyToken } = require('../server');

// GET /api/users/{id}/progress
router.get('/:id/progress', verifyToken, async (req, res) => {
    try {
        const userId = req.params.id;
        
        // Check if user is authorized
        if (parseInt(userId) !== req.user.id) {
            return res.status(403).json({
                success: false,
                message: 'Unauthorized access'
            });
        }
        
        const [progress] = await pool.promise().query(
            'SELECT * FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        if (progress.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Progress not found'
            });
        }
        
        const progressData = progress[0];
        
        res.json({
            success: true,
            progress: {
                user_id: progressData.user_id,
                lessons_completed: progressData.lessons_completed || 0,
                exercises_completed: progressData.exercises_completed || 0,
                quiz_score: progressData.quiz_score || 0,
                average_time: progressData.average_time || 0,
                streak_days: progressData.streak_days || 0,
                achievements: progressData.achievements || 0,
                accuracy_rate: progressData.accuracy_rate || 0,
                last_updated: progressData.last_updated
            }
        });
        
    } catch (error) {
        console.error('❌ Get progress error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// POST /api/lessons/{id}/progress
router.post('/lessons/:id/progress', verifyToken, async (req, res) => {
    try {
        const lessonId = req.params.id;
        const userId = req.user.id;
        const { completed, score, time_spent } = req.body;
        
        // First, get current progress
        const [currentProgress] = await pool.promise().query(
            'SELECT * FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        if (currentProgress.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'User progress not found'
            });
        }
        
        const progress = currentProgress[0];
        let newLessonsCompleted = progress.lessons_completed || 0;
        let newExercisesCompleted = progress.exercises_completed || 0;
        
        // Update based on completion
        if (completed) {
            newLessonsCompleted += 1;
        }
        
        // Update progress in database
        await pool.promise().query(
            `UPDATE user_progress 
             SET lessons_completed = ?,
                 last_updated = NOW()
             WHERE user_id = ?`,
            [newLessonsCompleted, userId]
        );
        
        // Record lesson completion in lesson_progress table
        await pool.promise().query(
            `INSERT INTO lesson_progress (user_id, lesson_id, completed, score, time_spent)
             VALUES (?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE 
                completed = VALUES(completed),
                score = VALUES(score),
                time_spent = VALUES(time_spent),
                completed_at = NOW()`,
            [userId, lessonId, completed || true, score || 100, time_spent || 0]
        );
        
        res.json({
            success: true,
            message: 'Lesson progress updated',
            progress: {
                lessons_completed: newLessonsCompleted,
                last_updated: new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('❌ Update lesson progress error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// GET /api/users/dashboard
router.get('/dashboard', verifyToken, async (req, res) => {
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
        
        // Calculate percentages
        const lessonsPercentage = Math.round((userData.lessons_completed / 20) * 100);
        const exercisesPercentage = Math.round((userData.exercises_completed / 100) * 100);
        
        res.json({
            success: true,
            dashboard: {
                user: {
                    id: userData.user_id,
                    username: userData.username,
                    full_name: userData.full_name,
                    email: userData.email
                },
                progress: {
                    lessons_completed: userData.lessons_completed,
                    total_lessons: 20,
                    lessons_percentage: lessonsPercentage,
                    exercises_completed: userData.exercises_completed,
                    total_exercises: 100,
                    exercises_percentage: exercisesPercentage,
                    quiz_score: userData.quiz_score,
                    average_time: userData.average_time,
                    streak_days: userData.streak_days || 0,
                    achievements: userData.achievements || 0,
                    accuracy_rate: userData.accuracy_rate || 0,
                    overall_progress: lessonsPercentage
                },
                last_updated: userData.last_updated || new Date().toISOString()
            }
        });
        
    } catch (error) {
        console.error('❌ Dashboard error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// User routes (protected)
router.get('/user/lessons', auth.verifyToken, userController.getUserLessons);
router.get('/user/lesson/:lesson_id', auth.verifyToken, userController.getLessonDetails);
router.post('/user/complete-content', auth.verifyToken, userController.markContentCompleted);
module.exports = router;