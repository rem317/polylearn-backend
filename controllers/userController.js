const User = require('../models/User');
const Progress = require('../models/Progress');

// @desc    Update user progress
// @route   PUT /api/users/progress
exports.updateProgress = async (req, res) => {
    try {
        const userId = req.user.id;
        const progressData = req.body;
        
        // Validate progress data
        const allowedFields = [
            'lessons_completed', 'exercises_completed', 
            'quiz_score', 'average_time', 'streak_days',
            'achievements', 'accuracy_rate'
        ];
        
        const filteredData = {};
        allowedFields.forEach(field => {
            if (progressData[field] !== undefined) {
                filteredData[field] = progressData[field];
            }
        });
        
        // Update progress
        const updatedUser = await User.updateProgress(userId, filteredData);
        
        res.json({
            success: true,
            message: 'Progress updated successfully',
            progress: {
                lessons_completed: updatedUser.lessons_completed,
                exercises_completed: updatedUser.exercises_completed,
                quiz_score: updatedUser.quiz_score,
                average_time: updatedUser.average_time,
                streak_days: updatedUser.streak_days,
                achievements: updatedUser.achievements,
                accuracy_rate: updatedUser.accuracy_rate
            }
        });
        
    } catch (error) {
        console.error('Update progress error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};


// @desc    Get dashboard data
// @route   GET /api/users/dashboard
exports.getDashboard = async (req, res) => {
    try {
        const userId = req.user.id;
        const dashboardData = await Progress.getDashboardData(userId);
        
        if (!dashboardData) {
            return res.status(404).json({
                success: false,
                message: 'Dashboard data not found'
            });
        }
        
        // Calculate percentages
        const progressPercentage = Math.round((dashboardData.lessons_completed / dashboardData.total_lessons) * 100);
        const exercisesPercentage = Math.round((dashboardData.exercises_completed / dashboardData.total_exercises) * 100);
        
        res.json({
            success: true,
            dashboard: {
                user: {
                    id: dashboardData.user_id,
                    username: dashboardData.username,
                    full_name: dashboardData.full_name,
                    email: dashboardData.email,
                    avatar_color: dashboardData.avatar_color
                },
                progress: {
                    lessons_completed: dashboardData.lessons_completed,
                    total_lessons: dashboardData.total_lessons,
                    lessons_percentage: progressPercentage,
                    exercises_completed: dashboardData.exercises_completed,
                    total_exercises: dashboardData.total_exercises,
                    exercises_percentage: exercisesPercentage,
                    quiz_score: dashboardData.quiz_score,
                    average_time: dashboardData.average_time,
                    streak_days: dashboardData.streak_days,
                    achievements: dashboardData.achievements,
                    accuracy_rate: dashboardData.accuracy_rate,
                    overall_progress: dashboardData.progress_percentage
                },
                last_updated: dashboardData.last_updated
            }
        });
        
    } catch (error) {
        console.error('Get dashboard error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// @desc    Update user profile
// @route   PUT /api/users/profile
exports.updateProfile = async (req, res) => {
    try {
        const userId = req.user.id;
        const { full_name } = req.body;
        
        const updatedUser = await User.updateProfile(userId, { full_name });
        
        res.json({
            success: true,
            message: 'Profile updated successfully',
            user: {
                id: updatedUser.user_id,
                username: updatedUser.username,
                email: updatedUser.email,
                full_name: updatedUser.full_name
            }
        });
        
    } catch (error) {
        console.error('Update profile error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

const pool = require('../database');

// Get user's enrolled lessons
exports.getUserLessons = async (req, res) => {
    try {
        const user_id = req.user.user_id;
        
        // Get all lessons where user is enrolled
        const [lessons] = await pool.query(
            `SELECT 
                l.lesson_id,
                l.lesson_name,
                ul.enrolled_at,
                ul.completion_status,
                ul.progress_percentage,
                ul.last_accessed,
                (SELECT COUNT(*) FROM user_content_progress 
                 WHERE user_id = ? AND lesson_id = l.lesson_id 
                 AND completion_status = 'completed') as completed_contents,
                (SELECT COUNT(*) FROM topic_content_items tci
                 JOIN module_topics mt ON tci.topic_id = mt.topic_id
                 JOIN course_modules cm ON mt.module_id = cm.module_id
                 WHERE cm.lesson_id = l.lesson_id AND tci.is_active = TRUE) as total_contents
             FROM user_lessons ul
             JOIN lessons l ON ul.lesson_id = l.lesson_id
             WHERE ul.user_id = ? AND l.is_active = TRUE
             ORDER BY ul.last_accessed DESC NULLS LAST, ul.enrolled_at DESC`,
            [user_id, user_id]
        );

        // Calculate progress
        for (let lesson of lessons) {
            if (lesson.total_contents > 0) {
                const progress = (lesson.completed_contents / lesson.total_contents) * 100;
                
                // Update progress in database
                await pool.query(
                    'UPDATE user_lessons SET progress_percentage = ? WHERE user_id = ? AND lesson_id = ?',
                    [progress, user_id, lesson.lesson_id]
                );
                
                lesson.progress_percentage = progress;
            }
        }

        res.json({
            success: true,
            lessons: lessons
        });

    } catch (error) {
        console.error('Error fetching user lessons:', error);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to fetch user lessons' 
        });
    }
};

// Get specific lesson details
exports.getLessonDetails = async (req, res) => {
    try {
        const user_id = req.user.user_id;
        const { lesson_id } = req.params;

        // Check if user is enrolled
        const [enrollment] = await pool.query(
            'SELECT * FROM user_lessons WHERE user_id = ? AND lesson_id = ?',
            [user_id, lesson_id]
        );

        if (enrollment.length === 0) {
            return res.status(403).json({
                success: false,
                error: 'You are not enrolled in this lesson'
            });
        }

        // Get lesson structure with progress
        const [modules] = await pool.query(
            `SELECT 
                cm.module_id,
                cm.module_name,
                cm.module_order,
                mt.topic_id,
                mt.topic_title,
                mt.topic_order,
                tci.content_id,
                tci.content_type,
                tci.content_title,
                tci.content_description,
                tci.content_url,
                tci.content_order,
                ucp.completion_status as user_completion,
                ucp.time_spent_seconds,
                ucp.last_accessed
             FROM course_modules cm
             JOIN module_topics mt ON cm.module_id = mt.module_id
             JOIN topic_content_items tci ON mt.topic_id = tci.topic_id
             LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
             WHERE cm.lesson_id = ? 
             AND cm.is_active = TRUE
             AND mt.is_active = TRUE
             AND tci.is_active = TRUE
             ORDER BY cm.module_order, mt.topic_order, tci.content_order`,
            [user_id, lesson_id]
        );

        // Update last accessed
        await pool.query(
            'UPDATE user_lessons SET last_accessed = NOW() WHERE user_id = ? AND lesson_id = ?',
            [user_id, lesson_id]
        );

        // Format response
        const formattedModules = formatModules(modules);

        res.json({
            success: true,
            lesson_id: lesson_id,
            modules: formattedModules
        });

    } catch (error) {
        console.error('Error fetching lesson details:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to fetch lesson details'
        });
    }
};

// Helper to format modules
function formatModules(modules) {
    const result = [];
    let currentModule = null;
    let currentTopic = null;

    modules.forEach(row => {
        // New module
        if (!currentModule || currentModule.module_id !== row.module_id) {
            if (currentModule) result.push(currentModule);
            
            currentModule = {
                module_id: row.module_id,
                module_name: row.module_name,
                module_order: row.module_order,
                topics: []
            };
            currentTopic = null;
        }

        // New topic
        if (!currentTopic || currentTopic.topic_id !== row.topic_id) {
            currentTopic = {
                topic_id: row.topic_id,
                topic_title: row.topic_title,
                topic_order: row.topic_order,
                contents: []
            };
            currentModule.topics.push(currentTopic);
        }

        // Add content
        currentTopic.contents.push({
            content_id: row.content_id,
            content_type: row.content_type,
            content_title: row.content_title,
            content_description: row.content_description,
            content_url: row.content_url,
            content_order: row.content_order,
            user_completion: row.user_completion || 'not_started',
            time_spent_seconds: row.time_spent_seconds || 0,
            last_accessed: row.last_accessed
        });
    });

    if (currentModule) result.push(currentModule);
    return result;
}

// Mark content as completed
exports.markContentCompleted = async (req, res) => {
    try {
        const user_id = req.user.user_id;
        const { content_id, lesson_id, time_spent, score } = req.body;

        // Update content progress
        await pool.query(
            `INSERT INTO user_content_progress 
             (user_id, content_id, lesson_id, completion_status, time_spent_seconds, score, completed_at, last_accessed)
             VALUES (?, ?, ?, 'completed', ?, ?, NOW(), NOW())
             ON DUPLICATE KEY UPDATE 
             completion_status = 'completed',
             time_spent_seconds = time_spent_seconds + VALUES(time_spent_seconds),
             score = VALUES(score),
             completed_at = NOW(),
             last_accessed = NOW(),
             attempts = attempts + 1`,
            [user_id, content_id, lesson_id, time_spent || 0, score || null]
        );

        // Update overall lesson progress
        await updateLessonProgress(user_id, lesson_id);

        res.json({
            success: true,
            message: 'Content marked as completed'
        });

    } catch (error) {
        console.error('Error marking content completed:', error);
        res.status(500).json({
            success: false,
            error: 'Failed to update progress'
        });
    }
};

// Update overall lesson progress
async function updateLessonProgress(user_id, lesson_id) {
    try {
        const [progress] = await pool.query(
            `SELECT 
                COUNT(*) as total_contents,
                SUM(CASE WHEN completion_status = 'completed' THEN 1 ELSE 0 END) as completed_contents
             FROM user_content_progress 
             WHERE user_id = ? AND lesson_id = ?`,
            [user_id, lesson_id]
        );

        if (progress[0].total_contents > 0) {
            const percentage = (progress[0].completed_contents / progress[0].total_contents) * 100;
            const completion_status = percentage === 100 ? 'completed' : 'in_progress';

            await pool.query(
                `UPDATE user_lessons 
                 SET progress_percentage = ?, 
                     completion_status = ?,
                     last_accessed = NOW()
                 WHERE user_id = ? AND lesson_id = ?`,
                [percentage, completion_status, user_id, lesson_id]
            );
        }
    } catch (error) {
        console.error('Error updating lesson progress:', error);
    }
}