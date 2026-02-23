const pool = require('../config/database');

// Auto-enroll user when admin uploads content to a lesson
exports.autoEnrollUsersToLesson = async (lesson_id, content_title) => {
    try {
        // Get all ACTIVE users (students)
        const [allUsers] = await pool.query(
            `SELECT user_id FROM users 
             WHERE role = 'student' AND is_active = TRUE`
        );

        const enrolledUsers = [];
        
        for (const user of allUsers) {
            try {
                // Check if already enrolled
                const [existing] = await pool.query(
                    'SELECT enrollment_id FROM user_lessons WHERE user_id = ? AND lesson_id = ?',
                    [user.user_id, lesson_id]
                );

                if (existing.length === 0) {
                    // Auto-enroll the user
                    await pool.query(
                        `INSERT INTO user_lessons 
                         (user_id, lesson_id, enrolled_at, completion_status) 
                         VALUES (?, ?, NOW(), 'not_started')`,
                        [user.user_id, lesson_id]
                    );

                    enrolledUsers.push(user.user_id);

                    // Create initial progress records for all contents in this lesson
                    await initializeUserProgress(user.user_id, lesson_id);
                }
            } catch (userError) {
                console.error(`Error enrolling user ${user.user_id}:`, userError);
                // Continue with other users
            }
        }

        console.log(`Auto-enrolled ${enrolledUsers.length} users to lesson ${lesson_id}`);
        return enrolledUsers;

    } catch (error) {
        console.error('Error in autoEnrollUsersToLesson:', error);
        throw error;
    }
};

// Initialize user progress for all contents in a lesson
async function initializeUserProgress(user_id, lesson_id) {
    try {
        // Get all contents in this lesson
        const [contents] = await pool.query(
            `SELECT tci.content_id, tci.topic_id 
             FROM topic_content_items tci
             JOIN module_topics mt ON tci.topic_id = mt.topic_id
             JOIN course_modules cm ON mt.module_id = cm.module_id
             WHERE cm.lesson_id = ? AND tci.is_active = TRUE`,
            [lesson_id]
        );

        for (const content of contents) {
            // Check if progress record exists
            const [existing] = await pool.query(
                'SELECT progress_id FROM user_content_progress WHERE user_id = ? AND content_id = ?',
                [user_id, content.content_id]
            );

            if (existing.length === 0) {
                // Create initial progress record
                await pool.query(
                    `INSERT INTO user_content_progress 
                     (user_id, content_id, lesson_id, completion_status, last_accessed) 
                     VALUES (?, ?, ?, 'not_started', NOW())`,
                    [user_id, content.content_id, lesson_id]
                );
            }
        }
    } catch (error) {
        console.error('Error initializing user progress:', error);
    }
}

// Manual enrollment (admin can enroll specific users)
exports.enrollUserToLesson = async (req, res) => {
    try {
        const { user_id, lesson_id } = req.body;
        const admin_id = req.user.user_id;

        // Verify admin is enrolling
        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only admins can enroll users' });
        }

        // Check if user exists and is student
        const [user] = await pool.query(
            'SELECT user_id, role FROM users WHERE user_id = ? AND is_active = TRUE',
            [user_id]
        );

        if (user.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (user[0].role !== 'student') {
            return res.status(400).json({ error: 'Can only enroll students' });
        }

        // Check if already enrolled
        const [existing] = await pool.query(
            'SELECT enrollment_id FROM user_lessons WHERE user_id = ? AND lesson_id = ?',
            [user_id, lesson_id]
        );

        if (existing.length > 0) {
            return res.status(400).json({ error: 'User already enrolled in this lesson' });
        }

        // Enroll user
        await pool.query(
            `INSERT INTO user_lessons 
             (user_id, lesson_id, enrolled_at, completion_status) 
             VALUES (?, ?, NOW(), 'not_started')`,
            [user_id, lesson_id]
        );

        // Initialize progress
        await initializeUserProgress(user_id, lesson_id);

        res.json({
            success: true,
            message: 'User enrolled successfully'
        });

    } catch (error) {
        console.error('Error enrolling user:', error);
        res.status(500).json({ error: 'Failed to enroll user' });
    }
};

// Bulk enroll users to a lesson
exports.bulkEnrollUsers = async (req, res) => {
    try {
        const { lesson_id, user_ids } = req.body;
        const admin_id = req.user.user_id;

        if (req.user.role !== 'admin') {
            return res.status(403).json({ error: 'Only admins can enroll users' });
        }

        const results = {
            successful: [],
            failed: [],
            already_enrolled: []
        };

        for (const user_id of user_ids) {
            try {
                // Check if already enrolled
                const [existing] = await pool.query(
                    'SELECT enrollment_id FROM user_lessons WHERE user_id = ? AND lesson_id = ?',
                    [user_id, lesson_id]
                );

                if (existing.length > 0) {
                    results.already_enrolled.push(user_id);
                    continue;
                }

                // Enroll user
                await pool.query(
                    `INSERT INTO user_lessons 
                     (user_id, lesson_id, enrolled_at, completion_status) 
                     VALUES (?, ?, NOW(), 'not_started')`,
                    [user_id, lesson_id]
                );

                // Initialize progress
                await initializeUserProgress(user_id, lesson_id);

                results.successful.push(user_id);

            } catch (error) {
                console.error(`Error enrolling user ${user_id}:`, error);
                results.failed.push({ user_id, error: error.message });
            }
        }

        res.json({
            success: true,
            message: 'Bulk enrollment completed',
            results: results
        });

    } catch (error) {
        console.error('Error in bulk enrollment:', error);
        res.status(500).json({ error: 'Failed to bulk enroll users' });
    }
};