const pool = require('../config/database');

class Progress {
    static async getDashboardData(userId) {
        const query = `
            SELECT 
                u.user_id,
                u.username,
                u.email,
                u.full_name,
                u.avatar_color,
                u.created_at,
                p.lessons_completed,
                p.total_lessons,
                p.exercises_completed,
                p.total_exercises,
                p.quiz_score,
                p.average_time,
                p.streak_days,
                p.achievements,
                p.accuracy_rate,
                p.last_updated,
                ROUND((p.lessons_completed / p.total_lessons) * 100, 0) as progress_percentage,
                ROUND((p.exercises_completed / p.total_exercises) * 100, 0) as exercises_percentage
            FROM users u
            LEFT JOIN user_progress p ON u.user_id = p.user_id
            WHERE u.user_id = ?
        `;
        
        const [rows] = await pool.execute(query, [userId]);
        return rows[0];
    }
    
    static async updateStreak(userId) {
        const query = `
            UPDATE user_progress 
            SET streak_days = streak_days + 1 
            WHERE user_id = ?
        `;
        await pool.execute(query, [userId]);
    }
}

module.exports = Progress;