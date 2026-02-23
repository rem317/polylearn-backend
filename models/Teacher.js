const db = require('../server').promisePool;

class Teacher {
    static async getById(userId) {
        const [teachers] = await db.execute(
            `SELECT t.*, u.username, u.email, u.full_name 
             FROM teachers t
             JOIN users u ON t.user_id = u.user_id
             WHERE t.user_id = ?`,
            [userId]
        );
        return teachers[0];
    }

    static async createProfile(userId, data = {}) {
        const [result] = await db.execute(
            `INSERT INTO teachers (user_id, bio, qualifications, experience_years) 
             VALUES (?, ?, ?, ?)`,
            [userId, data.bio || '', data.qualifications || '', data.experience_years || 0]
        );
        return result.insertId;
    }

    static async updateProfile(userId, data) {
        await db.execute(
            `UPDATE teachers SET 
             bio = ?, qualifications = ?, experience_years = ?,
             subjects_taught = ?, hourly_rate = ?, updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ?`,
            [data.bio, data.qualifications, data.experience_years,
             data.subjects_taught, data.hourly_rate, userId]
        );
    }

    static async getClasses(teacherId) {
        const [classes] = await db.execute(
            `SELECT c.*, COUNT(ce.student_id) as student_count
             FROM classes c
             LEFT JOIN class_enrollments ce ON c.class_id = ce.class_id
             WHERE c.teacher_id = ?
             GROUP BY c.class_id
             ORDER BY c.created_at DESC`,
            [teacherId]
        );
        return classes;
    }
}

module.exports = Teacher;