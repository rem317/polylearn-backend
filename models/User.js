const pool = require('../config/database');
const bcrypt = require('bcryptjs');

class User {
    static async create(userData) {
        const { username, email, password, full_name } = userData;
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        
        const query = `
            INSERT INTO users (username, email, password_hash, full_name)
            VALUES (?, ?, ?, ?)
        `;
        
        try {
            const [result] = await pool.execute(query, [
                username, 
                email, 
                passwordHash, 
                full_name || username
            ]);
            
            // Create initial progress record
            await this.createUserProgress(result.insertId);
            
            return this.findById(result.insertId);
        } catch (error) {
            if (error.code === 'ER_DUP_ENTRY') {
                throw new Error('User with this email or username already exists');
            }
            throw error;
        }
    }
    
    static async createUserProgress(userId) {
        const query = `
            INSERT INTO user_progress (user_id) 
            VALUES (?)
        `;
        await pool.execute(query, [userId]);
    }
    
    static async findByEmail(email) {
        const query = 'SELECT * FROM users WHERE email = ?';
        const [rows] = await pool.execute(query, [email]);
        return rows[0];
    }
    
    static async findByUsername(username) {
        const query = 'SELECT * FROM users WHERE username = ?';
        const [rows] = await pool.execute(query, [username]);
        return rows[0];
    }
    
    static async findById(id) {
        const query = `
            SELECT u.*, 
                   p.lessons_completed, p.total_lessons,
                   p.exercises_completed, p.total_exercises,
                   p.quiz_score, p.average_time,
                   p.streak_days, p.achievements, p.accuracy_rate
            FROM users u
            LEFT JOIN user_progress p ON u.user_id = p.user_id
            WHERE u.user_id = ?
        `;
        const [rows] = await pool.execute(query, [id]);
        return rows[0];
    }
    
    static async updateLoginTime(userId) {
        const query = 'UPDATE users SET last_login = NOW() WHERE user_id = ?';
        await pool.execute(query, [userId]);
    }
    
    static async comparePassword(candidatePassword, hashedPassword) {
        return await bcrypt.compare(candidatePassword, hashedPassword);
    }
    
    static async updateProgress(userId, progressData) {
        const {
            lessons_completed,
            exercises_completed,
            quiz_score,
            average_time,
            streak_days,
            achievements,
            accuracy_rate
        } = progressData;
        
        const query = `
            UPDATE user_progress 
            SET lessons_completed = COALESCE(?, lessons_completed),
                exercises_completed = COALESCE(?, exercises_completed),
                quiz_score = COALESCE(?, quiz_score),
                average_time = COALESCE(?, average_time),
                streak_days = COALESCE(?, streak_days),
                achievements = COALESCE(?, achievements),
                accuracy_rate = COALESCE(?, accuracy_rate)
            WHERE user_id = ?
        `;
        
        await pool.execute(query, [
            lessons_completed, exercises_completed, quiz_score, 
            average_time, streak_days, achievements, accuracy_rate, userId
        ]);
        
        return this.findById(userId);
    }
    
    static async updateProfile(userId, profileData) {
        const { full_name } = profileData;
        
        if (!full_name) return this.findById(userId);
        
        const query = `
            UPDATE users 
            SET full_name = ?
            WHERE user_id = ?
        `;
        
        await pool.execute(query, [full_name, userId]);
        return this.findById(userId);
    }
}

module.exports = User;