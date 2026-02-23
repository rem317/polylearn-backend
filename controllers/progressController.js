// controllers/progressController.js
const pool = require('../config/database');

class ProgressController {
    // Get user content progress
    static async getUserContentProgress(req, res) {
        try {
            const { userId } = req.user;
            const { contentId } = req.params;
            
            let query = '';
            let params = [];
            
            if (contentId) {
                // Get progress for specific content
                query = `
                    SELECT * FROM user_content_progress 
                    WHERE user_id = ? AND content_id = ?
                `;
                params = [userId, contentId];
            } else {
                // Get all progress for user
                query = `
                    SELECT * FROM user_content_progress 
                    WHERE user_id = ?
                `;
                params = [userId];
            }
            
            const [rows] = await pool.execute(query, params);
            
            res.json({
                success: true,
                progress: contentId ? rows[0] : rows
            });
        } catch (error) {
            console.error('Error getting content progress:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get progress'
            });
        }
    }
    
    // Update or create content progress
    static async updateContentProgress(req, res) {
        try {
            const { userId } = req.user;
            const { contentId } = req.params;
            const {
                completion_status,
                time_spent_seconds = 0,
                score = null,
                notes = null
            } = req.body;
            
            // Validate completion_status
            const validStatuses = ['not_started', 'in_progress', 'completed'];
            if (completion_status && !validStatuses.includes(completion_status)) {
                return res.status(400).json({
                    success: false,
                    message: 'Invalid completion status'
                });
            }
            
            // Check if progress exists
            const [existing] = await pool.execute(
                'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
                [userId, contentId]
            );
            
            let result;
            if (existing.length > 0) {
                // Update existing progress
                query = `
                    UPDATE user_content_progress 
                    SET 
                        completion_status = COALESCE(?, completion_status),
                        time_spent_seconds = time_spent_seconds + ?,
                        last_accessed = NOW(),
                        score = COALESCE(?, score),
                        notes = COALESCE(?, notes),
                        completed_at = CASE 
                            WHEN ? = 'completed' AND completed_at IS NULL THEN NOW()
                            WHEN ? != 'completed' THEN NULL
                            ELSE completed_at 
                        END
                    WHERE user_id = ? AND content_id = ?
                `;
                
                params = [
                    completion_status,
                    time_spent_seconds,
                    score,
                    notes,
                    completion_status,
                    completion_status,
                    userId,
                    contentId
                ];
                
                [result] = await pool.execute(query, params);
            } else {
                // Create new progress
                query = `
                    INSERT INTO user_content_progress 
                    (user_id, content_id, completion_status, time_spent_seconds, score, notes, completed_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                `;
                
                params = [
                    userId,
                    contentId,
                    completion_status || 'not_started',
                    time_spent_seconds,
                    score,
                    notes,
                    completion_status === 'completed' ? new Date() : null
                ];
                
                [result] = await pool.execute(query, params);
            }
            
            // Get updated progress
            const [updated] = await pool.execute(
                'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
                [userId, contentId]
            );
            
            res.json({
                success: true,
                message: 'Progress updated successfully',
                progress: updated[0]
            });
        } catch (error) {
            console.error('Error updating content progress:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to update progress'
            });
        }
    }
    
    // Get content progress summary for a lesson
    static async getLessonProgressSummary(req, res) {
        try {
            const { userId } = req.user;
            const { lessonId } = req.params;
            
            const query = `
                SELECT 
                    COUNT(DISTINCT tci.content_id) as total_items,
                    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as completed_items,
                    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'in_progress' THEN tci.content_id END) as in_progress_items,
                    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'not_started' OR ucp.completion_status IS NULL THEN tci.content_id END) as not_started_items,
                    COALESCE(AVG(ucp.score), 0) as average_score,
                    COALESCE(SUM(ucp.time_spent_seconds), 0) as total_time_spent
                FROM topic_content_items tci
                JOIN module_topics mt ON tci.topic_id = mt.topic_id
                JOIN course_modules cm ON mt.module_id = cm.module_id
                LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
                WHERE cm.lesson_id = ?
            `;
            
            const [rows] = await pool.execute(query, [userId, lessonId]);
            
            const summary = rows[0];
            const progressPercentage = summary.total_items > 0 
                ? Math.round((summary.completed_items / summary.total_items) * 100)
                : 0;
            
            res.json({
                success: true,
                summary: {
                    ...summary,
                    progress_percentage: progressPercentage
                }
            });
        } catch (error) {
            console.error('Error getting lesson progress summary:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get lesson progress summary'
            });
        }
    }
    
    // Get user's recent activity
    static async getRecentActivity(req, res) {
        try {
            const { userId } = req.user;
            const limit = parseInt(req.query.limit) || 10;
            
            const query = `
                SELECT 
                    ucp.*,
                    tci.content_title,
                    tci.content_type,
                    mt.topic_title,
                    cm.module_name,
                    l.lesson_name
                FROM user_content_progress ucp
                JOIN topic_content_items tci ON ucp.content_id = tci.content_id
                JOIN module_topics mt ON tci.topic_id = mt.topic_id
                JOIN course_modules cm ON mt.module_id = cm.module_id
                JOIN lessons l ON cm.lesson_id = l.lesson_id
                WHERE ucp.user_id = ?
                ORDER BY ucp.last_accessed DESC
                LIMIT ?
            `;
            
            const [rows] = await pool.execute(query, [userId, limit]);
            
            res.json({
                success: true,
                activities: rows
            });
        } catch (error) {
            console.error('Error getting recent activity:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get recent activity'
            });
        }
    }
    
    // Batch update progress for multiple content items
    static async batchUpdateProgress(req, res) {
        try {
            const { userId } = req.user;
            const { updates } = req.body;
            
            if (!Array.isArray(updates) || updates.length === 0) {
                return res.status(400).json({
                    success: false,
                    message: 'Updates array is required'
                });
            }
            
            const results = [];
            
            for (const update of updates) {
                const { content_id, completion_status, time_spent_seconds, score, notes } = update;
                
                if (!content_id) {
                    continue;
                }
                
                // Check if progress exists
                const [existing] = await pool.execute(
                    'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
                    [userId, content_id]
                );
                
                if (existing.length > 0) {
                    // Update existing
                    const query = `
                        UPDATE user_content_progress 
                        SET 
                            completion_status = COALESCE(?, completion_status),
                            time_spent_seconds = time_spent_seconds + ?,
                            last_accessed = NOW(),
                            score = COALESCE(?, score),
                            notes = COALESCE(?, notes),
                            completed_at = CASE 
                                WHEN ? = 'completed' AND completed_at IS NULL THEN NOW()
                                ELSE completed_at 
                            END
                        WHERE user_id = ? AND content_id = ?
                    `;
                    
                    await pool.execute(query, [
                        completion_status,
                        time_spent_seconds || 0,
                        score,
                        notes,
                        completion_status,
                        userId,
                        content_id
                    ]);
                } else {
                    // Create new
                    const query = `
                        INSERT INTO user_content_progress 
                        (user_id, content_id, completion_status, time_spent_seconds, score, notes, completed_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    `;
                    
                    await pool.execute(query, [
                        userId,
                        content_id,
                        completion_status || 'not_started',
                        time_spent_seconds || 0,
                        score,
                        notes,
                        completion_status === 'completed' ? new Date() : null
                    ]);
                }
                
                // Get updated progress
                const [updated] = await pool.execute(
                    'SELECT * FROM user_content_progress WHERE user_id = ? AND content_id = ?',
                    [userId, content_id]
                );
                
                results.push(updated[0]);
            }
            
            res.json({
                success: true,
                message: 'Batch update completed',
                updated_progress: results
            });
        } catch (error) {
            console.error('Error in batch update:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to batch update progress'
            });
        }
    }
    
    // Get content progress by topic
    static async getTopicProgress(req, res) {
        try {
            const { userId } = req.user;
            const { topicId } = req.params;
            
            const query = `
                SELECT 
                    tci.content_id,
                    tci.content_title,
                    tci.content_type,
                    tci.content_order,
                    ucp.completion_status,
                    ucp.time_spent_seconds,
                    ucp.score,
                    ucp.last_accessed,
                    ucp.completed_at
                FROM topic_content_items tci
                LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id AND ucp.user_id = ?
                WHERE tci.topic_id = ?
                ORDER BY tci.content_order
            `;
            
            const [rows] = await pool.execute(query, [userId, topicId]);
            
            // Calculate statistics
            const totalItems = rows.length;
            const completedItems = rows.filter(item => item.completion_status === 'completed').length;
            const progressPercentage = totalItems > 0 ? 
                Math.round((completedItems / totalItems) * 100) : 0;
            
            res.json({
                success: true,
                topic_id: topicId,
                content_items: rows,
                statistics: {
                    total_items: totalItems,
                    completed_items: completedItems,
                    in_progress_items: rows.filter(item => item.completion_status === 'in_progress').length,
                    not_started_items: rows.filter(item => 
                        !item.completion_status || item.completion_status === 'not_started'
                    ).length,
                    progress_percentage: progressPercentage,
                    average_score: rows.length > 0 ? 
                        rows.reduce((sum, item) => sum + (item.score || 0), 0) / rows.length : 0
                }
            });
        } catch (error) {
            console.error('Error getting topic progress:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get topic progress'
            });
        }
    }
    
    // Reset progress for specific content
    static async resetProgress(req, res) {
        try {
            const { userId } = req.user;
            const { contentId } = req.params;
            
            const query = `
                DELETE FROM user_content_progress 
                WHERE user_id = ? AND content_id = ?
            `;
            
            await pool.execute(query, [userId, contentId]);
            
            res.json({
                success: true,
                message: 'Progress reset successfully'
            });
        } catch (error) {
            console.error('Error resetting progress:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to reset progress'
            });
        }
    }
}

module.exports = ProgressController;