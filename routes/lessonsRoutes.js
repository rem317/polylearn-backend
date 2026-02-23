// routes/lessons.js
const express = require('express');
const router = express.Router();
const db = require('../db');

// Get all active lessons
router.get('/', async (req, res) => {
    try {
        const [lessons] = await db.query(
            'SELECT * FROM lessons WHERE is_active = TRUE ORDER BY lesson_id'
        );
        res.json({ success: true, data: lessons });
    } catch (error) {
        console.error('Error fetching lessons:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get specific lesson by ID
router.get('/:lessonId', async (req, res) => {
    try {
        const [lesson] = await db.query(
            'SELECT * FROM lessons WHERE lesson_id = ? AND is_active = TRUE',
            [req.params.lessonId]
        );
        
        if (lesson.length === 0) {
            return res.status(404).json({ success: false, message: 'Lesson not found' });
        }
        
        res.json({ success: true, data: lesson[0] });
    } catch (error) {
        console.error('Error fetching lesson:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get modules for a lesson
router.get('/:lessonId/modules', async (req, res) => {
    try {
        const [modules] = await db.query(
            `SELECT cm.* FROM course_modules cm
             JOIN lessons l ON cm.lesson_id = l.lesson_id
             WHERE l.lesson_id = ? AND cm.is_active = TRUE
             ORDER BY cm.module_order`,
            [req.params.lessonId]
        );
        
        res.json({ success: true, data: modules });
    } catch (error) {
        console.error('Error fetching modules:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get topics for a module
router.get('/modules/:moduleId/topics', async (req, res) => {
    try {
        const [topics] = await db.query(
            `SELECT * FROM module_topics 
             WHERE module_id = ? AND is_active = TRUE
             ORDER BY topic_order`,
            [req.params.moduleId]
        );
        
        res.json({ success: true, data: topics });
    } catch (error) {
        console.error('Error fetching topics:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get content items for a topic
router.get('/topics/:topicId/content', async (req, res) => {
    try {
        const [content] = await db.query(
            `SELECT * FROM topic_content_items 
             WHERE topic_id = ? AND is_active = TRUE
             ORDER BY content_order`,
            [req.params.topicId]
        );
        
        res.json({ success: true, data: content });
    } catch (error) {
        console.error('Error fetching content:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// Get complete lesson structure (lessons, modules, topics, content)
router.get('/:lessonId/complete-structure', async (req, res) => {
    try {
        const [lesson] = await db.query(
            'SELECT * FROM lessons WHERE lesson_id = ? AND is_active = TRUE',
            [req.params.lessonId]
        );
        
        if (lesson.length === 0) {
            return res.status(404).json({ success: false, message: 'Lesson not found' });
        }
        
        const [modules] = await db.query(
            `SELECT * FROM course_modules 
             WHERE lesson_id = ? AND is_active = TRUE
             ORDER BY module_order`,
            [req.params.lessonId]
        );
        
        // Get topics and content for each module
        const completeModules = await Promise.all(
            modules.map(async (module) => {
                const [topics] = await db.query(
                    `SELECT * FROM module_topics 
                     WHERE module_id = ? AND is_active = TRUE
                     ORDER BY topic_order`,
                    [module.module_id]
                );
                
                // Get content for each topic
                const topicsWithContent = await Promise.all(
                    topics.map(async (topic) => {
                        const [content] = await db.query(
                            `SELECT * FROM topic_content_items 
                             WHERE topic_id = ? AND is_active = TRUE
                             ORDER BY content_order`,
                            [topic.topic_id]
                        );
                        
                        return {
                            ...topic,
                            content
                        };
                    })
                );
                
                return {
                    ...module,
                    topics: topicsWithContent
                };
            })
        );
        
        res.json({
            success: true,
            data: {
                ...lesson[0],
                modules: completeModules
            }
        });
    } catch (error) {
        console.error('Error fetching complete structure:', error);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

module.exports = router;