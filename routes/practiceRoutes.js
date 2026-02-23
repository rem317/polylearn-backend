const express = require('express');
const router = express.Router();
const { pool, verifyToken } = require('../server');

// GET /api/practice/topics - Get practice topics
router.get('/practice/topics', verifyToken, async (req, res) => {
    try {
        const [topics] = await pool.promise().query(
            'SELECT * FROM practice_topics ORDER BY category, difficulty_level'
        );
        
        // If no topics in DB, return default ones
        if (topics.length === 0) {
            const defaultTopics = [
                {
                    topic_id: 1,
                    title: "Polynomial Basics",
                    description: "Introduction to polynomials, terms, and degrees",
                    category: "polynomials",
                    difficulty_level: "beginner",
                    estimated_time: 15
                },
                {
                    topic_id: 2,
                    title: "Polynomial Addition & Subtraction",
                    description: "Learn how to add and subtract polynomials",
                    category: "polynomials",
                    difficulty_level: "beginner",
                    estimated_time: 20
                },
                {
                    topic_id: 3,
                    title: "Polynomial Multiplication",
                    description: "Multiplying polynomials using FOIL method",
                    category: "polynomials",
                    difficulty_level: "intermediate",
                    estimated_time: 25
                },
                {
                    topic_id: 4,
                    title: "Factoring Polynomials",
                    description: "Factoring quadratic and cubic polynomials",
                    category: "polynomials",
                    difficulty_level: "intermediate",
                    estimated_time: 30
                },
                {
                    topic_id: 5,
                    title: "Polynomial Division",
                    description: "Long division and synthetic division of polynomials",
                    category: "polynomials",
                    difficulty_level: "advanced",
                    estimated_time: 35
                }
            ];
            
            return res.json({
                success: true,
                topics: defaultTopics
            });
        }
        
        res.json({
            success: true,
            topics: topics
        });
        
    } catch (error) {
        console.error('❌ Get practice topics error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// GET /api/practice/topics/{id}/exercises
router.get('/practice/topics/:id/exercises', verifyToken, async (req, res) => {
    try {
        const topicId = req.params.id;
        
        const [exercises] = await pool.promise().query(
            'SELECT * FROM practice_exercises WHERE topic_id = ? ORDER BY exercise_order',
            [topicId]
        );
        
        // If no exercises in DB, return sample ones
        if (exercises.length === 0) {
            const sampleExercises = [
                {
                    exercise_id: 1,
                    topic_id: topicId,
                    question: "Simplify: (3x² + 2x - 5) + (x² - 4x + 7)",
                    options: ["4x² - 2x + 2", "3x² - 2x + 2", "4x² + 2x + 2", "3x² + 6x + 2"],
                    correct_answer: "4x² - 2x + 2",
                    explanation: "Combine like terms: (3x² + x²) + (2x - 4x) + (-5 + 7) = 4x² - 2x + 2",
                    difficulty: "easy"
                }
            ];
            
            return res.json({
                success: true,
                exercises: sampleExercises
            });
        }
        
        // Don't send correct answers to client
        const exercisesWithoutAnswers = exercises.map(ex => ({
            exercise_id: ex.exercise_id,
            topic_id: ex.topic_id,
            question: ex.question,
            options: JSON.parse(ex.options || '[]'),
            explanation: ex.explanation,
            difficulty: ex.difficulty
        }));
        
        res.json({
            success: true,
            exercises: exercisesWithoutAnswers
        });
        
    } catch (error) {
        console.error('❌ Get exercises error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

module.exports = router;