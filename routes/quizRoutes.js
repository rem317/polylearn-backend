const express = require('express');
const router = express.Router();
const { pool, verifyToken } = require('../server');

// GET /api/quizzes - List available quizzes
router.get('/quizzes', verifyToken, async (req, res) => {
    try {
        const [quizzes] = await pool.promise().query(
            'SELECT * FROM quizzes ORDER BY category, difficulty'
        );
        
        res.json({
            success: true,
            quizzes: quizzes
        });
        
    } catch (error) {
        console.error('❌ Get quizzes error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// GET /api/quizzes/{id} - Get specific quiz
router.get('/quizzes/:id', verifyToken, async (req, res) => {
    try {
        const quizId = req.params.id;
        
        const [quizzes] = await pool.promise().query(
            'SELECT * FROM quizzes WHERE quiz_id = ?',
            [quizId]
        );
        
        if (quizzes.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        const [questions] = await pool.promise().query(
            'SELECT * FROM quiz_questions WHERE quiz_id = ? ORDER BY question_order',
            [quizId]
        );
        
        // Don't send correct answers to client
        const questionsWithoutAnswers = questions.map(q => ({
            question_id: q.question_id,
            question_text: q.question_text,
            options: JSON.parse(q.options || '[]'),
            question_type: q.question_type,
            points: q.points
        }));
        
        res.json({
            success: true,
            quiz: {
                ...quizzes[0],
                questions: questionsWithoutAnswers
            }
        });
        
    } catch (error) {
        console.error('❌ Get quiz error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

// POST /api/quizzes/{id}/submit - Submit quiz answers
router.post('/quizzes/:id/submit', verifyToken, async (req, res) => {
    try {
        const quizId = req.params.id;
        const userId = req.user.id;
        const { answers, time_spent } = req.body;
        
        // Get quiz questions with correct answers
        const [questions] = await pool.promise().query(
            'SELECT * FROM quiz_questions WHERE quiz_id = ?',
            [quizId]
        );
        
        if (questions.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Quiz not found'
            });
        }
        
        // Calculate score
        let totalScore = 0;
        let maxScore = 0;
        const results = [];
        
        questions.forEach(question => {
            maxScore += question.points || 1;
            const userAnswer = answers.find(a => a.question_id === question.question_id);
            const correctAnswer = question.correct_answer;
            
            let isCorrect = false;
            let pointsEarned = 0;
            
            // Simple answer checking (extend based on your question types)
            if (userAnswer && userAnswer.answer === correctAnswer) {
                isCorrect = true;
                pointsEarned = question.points || 1;
                totalScore += pointsEarned;
            }
            
            results.push({
                question_id: question.question_id,
                is_correct: isCorrect,
                points_earned: pointsEarned,
                correct_answer: correctAnswer,
                user_answer: userAnswer?.answer
            });
        });
        
        const percentageScore = Math.round((totalScore / maxScore) * 100);
        
        // Save quiz attempt
        const [attemptResult] = await pool.promise().query(
            `INSERT INTO quiz_attempts 
             (user_id, quiz_id, score, percentage, time_spent, answers, created_at)
             VALUES (?, ?, ?, ?, ?, ?, NOW())`,
            [userId, quizId, totalScore, percentageScore, time_spent || 0, JSON.stringify(answers)]
        );
        
        // Update user progress with quiz score
        const [currentProgress] = await pool.promise().query(
            'SELECT * FROM user_progress WHERE user_id = ?',
            [userId]
        );
        
        if (currentProgress.length > 0) {
            const progress = currentProgress[0];
            const newQuizScore = Math.max(progress.quiz_score || 0, percentageScore);
            
            await pool.promise().query(
                `UPDATE user_progress 
                 SET quiz_score = ?,
                     last_updated = NOW()
                 WHERE user_id = ?`,
                [newQuizScore, userId]
            );
        }
        
        res.json({
            success: true,
            message: 'Quiz submitted successfully',
            results: {
                total_score: totalScore,
                max_score: maxScore,
                percentage: percentageScore,
                attempt_id: attemptResult.insertId,
                detailed_results: results
            }
        });
        
    } catch (error) {
        console.error('❌ Submit quiz error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
});

module.exports = router;