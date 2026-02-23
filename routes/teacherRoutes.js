const express = require('express');
const router = express.Router();
const TeacherController = require('../controllers/teacherController');

// Updated to accept verifyToken and checkRole as parameters
module.exports = function(pool, verifyToken, checkRole) {
    const teacherController = new TeacherController(pool);

    // Middleware to verify teacher access
    const verifyTeacher = async (req, res, next) => {
        try {
            const isTeacher = await teacherController.verifyTeacher(req.user.id);
            if (!isTeacher) {
                return res.status(403).json({
                    success: false,
                    message: 'Access denied. Teacher privileges required.'
                });
            }
            next();
        } catch (error) {
            console.error('Verify teacher middleware error:', error);
            return res.status(500).json({
                success: false,
                message: 'Internal server error'
            });
        }
    };

    // ============================================
    // TEACHER PROFILE ROUTES
    // ============================================

    // Get teacher profile - uses verifyToken (from server.js) and verifyTeacher
    router.get('/profile', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const result = await teacherController.getTeacherProfile(req.user.id);
            if (result.success) {
                res.json(result);
            } else {
                res.status(404).json(result);
            }
        } catch (error) {
            console.error('Get profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get teacher profile'
            });
        }
    });

    // Update teacher profile
    router.put('/profile', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const result = await teacherController.updateTeacherProfile(req.user.id, req.body);
            if (result.success) {
                res.json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Update profile error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to update profile'
            });
        }
    });

    // ============================================
    // CLASS MANAGEMENT ROUTES
    // ============================================

    // Create a new class
    router.post('/classes', verifyToken, verifyTeacher, async (req, res) => {
        try {
            // Get teacher_id from teachers table
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.createClass(teachers[0].teacher_id, req.body);
            if (result.success) {
                res.status(201).json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Create class error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to create class'
            });
        }
    });

    // Get all teacher classes
    router.get('/classes', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.getTeacherClasses(teachers[0].teacher_id);
            res.json(result);
        } catch (error) {
            console.error('Get classes error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get classes'
            });
        }
    });

    // Update a class
    router.put('/classes/:classId', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.updateClass(
                teachers[0].teacher_id,
                req.params.classId,
                req.body
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Update class error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to update class'
            });
        }
    });

    // Delete a class
    router.delete('/classes/:classId', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.deleteClass(
                teachers[0].teacher_id,
                req.params.classId
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Delete class error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to delete class'
            });
        }
    });

    // Get class students
    router.get('/classes/:classId/students', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.getClassStudents(
                teachers[0].teacher_id,
                req.params.classId
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(403).json(result);
            }
        } catch (error) {
            console.error('Get class students error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get students'
            });
        }
    });

    // ============================================
    // ASSIGNMENT ROUTES
    // ============================================

    // Create assignment
    router.post('/classes/:classId/assignments', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.createAssignment(
                teachers[0].teacher_id,
                req.params.classId,
                req.body
            );

            if (result.success) {
                res.status(201).json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Create assignment error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to create assignment'
            });
        }
    });

    // Publish assignment
    router.post('/assignments/:assignmentId/publish', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.publishAssignment(
                teachers[0].teacher_id,
                req.params.assignmentId
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Publish assignment error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to publish assignment'
            });
        }
    });

    // Get assignment submissions
    router.get('/assignments/:assignmentId/submissions', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.getAssignmentSubmissions(
                teachers[0].teacher_id,
                req.params.assignmentId
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(403).json(result);
            }
        } catch (error) {
            console.error('Get submissions error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get submissions'
            });
        }
    });

    // Grade submission
    router.post('/submissions/:submissionId/grade', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.gradeSubmission(
                teachers[0].teacher_id,
                req.params.submissionId,
                req.body
            );

            if (result.success) {
                res.json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Grade submission error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to grade submission'
            });
        }
    });

    // ============================================
    // ANNOUNCEMENT ROUTES
    // ============================================

    // Create announcement
    router.post('/announcements', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.createAnnouncement(
                teachers[0].teacher_id,
                req.body
            );

            if (result.success) {
                res.status(201).json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Create announcement error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to create announcement'
            });
        }
    });

    // ============================================
    // STUDY MATERIAL ROUTES
    // ============================================

    // Upload study material
    router.post('/materials', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const result = await teacherController.uploadStudyMaterial(
                teachers[0].teacher_id,
                req.body
            );

            if (result.success) {
                res.status(201).json(result);
            } else {
                res.status(400).json(result);
            }
        } catch (error) {
            console.error('Upload material error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to upload study material'
            });
        }
    });

    // ============================================
    // ANALYTICS ROUTES
    // ============================================

    // Get teacher analytics
    router.get('/analytics', verifyToken, verifyTeacher, async (req, res) => {
        try {
            const [teachers] = await pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [req.user.id]
            );

            if (teachers.length === 0) {
                return res.status(403).json({
                    success: false,
                    message: 'Teacher profile not found'
                });
            }

            const timeframe = req.query.timeframe || 'week';
            const result = await teacherController.getTeacherAnalytics(
                teachers[0].teacher_id,
                timeframe
            );

            res.json(result);
        } catch (error) {
            console.error('Get analytics error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to get analytics'
            });
        }
    });

    // ============================================
    // UTILITY ROUTES
    // ============================================

    // Check if user is a teacher
    router.get('/verify', verifyToken, async (req, res) => {
        try {
            const isTeacher = await teacherController.verifyTeacher(req.user.id);
            res.json({
                success: true,
                isTeacher
            });
        } catch (error) {
            console.error('Verify teacher error:', error);
            res.status(500).json({
                success: false,
                message: 'Failed to verify teacher status'
            });
        }
    });

    return router;
};

// Admin/Teacher routes
router.post('/admin/upload-content', auth.verifyToken, auth.verifyAdmin, teacherController.uploadLessonContent);
module.exports = router;