const bcrypt = require('bcryptjs');

class TeacherController {
    constructor(pool) {
        this.pool = pool;
    }

    // ============================================
    // TEACHER PROFILE MANAGEMENT
    // ============================================
    // Sa TeacherController class, idagdag ito bago ang module.exports

    // ============================================
    // LESSON CONTENT UPLOAD (ADMIN FUNCTION)
    // ============================================

    async uploadContent(req, res) {
        try {
            const { 
                lesson_id, 
                module_id, 
                topic_id, 
                content_title, 
                content_description, 
                content_type,
                content_order
            } = req.body;
            
            const admin_id = req.user.user_id;

            // Verify admin
            if (req.user.role !== 'admin') {
                return res.status(403).json({ 
                    success: false, 
                    message: 'Only admins can upload content' 
                });
            }

            // Check if topic_id is provided, if not use module's first topic
            let actual_topic_id = topic_id;
            if (!actual_topic_id && module_id) {
                const [topics] = await this.pool.execute(
                    'SELECT topic_id FROM module_topics WHERE module_id = ? ORDER BY topic_order LIMIT 1',
                    [module_id]
                );
                if (topics.length > 0) {
                    actual_topic_id = topics[0].topic_id;
                }
            }

            if (!actual_topic_id) {
                return res.status(400).json({ 
                    success: false, 
                    message: 'Topic ID is required' 
                });
            }

            // Get next content order if not provided
            let content_order_value = content_order;
            if (!content_order_value) {
                const [order] = await this.pool.execute(
                    'SELECT MAX(content_order) as max_order FROM topic_content_items WHERE topic_id = ?',
                    [actual_topic_id]
                );
                content_order_value = (order[0]?.max_order || 0) + 1;
            }

            // Handle file upload if exists
            let file_url = null;
            if (req.file) {
                file_url = `/uploads/lessons/${req.file.filename}`;
            }

            // Insert into topic_content_items
            const [contentResult] = await this.pool.execute(
                `INSERT INTO topic_content_items 
                (topic_id, content_type, content_title, content_description, 
                content_order, content_url, is_active) 
                VALUES (?, ?, ?, ?, ?, ?, TRUE)`,
                [actual_topic_id, content_type, content_title, content_description,
                content_order_value, file_url]
            );

            const content_id = contentResult.insertId;

            // ✅ AUTO-ENROLL ALL STUDENTS TO THIS LESSON
            try {
                // Import enrollmentController dynamically
                const EnrollmentController = require('./enrollmentController');
                const enrollmentController = new EnrollmentController(this.pool);
                
                const enrolledUsers = await enrollmentController.autoEnrollUsersToLesson(
                    lesson_id, 
                    content_title
                );
                
                console.log(`✅ Auto-enrolled ${enrolledUsers.length} users to lesson ${lesson_id}`);
            } catch (enrollError) {
                console.error('⚠️ Auto-enrollment failed (but content uploaded):', enrollError);
                // Continue even if enrollment fails
            }

            return res.json({
                success: true,
                message: 'Content uploaded successfully',
                data: {
                    content_id: content_id,
                    content_title: content_title,
                    lesson_id: lesson_id
                }
            });

        } catch (error) {
            console.error('Error uploading content:', error);
            return res.status(500).json({ 
                success: false, 
                message: 'Failed to upload content' 
            });
        }
    }

    // ============================================
    // GET LESSONS FOR ADMIN (for dropdown)
    // ============================================

    async getLessonsForAdmin() {
        try {
            const [lessons] = await this.pool.execute(
                'SELECT lesson_id, lesson_name FROM lessons WHERE is_active = TRUE ORDER BY lesson_order'
            );

            return {
                success: true,
                lessons: lessons
            };
        } catch (error) {
            console.error('Get lessons error:', error);
            return { 
                success: false, 
                message: 'Failed to fetch lessons' 
            };
        }
    }

    // ============================================
    // GET MODULES BY LESSON
    // ============================================

    async getModulesByLesson(lesson_id) {
        try {
            const [modules] = await this.pool.execute(
                `SELECT module_id, module_name FROM course_modules 
                WHERE lesson_id = ? AND is_active = TRUE 
                ORDER BY module_order`,
                [lesson_id]
            );

            return {
                success: true,
                modules: modules
            };
        } catch (error) {
            console.error('Get modules error:', error);
            return { 
                success: false, 
                message: 'Failed to fetch modules' 
            };
        }
    }

    // ============================================
    // GET TOPICS BY MODULE
    // ============================================

    async getTopicsByModule(module_id) {
        try {
            const [topics] = await this.pool.execute(
                `SELECT topic_id, topic_title FROM module_topics 
                WHERE module_id = ? AND is_active = TRUE 
                ORDER BY topic_order`,
                [module_id]
            );

            return {
                success: true,
                topics: topics
            };
        } catch (error) {
            console.error('Get topics error:', error);
            return { 
                success: false, 
                message: 'Failed to fetch topics' 
            };
        }
    }


    async getTeacherProfile(userId) {
        try {
            const [teachers] = await this.pool.execute(
                `SELECT t.*, u.username, u.email, u.full_name, u.created_at
                 FROM teachers t
                 JOIN users u ON t.user_id = u.user_id
                 WHERE t.user_id = ?`,
                [userId]
            );

            if (teachers.length === 0) {
                return { success: false, message: 'Teacher profile not found' };
            }

            const teacher = teachers[0];

            // Get teacher statistics
            const [stats] = await this.pool.execute(
                `SELECT 
                    COUNT(DISTINCT c.class_id) as total_classes,
                    COUNT(DISTINCT ce.student_id) as total_students,
                    COUNT(DISTINCT a.assignment_id) as total_assignments,
                    AVG(t.rating) as average_rating
                 FROM teachers t
                 LEFT JOIN classes c ON t.teacher_id = c.teacher_id
                 LEFT JOIN class_enrollments ce ON c.class_id = ce.class_id
                 LEFT JOIN assignments a ON c.class_id = a.class_id
                 WHERE t.user_id = ?`,
                [userId]
            );

            return {
                success: true,
                teacher: {
                    ...teacher,
                    statistics: stats[0]
                }
            };
        } catch (error) {
            console.error('Get teacher profile error:', error);
            return { success: false, message: 'Failed to get teacher profile' };
        }
    }

    async updateTeacherProfile(userId, profileData) {
        try {
            const { bio, qualifications, experience_years, subjects_taught, hourly_rate } = profileData;

            // Check if teacher exists
            const [existing] = await this.pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [userId]
            );

            let result;
            if (existing.length === 0) {
                // Create teacher profile
                [result] = await this.pool.execute(
                    `INSERT INTO teachers 
                     (user_id, bio, qualifications, experience_years, subjects_taught, hourly_rate) 
                     VALUES (?, ?, ?, ?, ?, ?)`,
                    [userId, bio, qualifications, experience_years, subjects_taught, hourly_rate]
                );
            } else {
                // Update existing profile
                [result] = await this.pool.execute(
                    `UPDATE teachers SET 
                     bio = COALESCE(?, bio),
                     qualifications = COALESCE(?, qualifications),
                     experience_years = COALESCE(?, experience_years),
                     subjects_taught = COALESCE(?, subjects_taught),
                     hourly_rate = COALESCE(?, hourly_rate),
                     updated_at = CURRENT_TIMESTAMP
                     WHERE user_id = ?`,
                    [bio, qualifications, experience_years, subjects_taught, hourly_rate, userId]
                );
            }

            return { success: true, message: 'Profile updated successfully' };
        } catch (error) {
            console.error('Update teacher profile error:', error);
            return { success: false, message: 'Failed to update profile' };
        }
    }

    // ============================================
    // CLASS MANAGEMENT
    // ============================================

    async createClass(teacherId, classData) {
        try {
            const { class_name, class_description, subject, grade_level, max_students, is_public } = classData;

            // Generate unique class code
            const classCode = this.generateClassCode();

            const [result] = await this.pool.execute(
                `INSERT INTO classes 
                 (teacher_id, class_name, class_description, subject, grade_level, 
                  class_code, max_students, is_public) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [teacherId, class_name, class_description, subject, grade_level, 
                 classCode, max_students, is_public || true]
            );

            return {
                success: true,
                message: 'Class created successfully',
                class: {
                    class_id: result.insertId,
                    class_code: classCode,
                    ...classData
                }
            };
        } catch (error) {
            console.error('Create class error:', error);
            return { success: false, message: 'Failed to create class' };
        }
    }

    async getTeacherClasses(teacherId) {
        try {
            const [classes] = await this.pool.execute(
                `SELECT c.*, 
                        COUNT(ce.enrollment_id) as student_count
                 FROM classes c
                 LEFT JOIN class_enrollments ce ON c.class_id = ce.class_id 
                     AND ce.status = 'active'
                 WHERE c.teacher_id = ?
                 GROUP BY c.class_id
                 ORDER BY c.created_at DESC`,
                [teacherId]
            );

            return { success: true, classes };
        } catch (error) {
            console.error('Get teacher classes error:', error);
            return { success: false, message: 'Failed to get classes' };
        }
    }

    async updateClass(teacherId, classId, classData) {
        try {
            const { class_name, class_description, subject, grade_level, max_students, is_public, is_active } = classData;

            // Verify teacher owns the class
            const [ownership] = await this.pool.execute(
                'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                [classId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Class not found or access denied' };
            }

            await this.pool.execute(
                `UPDATE classes SET 
                 class_name = COALESCE(?, class_name),
                 class_description = COALESCE(?, class_description),
                 subject = COALESCE(?, subject),
                 grade_level = COALESCE(?, grade_level),
                 max_students = COALESCE(?, max_students),
                 is_public = COALESCE(?, is_public),
                 is_active = COALESCE(?, is_active),
                 updated_at = CURRENT_TIMESTAMP
                 WHERE class_id = ?`,
                [class_name, class_description, subject, grade_level, 
                 max_students, is_public, is_active, classId]
            );

            return { success: true, message: 'Class updated successfully' };
        } catch (error) {
            console.error('Update class error:', error);
            return { success: false, message: 'Failed to update class' };
        }
    }

    async deleteClass(teacherId, classId) {
        try {
            // Verify teacher owns the class
            const [ownership] = await this.pool.execute(
                'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                [classId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Class not found or access denied' };
            }

            await this.pool.execute(
                'DELETE FROM classes WHERE class_id = ?',
                [classId]
            );

            return { success: true, message: 'Class deleted successfully' };
        } catch (error) {
            console.error('Delete class error:', error);
            return { success: false, message: 'Failed to delete class' };
        }
    }

    // ============================================
    // STUDENT MANAGEMENT
    // ============================================

    async getClassStudents(teacherId, classId) {
        try {
            // Verify teacher owns the class
            const [ownership] = await this.pool.execute(
                'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                [classId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            const [students] = await this.pool.execute(
                `SELECT u.user_id, u.username, u.email, u.full_name, 
                        ce.enrolled_at, ce.status, ce.progress, ce.last_accessed
                 FROM class_enrollments ce
                 JOIN users u ON ce.student_id = u.user_id
                 WHERE ce.class_id = ?
                 ORDER BY ce.enrolled_at DESC`,
                [classId]
            );

            return { success: true, students };
        } catch (error) {
            console.error('Get class students error:', error);
            return { success: false, message: 'Failed to get students' };
        }
    }

    async updateStudentStatus(teacherId, enrollmentId, status) {
        try {
            // Verify teacher has permission
            const [permission] = await this.pool.execute(
                `SELECT ce.enrollment_id 
                 FROM class_enrollments ce
                 JOIN classes c ON ce.class_id = c.class_id
                 WHERE ce.enrollment_id = ? AND c.teacher_id = ?`,
                [enrollmentId, teacherId]
            );

            if (permission.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            await this.pool.execute(
                'UPDATE class_enrollments SET status = ? WHERE enrollment_id = ?',
                [status, enrollmentId]
            );

            return { success: true, message: 'Student status updated' };
        } catch (error) {
            console.error('Update student status error:', error);
            return { success: false, message: 'Failed to update student status' };
        }
    }

    // ============================================
    // ASSIGNMENT MANAGEMENT
    // ============================================

    async createAssignment(teacherId, classId, assignmentData) {
        try {
            const { title, description, instructions, assignment_type, due_date, max_points, questions } = assignmentData;

            // Verify teacher owns the class
            const [ownership] = await this.pool.execute(
                'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                [classId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            const connection = await this.pool.getConnection();
            await connection.beginTransaction();

            try {
                // Create assignment
                const [assignmentResult] = await connection.execute(
                    `INSERT INTO assignments 
                     (class_id, teacher_id, title, description, instructions, 
                      assignment_type, due_date, max_points, is_published) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [classId, teacherId, title, description, instructions, 
                     assignment_type, due_date, max_points || 100, false]
                );

                const assignmentId = assignmentResult.insertId;

                // Add questions if provided
                if (questions && questions.length > 0) {
                    for (const [index, question] of questions.entries()) {
                        await connection.execute(
                            `INSERT INTO assignment_questions 
                             (assignment_id, question_text, question_type, options, 
                              correct_answer, points, question_order) 
                             VALUES (?, ?, ?, ?, ?, ?, ?)`,
                            [assignmentId, question.question_text, question.question_type,
                             JSON.stringify(question.options || []), question.correct_answer,
                             question.points || 1, index]
                        );
                    }
                }

                await connection.commit();
                connection.release();

                return {
                    success: true,
                    message: 'Assignment created successfully',
                    assignment_id: assignmentId
                };
            } catch (error) {
                await connection.rollback();
                connection.release();
                throw error;
            }
        } catch (error) {
            console.error('Create assignment error:', error);
            return { success: false, message: 'Failed to create assignment' };
        }
    }

    async publishAssignment(teacherId, assignmentId) {
        try {
            // Verify teacher owns the assignment
            const [ownership] = await this.pool.execute(
                'SELECT teacher_id FROM assignments WHERE assignment_id = ? AND teacher_id = ?',
                [assignmentId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            await this.pool.execute(
                `UPDATE assignments SET 
                 is_published = TRUE, 
                 published_at = CURRENT_TIMESTAMP 
                 WHERE assignment_id = ?`,
                [assignmentId]
            );

            return { success: true, message: 'Assignment published successfully' };
        } catch (error) {
            console.error('Publish assignment error:', error);
            return { success: false, message: 'Failed to publish assignment' };
        }
    }

    async getAssignmentSubmissions(teacherId, assignmentId) {
        try {
            // Verify teacher owns the assignment
            const [ownership] = await this.pool.execute(
                `SELECT a.assignment_id 
                 FROM assignments a
                 WHERE a.assignment_id = ? AND a.teacher_id = ?`,
                [assignmentId, teacherId]
            );

            if (ownership.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            const [submissions] = await this.pool.execute(
                `SELECT s.*, u.username, u.full_name,
                        (SELECT COUNT(*) 
                         FROM student_answers sa 
                         WHERE sa.submission_id = s.submission_id) as total_questions,
                        (SELECT COUNT(*) 
                         FROM student_answers sa 
                         WHERE sa.submission_id = s.submission_id AND sa.is_correct = TRUE) as correct_answers
                 FROM assignment_submissions s
                 JOIN users u ON s.student_id = u.user_id
                 WHERE s.assignment_id = ?
                 ORDER BY s.submitted_at DESC`,
                [assignmentId]
            );

            return { success: true, submissions };
        } catch (error) {
            console.error('Get assignment submissions error:', error);
            return { success: false, message: 'Failed to get submissions' };
        }
    }

    async gradeSubmission(teacherId, submissionId, gradeData) {
        try {
            const { grade, total_points, feedback, answers } = gradeData;

            // Verify teacher can grade this submission
            const [permission] = await this.pool.execute(
                `SELECT s.submission_id 
                 FROM assignment_submissions s
                 JOIN assignments a ON s.assignment_id = a.assignment_id
                 WHERE s.submission_id = ? AND a.teacher_id = ?`,
                [submissionId, teacherId]
            );

            if (permission.length === 0) {
                return { success: false, message: 'Access denied' };
            }

            const connection = await this.pool.getConnection();
            await connection.beginTransaction();

            try {
                // Update individual answers if provided
                if (answers && answers.length > 0) {
                    for (const answer of answers) {
                        await connection.execute(
                            `UPDATE student_answers SET 
                             is_correct = ?,
                             points_earned = ?,
                             feedback = ?
                             WHERE answer_id = ? AND submission_id = ?`,
                            [answer.is_correct, answer.points_earned, answer.feedback, 
                             answer.answer_id, submissionId]
                        );
                    }
                }

                // Update submission
                await connection.execute(
                    `UPDATE assignment_submissions SET 
                     grade = ?,
                     total_points = ?,
                     feedback = ?,
                     graded_by = ?,
                     graded_at = CURRENT_TIMESTAMP,
                     status = 'graded'
                     WHERE submission_id = ?`,
                    [grade, total_points, feedback, teacherId, submissionId]
                );

                await connection.commit();
                connection.release();

                return { success: true, message: 'Submission graded successfully' };
            } catch (error) {
                await connection.rollback();
                connection.release();
                throw error;
            }
        } catch (error) {
            console.error('Grade submission error:', error);
            return { success: false, message: 'Failed to grade submission' };
        }
    }

    // ============================================
    // ANNOUNCEMENTS
    // ============================================

    async createAnnouncement(teacherId, announcementData) {
        try {
            const { class_id, title, content, priority, is_pinned, expires_at } = announcementData;

            // Verify teacher owns the class if class_id is provided
            if (class_id) {
                const [ownership] = await this.pool.execute(
                    'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                    [class_id, teacherId]
                );

                if (ownership.length === 0) {
                    return { success: false, message: 'Access denied' };
                }
            }

            const [result] = await this.pool.execute(
                `INSERT INTO announcements 
                 (teacher_id, class_id, title, content, priority, is_pinned, expires_at) 
                 VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [teacherId, class_id, title, content, priority || 'normal', 
                 is_pinned || false, expires_at]
            );

            return {
                success: true,
                message: 'Announcement created successfully',
                announcement_id: result.insertId
            };
        } catch (error) {
            console.error('Create announcement error:', error);
            return { success: false, message: 'Failed to create announcement' };
        }
    }

    // ============================================
    // STUDY MATERIALS
    // ============================================

    async uploadStudyMaterial(teacherId, materialData) {
        try {
            const { class_id, title, description, file_url, file_type, file_size, is_public } = materialData;

            // Verify teacher owns the class if class_id is provided
            if (class_id) {
                const [ownership] = await this.pool.execute(
                    'SELECT teacher_id FROM classes WHERE class_id = ? AND teacher_id = ?',
                    [class_id, teacherId]
                );

                if (ownership.length === 0) {
                    return { success: false, message: 'Access denied' };
                }
            }

            const [result] = await this.pool.execute(
                `INSERT INTO study_materials 
                 (teacher_id, class_id, title, description, file_url, 
                  file_type, file_size, is_public) 
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [teacherId, class_id, title, description, file_url, 
                 file_type, file_size, is_public || true]
            );

            return {
                success: true,
                message: 'Study material uploaded successfully',
                material_id: result.insertId
            };
        } catch (error) {
            console.error('Upload study material error:', error);
            return { success: false, message: 'Failed to upload study material' };
        }
    }

    // ============================================
    // ANALYTICS
    // ============================================

    async getTeacherAnalytics(teacherId, timeframe = 'week') {
        try {
            let dateFilter = '';
            const params = [teacherId];

            switch (timeframe) {
                case 'day':
                    dateFilter = 'AND ta.date = CURDATE()';
                    break;
                case 'week':
                    dateFilter = 'AND ta.date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)';
                    break;
                case 'month':
                    dateFilter = 'AND ta.date >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)';
                    break;
                case 'year':
                    dateFilter = 'AND ta.date >= DATE_SUB(CURDATE(), INTERVAL 365 DAY)';
                    break;
            }

            const [analytics] = await this.pool.execute(
                `SELECT ta.* 
                 FROM teacher_analytics ta
                 WHERE ta.teacher_id = ? ${dateFilter}
                 ORDER BY ta.date DESC`,
                params
            );

            // Calculate totals
            const totals = analytics.reduce((acc, curr) => ({
                total_students: acc.total_students + curr.total_students,
                total_assignments: acc.total_assignments + curr.total_assignments,
                assignments_graded: acc.assignments_graded + curr.assignments_graded,
                total_engagement: acc.total_engagement + curr.student_engagement
            }), {
                total_students: 0,
                total_assignments: 0,
                assignments_graded: 0,
                total_engagement: 0
            });

            return {
                success: true,
                analytics,
                totals: {
                    ...totals,
                    avg_engagement: analytics.length > 0 ? totals.total_engagement / analytics.length : 0,
                    grading_completion: totals.total_assignments > 0 
                        ? (totals.assignments_graded / totals.total_assignments) * 100 
                        : 0
                }
            };
        } catch (error) {
            console.error('Get teacher analytics error:', error);
            return { success: false, message: 'Failed to get analytics' };
        }
    }

    // ============================================
    // UTILITY FUNCTIONS
    // ============================================

    generateClassCode() {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let code = '';
        for (let i = 0; i < 6; i++) {
            code += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return code;
    }

    async verifyTeacher(userId) {
        try {
            // Check if user is a teacher
            const [teachers] = await this.pool.execute(
                'SELECT teacher_id FROM teachers WHERE user_id = ?',
                [userId]
            );

            if (teachers.length === 0) {
                // Check if user has teacher role in users table
                const [user] = await this.pool.execute(
                    'SELECT role FROM users WHERE user_id = ?',
                    [userId]
                );

                if (user[0] && user[0].role === 'teacher') {
                    // Create teacher profile
                    await this.pool.execute(
                        'INSERT INTO teachers (user_id) VALUES (?)',
                        [userId]
                    );
                    return true;
                }
                return false;
            }

            return true;
        } catch (error) {
            console.error('Verify teacher error:', error);
            return false;
        }
    }
}

module.exports = TeacherController;