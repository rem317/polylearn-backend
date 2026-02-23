-- ============================================
-- COMPLETE DATABASE SETUP - POLYLEARN
-- ============================================

-- 1. Create and select database
DROP DATABASE IF EXISTS polylearn_db;
CREATE DATABASE polylearn_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE polylearn_db;

-- ============================================
-- CORE TABLES (No foreign key dependencies)
-- ============================================

-- Users table
CREATE TABLE users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    role ENUM('student', 'teacher', 'admin') DEFAULT 'student',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);
select * from lessons;
-- Lessons table
CREATE TABLE lessons (
    lesson_id INT AUTO_INCREMENT PRIMARY KEY,
    lesson_name ENUM('mathease', 'polylearn', 'factolearn') NOT NULL,
    lesson_title VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    lesson_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_lesson_name_order (lesson_name, lesson_order)
);
select * from quiz_categories;
-- Quiz categories table
CREATE TABLE quiz_categories (
    category_id INT AUTO_INCREMENT PRIMARY KEY,
    category_name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(50),
    color VARCHAR(20) DEFAULT '#3498db',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_category_name (category_name)
);

-- Badges table
CREATE TABLE badges (
    badge_id INT AUTO_INCREMENT PRIMARY KEY,
    badge_name VARCHAR(100) NOT NULL,
    description TEXT,
    icon VARCHAR(100),
    badge_type ENUM('achievement', 'milestone', 'special') DEFAULT 'achievement',
    criteria_type ENUM('quiz_score', 'quiz_completed', 'streak', 'accuracy', 'speed', 'custom') DEFAULT 'quiz_completed',
    criteria_value VARCHAR(100),
    points_awarded INT DEFAULT 100,
    color VARCHAR(20) DEFAULT '#3498db',
    difficulty VARCHAR(50) DEFAULT 'easy',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_badge_name (badge_name)
);


-- Run this in MySQL to check your quiz data
SELECT 
    q.quiz_id,
    q.quiz_title,
    qq.question_id,
    qq.question_text,
    qo.option_id,
    qo.option_text,
    qo.is_correct
FROM quizzes q
JOIN quiz_questions qq ON q.quiz_id = qq.quiz_id
JOIN quiz_options qo ON qq.question_id = qo.question_id
WHERE q.quiz_id = 1
ORDER BY qq.question_order, qo.option_order;

-- ============================================
-- TABLES WITH SINGLE DEPENDENCY
-- ============================================
ALTER TABLE users ADD COLUMN updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;

SELECT user_id, full_name, email, role, is_active 
FROM users 
WHERE user_id = 2;
SELECT user_id, username, email, role, is_active FROM users;
-- Teachers table (depends on users)
CREATE TABLE teachers (
    teacher_id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT UNIQUE NOT NULL,
    department VARCHAR(100),
    qualification TEXT,
    years_experience INT DEFAULT 0,
    bio TEXT,
    rating DECIMAL(3,2) DEFAULT 0.00,
    total_students INT DEFAULT 0,
    total_lessons INT DEFAULT 0,
    specialization TEXT,
    available_hours TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_rating (rating)
);

-- Course modules table (depends on lessons)
CREATE TABLE course_modules (
    module_id INT AUTO_INCREMENT PRIMARY KEY,
    lesson_id INT NOT NULL,
    module_name VARCHAR(100) NOT NULL,
    module_order INT NOT NULL,
    module_description TEXT,
    description TEXT,
    estimated_duration_minutes INT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lesson_id) REFERENCES lessons(lesson_id) ON DELETE CASCADE,
    UNIQUE KEY unique_module_order (lesson_id, module_order)
);

select * from module_topics;
-- Module topics table (depends on course_modules)
CREATE TABLE module_topics (
    topic_id INT AUTO_INCREMENT PRIMARY KEY,
    module_id INT NOT NULL,
    topic_title VARCHAR(200) NOT NULL,
    topic_description TEXT,
    topic_order INT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (module_id) REFERENCES course_modules(module_id) ON DELETE CASCADE,
    UNIQUE KEY unique_topic_order (module_id, topic_order)
);

-- ============================================
-- CONTENT TABLES
-- ============================================

-- Topic content items table (depends on module_topics)
CREATE TABLE topic_content_items (
    content_id INT AUTO_INCREMENT PRIMARY KEY,
    topic_id INT NOT NULL,
    module_id INT NULL,
    content_type ENUM('video', 'audio', 'pdf', 'interactive', 'text', 'quiz', 'practice') NOT NULL,
    content_title VARCHAR(200),
    content_description TEXT,
    content_url VARCHAR(500),
    content_order INT NOT NULL,
    content_duration_minutes INT,
    
    -- Video-specific columns
    video_filename VARCHAR(255),
    video_path VARCHAR(500),
    video_size BIGINT,
    video_duration_seconds INT,
    thumbnail_url VARCHAR(500),
    video_metadata JSON,
    
    -- Audio-specific columns
    audio_filename VARCHAR(255),
    audio_path VARCHAR(500),
    audio_duration_seconds INT,
    
    -- Status columns
    is_required BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES course_modules(module_id) ON DELETE SET NULL,
    UNIQUE KEY unique_content_order (topic_id, content_order)
);

DESCRIBE feedback;
-- Practice exercises table (depends on module_topics)
CREATE TABLE practice_exercises (
    exercise_id INT AUTO_INCREMENT PRIMARY KEY,
    topic_id INT NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    content_type ENUM('multiple_choice', 'fill_blank', 'matching', 'interactive') NOT NULL,
    difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
    points INT DEFAULT 10,
    content_json JSON NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE CASCADE
);

select * from user_content_progress;

-- Quizzes table (depends on quiz_categories and module_topics)
CREATE TABLE quizzes (
    quiz_id INT AUTO_INCREMENT PRIMARY KEY,
    category_id INT NOT NULL,
    topic_id INT,
    quiz_title VARCHAR(200) NOT NULL,
    description TEXT,
    difficulty ENUM('easy', 'medium', 'hard') DEFAULT 'medium',
    duration_minutes INT DEFAULT 30,
    total_questions INT DEFAULT 10,
    passing_score DECIMAL(5,2) DEFAULT 70.00,
    max_attempts INT DEFAULT 3,
    is_active BOOLEAN DEFAULT TRUE,
    requires_lesson_completion BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES quiz_categories(category_id) ON DELETE CASCADE,
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE SET NULL,
    INDEX idx_topic (topic_id),
    INDEX idx_difficulty (difficulty)
);

-- Video uploads table (depends on topic_content_items and users)
CREATE TABLE video_uploads (
    upload_id INT AUTO_INCREMENT PRIMARY KEY,
    content_id INT NOT NULL,
    original_filename VARCHAR(255),
    stored_filename VARCHAR(255),
    file_path VARCHAR(500),
    file_size BIGINT,
    duration_seconds INT,
    resolution VARCHAR(20),
    uploaded_by INT NOT NULL,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (content_id) REFERENCES topic_content_items(content_id) ON DELETE CASCADE,
    FOREIGN KEY (uploaded_by) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ============================================
-- QUIZ RELATED TABLES
-- ============================================

-- Quiz questions table
CREATE TABLE quiz_questions (
    question_id INT AUTO_INCREMENT PRIMARY KEY,
    quiz_id INT NOT NULL,
    question_text TEXT NOT NULL,
    question_type ENUM('multiple_choice', 'true_false', 'fill_blank', 'matching', 'short_answer') DEFAULT 'multiple_choice',
    points INT DEFAULT 10,
    explanation TEXT,
    question_order INT NOT NULL,
    time_limit_seconds INT DEFAULT 60,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE,
    INDEX idx_quiz_order (quiz_id, question_order)
);

-- Quiz options table
CREATE TABLE quiz_options (
    option_id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    option_text TEXT NOT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    option_order INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES quiz_questions(question_id) ON DELETE CASCADE,
    UNIQUE KEY unique_question_option (question_id, option_order)
);

-- ============================================
-- USER PROGRESS TRACKING TABLES
-- ============================================

-- User progress summary table
CREATE TABLE user_progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content_items_completed INT DEFAULT 0,
    total_content_items INT DEFAULT 0,
    lessons_completed INT DEFAULT 0,
    total_lessons INT DEFAULT 0,
    exercises_completed INT DEFAULT 0,
    quiz_score DECIMAL(5,2) DEFAULT 0,
    average_time INT DEFAULT 0,
    streak_days INT DEFAULT 0,
    achievements INT DEFAULT 0,
    accuracy_rate DECIMAL(5,2) DEFAULT 0,
    average_practice_score DECIMAL(5,2) DEFAULT 0,
    total_practice_time_seconds INT DEFAULT 0,
    practice_streak INT DEFAULT 0,
    last_practice_date DATETIME,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_progress (user_id)
);

-- User content progress table
CREATE TABLE user_content_progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content_id INT NOT NULL,
    completion_status ENUM('not_started', 'in_progress', 'completed') DEFAULT 'not_started',
    time_spent_seconds INT DEFAULT 0,
    score DECIMAL(5,2),
    last_accessed TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    notes TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (content_id) REFERENCES topic_content_items(content_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_content (user_id, content_id)
);

-- User practice progress table
CREATE TABLE user_practice_progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    exercise_id INT NOT NULL,
    completion_status ENUM('not_started', 'in_progress', 'completed') DEFAULT 'not_started',
    score DECIMAL(5,2) DEFAULT 0,
    attempts INT DEFAULT 0,
    time_spent_seconds INT DEFAULT 0,
    last_attempted TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    answers_json JSON,
    feedback TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (exercise_id) REFERENCES practice_exercises(exercise_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_exercise (user_id, exercise_id)
);

-- User topic progress table
CREATE TABLE user_topic_progress (
    summary_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    topic_id INT NOT NULL,
    lessons_completed INT DEFAULT 0,
    total_lessons INT DEFAULT 0,
    practice_unlocked BOOLEAN DEFAULT FALSE,
    practice_completed BOOLEAN DEFAULT FALSE,
    last_accessed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_topic (user_id, topic_id)
);

-- User quiz attempts table
CREATE TABLE user_quiz_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    quiz_id INT NOT NULL,
    attempt_number INT DEFAULT 1,
    start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    end_time TIMESTAMP NULL,
    score DECIMAL(5,2) DEFAULT 0.00,
    total_questions INT DEFAULT 0,
    correct_answers INT DEFAULT 0,
    time_spent_seconds INT DEFAULT 0,
    completion_status ENUM('in_progress', 'completed', 'abandoned') DEFAULT 'in_progress',
    passed BOOLEAN DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (quiz_id) REFERENCES quizzes(quiz_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_quiz_attempt (user_id, quiz_id, attempt_number),
    INDEX idx_user_quiz (user_id, quiz_id),
    INDEX idx_start_time (start_time)
);

-- User quiz answers table
CREATE TABLE user_quiz_answers (
    answer_id INT AUTO_INCREMENT PRIMARY KEY,
    attempt_id INT NOT NULL,
    question_id INT NOT NULL,
    user_answer TEXT,
    selected_option_id INT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    points_earned INT DEFAULT 0,
    time_spent_seconds INT DEFAULT 0,
    answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (attempt_id) REFERENCES user_quiz_attempts(attempt_id) ON DELETE CASCADE,
    FOREIGN KEY (question_id) REFERENCES quiz_questions(question_id) ON DELETE CASCADE,
    FOREIGN KEY (selected_option_id) REFERENCES quiz_options(option_id) ON DELETE SET NULL,
    INDEX idx_attempt_question (attempt_id, question_id)
);

-- User badges table
CREATE TABLE user_badges (
    user_badge_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    badge_id INT NOT NULL,
    awarded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    context TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (badge_id) REFERENCES badges(badge_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_badge (user_id, badge_id),
    INDEX idx_user_badges (user_id)
);

-- User points table
CREATE TABLE user_points (
    points_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    points_type VARCHAR(50) NOT NULL,
    points_amount INT NOT NULL,
    description TEXT,
    reference_id INT,
    earned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_points (user_id, earned_at),
    INDEX idx_points_type (points_type)
);

-- ============================================
-- DAILY & CUMULATIVE PROGRESS TABLES
-- ============================================

-- Daily progress tracking
CREATE TABLE daily_progress (
    progress_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    progress_date DATE NOT NULL,
    lessons_completed INT DEFAULT 0,
    exercises_completed INT DEFAULT 0,
    quizzes_completed INT DEFAULT 0,
    total_time_minutes INT DEFAULT 0,
    points_earned INT DEFAULT 0,
    streak_maintained BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_date (user_id, progress_date),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_progress_date (user_id, progress_date)
);

-- Cumulative progress table
CREATE TABLE cumulative_progress (
    user_id INT PRIMARY KEY,
    total_lessons_completed INT DEFAULT 0,
    total_exercises_completed INT DEFAULT 0,
    total_quizzes_completed INT DEFAULT 0,
    total_points_earned INT DEFAULT 0,
    total_time_spent_minutes INT DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- User activity log
CREATE TABLE user_activity_log (
    activity_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    activity_type VARCHAR(50) NOT NULL,
    related_id INT,
    details JSON,
    points_earned INT DEFAULT 0,
    activity_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_activity (user_id, activity_timestamp),
    INDEX idx_activity_type (activity_type, activity_timestamp)
);

-- Topic mastery table
CREATE TABLE topic_mastery (
    mastery_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    topic_id INT NOT NULL,
    mastery_level ENUM('beginner', 'intermediate', 'advanced', 'expert') DEFAULT 'beginner',
    accuracy_rate DECIMAL(5,2) DEFAULT 0,
    completion_rate DECIMAL(5,2) DEFAULT 0,
    skill_score DECIMAL(5,2) DEFAULT 0,
    total_practice_time INT DEFAULT 0,
    last_practiced TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_topic (user_id, topic_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE CASCADE,
    INDEX idx_user_mastery (user_id, mastery_level),
    INDEX idx_topic_skill (topic_id, skill_score)
);

-- Progress heatmap
CREATE TABLE progress_heatmap (
    heatmap_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    activity_date DATE NOT NULL,
    activity_count INT DEFAULT 0,
    total_time_minutes INT DEFAULT 0,
    points_earned INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_user_date_activity (user_id, activity_date),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_user_activity_date (user_id, activity_date)
);

-- Feedback table
CREATE TABLE feedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    feedback_type ENUM('suggestion', 'bug', 'praise', 'other') NOT NULL,
    feedback_message TEXT NOT NULL,
    rating INT CHECK (rating >= 0 AND rating <= 5),
    user_agent TEXT,
    page_url VARCHAR(500),
    ip_address VARCHAR(45),
    status ENUM('new', 'reviewed', 'in_progress', 'resolved', 'closed') DEFAULT 'new',
    admin_notes TEXT,
    admin_id INT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP NULL,
    resolved_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_feedback_type (feedback_type),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id)
);
select * from feedback;
ALTER TABLE feedback 
MODIFY feedback_type ENUM('suggestion', 'bug', 'praise', 'rating', 'complaint', 'question', 'other') NOT NULL;

-- ============================================
-- VIEWS
-- ============================================

-- Comprehensive progress view
CREATE VIEW vw_user_comprehensive_progress AS
SELECT 
    u.user_id,
    u.username,
    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN l.lesson_id END) as lessons_completed,
    COUNT(DISTINCT l.lesson_id) as total_lessons,
    COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN tci.content_id END) as contents_completed,
    COUNT(DISTINCT tci.content_id) as total_contents,
    COUNT(DISTINCT CASE WHEN upp.completion_status = 'completed' THEN pe.exercise_id END) as practices_completed,
    COUNT(DISTINCT pe.exercise_id) as total_practices,
    COUNT(DISTINCT CASE WHEN uqa.score >= 70 THEN q.quiz_id END) as quizzes_passed,
    COUNT(DISTINCT q.quiz_id) as total_quizzes
FROM users u
LEFT JOIN user_content_progress ucp ON u.user_id = ucp.user_id
LEFT JOIN topic_content_items tci ON ucp.content_id = tci.content_id
LEFT JOIN module_topics mt ON tci.topic_id = mt.topic_id
LEFT JOIN course_modules cm ON mt.module_id = cm.module_id
LEFT JOIN lessons l ON cm.lesson_id = l.lesson_id
LEFT JOIN user_practice_progress upp ON u.user_id = upp.user_id
LEFT JOIN practice_exercises pe ON upp.exercise_id = pe.exercise_id
LEFT JOIN user_quiz_attempts uqa ON u.user_id = uqa.user_id
LEFT JOIN quizzes q ON uqa.quiz_id = q.quiz_id
GROUP BY u.user_id, u.username;

-- ============================================
-- STORED PROCEDURES
-- ============================================

DELIMITER //

-- Initialize user progress
CREATE PROCEDURE sp_initialize_user_progress(IN p_user_id INT)
BEGIN
    DECLARE total_lessons INT DEFAULT 0;
    DECLARE total_contents INT DEFAULT 0;
    DECLARE total_practices INT DEFAULT 0;
    
    SELECT COUNT(*) INTO total_lessons FROM lessons WHERE is_active = TRUE;
    SELECT COUNT(*) INTO total_contents FROM topic_content_items WHERE is_active = TRUE;
    SELECT COUNT(*) INTO total_practices FROM practice_exercises WHERE is_active = TRUE;
    
    INSERT INTO user_progress (user_id, total_lessons, total_content_items, total_practices) 
    VALUES (p_user_id, total_lessons, total_contents, total_practices)
    ON DUPLICATE KEY UPDATE 
        total_lessons = total_lessons,
        total_content_items = total_contents;
    
    INSERT IGNORE INTO user_content_progress (user_id, content_id, completion_status)
    SELECT p_user_id, tci.content_id, 'not_started'
    FROM topic_content_items tci
    WHERE tci.is_active = TRUE;
    
    INSERT IGNORE INTO user_practice_progress (user_id, exercise_id, completion_status)
    SELECT p_user_id, pe.exercise_id, 'not_started'
    FROM practice_exercises pe
    WHERE pe.is_active = TRUE;
    
    INSERT IGNORE INTO user_topic_progress (user_id, topic_id)
    SELECT p_user_id, mt.topic_id
    FROM module_topics mt
    WHERE mt.is_active = TRUE;
    
    COMMIT;
END //
DELIMITER //
-- Get accurate progress
CREATE PROCEDURE sp_get_accurate_progress(IN p_user_id INT)
BEGIN
    DECLARE total_lessons INT DEFAULT 0;
    DECLARE completed_lessons INT DEFAULT 0;
    DECLARE total_practices INT DEFAULT 0;
    DECLARE completed_practices INT DEFAULT 0;
    DECLARE total_quizzes INT DEFAULT 0;
    DECLARE passed_quizzes INT DEFAULT 0;
    
    SELECT 
        COUNT(DISTINCT l.lesson_id),
        COUNT(DISTINCT CASE WHEN ucp.completion_status = 'completed' THEN l.lesson_id END)
    INTO total_lessons, completed_lessons
    FROM lessons l
    LEFT JOIN course_modules cm ON l.lesson_id = cm.lesson_id
    LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
    LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id
    LEFT JOIN user_content_progress ucp ON tci.content_id = ucp.content_id 
        AND ucp.user_id = p_user_id
    WHERE l.is_active = TRUE;
    
    SELECT 
        COUNT(DISTINCT pe.exercise_id),
        COUNT(DISTINCT CASE WHEN upp.completion_status = 'completed' THEN pe.exercise_id END)
    INTO total_practices, completed_practices
    FROM practice_exercises pe
    LEFT JOIN user_practice_progress upp ON pe.exercise_id = upp.exercise_id 
        AND upp.user_id = p_user_id
    WHERE pe.is_active = TRUE;
    
    SELECT 
        COUNT(DISTINCT q.quiz_id),
        COUNT(DISTINCT CASE WHEN uqa.score >= q.passing_score THEN q.quiz_id END)
    INTO total_quizzes, passed_quizzes
    FROM quizzes q
    LEFT JOIN user_quiz_attempts uqa ON q.quiz_id = uqa.quiz_id 
        AND uqa.user_id = p_user_id
    WHERE q.is_active = TRUE;
    
    SELECT 
        completed_lessons,
        total_lessons,
        completed_practices,
        total_practices,
        passed_quizzes,
        total_quizzes,
        ROUND((completed_lessons * 100.0) / NULLIF(total_lessons, 0), 2) as lesson_progress_percent,
        ROUND((completed_practices * 100.0) / NULLIF(total_practices, 0), 2) as practice_progress_percent,
        ROUND((passed_quizzes * 100.0) / NULLIF(total_quizzes, 0), 2) as quiz_progress_percent;
END //

DELIMITER ;


CREATE TABLE IF NOT EXISTS practice_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    exercise_id INT NOT NULL,
    score INT DEFAULT 0,
    completion_status ENUM('in_progress', 'completed', 'failed') DEFAULT 'in_progress',
    attempts INT DEFAULT 1,
    time_spent_seconds INT DEFAULT 0,
    last_attempted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (exercise_id) REFERENCES practice_exercises(exercise_id) ON DELETE CASCADE,
    INDEX idx_user_practice (user_id, exercise_id),
    INDEX idx_completion (completion_status)
);

SELECT * FROM practice_exercises;
SELECT COUNT(*) as total FROM practice_exercises;
SELECT COUNT(*) as active FROM practice_exercises WHERE status = 'active' OR is_active = 1;

-- ============================================
-- INSERT SAMPLE DATA
-- ============================================

-- Insert users
INSERT INTO users (username, email, password_hash, full_name, role, is_active) VALUES 
('rembenares', 'rembenares3@gmail.com', '$2a$12$rxhwPbTBl12m1EVMMS9Cm.kRZDPgAY.srbNhm0yXHuNAAUhut3qpK', 'Rem Benares', 'student', 1),
('karlSuarez', 'karlsuarez@gmail.com', '$2a$12$n3Ctl.6BpPWECdG3UsEyD.VQ8wj4B2qRWlOQ0917lMaO2pCsnkLmK', 'Karl Suarez', 'admin', 1);

select * from users;

-- Insert lessons
INSERT INTO lessons (lesson_name, lesson_title, description, lesson_order, is_active) VALUES
('mathease', 'Basic Operations', 'Comprehensive guide to basic operations', 1, TRUE),
('polylearn', 'Polynomial Factors', 'Comprehensive guide to polynomial factors', 2, TRUE),
('factolearn', 'Factorial Factors', 'Comprehensive guide to factorials factors', 3, TRUE);

-- Insert quiz categories
select * from quiz_categories;
INSERT INTO quiz_categories (category_name, description, icon, color) VALUES
('Polynomial Division Basics', 'Basic concepts of Division of polynomials', 'fas fa-cube', '#3498db');

-- Insert badges
INSERT INTO badges (badge_name, description, icon, badge_type, criteria_type, criteria_value, points_awarded, color, difficulty) VALUES
('Quiz Novice', 'Complete your first quiz', 'fas fa-star', 'achievement', 'quiz_completed', '1', 100, '#3498db', 'easy');

-- Insert course modules
INSERT INTO course_modules (lesson_id, module_name, module_order, module_description, description, estimated_duration_minutes) VALUES
(2, 'Dividing Polynomials Using Long and Synthetic Division', 1, 
 'Dividing Polynomials Using Long and Synthetic Division',
 'Dividing Polynomials Using Long and Synthetic Division introduces efficient methods for dividing polynomials to find quotients and remainders.', 60);

INSERT INTO course_modules (lesson_id, module_name, module_order, module_description, description, estimated_duration_minutes) VALUES
(1, 'Polynomial Factors', 2, 
 'Polynomial Factors',
 'Factoring a polynomial is the process of decomposing a polynomial into a product of two or more polynomials.', 60);

select * from course_modules;
-- Insert module topics
INSERT INTO module_topics (module_id, topic_title, topic_description, topic_order, description, is_active) VALUES
(1, 'Dividing Polynomials Using Long and Synthetic Division', 
 'Dividing Polynomials Using Long and Synthetic Division', 1, 
 'Dividing Polynomials Using Long and Synthetic Division', TRUE);

INSERT INTO module_topics (module_id, topic_title, topic_description, topic_order, description, is_active) VALUES
(1, 'Polynomial Factors', 
 'Polynomial Factors', 2, 
 'Polynomial Factors', TRUE);

-- Insert topic content items
select * from topic_content_items;
INSERT INTO topic_content_items (
    topic_id, module_id, content_type, content_title, content_description, content_order,
    content_duration_minutes, content_url, video_filename, video_path, video_size,
    video_duration_seconds, video_metadata, is_required, is_active
) VALUES (
    1, 1, 'video',
    'Dividing Polynomials Using Long and Synthetic Division',
    'This lesson covers polynomial division methods including long division and synthetic division...',
    1, 12,
    'http://localhost:5000/videos/quarter1-polynomial-equations.mp4',
    'quarter1-polynomial-equations.mp4',
    '/videos/quarter1-polynomial-equations.mp4',
    16170813, 720,
    '{"resolution": "1080p", "format": "mp4", "codec": "h264", "bitrate": "5000kbps"}',
    TRUE, TRUE
);

INSERT INTO topic_content_items (
    topic_id, module_id, content_type, content_title, content_description, content_order,
    content_duration_minutes, content_url, video_filename, video_path, video_size,
    video_duration_seconds, video_metadata, is_required, is_active
) VALUES (
    2, 1, 'video',
    'Polynomial Factors',
    'This lesson covers polynomial factors and factoring techniques...',
    1, 37,
    'http://localhost:5000/videos/Factoring_polynomials_1.mp4',
    'Factoring_polynomials_1.mp4',
    '/videos/Factoring_polynomials_1.mp4',
    42954684, 2220,
    '{"resolution": "1080p", "format": "mp4", "codec": "h264", "bitrate": "5000kbps"}',
    TRUE, TRUE
);

-- Insert practice exercises
select * from practice_exercises;
INSERT INTO practice_exercises (topic_id, title, description, content_type, difficulty, points, content_json) VALUES
(1, 'Polynomial Division Basics', 'Practice basic polynomial division problems', 'multiple_choice', 'easy', 10, 
 '{
   "questions": [
     {
       "id": 1,
       "text": "Divide (x² + 5x + 6) by (x + 2)",
       "type": "multiple_choice",
       "options": [
         {"id": 1, "text": "x + 3", "correct": true},
         {"id": 2, "text": "x - 3", "correct": false},
         {"id": 3, "text": "x² + 3", "correct": false},
         {"id": 4, "text": "x - 2", "correct": false}
       ]
     },
     {
       "id": 2,
       "text": "What is the remainder when dividing (2x³ - 3x² + x - 1) by (x - 1)?",
       "type": "multiple_choice",
       "options": [
         {"id": 1, "text": "-1", "correct": true},
         {"id": 2, "text": "0", "correct": false},
         {"id": 3, "text": "1", "correct": false},
         {"id": 4, "text": "2", "correct": false}
       ]
     }
   ]
 }');

select * from quizzes;
-- Insert quizzes
INSERT INTO quizzes (category_id, topic_id, quiz_title, description, difficulty, duration_minutes, total_questions, passing_score) VALUES
(1, 1, 'Polynomial Division Fundamentals', 'Test your understanding of basic polynomial division concepts', 'easy', 10, 7, 70.00);

-- Insert quiz questions
select * from quiz_questions;
INSERT INTO quiz_questions (quiz_id, question_text, question_type, points, question_order) VALUES
(1, 'What is the result of dividing (x² + 5x + 6) by (x + 2)?', 'multiple_choice', 10, 1),
(1, 'Which method is used when dividing by a linear factor (x - c)?', 'multiple_choice', 10, 2),
(1, 'What is the remainder when dividing (x³ - 8) by (x - 2)?', 'multiple_choice', 10, 3),
(1, 'True or False: Synthetic division can be used for any divisor.', 'true_false', 10, 4),
(1, 'Complete the division: (2x³ - 3x² + x - 1) ÷ (x - 1) = ________', 'fill_blank', 15, 5);

-- Insert quiz options
select * from quiz_options;
INSERT INTO quiz_options (question_id, option_text, is_correct, option_order) VALUES
(1, 'x + 3', TRUE, 1),
(1, 'x - 3', FALSE, 2),
(1, 'x² + 3x + 2', FALSE, 3),
(1, 'x - 2', FALSE, 4),
(2, 'Synthetic division', TRUE, 1),
(2, 'Long division', FALSE, 2),
(2, 'Polynomial expansion', FALSE, 3),
(2, 'Both synthetic and long division work', FALSE, 4),
(3, '0', TRUE, 1),
(3, '16', FALSE, 2),
(3, '-8', FALSE, 3),
(3, '2', FALSE, 4),
(4, 'True', FALSE, 1),
(4, 'False', TRUE, 2),
(5, '2x² - x', TRUE, 1),
(5, '2x² - x + 1', FALSE, 2),
(5, '2x² - x - 1', FALSE, 3),
(5, '2x² + x', FALSE, 4);

-- Insert video uploads
INSERT INTO video_uploads (content_id, original_filename, stored_filename, file_path, file_size, duration_seconds, resolution, uploaded_by, is_active) VALUES
(1, 'quarter1-polynomial-equations.mp4', 'quarter1-polynomial-equations.mp4', '/videos/quarter1-polynomial-equations.mp4', 16170813, 720, '1280x720', 2, TRUE),
(2, 'Factoring_polynomials_1.mp4', 'Factoring_polynomials_1.mp4', '/videos/Factoring_polynomials_1.mp4', 42954684, 2220, '1280x720', 2, TRUE);

-- Initialize progress for existing users
CALL sp_initialize_user_progress(1);

-- ============================================
-- VERIFY INSTALLATION
-- ============================================
SELECT * FROM content_video ORDER BY video_id DESC LIMIT 5;


SELECT 
    content_id,
    content_title,
    content_type,
    video_filename,
    content_url,
    topic_id,
    module_id,
    created_at,
    is_active
FROM topic_content_items
ORDER BY content_id DESC
LIMIT 20;

UPDATE topic_content_items 
SET content_url = CONCAT('http://localhost:5000/uploads/videos/', video_filename)
WHERE content_id = 3;

-- I-verify ang update



-- Show all tables
SHOW TABLES;



-- Show counts for verification
SELECT 'users' as table_name, COUNT(*) as count FROM users
UNION ALL
SELECT 'lessons', COUNT(*) FROM lessons
UNION ALL
SELECT 'course_modules', COUNT(*) FROM course_modules
UNION ALL
SELECT 'module_topics', COUNT(*) FROM module_topics
UNION ALL
SELECT 'topic_content_items', COUNT(*) FROM topic_content_items
UNION ALL
SELECT 'practice_exercises', COUNT(*) FROM practice_exercises
UNION ALL
SELECT 'quizzes', COUNT(*) FROM quizzes
UNION ALL
SELECT 'quiz_questions', COUNT(*) FROM quiz_questions
UNION ALL
SELECT 'quiz_options', COUNT(*) FROM quiz_options
ORDER BY table_name;


-- Tingnan kung ilan ang duplicate
SELECT user_id, feedback_message, COUNT(*) as count, MIN(created_at) as first, MAX(created_at) as last
FROM feedback 
GROUP BY user_id, feedback_message, DATE(created_at)
HAVING COUNT(*) > 1;

-- Delete duplicates (keep the earliest one)
DELETE f1 FROM feedback f1
INNER JOIN feedback f2 
WHERE 
    f1.feedback_id > f2.feedback_id 
    AND f1.user_id = f2.user_id 
    AND f1.feedback_message = f2.feedback_message
    AND DATE(f1.created_at) = DATE(f2.created_at);

-- I-verify na isa na lang per submission
SELECT * FROM feedback WHERE user_id = 1 ORDER BY created_at DESC;


-- Tingnan ang lahat ng attempts
SELECT 
    uqa.attempt_id,
    u.username,
    u.user_id,
    q.quiz_title,
    uqa.score,
    uqa.end_time,
    DATE(uqa.end_time) as attempt_date
FROM user_quiz_attempts uqa
JOIN users u ON uqa.user_id = u.user_id
JOIN quizzes q ON uqa.quiz_id = q.quiz_id
WHERE uqa.completion_status = 'completed'
ORDER BY uqa.end_time DESC
LIMIT 20;


-- Check if tables exist
SHOW TABLES;

-- Check if there are lessons (topic_content_items)
SELECT COUNT(*) as total_lessons FROM topic_content_items WHERE is_active = TRUE;

-- Check if there are subjects (lessons)
SELECT COUNT(*) as total_subjects FROM lessons WHERE is_active = TRUE;

-- Check if there are students
SELECT COUNT(*) as total_students FROM users WHERE role = 'student' AND is_active = 1;

-- Check all users
SELECT user_id, username, email, role, is_active FROM users;

SELECT 
    l.lesson_id,
    l.lesson_name,
    COUNT(tci.content_id) as lesson_count
FROM lessons l
LEFT JOIN course_modules cm ON l.lesson_id = cm.lesson_id
LEFT JOIN module_topics mt ON cm.module_id = mt.module_id
LEFT JOIN topic_content_items tci ON mt.topic_id = tci.topic_id
WHERE l.is_active = TRUE
GROUP BY l.lesson_id;

-- Check all quizzes with their subject_id
SELECT 
    quiz_id,
    quiz_title,
    category_id as subject_id,
    CASE 
        WHEN category_id = 2 THEN 'PolyLearn'
        WHEN category_id = 1 THEN 'MathEase'
        WHEN category_id = 3 THEN 'FactoLearn'
        ELSE 'Unknown'
    END as subject_name
FROM quizzes;

UPDATE quizzes 
SET category_id = 2 
WHERE quiz_id IN (3, 4);

select * from quiz_categories;

UPDATE quiz_categories 
SET category_name = 'MathEase',
    description = 'Order of operations: Multiplication, Division, Addition, Subtraction',
    icon = 'fas fa-divide',
    color = '#0066cc'
WHERE category_id = 1;

INSERT INTO quiz_categories (category_id, category_name, description, icon, color) 
VALUES (2, 'PolyLearn', 'Polynomial functions and algebraic expressions', 'fas fa-superscript', '#7a0000');
