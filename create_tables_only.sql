-- ============================================
-- CORE TABLES (No foreign key dependencies)
-- ============================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
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

-- Lessons table
CREATE TABLE IF NOT EXISTS lessons (
    lesson_id INT AUTO_INCREMENT PRIMARY KEY,
    lesson_name ENUM('mathease', 'polylearn', 'factolearn') NOT NULL,
    lesson_title VARCHAR(100) NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    lesson_order INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_lesson_name_order (lesson_name, lesson_order)
);

-- Quiz categories table
CREATE TABLE IF NOT EXISTS quiz_categories (
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
CREATE TABLE IF NOT EXISTS badges (
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

-- ============================================
-- TABLES WITH SINGLE DEPENDENCY
-- ============================================

-- Teachers table (depends on users)
CREATE TABLE IF NOT EXISTS teachers (
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    INDEX idx_rating (rating)
);

-- Course modules table (depends on lessons)
CREATE TABLE IF NOT EXISTS course_modules (
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

-- Module topics table (depends on course_modules)
CREATE TABLE IF NOT EXISTS module_topics (
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

-- Practice exercises table (depends on module_topics)
CREATE TABLE IF NOT EXISTS practice_exercises (
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

-- Topic content items table (depends on module_topics and course_modules)
CREATE TABLE IF NOT EXISTS topic_content_items (
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
    
    -- Teacher reference columns
    teacher_id INT NULL,
    created_by INT NULL,
    
    -- Status columns
    is_required BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE CASCADE,
    FOREIGN KEY (module_id) REFERENCES course_modules(module_id) ON DELETE SET NULL,
    FOREIGN KEY (teacher_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_teacher (teacher_id),
    UNIQUE KEY unique_content_order (topic_id, content_order)
);

-- Quizzes table (depends on quiz_categories and module_topics)
CREATE TABLE IF NOT EXISTS quizzes (
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
    created_by INT NULL,
    assigned_teacher_id INT NULL,
    FOREIGN KEY (category_id) REFERENCES quiz_categories(category_id) ON DELETE CASCADE,
    FOREIGN KEY (topic_id) REFERENCES module_topics(topic_id) ON DELETE SET NULL,
    FOREIGN KEY (assigned_teacher_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_topic (topic_id),
    INDEX idx_difficulty (difficulty)
);

-- Quiz questions table (depends on quizzes)
CREATE TABLE IF NOT EXISTS quiz_questions (
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

-- Quiz options table (depends on quiz_questions)
CREATE TABLE IF NOT EXISTS quiz_options (
    option_id INT AUTO_INCREMENT PRIMARY KEY,
    question_id INT NOT NULL,
    option_text TEXT NOT NULL,
    is_correct BOOLEAN DEFAULT FALSE,
    option_order INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (question_id) REFERENCES quiz_questions(question_id) ON DELETE CASCADE,
    UNIQUE KEY unique_question_option (question_id, option_order)
);

-- Video uploads table (depends on topic_content_items and users)
CREATE TABLE IF NOT EXISTS video_uploads (
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
-- USER PROGRESS TABLES
-- ============================================

-- User progress summary table
CREATE TABLE IF NOT EXISTS user_progress (
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
CREATE TABLE IF NOT EXISTS user_content_progress (
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
CREATE TABLE IF NOT EXISTS user_practice_progress (
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
CREATE TABLE IF NOT EXISTS user_topic_progress (
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
CREATE TABLE IF NOT EXISTS user_quiz_attempts (
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
CREATE TABLE IF NOT EXISTS user_quiz_answers (
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
CREATE TABLE IF NOT EXISTS user_badges (
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
CREATE TABLE IF NOT EXISTS user_points (
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
CREATE TABLE IF NOT EXISTS daily_progress (
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
CREATE TABLE IF NOT EXISTS cumulative_progress (
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
CREATE TABLE IF NOT EXISTS user_activity_log (
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
CREATE TABLE IF NOT EXISTS topic_mastery (
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
CREATE TABLE IF NOT EXISTS progress_heatmap (
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
CREATE TABLE IF NOT EXISTS feedback (
    feedback_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    teacher_id INT NULL,
    related_id INT NULL,
    feedback_type ENUM('suggestion', 'bug', 'praise', 'rating', 'complaint', 'question', 'other') NOT NULL,
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
    FOREIGN KEY (teacher_id) REFERENCES users(user_id) ON DELETE SET NULL,
    FOREIGN KEY (admin_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_feedback_type (feedback_type),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at),
    INDEX idx_user_id (user_id),
    INDEX idx_related (related_id),
    INDEX idx_feedback_teacher (teacher_id)
);

-- Practice attempts table
CREATE TABLE IF NOT EXISTS practice_attempts (
    attempt_id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    exercise_id INT NOT NULL,
    answers JSON NULL,
    max_score INT DEFAULT 0,
    score INT DEFAULT 0,
    percentage INT DEFAULT 0,
    completion_status ENUM('in_progress', 'completed', 'failed') DEFAULT 'in_progress',
    attempt_number INT DEFAULT 1,
    attempts INT DEFAULT 1,
    time_spent_seconds INT DEFAULT 0,
    last_attempted TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (exercise_id) REFERENCES practice_exercises(exercise_id) ON DELETE CASCADE,
    INDEX idx_user_practice (user_id, exercise_id),
    INDEX idx_completion (completion_status),
    INDEX idx_created_at (created_at),
    INDEX idx_percentage (percentage)
);