const User = require('../models/User');
const jwt = require('jsonwebtoken');

// Generate JWT Token
const generateToken = (userId) => {
    return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRE
    });
};

// @desc    Register user
// @route   POST /api/auth/register
exports.register = async (req, res) => {
    try {
        const { username, email, password, full_name } = req.body;
        
        // Validation
        if (!username || !email || !password) {
            return res.status(400).json({ 
                success: false, 
                message: 'Please provide username, email and password' 
            });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 6 characters' 
            });
        }
        
        // Check if user exists
        const existingEmail = await User.findByEmail(email);
        if (existingEmail) {
            return res.status(400).json({ 
                success: false, 
                message: 'Email already registered' 
            });
        }
        
        const existingUsername = await User.findByUsername(username);
        if (existingUsername) {
            return res.status(400).json({ 
                success: false, 
                message: 'Username already taken' 
            });
        }
        
        // Create user
        const user = await User.create({
            username,
            email,
            password,
            full_name
        });
        
        // Generate token
        const token = generateToken(user.user_id);
        
        // Update last login
        await User.updateLoginTime(user.user_id);
        
        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            token,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email,
                full_name: user.full_name || user.username,
                lessons_completed: user.lessons_completed || 0,
                exercises_completed: user.exercises_completed || 0,
                quiz_score: user.quiz_score || 0,
                average_time: user.average_time || 0,
                streak_days: user.streak_days || 0,
                achievements: user.achievements || 0,
                accuracy_rate: user.accuracy_rate || 0
            }
        });
        
    } catch (error) {
        console.error('Registration error:', error.message);
        res.status(500).json({
            success: false,
            message: error.message || 'Server error'
        });
    }
};

// @desc    Login user
// @route   POST /api/auth/login
exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Validation
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: 'Please provide email and password'
            });
        }
        
        // Check if user exists
        const user = await User.findByEmail(email);
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Check password
        const isMatch = await User.comparePassword(password, user.password_hash);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid credentials'
            });
        }
        
        // Generate token
        const token = generateToken(user.user_id);
        
        // Update last login
        await User.updateLoginTime(user.user_id);
        
        // Get updated user with progress
        const userWithProgress = await User.findById(user.user_id);
        
        res.json({
            success: true,
            message: 'Login successful',
            token,
            user: {
                id: userWithProgress.user_id,
                username: userWithProgress.username,
                email: userWithProgress.email,
                full_name: userWithProgress.full_name || userWithProgress.username,
                lessons_completed: userWithProgress.lessons_completed || 0,
                exercises_completed: userWithProgress.exercises_completed || 0,
                quiz_score: userWithProgress.quiz_score || 0,
                average_time: userWithProgress.average_time || 0,
                streak_days: userWithProgress.streak_days || 0,
                achievements: userWithProgress.achievements || 0,
                accuracy_rate: userWithProgress.accuracy_rate || 0
            }
        });
        
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// @desc    Get current user
// @route   GET /api/auth/me
exports.getMe = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }
        
        res.json({
            success: true,
            user: {
                id: user.user_id,
                username: user.username,
                email: user.email,
                full_name: user.full_name || user.username,
                lessons_completed: user.lessons_completed || 0,
                exercises_completed: user.exercises_completed || 0,
                quiz_score: user.quiz_score || 0,
                average_time: user.average_time || 0,
                streak_days: user.streak_days || 0,
                achievements: user.achievements || 0,
                accuracy_rate: user.accuracy_rate || 0
            }
        });
        
    } catch (error) {
        console.error('Get user error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};

// @desc    Logout user
// @route   POST /api/auth/logout
exports.logout = async (req, res) => {
    try {
        // In production, you might want to blacklist the token
        res.json({
            success: true,
            message: 'Logout successful'
        });
    } catch (error) {
        console.error('Logout error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Server error'
        });
    }
};