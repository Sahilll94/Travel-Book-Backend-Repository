require("dotenv").config(); //It will point on config.json file and fetch the data;


const cloudinary = require('cloudinary').v2;
// const config = require('./config.json');
const config = require("./config.json");
const mongoose = require("mongoose")
const bcrypt = require("bcrypt");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
// Importing the nodemailer module
const nodemailer = require("nodemailer");
const crypto = require("crypto");

// Import Firebase Admin
const admin = require('./firebase-admin');

// Import Chatbot Service
const { handleChatRequest, getChatbotStatus } = require('./services/chatbot.service');

// Helper function to get client IP from various headers
function getClientIp(req) {
    // For AWS EC2, try multiple headers
    const forwardedIps = (
        req.headers['x-forwarded-for'] || 
        req.headers['x-real-ip'] || 
        req.headers['cf-connecting-ip'] || // Cloudflare
        req.headers['true-client-ip'] || // Akamai
        ''
    ).split(',');
    
    // Get the first IP in the list (client's original IP)
    const clientIp = forwardedIps[0]?.trim() || req.ip || req.connection.remoteAddress || '';
    
    // If we still have a localhost IP, try to get the real external IP
    return clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '' ? 
        process.env.NODE_ENV === 'production' ? 'Unknown' : '127.0.0.1' : 
        clientIp;
}

// Helper function to parse device info from user agent
function getDeviceInfo(userAgent) {
    if (!userAgent) return 'Unknown Device';
    
    // Simple OS detection
    if (userAgent.includes('Windows')) return 'Windows';
    if (userAgent.includes('Mac OS')) return 'Mac OS';
    if (userAgent.includes('iPhone') || userAgent.includes('iPad')) return 'iOS';
    if (userAgent.includes('Android')) return 'Android';
    if (userAgent.includes('Linux')) return 'Linux';
    
    return 'Unknown OS';
}

// app.use(cors());
const app = express();

// Trust proxy for AWS EC2
app.set('trust proxy', true);

cloudinary.config({
    cloud_name: config.cloudinary.cloud_name,
    api_key: config.cloudinary.api_key,
    api_secret: config.cloudinary.api_secret,
});

// Parse CORS origins from .env
const corsOrigins = process.env.CORS_ORIGINS 
    ? process.env.CORS_ORIGINS.split(',').map(origin => origin.trim())
    : ['http://localhost:5173'];

const corsOptions = {
    origin: corsOrigins,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true,
    maxAge: 86400
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Importing all the models;
const User = require("./models/user.model");
const TravelStory = require("./models/travelStory.model");
const Contributor = require("./models/contributor.model");


const { authenticateToken, generateOTP, sendOTP, sendPasswordResetConfirmation } = require("./utilities");
const { sendLoginNotification } = require("./sendLoginNotification");
const upload = require("./multer");
const fs = require("fs");
const path = require("path");
const { Readable } = require("stream");
const { error } = require("console");

mongoose.connect(config.connectionString)
    .then(() => console.log("Connected to MongoDB successfully"))
    .catch(err => console.error("MongoDB connection error:", err));


app.use(express.json());
// app.use(cors({ origin: "*" })) //To allow anyone to use the backend;

// TO CREATE AN ACCOUNT and we will configure it using POSTMAN;
app.post("/create-account", async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({
            error: true,
            message: "All fields are required to create your travel memory!"
        });
    }

    try {
        const isUser = await User.findOne({ email });
        if (isUser) {
            return res.status(400).json({
                error: true,
                message: "User already has a travel book!"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({
            fullName,
            email,
            password: hashedPassword,
        });

        await user.save();

        const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
        console.log(process.env.ACCESS_TOKEN_SECRET);

        return res.status(201).json({
            error: false,
            user: { fullName: user.fullName, email: user.email },
            accessToken,
            message: "Successfully Registered for a Travel Book!",
        });
    } catch (error) {
        if (error.code === 11000) {
            return res.status(400).json({
                error: true,
                message: `Email ${email} is already registered. Please use a different email address.`,
            });
        }
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});


// Send OTP for signup
app.post("/send-signup-otp", async (req, res) => {
    const { fullName, email, password } = req.body;

    if (!fullName || !email || !password) {
        return res.status(400).json({
            error: true,
            message: "All fields are required to create your travel memory!"
        });
    }

    try {
        // Check if user already exists
        const isUser = await User.findOne({ email });
        if (isUser && isUser.isVerified) {
            return res.status(400).json({
                error: true,
                message: "User already has a travel book!"
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP valid for 10 minutes

        if (isUser) {
            // Update existing unverified user with new OTP
            isUser.otp = otp;
            isUser.otpExpiry = otpExpiry;
            await isUser.save();
        } else {
            // Create new user with OTP
            const hashedPassword = await bcrypt.hash(password, 10);
            const user = new User({
                fullName,
                email,
                password: hashedPassword,
                otp,
                otpExpiry,
                isVerified: false
            });
            await user.save();
        }

        // Send OTP via email
        const emailSent = await sendOTP(email, otp);

        if (!emailSent) {
            return res.status(500).json({
                error: true,
                message: "Failed to send OTP. Please try again."
            });
        }

        return res.status(200).json({
            error: false,
            message: "OTP sent to your email. Please verify to complete registration."
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// Verify OTP for signup
app.post("/verify-signup-otp", async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({
            error: true,
            message: "Email and OTP are required"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                error: true,
                message: "User not found"
            });
        }

        // Check if OTP is valid and not expired
        if (user.otp !== otp) {
            return res.status(400).json({
                error: true,
                message: "Invalid OTP"
            });
        }

        if (new Date() > user.otpExpiry) {
            return res.status(400).json({
                error: true,
                message: "OTP has expired. Please request a new one."
            });
        }

        // Mark user as verified
        user.isVerified = true;
        user.otp = undefined;
        user.otpExpiry = undefined;
        await user.save();

        // Generate JWT token
        const accessToken = jwt.sign(
            { userId: user._id },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "72h" }
        );

        return res.status(200).json({
            error: false,
            message: "Account verified successfully!",
            user: { fullName: user.fullName, email: user.email },
            accessToken
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// Send OTP for login
app.post("/send-login-otp", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            error: true,
            message: "Email is required"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                error: true,
                message: "User not found"
            });
        }

        if (!user.isVerified) {
            return res.status(400).json({
                error: true,
                message: "Account not verified. Please sign up first."
            });
        }

        // Generate OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP valid for 10 minutes

        // Save OTP to user
        user.otp = otp;
        user.otpExpiry = otpExpiry;
        await user.save();

        // Send OTP via email
        const emailSent = await sendOTP(email, otp);

        if (!emailSent) {
            return res.status(500).json({
                error: true,
                message: "Failed to send OTP. Please try again."
            });
        }

        return res.status(200).json({
            error: false,
            message: "OTP sent to your email. Please verify to login."
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// Verify OTP for login
app.post("/verify-login-otp", async (req, res) => {
    const { email, otp } = req.body;

    if (!email || !otp) {
        return res.status(400).json({
            error: true,
            message: "Email and OTP are required"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                error: true,
                message: "User not found"
            });
        }

        // Check if OTP is valid and not expired
        if (user.otp !== otp) {
            return res.status(400).json({
                error: true,
                message: "Invalid OTP"
            });
        }

        if (new Date() > user.otpExpiry) {
            return res.status(400).json({
                error: true,
                message: "OTP has expired. Please request a new one."
            });
        }

        // Clear OTP after successful verification
        user.otp = undefined;
        user.otpExpiry = undefined;
        await user.save();

        // Generate JWT token
        const accessToken = jwt.sign(
            { userId: user._id },
            process.env.ACCESS_TOKEN_SECRET,
            { expiresIn: "72h" }
        );

        // Collect device information from request headers
        const deviceInfo = {
            ip: getClientIp(req),
            browser: req.headers['user-agent'] || 'Unknown Browser',
            os: getDeviceInfo(req.headers['user-agent'] || '')
        };

        // Send login notification email (don't await to prevent blocking response)
        sendLoginNotification(email, deviceInfo)
            .then(sent => {
                if (sent) {
                    console.log(`Login notification email sent to ${email}`);
                } else {
                    console.log(`Failed to send login notification email to ${email}`);
                }
            })
            .catch(err => {
                console.error('Error sending login notification:', err);
            });

        return res.status(200).json({
            error: false,
            message: "Login successful!",
            user: { fullName: user.fullName, email: user.email },
            accessToken
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// Resend OTP (can be used for both signup and login)
app.post("/resend-otp", async (req, res) => {
    const { email, isSignup } = req.body;

    if (!email) {
        return res.status(400).json({
            error: true,
            message: "Email is required"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                error: true,
                message: "User not found"
            });
        }

        // For login, check if user is verified
        if (!isSignup && !user.isVerified) {
            return res.status(400).json({
                error: true,
                message: "Account not verified. Please sign up first."
            });
        }

        // Generate new OTP
        const otp = generateOTP();
        const otpExpiry = new Date();
        otpExpiry.setMinutes(otpExpiry.getMinutes() + 10); // OTP valid for 10 minutes

        // Save OTP to user
        user.otp = otp;
        user.otpExpiry = otpExpiry;
        await user.save();

        // Send OTP via email
        const emailSent = await sendOTP(email, otp);

        if (!emailSent) {
            return res.status(500).json({
                error: true,
                message: "Failed to send OTP. Please try again."
            });
        }

        return res.status(200).json({
            error: false,
            message: "OTP resent to your email."
        });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// TO LOGIN;
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({
            message: "Email and Password is required to use your Travel Book"
        });
    }

    const user = await User.findOne({ email });
    if (!user) {
        return res.status(400).json({
            message: "User not found"
        });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
        return res.status(400).json({
            message: "Invalid Credentials!"
        });
    }

    const accessToken = jwt.sign(
        { userId: user._id },
        process.env.ACCESS_TOKEN_SECRET,
        { expiresIn: "72h", }
    );

    // Collect device information from request headers
    const deviceInfo = {
        ip: getClientIp(req),
        browser: req.headers['user-agent'] || 'Unknown Browser',
        os: getDeviceInfo(req.headers['user-agent'] || '')
    };

    // Send login notification email (don't await to prevent blocking response)
    sendLoginNotification(email, deviceInfo)
        .then(sent => {
            if (sent) {
                console.log(`Login notification email sent to ${email}`);
            } else {
                console.log(`Failed to send login notification email to ${email}`);
            }
        })
        .catch(err => {
            console.error('Error sending login notification:', err);
        });

    return res.json({
        error: false,
        message: "Login Succefully to Travel Book",
        user: { fullName: user.fullName, email: user.email },
        accessToken,
    });
});


// Google OAuth Authentication
app.post("/google-auth", async (req, res) => {
    const { email, fullName, photoURL, uid } = req.body;
    console.log('Google auth endpoint - received request');
    
    if (!email || !uid) {
        return res.status(400).json({
            error: true,
            message: "Email and user ID are required for Google authentication"
        });
    }
    
    try {
        // Verify the Firebase token
        const authHeader = req.headers.authorization;
        console.log('Google auth - received auth header:', authHeader ? 'present' : 'missing');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('Google auth - invalid header format');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        const idToken = authHeader.split('Bearer ')[1];
        console.log('Google auth - token present:', idToken ? 'yes' : 'no', 'token preview:', idToken ? `${idToken.substring(0, 10)}...` : 'none');
        
        if (!idToken) {            console.log('Google auth - empty token after Bearer prefix');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        try {
            console.log('Google auth - verifying token with Firebase Admin...');
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            console.log('Google auth - token verified successfully, decoded UID:', decodedToken.uid);
            
            if (decodedToken.uid !== uid) {
                console.log('Google auth - UID mismatch:', decodedToken.uid, 'vs', uid);
                return res.status(403).json({
                    error: true,
                    message: "Unauthorized access. Token UID does not match provided UID."
                });
            }
        } catch (tokenError) {
            console.error("Google auth - Token verification error:", tokenError);
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid or expired Firebase ID token."
            });
        }
        
        // Check if user exists
        let user = await User.findOne({ email });
        
        if (user) {
            // User exists, update Google information if not already set
            if (!user.googleId) {
                user.googleId = uid;
                user.profilePicture = user.profilePicture || photoURL;
                await user.save();
            }
        } else {
            // Create new user
            user = new User({
                fullName,
                email,
                googleId: uid,
                profilePicture: photoURL,
                emailVerified: true // Google emails are verified
            });
            
            await user.save();
        }
        
        // Generate JWT token
        const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
        
        // Log login information
        const ip = getClientIp(req);
        const device = getDeviceInfo(req.headers['user-agent']);
        
        // Attempt to send login notification in background
        try {
            sendLoginNotification(user.email, ip, device, 'Google');
        } catch (notificationError) {
            console.error("Failed to send login notification:", notificationError);
        }
        
        return res.status(200).json({
            success: true,
            token: accessToken,
            user: {
                fullName: user.fullName,
                email: user.email,
                profilePicture: user.profilePicture,
                id: user._id
            }
        });    } catch (error) {
        console.error("Google auth error:", error);
        
        // Provide more detailed error messages
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).json({
                error: true,
                code: 'token_expired',
                message: "Authentication token has expired. Please sign in again."
            });
        } else if (error.code === 'auth/id-token-revoked') {
            return res.status(401).json({
                error: true,
                code: 'token_revoked',
                message: "Authentication token has been revoked. Please sign in again."
            });
        } else if (error.code === 'auth/invalid-id-token') {
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid authentication token. Please sign in again."
            });
        } else if (error.message && error.message.includes('email')) {
            return res.status(400).json({
                error: true,
                code: 'email_conflict',
                message: "This email is already associated with a different authentication method. Please use your original sign-in method."
            });
        } else {
            return res.status(500).json({
                error: true,
                message: "Authentication failed. Please try again."
            });
        }
    }
});

// GitHub OAuth Authentication
app.post("/github-auth", async (req, res) => {
    const { email, fullName, photoURL, uid } = req.body;
    console.log('GitHub auth endpoint - received request');
    
    if (!email || !uid) {
        return res.status(400).json({
            error: true,
            message: "Email and user ID are required for GitHub authentication"
        });
    }
    
    try {
        // Verify the Firebase token
        const authHeader = req.headers.authorization;
        console.log('GitHub auth - received auth header:', authHeader ? 'present' : 'missing');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('GitHub auth - invalid header format');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        const idToken = authHeader.split('Bearer ')[1];
        console.log('GitHub auth - token present:', idToken ? 'yes' : 'no', 'token preview:', idToken ? `${idToken.substring(0, 10)}...` : 'none');
        
        if (!idToken) {            console.log('GitHub auth - empty token after Bearer prefix');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        try {
            console.log('GitHub auth - verifying token with Firebase Admin...');
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            console.log('GitHub auth - token verified successfully, decoded UID:', decodedToken.uid);
            
            if (decodedToken.uid !== uid) {
                console.log('GitHub auth - UID mismatch:', decodedToken.uid, 'vs', uid);
                return res.status(403).json({
                    error: true,
                    message: "Unauthorized access. Token UID does not match provided UID."
                });
            }
        } catch (tokenError) {
            console.error("GitHub auth - Token verification error:", tokenError);
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid or expired Firebase ID token."
            });
        }
        
        // Check if user exists
        let user = await User.findOne({ email });
        
        if (user) {
            // User exists, update GitHub information if not already set
            if (!user.githubId) {
                user.githubId = uid;
                user.profilePicture = user.profilePicture || photoURL;
                await user.save();
            }
        } else {
            // Create new user
            user = new User({
                fullName,
                email,
                githubId: uid,
                profilePicture: photoURL,
                emailVerified: true // GitHub emails are verified
            });
            
            await user.save();
        }
        
        // Generate JWT token
        const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
        
        // Log login information
        const ip = getClientIp(req);
        const device = getDeviceInfo(req.headers['user-agent']);
        
        // Attempt to send login notification in background
        try {
            sendLoginNotification(user.email, ip, device, 'GitHub');
        } catch (notificationError) {
            console.error("Failed to send login notification:", notificationError);
        }
        
        return res.status(200).json({
            success: true,
            token: accessToken,
            user: {
                fullName: user.fullName,
                email: user.email,
                profilePicture: user.profilePicture,
                id: user._id
            }
        });    } catch (error) {
        console.error("GitHub auth error:", error);
        
        // Provide more detailed error messages
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).json({
                error: true,
                code: 'token_expired',
                message: "Authentication token has expired. Please sign in again."
            });
        } else if (error.code === 'auth/id-token-revoked') {
            return res.status(401).json({
                error: true,
                code: 'token_revoked',
                message: "Authentication token has been revoked. Please sign in again."
            });
        } else if (error.code === 'auth/invalid-id-token') {
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid authentication token. Please sign in again."
            });
        } else if (error.message && error.message.includes('email')) {
            return res.status(400).json({
                error: true,
                code: 'email_conflict',
                message: "This email is already associated with a different authentication method. Please use your original sign-in method."
            });
        } else {
            return res.status(500).json({
                error: true,
                message: "Authentication failed. Please try again."
            });
        }
    }
});

// Twitter OAuth Authentication
app.post("/twitter-auth", async (req, res) => {
    const { email, fullName, photoURL, uid } = req.body;
    console.log('Twitter auth endpoint - received request');
    
    if (!email || !uid) {
        return res.status(400).json({
            error: true,
            message: "Email and user ID are required for Twitter authentication"
        });
    }
    
    try {
        // Verify the Firebase token
        const authHeader = req.headers.authorization;
        console.log('Twitter auth - received auth header:', authHeader ? 'present' : 'missing');
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            console.log('Twitter auth - invalid header format');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        const idToken = authHeader.split('Bearer ')[1];
        console.log('Twitter auth - token present:', idToken ? 'yes' : 'no', 'token preview:', idToken ? `${idToken.substring(0, 10)}...` : 'none');
        
        if (!idToken) {
            console.log('Twitter auth - empty token after Bearer prefix');
            return res.status(401).json({
                error: true,
                code: 'missing_token',
                message: "Authentication token is missing or invalid."
            });
        }
        
        try {
            console.log('Twitter auth - verifying token with Firebase Admin...');
            const decodedToken = await admin.auth().verifyIdToken(idToken);
            console.log('Twitter auth - token verified successfully, decoded UID:', decodedToken.uid);
            
            if (decodedToken.uid !== uid) {
                console.log('Twitter auth - UID mismatch:', decodedToken.uid, 'vs', uid);
                return res.status(403).json({
                    error: true,
                    message: "Unauthorized access. Token UID does not match provided UID."
                });
            }
        } catch (tokenError) {
            console.error("Twitter auth - Token verification error:", tokenError);
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid or expired Firebase ID token."
            });
        }
        
        // Check if user exists
        let user = await User.findOne({ email });
        
        if (user) {
            // User exists, update Twitter information if not already set
            if (!user.twitterId) {
                user.twitterId = uid;
                user.profilePicture = user.profilePicture || photoURL;
                await user.save();
            }
        } else {
            // Create new user
            user = new User({
                fullName,
                email,
                twitterId: uid,
                profilePicture: photoURL,
                emailVerified: true // Twitter emails are verified
            });
            
            await user.save();
        }
        
        // Generate JWT token
        const accessToken = jwt.sign({ userId: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "72h" });
        
        // Log login information
        const ip = getClientIp(req);
        const device = getDeviceInfo(req.headers['user-agent']);
        
        // Attempt to send login notification in background
        try {
            sendLoginNotification(user.email, ip, device, 'Twitter');
        } catch (notificationError) {
            console.error("Failed to send login notification:", notificationError);
        }
        
        return res.status(200).json({
            success: true,
            token: accessToken,
            user: {
                fullName: user.fullName,
                email: user.email,
                profilePicture: user.profilePicture,
                id: user._id
            }
        });
    } catch (error) {
        console.error("Twitter auth error:", error);
        
        // Provide more detailed error messages
        if (error.code === 'auth/id-token-expired') {
            return res.status(401).json({
                error: true,
                code: 'token_expired',
                message: "Authentication token has expired. Please sign in again."
            });
        } else if (error.code === 'auth/id-token-revoked') {
            return res.status(401).json({
                error: true,
                code: 'token_revoked',
                message: "Authentication token has been revoked. Please sign in again."
            });
        } else if (error.code === 'auth/invalid-id-token') {
            return res.status(401).json({
                error: true,
                code: 'invalid_token',
                message: "Invalid authentication token. Please sign in again."
            });
        } else if (error.message && error.message.includes('email')) {
            return res.status(400).json({
                error: true,
                code: 'email_conflict',
                message: "This email is already associated with a different authentication method. Please use your original sign-in method."
            });
        } else {
            return res.status(500).json({
                error: true,
                message: "Authentication failed. Please try again."
            });
        }
    }
});

// TO GET USER;
app.get("/get-user", authenticateToken, async (req, res) => {
    const { userId } = req.user;

    const isUser = await User.findOne({ _id: userId });

    if (!isUser) {
        return res.sendStatus(401);
    }

    return res.json({
        user: isUser,
        message: "",
    });
});

// GET PROFILE - Get detailed user profile with stats
app.get("/profile", authenticateToken, async (req, res) => {
    const { userId } = req.user;

    try {
        // Find user but exclude password and sensitive fields
        const user = await User.findById(userId).select('-password -otp -otpExpiry -resetPasswordToken -resetPasswordExpiry');

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        // Get count of user's travel stories
        const storiesCount = await TravelStory.countDocuments({ userId });

        // Count locations visited (unique locations)
        const locationsCount = await TravelStory.distinct('visitedLocation', { userId }).length;

        // Get favorite stories count
        const favoritesCount = await TravelStory.countDocuments({ userId, isFavourite: true });

        res.status(200).json({
            error: false,
            user,
            stats: {
                stories: storiesCount,
                locations: locationsCount,
                favorites: favoritesCount
            }
        });
    } catch (error) {
        console.error("Error fetching profile:", error);
        res.status(500).json({ error: true, message: "Failed to fetch profile" });
    }
});

// UPDATE PROFILE - Update user profile information
app.put("/update-profile", authenticateToken, async (req, res) => {
    const { userId } = req.user;
    const { fullName, bio, location, phone, website, socialLinks, preferences } = req.body;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                error: true,
                message: "User not found"
            });
        }

        // Update user fields
        if (fullName) user.fullName = fullName;
        if (bio !== undefined) user.bio = bio;
        if (location !== undefined) user.location = location;
        if (phone !== undefined) user.phone = phone;
        if (website !== undefined) user.website = website;

        // Update social links if provided
        if (socialLinks) {
            user.socialLinks = {
                ...user.socialLinks || {},
                ...socialLinks
            };
        }

        // Update preferences if provided
        if (preferences) {
            user.preferences = {
                ...user.preferences || {},
                ...preferences
            };
        }

        await user.save();

        return res.status(200).json({
            user,
            message: "Profile updated successfully"
        });
    } catch (error) {
        console.error("Error updating profile:", error);
        return res.status(500).json({
            error: true,
            message: "Failed to update profile"
        });
    }
});

// UPDATE PROFILE IMAGE - Update user profile image
app.put("/update-profile-image", authenticateToken, upload.single("image"), async (req, res) => {
    const { userId } = req.user;

    try {
        if (!req.file) {
            return res.status(400).json({
                error: true,
                message: "No image uploaded"
            });
        }

        // Upload buffer directly to Cloudinary using a stream
        const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder: "travel_book/profiles",
                    resource_type: "auto",
                    quality: "auto",
                },
                (error, result) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(result);
                    }
                }
            );

            // Create a readable stream from the buffer and pipe it
            const bufferStream = Readable.from(req.file.buffer);
            bufferStream.pipe(uploadStream);
        });

        // Update user profile with new image URL
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({
                error: true,
                message: "User not found"
            });
        }

        user.profileImage = result.secure_url;
        await user.save();

        return res.status(200).json({
            error: false,
            profileImage: result.secure_url,
            message: "Profile image updated successfully"
        });
    } catch (error) {
        console.error("Profile image upload error:", error);
        return res.status(500).json({
            error: true,
            message: error.message || "Failed to update profile image"
        });
    }
});

// Route to handle image upload;
app.post("/image-upload", upload.single("image"), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({
                error: true,
                message: "No image uploaded"
            });
        }

        // Upload buffer directly to Cloudinary using upload_stream
        const result = await new Promise((resolve, reject) => {
            const uploadStream = cloudinary.uploader.upload_stream(
                {
                    folder: "travel_book", // Organize uploads by folder
                    resource_type: "auto",
                    quality: "auto",
                },
                (error, result) => {
                    if (error) {
                        reject(error);
                    } else {
                        resolve(result);
                    }
                }
            );

            // Create a readable stream from the buffer and pipe it
            const bufferStream = Readable.from(req.file.buffer);
            bufferStream.pipe(uploadStream);
        });

        // Respond with the image URL
        res.status(200).json({ 
            error: false,
            imageUrl: result.secure_url,
            message: "Image uploaded successfully"
        });
    } catch (error) {
        console.error("Image upload error:", error);
        res.status(500).json({ 
            error: true, 
            message: error.message || "Failed to upload image"
        });
    }
});


app.delete("/delete-story/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { userId } = req.user;

    try {
        // Find the travel story by ID and ensure it belongs to the authenticated user
        const travelStory = await TravelStory.findOne({ _id: id, userId: userId });

        if (!travelStory) {
            return res.status(404).json({ error: true, message: "Travel story not found" });
        }

        // Delete the travel story from the database
        await travelStory.deleteOne({ _id: id, userId: userId });

        // Extract the imageUrl and publicId from the travel story
        const imageUrl = travelStory.imageUrl;
        const publicId = imageUrl.split("/").pop().split(".")[0]; // Assuming publicId is the last part of the URL

        // If the image is hosted on Cloudinary, delete from Cloudinary
        if (imageUrl.includes("cloudinary.com")) {
            await cloudinary.uploader.destroy(publicId);
        } else {
            // For local images (if any), delete the image file from the uploads folder
            const filename = path.basename(imageUrl);
            const filePath = path.join(__dirname, 'uploads', filename);

            fs.unlink(filePath, (err) => {
                if (err) {
                    console.error("Failed to delete image file: ", err);
                }
            });
        }

        res.status(200).json({ message: "Travel Story deleted successfully!" });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }
});



// Serve static files from the uploads and the assets directory;
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use("/assets", express.static(path.join(__dirname, "assets")));

// TO ADD TRAVEL STORY;
app.post("/add-travel-story", authenticateToken, async (req, res) => {
    const { title, story, visitedLocation, imageUrl, visitedDate } = req.body;
    const { userId } = req.user;

    // Validate required fields
    if (!title || !story || !visitedLocation || !imageUrl || !visitedDate) {
        return res.status(400).json({
            error: true,
            message: "All fields are required"
        });
    };

    // Convert visitedDate from milliseconds to Date object
    const parsedVisitedDate = new Date(parseInt(visitedDate));

    try {
        const travelStory = new TravelStory({
            title,
            story,
            visitedLocation,
            userId,
            imageUrl,
            visitedDate: parsedVisitedDate,
        });

        await travelStory.save();
        res.status(201).json({ story: travelStory, message: 'Added Successfully' });
    } catch (error) {
        res.status(400).json({ error: true, message: error.message });
    }
});

// TO GET ALL THE TRAVEL STORIES;
app.get("/get-all-stories", authenticateToken, async (req, res) => {
    const { userId } = req.user;

    try {
        const travelStories = await TravelStory.find({ userId: userId }).sort({
            isFavourite: -1,
        });
        res.status(200).json({ stories: travelStories });
    } catch (error) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// Edit Travel story;
app.put("/edit-story/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { title, story, visitedLocation, imageUrl, visitedDate } = req.body;
    const { userId } = req.user;

    // Validate required fields
    if (!title || !story || !visitedLocation || !visitedDate) {
        return res
            .status(400)
            .json({ error: true, message: "All fields are required" });
    }

    // Convert visitedDate from milliseconds to Date object
    const parsedVisitedDate = new Date(parseInt(visitedDate));

    try {
        // Find the travel story by ID and ensure it belongs to the authenticated user
        const travelStory = await TravelStory.findOne({ _id: id, userId: userId });
        if (!travelStory) {
            return res.status(404).json({ error: true, message: "Travel story not found" });
        }

        const placeholderImgUrl = process.env.PLACEHOLDER_IMAGE_URL || 'https://github.com/Sahilll94/Travel-Book-Backend/blob/Updated-Branch/logo.png?raw=true';

        travelStory.title = title;
        travelStory.story = story;
        travelStory.visitedLocation = visitedLocation;
        travelStory.imageUrl = imageUrl || placeholderImgUrl;
        travelStory.visitedDate = parsedVisitedDate;

        await travelStory.save();
        res.status(200).json({ story: travelStory, message: 'Update Successful' });
    } catch (error) {
        res.status(500).json({
            error: true,
            message: error.message
        });
    }

});


// Update isFavourite
app.put("/update-is-favourite/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { isFavourite } = req.body;
    const { userId } = req.user;

    try {
        // Find the travel story by ID and ensure it belongs to the authenticated user
        const travelStory = await TravelStory.findOne({ _id: id, userId: userId });

        if (!travelStory) {
            return res.status(404).json({ error: true, message: "Travel story not found" });
        }

        // Update the isFavourite property
        travelStory.isFavourite = isFavourite;

        // Save the updated travel story
        await travelStory.save();

        // Send success response
        res.status(200).json({ story: travelStory, message: "Update Successful" });
    } catch (error) {
        // Handle errors
        res.status(500).json({ error: true, message: error.message });
    }
});

// Update showOnProfile status
app.put("/toggle-show-on-profile/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { showOnProfile } = req.body;
    const { userId } = req.user;

    try {
        // Find the travel story by ID and ensure it belongs to the authenticated user
        const travelStory = await TravelStory.findOne({ _id: id, userId: userId });

        if (!travelStory) {
            return res.status(404).json({ error: true, message: "Travel story not found" });
        }

        // Update the showOnProfile property
        travelStory.showOnProfile = showOnProfile;

        // Save the updated travel story
        await travelStory.save();

        // Send success response
        res.status(200).json({ story: travelStory, message: "Profile visibility updated successfully" });
    } catch (error) {
        // Handle errors
        res.status(500).json({ error: true, message: error.message });
    }
});

// Toggle showOnProfile status of a travel story
app.put('/toggle-show-on-profile/:id', authenticateToken, async (req, res) => {
    try {
        const storyId = req.params.id;
        const userId = req.user.userId;  // Fixed: user.id to user.userId to match other routes

        // Find the story and verify ownership
        const story = await TravelStory.findOne({ _id: storyId, userId });

        if (!story) {
            return res.status(404).json({ error: 'Story not found or you do not have permission' });
        }

        // Toggle the showOnProfile status
        story.showOnProfile = !story.showOnProfile;
        await story.save();

        res.json({ success: true, story });
    } catch (error) {
        console.error('Error toggling showOnProfile status:', error);
        res.status(500).json({ error: 'Failed to update profile visibility' });
    }
});

// Search travel stories
app.get("/search", authenticateToken, async (req, res) => {
    const { query } = req.query;
    const { userId } = req.user;

    if (!query) {
        return res.status(404).json({ error: true, message: "query is required" });
    }

    try {
        const searchResults = await TravelStory.find({
            userId: userId,
            $or: [
                { title: { $regex: query, $options: "i" } },
                { story: { $regex: query, $options: "i" } },
                { visitedLocation: { $regex: query, $options: "i" } },
            ],
        }).sort({ isFavourite: -1 });

        res.status(200).json({ stories: searchResults });
    } catch (error) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// Filter travel stories by date range
app.get("/travel-stories-filter", authenticateToken, async (req, res) => {
    const { startDate, endDate } = req.query;
    const { userId } = req.user;

    if (!startDate || !endDate) {
        return res.status(400).json({ error: true, message: "startDate and endDate parameters are required" });
    }

    try {
        // Parse dates properly - handle both ISO strings and timestamps
        let start, end;

        if (isNaN(startDate)) {
            // If it's not a number, treat as ISO string
            start = new Date(startDate);
        } else {
            // If it's a number, treat as timestamp
            start = new Date(parseInt(startDate));
        }

        if (isNaN(endDate)) {
            // If it's not a number, treat as ISO string
            end = new Date(endDate);
        } else {
            // If it's a number, treat as timestamp
            end = new Date(parseInt(endDate));
        }

        // Validate the parsed dates
        if (isNaN(start.getTime()) || isNaN(end.getTime())) {
            return res.status(400).json({ error: true, message: "Invalid date format provided" });
        }

        // Find travel stories that belong to the authenticated user and fall within the date range
        const filteredStories = await TravelStory.find({
            userId: userId,
            visitedDate: { $gte: start, $lte: end },
        }).sort({ isFavourite: -1 });

        res.status(200).json({ stories: filteredStories });
    } catch (error) {
        res.status(500).json({ error: true, message: error.message });
    }
});

// To share Card
app.get('/api/story/:id', async (req, res) => {
    const storyId = req.params.id;

    if (!mongoose.Types.ObjectId.isValid(storyId)) {
        return res.status(400).json({ error: 'Invalid story ID format' });
    }

    try {
        const story = await TravelStory.findById(storyId);
        if (story) {
            res.json(story);
        } else {
            res.status(404).json({ error: 'Story not found' });
        }
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get public profile
app.get('/api/public-profile/:userId', async (req, res) => {
    const { userId } = req.params;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ error: true, message: 'Invalid user ID format' });
    }

    try {
        // Find user but exclude sensitive fields
        const user = await User.findById(userId).select('-password -otp -otpExpiry -resetPasswordToken -resetPasswordExpiry -email');

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        // Check if profile is public
        if (user.preferences?.privacySettings?.profileVisibility !== 'public') {
            return res.status(403).json({ error: true, message: "This profile is private" });
        }

        // Get count of user's travel stories
        const storiesCount = await TravelStory.countDocuments({ userId });

        // Count locations visited (unique locations)
        const locationsCount = await TravelStory.distinct('visitedLocation', { userId }).length;

        // Get favorite stories count
        const favoritesCount = await TravelStory.countDocuments({ userId, isFavourite: true });

        // Get public travel stories - FIXED: Only get stories with showOnProfile set to true
        const recentStories = await TravelStory.find({
            userId,
            showOnProfile: true  // Only show stories marked for public profile
        })
            .sort({ createdAt: -1 })
            .limit(3);

        res.status(200).json({
            error: false,
            profile: user,
            stats: {
                stories: storiesCount,
                locations: locationsCount,
                favorites: favoritesCount
            },
            recentStories
        });
    } catch (error) {
        console.error("Error fetching public profile:", error);
        res.status(500).json({ error: true, message: "Failed to fetch profile" });
    }
});

// Advanced search API with multiple filter options
app.post("/advanced-search", authenticateToken, async (req, res) => {
    const { userId } = req.user;
    const { location, title, dateRange, isFavourite, sortBy } = req.body;

    try {
        // Build the query object
        let query = { userId };

        // Add location filter if provided
        if (location && location.trim() !== '') {
            query.visitedLocation = { $regex: location, $options: "i" };
        }

        // Add title filter if provided
        if (title && title.trim() !== '') {
            query.title = { $regex: title, $options: "i" };
        }

        // Add date range filter if provided
        if (dateRange && (dateRange.startDate || dateRange.endDate)) {
            query.visitedDate = {};

            if (dateRange.startDate) {
                const startDate = new Date(dateRange.startDate);
                if (!isNaN(startDate.getTime())) {
                    query.visitedDate.$gte = startDate;
                }
            }

            if (dateRange.endDate) {
                const endDate = new Date(dateRange.endDate);
                if (!isNaN(endDate.getTime())) {
                    // Set time to end of day for inclusive end date
                    endDate.setHours(23, 59, 59, 999);
                    query.visitedDate.$lte = endDate;
                }
            }
        }

        // Add favorite filter if provided
        if (isFavourite !== undefined && isFavourite !== null) {
            query.isFavourite = isFavourite;
        }

        // Define sort options
        let sortOptions = {};

        // Apply sorting based on sortBy parameter
        switch (sortBy) {
            case 'newest':
                sortOptions = { visitedDate: -1 };
                break;
            case 'oldest':
                sortOptions = { visitedDate: 1 };
                break;
            case 'a-z':
                sortOptions = { title: 1 };
                break;
            case 'z-a':
                sortOptions = { title: -1 };
                break;
            default:
                // Default sorting by favorite status and then date
                sortOptions = { isFavourite: -1, visitedDate: -1 };
        }

        // Execute the query with sorting
        const searchResults = await TravelStory.find(query).sort(sortOptions);

        res.status(200).json({
            stories: searchResults,
            count: searchResults.length,
            message: searchResults.length > 0 ? "Search results found" : "No stories match your search criteria"
        });
    } catch (error) {
        console.error("Advanced search error:", error);
        res.status(500).json({
            error: true,
            message: error.message || "An error occurred during advanced search"
        });
    }
});

// Handle forgot password request
app.post("/forgot-password", async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({
            error: true,
            message: "Email is required"
        });
    }

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({
                error: true,
                message: "No account found with this email address."
            });
        }

        if (!user.isVerified) {
            return res.status(400).json({
                error: true,
                message: "Account not verified. Please complete signup first."
            });
        }

        // Generate a random reset token
        const resetToken = crypto.randomBytes(32).toString('hex');

        // Hash the token before storing it (security best practice)
        const hashedToken = await bcrypt.hash(resetToken, 10);

        // Set the token and expiry in the user document
        user.resetPasswordToken = hashedToken;
        user.resetPasswordExpiry = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

        // Create reset URL from .env configuration
        const frontendURL = process.env.NODE_ENV === 'production'
            ? (process.env.FRONTEND_URL || 'https://travelbook.sahilfolio.live')
            : (process.env.FRONTEND_URL_DEV || 'http://localhost:5173');

        const resetURL = `${frontendURL}/reset-password?token=${resetToken}&email=${email}`;

        // Send email with reset link
        try {
            // Create a transporter
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });

            // Email content
            const mailOptions = {
                from: `"Travel Book Security" <${process.env.EMAIL_USER}>`,
                to: email,
                subject: 'Password Reset - Travel Book',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                        <div style="text-align: center; margin-bottom: 20px;">
                            <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png" alt="Travel Book Logo" style="max-width: 150px;">
                        </div>
                        <h2 style="color: #3498db; text-align: center;">Password Reset Request</h2>
                        <p style="font-size: 16px; color: #555; margin-bottom: 20px;">Hello,</p>
                        <p style="font-size: 16px; color: #555; margin-bottom: 20px;">You requested to reset your password for your Travel Book account. Click the button below to set a new password:</p>
                        
                        <div style="text-align: center; margin: 30px 0;">
                            <a href="${resetURL}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset Your Password</a>
                        </div>
                        
                        <p style="font-size: 16px; color: #555; margin-bottom: 20px;">This link will expire in 1 hour for security reasons.</p>
                        <p style="font-size: 16px; color: #555; margin-bottom: 20px;">If you did not request a password reset, please ignore this email or contact support if you have concerns.</p>
                        
                        <p style="font-size: 14px; color: #888; text-align: center; margin-top: 30px;">© ${new Date().getFullYear()} Travel Book. All rights reserved.</p>
                    </div>
                `
            };

            // Send email
            await transporter.sendMail(mailOptions);

            return res.status(200).json({
                error: false,
                message: "Password reset link sent to your email."
            });
        } catch (emailError) {
            console.error('Error sending password reset email:', emailError);
            return res.status(500).json({
                error: true,
                message: "Failed to send password reset email. Please try again."
            });
        }
    } catch (error) {
        console.error('Error in forgot password:', error);
        res.status(500).json({
            error: true,
            message: "An error occurred. Please try again later."
        });
    }
});

// Reset password with token
app.post("/reset-password", async (req, res) => {
    const { email, token, newPassword } = req.body;

    if (!email || !token || !newPassword) {
        return res.status(400).json({
            error: true,
            message: "All fields are required"
        });
    }

    try {
        // Find the user with the given email
        const user = await User.findOne({
            email,
            resetPasswordExpiry: { $gt: Date.now() } // Check if token hasn't expired
        });

        if (!user) {
            return res.status(400).json({
                error: true,
                message: "Invalid or expired password reset link. Please request a new one."
            });
        }

        // Verify that the provided token matches
        const isValidToken = await bcrypt.compare(token, user.resetPasswordToken);
        if (!isValidToken) {
            return res.status(400).json({
                error: true,
                message: "Invalid or expired password reset link. Please request a new one."
            });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update user's password and clear reset token fields
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpiry = undefined;

        await user.save();

        // Collect device information from request headers
        // Get the actual client IP address from headers if available (for proxy environments)
        const clientIp = req.headers['x-forwarded-for'] ||
            req.headers['x-real-ip'] ||
            req.ip ||
            req.connection.remoteAddress;

        const deviceInfo = {
            ip: clientIp === '::1' ? 'Local Development' : clientIp, // Handle localhost IP
            browser: req.headers['user-agent'] || 'Unknown Browser',
        };

        // Send password reset confirmation email
        sendPasswordResetConfirmation(email, deviceInfo)
            .then(sent => {
                if (sent) {
                    console.log(`Password reset confirmation email sent to ${email}`);
                } else {
                    console.log(`Failed to send password reset confirmation email to ${email}`);
                }
            })
            .catch(err => {
                console.error('Error sending password reset confirmation:', err);
            });

        return res.status(200).json({
            error: false,
            message: "Password has been reset successfully. Please log in with your new password."
        });
    } catch (error) {
        console.error('Error in reset password:', error);
        res.status(500).json({
            error: true,
            message: "An error occurred. Please try again later."
        });
    }
});

// Change password endpoint
app.post("/change-password", authenticateToken, async (req, res) => {
    const { currentPassword, newPassword } = req.body;
    const { userId } = req.user;  // Changed from req.user.id to req.user.userId to match the format used elsewhere

    // Validate request body
    if (!currentPassword || !newPassword) {
        return res.status(400).json({
            error: true,
            message: "Current password and new password are required"
        });
    }

    // Password validation - same pattern as used in signup
    const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}$/;
    if (!passwordRegex.test(newPassword)) {
        return res.status(400).json({
            error: true,
            message: "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character"
        });
    }

    try {
        // Find the user
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                error: true,
                message: "User not found"
            });
        }

        // Verify current password
        const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({
                error: true,
                message: "Current password is incorrect"
            });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the password
        user.password = hashedPassword;
        await user.save();

        return res.status(200).json({
            error: false,
            message: "Password changed successfully"
        });
    } catch (error) {
        console.error("Error changing password:", error);
        return res.status(500).json({
            error: true,
            message: "An error occurred while changing the password"
        });
    }
});

// Public profile endpoint
app.get("/public-profile/:userId", async (req, res) => {
    const { userId } = req.params;

    try {
        // Find user but exclude sensitive fields
        const user = await User.findById(userId).select('-password -otp -otpExpiry -resetPasswordToken -resetPasswordExpiry -email');

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        // Get user's public travel stories
        const travelStories = await TravelStory.find({
            userId: userId,
            visibility: "public" // Only fetch public stories
        }).sort({ createdAt: -1 });

        return res.status(200).json({
            error: false,
            profile: {
                userId: user._id,
                fullName: user.fullName,
                bio: user.bio || "",
                profileImage: user.profileImage || "",
                socialLinks: user.socialLinks || {},
                totalStories: travelStories.length,
                joinedAt: user.createdAt
            },
            travelStories
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            message: error.message
        });
    }
});

// PUBLIC PROFILE endpoint - Returns public profile information for a user by username
app.get("/public-profile/:username", async (req, res) => {
    const { username } = req.params;

    try {
        // Find the user by username
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(404).json({
                error: true,
                message: "User not found"
            });
        }

        // Create a public profile object with only the necessary fields
        const publicProfile = {
            id: user._id,
            username: user.username,
            name: user.name,
            bio: user.bio,
            profilePicture: user.profilePicture,
            location: user.location,
            socialLinks: user.socialLinks,
            travelPreferences: user.travelPreferences,
            totalTravelStories: 0,
            travelStories: []
        };

        // Get the user's public travel stories
        const travelStories = await TravelStory.find({
            authorId: user._id,
            isPrivate: false
        }).sort({ createdAt: -1 });

        publicProfile.totalTravelStories = travelStories.length;
        publicProfile.travelStories = travelStories.map(story => ({
            id: story._id,
            title: story.title,
            destination: story.destination,
            coverImage: story.images && story.images.length > 0 ? story.images[0] : null,
            dateVisited: story.dateVisited,
            createdAt: story.createdAt,
            likes: story.likes ? story.likes.length : 0,
            viewCount: story.viewCount || 0,
            tags: story.tags || []
        }));

        return res.status(200).json({
            error: false,
            profile: publicProfile
        });
    } catch (error) {
        console.error("Error fetching public profile:", error);
        return res.status(500).json({
            error: true,
            message: "An error occurred while fetching the public profile"
        });
    }
});

// Search travel stories by location with aggregation
app.get("/search-by-location", authenticateToken, async (req, res) => {
    const { userId } = req.user;

    try {
        // Aggregate stories by location and count them
        const locationResults = await TravelStory.aggregate([
            // Match only stories by this user
            { $match: { userId: mongoose.Types.ObjectId(userId) } },
            // Unwind the visitedLocation array to get individual locations
            { $unwind: "$visitedLocation" },
            // Group by location and count stories
            {
                $group: {
                    _id: "$visitedLocation",
                    count: { $sum: 1 },
                    stories: { $push: "$$ROOT" }
                }
            },
            // Sort by count (highest first)
            { $sort: { count: -1 } }
        ]);

        res.status(200).json({
            locations: locationResults.map(loc => ({
                location: loc._id,
                count: loc.count,
                previewStory: loc.stories[0] // Include first story as preview
            })),
            totalLocations: locationResults.length
        });
    } catch (error) {
        console.error("Location search error:", error);
        res.status(500).json({
            error: true,
            message: error.message || "An error occurred during location search"
        });
    }
});

// Search travel stories by tags
app.get("/search-by-tags", authenticateToken, async (req, res) => {
    const { tags } = req.query;
    const { userId } = req.user;

    if (!tags) {
        return res.status(400).json({
            error: true,
            message: "Tags parameter is required"
        });
    }

    // Split the tags string into an array and trim whitespace
    const tagArray = tags.split(',').map(tag => tag.trim());

    try {
        // Search for stories that contain any of the provided tags in their story content
        const tagResults = await TravelStory.find({
            userId,
            $or: tagArray.map(tag => ({
                $or: [
                    { story: { $regex: `#${tag}\\b`, $options: "i" } },
                    { title: { $regex: `#${tag}\\b`, $options: "i" } }
                ]
            }))
        }).sort({ isFavourite: -1, visitedDate: -1 });

        res.status(200).json({
            stories: tagResults,
            count: tagResults.length,
            tags: tagArray,
            message: tagResults.length > 0
                ? `Found ${tagResults.length} stories with the specified tags`
                : "No stories found with these tags"
        });
    } catch (error) {
        console.error("Tag search error:", error);
        res.status(500).json({
            error: true,
            message: error.message || "An error occurred during tag search"
        });
    }
});

// Get public travel stories for a specific user
app.get('/api/public-stories/:userId', async (req, res) => {
    const { userId } = req.params;
    const { limit = 10, page = 1 } = req.query;

    if (!mongoose.Types.ObjectId.isValid(userId)) {
        return res.status(400).json({ error: true, message: 'Invalid user ID format' });
    }

    try {
        // First check if user has public profile
        const user = await User.findById(userId).select('preferences.privacySettings.profileVisibility');

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        if (user.preferences?.privacySettings?.profileVisibility !== 'public') {
            return res.status(403).json({ error: true, message: "This profile is private" });
        }

        // Calculate pagination
        const skip = (parseInt(page) - 1) * parseInt(limit);

        // Get travel stories
        const stories = await TravelStory.find({ userId })
            .sort({ visitedDate: -1 })
            .skip(skip)
            .limit(parseInt(limit));

        // Get total count for pagination
        const total = await TravelStory.countDocuments({ userId });

        res.status(200).json({
            error: false,
            stories,
            pagination: {
                total,
                page: parseInt(page),
                limit: parseInt(limit),
                pages: Math.ceil(total / parseInt(limit))
            }
        });
    } catch (error) {
        console.error("Error fetching public stories:", error);
        res.status(500).json({ error: true, message: "Failed to fetch stories" });
    }
});

// API to update user privacy settings
app.patch('/api/user/privacy-settings', authenticateToken, async (req, res) => {
    try {
        const { userId } = req.user;
        const { profileVisibility } = req.body;

        // Validate input
        if (!profileVisibility || !['public', 'private'].includes(profileVisibility)) {
            return res.status(400).json({
                error: true,
                message: "Invalid privacy setting. Must be 'public' or 'private'."
            });
        }

        // Update user privacy settings
        const user = await User.findByIdAndUpdate(
            userId,
            { 'preferences.privacySettings.profileVisibility': profileVisibility },
            { new: true }
        );

        if (!user) {
            return res.status(404).json({ error: true, message: "User not found" });
        }

        res.status(200).json({
            error: false,
            message: "Privacy settings updated successfully",
            privacySettings: {
                profileVisibility: user.preferences?.privacySettings?.profileVisibility
            }
        });
    } catch (error) {
        console.error("Error updating privacy settings:", error);
        res.status(500).json({ error: true, message: "Failed to update privacy settings" });
    }
});

// Root route to display welcome message
app.get("/", (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Travel Book API</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {
                --primary-color: #3a86ff;
                --text-color: #333;
                --light-gray: #f5f5f5;
                --gray: #e0e0e0;
                --border-color: #ddd;
                --border-radius: 8px;
                --box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Inter', sans-serif;
                line-height: 1.5;
                color: var(--text-color);
                background-color: #fff;
                padding: 20px;
                max-width: 1000px;
                margin: 0 auto;
            }
            
            header {
                text-align: center;
                margin-bottom: 30px;
                padding: 20px 0;
            }
            
            .logo {
                max-width: 120px;
                height: auto;
                margin-bottom: 15px;
            }
            
            h1 {
                font-size: 24px;
                font-weight: 600;
                margin-bottom: 10px;
            }
            
            .subtitle {
                color: #666;
                font-size: 14px;
                max-width: 500px;
                margin: 0 auto;
            }
            
            section {
                background: #fff;
                border-radius: var(--border-radius);
                box-shadow: var(--box-shadow);
                margin-bottom: 20px;
                border: 1px solid var(--border-color);
                overflow: hidden;
            }
            
            section h2 {
                font-size: 16px;
                padding: 15px 20px;
                border-bottom: 1px solid var(--border-color);
                display: flex;
                align-items: center;
                gap: 8px;
                background-color: var(--light-gray);
            }
            
            .search-container {
                padding: 15px 20px;
                border-bottom: 1px solid var(--border-color);
            }
            
            .search-input {
                width: 100%;
                padding: 8px 12px;
                border: 1px solid var(--border-color);
                border-radius: 4px;
                font-size: 14px;
            }
            
            .search-input:focus {
                outline: none;
                border-color: var(--primary-color);
            }
            
            .route-tabs {
                display: flex;
                padding: 10px 20px;
                border-bottom: 1px solid var(--border-color);
                overflow-x: auto;
                gap: 10px;
            }
            
            .route-tab {
                background: none;
                border: 1px solid var(--border-color);
                padding: 5px 12px;
                border-radius: 4px;
                font-size: 12px;
                cursor: pointer;
                white-space: nowrap;
            }
            
            .route-tab.active {
                background-color: var(--primary-color);
                color: white;
                border-color: var(--primary-color);
            }
            
            .routes-list {
                max-height: 400px;
                overflow-y: auto;
            }
            
            .route-item {
                padding: 12px 20px;
                border-bottom: 1px solid var(--border-color);
            }
            
            .route-item:last-child {
                border-bottom: none;
            }
            
            .route-header {
                display: flex;
                align-items: center;
                gap: 8px;
                margin-bottom: 4px;
            }
            
            .method {
                font-size: 11px;
                padding: 3px 6px;
                border-radius: 3px;
                color: white;
                font-weight: 500;
                min-width: 50px;
                text-align: center;
            }
            
            .get { background-color: #22c55e; }
            .post { background-color: #3b82f6; }
            .put { background-color: #f59e0b; }
            .delete { background-color: #ef4444; }
            .patch { background-color: #8b5cf6; }
            
            .route-path {
                font-family: monospace;
                font-size: 13px;
                color: #555;
                word-break: break-all;
            }
            
            .route-description {
                font-size: 12px;
                color: #666;
                margin-left: 58px;
            }
            
            .developer {
                display: flex;
                padding: 20px;
                align-items: center;
                gap: 15px;
            }
            
            .dev-avatar {
                width: 60px;
                height: 60px;
                border-radius: 50%;
            }
            
            .dev-info {
                flex: 1;
            }
            
            .dev-name {
                font-weight: 600;
                margin-bottom: 2px;
            }
            
            .contact-info {
                font-size: 12px;
                color: #666;
                display: flex;
                align-items: center;
                gap: 5px;
                margin-bottom: 2px;
            }
            
            .social-links {
                display: flex;
                gap: 10px;
                margin-top: 8px;
            }
            
            .social-links a {
                color: #555;
                font-size: 14px;
            }
            
            .theme-toggle {
                position: fixed;
                top: 15px;
                right: 15px;
                background: none;
                border: none;
                font-size: 16px;
                color: #555;
                cursor: pointer;
                padding: 8px;
                border-radius: 50%;
                background-color: var(--light-gray);
            }
            
            .dark-mode {
                --primary-color: #60a5fa;
                --text-color: #e5e5e5;
                --light-gray: #2a2a2a;
                --gray: #333;
                --border-color: #444;
            }
            
            .dark-mode body {
                background-color: #1a1a1a;
                color: var(--text-color);
            }
            
            .dark-mode section {
                background-color: #222;
            }
            
            .dark-mode .route-path {
                color: #bbb;
            }
            
            .dark-mode .route-description,
            .dark-mode .contact-info {
                color: #999;
            }
            
            .dark-mode .social-links a {
                color: #bbb;
            }
            
            .dark-mode .search-input {
                background-color: #333;
                color: #e5e5e5;
            }
            
            .no-results {
                padding: 20px;
                text-align: center;
                color: #666;
                font-size: 14px;
            }
            
            @media (max-width: 600px) {
                .developer {
                    flex-direction: column;
                    text-align: center;
                }
                
                .route-description {
                    margin-left: 0;
                    margin-top: 5px;
                }
            }
        </style>
    </head>
    <body>
        <button class="theme-toggle" id="themeToggle">
            <i class="fas fa-moon"></i>
        </button>

        <header>
            <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png
" alt="Travel Book Logo" class="logo">
            <h1>Travel Book API</h1>
            <p class="subtitle">Backend server for your travel memories application</p>
        </header>
        
        <section>
            <h2><i class="fas fa-route"></i> API Routes</h2>
            <div class="search-container">
                <input type="text" id="searchRoutes" class="search-input" placeholder="Search routes...">
            </div>
            
            <div class="route-tabs">
                <button class="route-tab active" data-method="all">All</button>
                <button class="route-tab" data-method="get">GET</button>
                <button class="route-tab" data-method="post">POST</button>
                <button class="route-tab" data-method="put">PUT</button>
                <button class="route-tab" data-method="delete">DELETE</button>
            </div>
            
            <div class="routes-list" id="routesList">
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/create-account</span>
                    </div>
                    <p class="route-description">Create a new user account for Travel Book</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/send-signup-otp</span>
                    </div>
                    <p class="route-description">Send OTP to user's email for account verification</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/verify-signup-otp</span>
                    </div>
                    <p class="route-description">Verify OTP for new account signup</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/login</span>
                    </div>
                    <p class="route-description">Authenticate user and return access token</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/add-travel-story</span>
                    </div>
                    <p class="route-description">Add a new travel story to the user's collection</p>
                </div>
                <div class="route-item" data-method="get">
                    <div class="route-header">
                        <span class="method get">GET</span>
                        <span class="route-path">/get-all-stories</span>
                    </div>
                    <p class="route-description">Get all travel stories for the authenticated user</p>
                </div>
                <div class="route-item" data-method="put">
                    <div class="route-header">
                        <span class="method put">PUT</span>
                        <span class="route-path">/edit-story/:id</span>
                    </div>
                    <p class="route-description">Edit an existing travel story</p>
                </div>
                <div class="route-item" data-method="delete">
                    <div class="route-header">
                        <span class="method delete">DELETE</span>
                        <span class="route-path">/delete-story/:id</span>
                    </div>
                    <p class="route-description">Delete a travel story</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/image-upload</span>
                    </div>
                    <p class="route-description">Upload an image for a travel story</p>
                </div>
                <div class="route-item" data-method="get">
                    <div class="route-header">
                        <span class="method get">GET</span>
                        <span class="route-path">/search</span>
                    </div>
                    <p class="route-description">Search travel stories by query text</p>
                </div>
                <div class="route-item" data-method="get">
                    <div class="route-header">
                        <span class="method get">GET</span>
                        <span class="route-path">/profile</span>
                    </div>
                    <p class="route-description">Get user profile with statistics</p>
                </div>
                <div class="route-item" data-method="put">
                    <div class="route-header">
                        <span class="method put">PUT</span>
                        <span class="route-path">/update-profile</span>
                    </div>
                    <p class="route-description">Update user profile information</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/change-password</span>
                    </div>
                    <p class="route-description">Change user password</p>
                </div>
                <div class="route-item" data-method="post">
                    <div class="route-header">
                        <span class="method post">POST</span>
                        <span class="route-path">/forgot-password</span>
                    </div>
                    <p class="route-description">Request a password reset link</p>
                </div>
                <div class="route-item" data-method="get">
                    <div class="route-header">
                        <span class="method get">GET</span>
                        <span class="route-path">/api/public-profile/:userId</span>
                    </div>
                    <p class="route-description">View a user's public profile</p>
                </div>
            </div>
        </section>
        
<section>
  <h2><i class="fas fa-code"></i> Developer</h2>
  <div class="developer">
    <img src="https://avatars.githubusercontent.com/u/118194056?s=400&u=7399e110745c8bdbcf4dedbab3e4d54f88db8838&v=4" alt="Sahil" class="dev-avatar">
    <div class="dev-info">
      <p class="dev-name">SAHIL</p>
      <p class="contact-info">
        <i class="fas fa-envelope"></i>
        <a href="mailto:contact@sahilfolio.live" class="white-link">contact@sahilfolio.live</a>
      </p>
      <p class="contact-info">
        <i class="fas fa-globe"></i>
        <a href="https://sahilfolio.live" target="_blank" class="white-link">sahilfolio.live</a>
      </p>

      <p class="contact-info">
  <i class="fas fa-book"></i>
  For Travel-Book API documentation, refer this 
  <a href="https://travel-book-api-docs.hashnode.dev/travel-book-api-documentation" target="_blank" class="white-link">
    link
  </a>.
</p>


      <div class="social-links">
        <a href="https://www.linkedin.com/in/sahilll94" target="_blank" title="LinkedIn"><i class="fab fa-linkedin"></i></a>
        <a href="https://github.com/Sahilll94" target="_blank" title="GitHub"><i class="fab fa-github"></i></a>
        <a href="https://x.com/Sa_hilll94" target="_blank" title="Twitter"><i class="fab fa-twitter"></i></a>
      </div>
    </div>
  </div>
</section>

<style>
  .white-link {
    color: white;
    text-decoration: underline;
  }
</style>


        <script>
            // Dark mode toggle
            const themeToggle = document.getElementById('themeToggle');
            const icon = themeToggle.querySelector('i');
            
            // Check for saved theme preference, default to dark mode
            const isDarkMode = localStorage.getItem('darkMode') !== 'disabled';
            
            // Set initial theme
            if (isDarkMode) {
                document.documentElement.classList.add('dark-mode');
                icon.classList.replace('fa-moon', 'fa-sun');
            }
            
            // Toggle theme
            themeToggle.addEventListener('click', () => {
                document.documentElement.classList.toggle('dark-mode');
                
                if (document.documentElement.classList.contains('dark-mode')) {
                    localStorage.setItem('darkMode', 'enabled');
                    icon.classList.replace('fa-moon', 'fa-sun');
                } else {
                    localStorage.setItem('darkMode', 'disabled');
                    icon.classList.replace('fa-sun', 'fa-moon');
                }
            });
            
            // Route filtering
            const routeTabs = document.querySelectorAll('.route-tab');
            const routeItems = document.querySelectorAll('.route-item');
            const searchInput = document.getElementById('searchRoutes');
            const routesList = document.getElementById('routesList');
            
            // Filter routes by method
            routeTabs.forEach(tab => {
                tab.addEventListener('click', () => {
                    routeTabs.forEach(t => t.classList.remove('active'));
                    tab.classList.add('active');
                    filterRoutes();
                });
            });
            
            // Search routes
            searchInput.addEventListener('input', filterRoutes);
            
            function filterRoutes() {
                const searchTerm = searchInput.value.toLowerCase();
                const activeMethod = document.querySelector('.route-tab.active').getAttribute('data-method');
                let hasVisibleItems = false;
                
                routeItems.forEach(item => {
                    const method = item.getAttribute('data-method');
                    const routePath = item.querySelector('.route-path').textContent.toLowerCase();
                    const routeDesc = item.querySelector('.route-description').textContent.toLowerCase();
                    
                    const matchesMethod = activeMethod === 'all' || method === activeMethod;
                    const matchesSearch = routePath.includes(searchTerm) || routeDesc.includes(searchTerm);
                    
                    if (matchesMethod && matchesSearch) {
                        item.style.display = 'block';
                        hasVisibleItems = true;
                    } else {
                        item.style.display = 'none';
                    }
                });
                
                // Show "no results" message if needed
                const noResults = document.querySelector('.no-results');
                if (!hasVisibleItems) {
                    if (!noResults) {
                        const noResultsElement = document.createElement('div');
                        noResultsElement.className = 'no-results';
                        noResultsElement.textContent = 'No routes found';
                        routesList.appendChild(noResultsElement);
                    }
                } else if (noResults) {
                    noResults.remove();
                }
            }
        </script>
    </body>
    </html>
  `);
});

// for render activation using UptimeRobot.
app.get("/ping", (req, res) => {
    console.log("UptimeRobot ping received at", new Date().toLocaleString());
    res.status(200).send("Ping received correctly by backend!!");
});

// CONTRIBUTOR ENDPOINTS

// GET /admin/contributors - Get all contributors for admin (requires admin auth)
app.get("/admin/contributors", authenticateToken, async (req, res) => {
    const { status = 'all', limit = 50, offset = 0 } = req.query;
    
    // Check if user is admin
    const { userId } = req.user;
    const adminUser = await User.findById(userId);
    
    if (!adminUser || adminUser.email !== 'sahilk64555@gmail.com') {
        return res.status(403).json({
            success: false,
            message: "Access denied. Admin privileges required."
        });
    }
    
    try {
        // Build filter query
        const filter = {};
        if (status !== 'all') {
            filter.status = status;
        }
        
        // Get contributors with pagination
        const contributors = await Contributor.find(filter)
            .sort({ submittedAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(offset))
            .lean();
        
        // Get total count for pagination
        const totalCount = await Contributor.countDocuments(filter);
        
        // Get counts by status
        const statusCounts = await Contributor.aggregate([
            {
                $group: {
                    _id: "$status",
                    count: { $sum: 1 }
                }
            }
        ]);
        
        const counts = {
            pending: 0,
            approved: 0,
            rejected: 0,
            total: totalCount
        };
        
        statusCounts.forEach(item => {
            counts[item._id] = item.count;
        });
        
        res.status(200).json({
            success: true,
            contributors,
            counts,
            pagination: {
                total: totalCount,
                limit: parseInt(limit),
                offset: parseInt(offset),
                hasMore: parseInt(offset) + parseInt(limit) < totalCount
            }
        });
    } catch (error) {
        console.error("Error fetching admin contributors:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch contributors"
        });
    }
});

// GET /contributors - Get all approved contributors
app.get("/contributors", async (req, res) => {
    const { type, limit = 20, offset = 0 } = req.query;
    
    try {
        // Build filter query
        const filter = { status: 'approved' };
        if (type && type !== 'all') {
            filter.contributionType = type;
        }
        
        // Get contributors with pagination
        const contributors = await Contributor.find(filter)
            .sort({ createdAt: -1 })
            .limit(parseInt(limit))
            .skip(parseInt(offset))
            .lean();
        
        // Get total count for pagination
        const totalCount = await Contributor.countDocuments(filter);
        
        res.status(200).json({
            success: true,
            contributors,
            pagination: {
                total: totalCount,
                limit: parseInt(limit),
                offset: parseInt(offset),
                hasMore: parseInt(offset) + parseInt(limit) < totalCount
            }
        });
    } catch (error) {
        console.error("Error fetching contributors:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch contributors"
        });
    }
});

// POST /contributors/submit - Submit contributor application
app.post("/contributors/submit", async (req, res) => {
    const {
        fullName,
        email,
        githubUsername,
        linkedinProfile,
        portfolioWebsite,
        contributionDescription,
        contributionType,
        prLinks,
        issuesWorkedOn,
        country,
        bio,
        profilePicture,
        consentToDisplay
    } = req.body;
    
    // Validate required fields (matching the model)
    if (!fullName || !githubUsername || !contributionDescription || !contributionType || !consentToDisplay) {
        return res.status(400).json({
            success: false,
            message: "Missing required fields: fullName, githubUsername, contributionDescription, contributionType, and consentToDisplay are required"
        });
    }
    
    try {
        // Check if GitHub username already exists
        const existingContributor = await Contributor.findOne({ githubUsername });
        if (existingContributor) {
            return res.status(400).json({
                success: false,
                message: "A contributor with this GitHub username already exists"
            });
        }
        
        // Create new contributor using the correct model fields
        const contributor = new Contributor({
            fullName,
            githubUsername,
            email,
            linkedinProfile,
            portfolioWebsite,
            contributionDescription,
            contributionType,
            prLinks: Array.isArray(prLinks) ? prLinks : [],
            issuesWorkedOn,
            country,
            bio,
            profilePicture,
            consentToDisplay,
            status: 'pending'
        });
        
        await contributor.save();
        
        // Send notification email to admin
        try {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });
            
            const adminEmail = 'sahilk64555@gmail.com';
            const adminMailOptions = {
                from: `"Travel Book Contributors" <${process.env.EMAIL_USER}>`,
                to: adminEmail,
                subject: 'New Contributor Application - Travel Book',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #3498db;">New Contributor Application</h2>
                        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px;">
                            <p><strong>Contributor ID:</strong> <span style="background: #e9ecef; padding: 4px 8px; border-radius: 4px; font-family: monospace;">${contributor._id}</span></p>
                            <p><strong>Name:</strong> ${fullName}</p>
                            <p><strong>GitHub:</strong> <a href="https://github.com/${githubUsername}">@${githubUsername}</a></p>
                            <p><strong>Email:</strong> ${email || 'Not provided'}</p>
                            <p><strong>Contribution Type:</strong> ${contributionType}</p>
                            <p><strong>Description:</strong></p>
                            <p style="background: white; padding: 10px; border-radius: 4px;">${contributionDescription}</p>
                            ${linkedinProfile ? `<p><strong>LinkedIn:</strong> <a href="${linkedinProfile}">${linkedinProfile}</a></p>` : ''}
                            ${portfolioWebsite ? `<p><strong>Portfolio:</strong> <a href="${portfolioWebsite}">${portfolioWebsite}</a></p>` : ''}
                            ${country ? `<p><strong>Country:</strong> ${country}</p>` : ''}
                            ${issuesWorkedOn ? `<p><strong>Issues Worked On:</strong> ${issuesWorkedOn}</p>` : ''}
                            ${prLinks && prLinks.length ? `<p><strong>Pull Requests:</strong><br>${prLinks.map(pr => `<a href="${pr}">${pr}</a>`).join('<br>')}</p>` : ''}
                            ${bio ? `<p><strong>Bio:</strong></p><p style="background: white; padding: 10px; border-radius: 4px;">${bio}</p>` : ''}
                        </div>
                        
                        <div style="margin-top: 30px; padding: 20px; background: #e8f4fd; border-radius: 8px;">
                            <h3 style="color: #0066cc; margin-top: 0;">Quick Actions</h3>
                            <p style="margin-bottom: 15px;"><strong>To approve this contributor:</strong></p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #28a745;">
                                <p style="margin: 0; font-family: monospace; font-size: 12px;">
                                    PUT https://api.travelbook.sahilfolio.live/contributors/${contributor._id}/status<br>
                                    Headers: Authorization: Bearer [YOUR_JWT_TOKEN]<br>
                                    Body: {"status": "approved", "adminNotes": "Welcome to the team!"}
                                </p>
                            </div>
                            
                            <p style="margin: 15px 0;"><strong>To reject this contributor:</strong></p>
                            <div style="background: #f8f9fa; padding: 15px; border-radius: 4px; border-left: 4px solid #dc3545;">
                                <p style="margin: 0; font-family: monospace; font-size: 12px;">
                                    PUT https://api.travelbook.sahilfolio.live/contributors/${contributor._id}/status<br>
                                    Headers: Authorization: Bearer [YOUR_JWT_TOKEN]<br>
                                    Body: {"status": "rejected", "adminNotes": "Thank you for your interest..."}
                                </p>
                            </div>
                            
                            <p style="margin-top: 15px; font-size: 12px; color: #666;">
                                Get your JWT token by logging into Travel Book and checking browser localStorage or network requests.
                            </p>
                        </div>
                        
                        <p style="margin-top: 20px; color: #666;">
                            Please review this application and approve/reject as needed.
                        </p>
                    </div>
                `
            };
            
            await transporter.sendMail(adminMailOptions);
            console.log('Admin notification email sent successfully');
        } catch (emailError) {
            console.error('Failed to send admin notification email:', emailError);
            // Continue execution even if email fails
        }
        
        res.status(201).json({
            success: true,
            message: "Your contributor application has been submitted successfully! We'll review it and get back to you soon.",
            contributorId: contributor._id
        });
    } catch (error) {
        console.error("Error submitting contributor application:", error);
        console.error("Error details:", error.message);
        console.error("Error stack:", error.stack);
        res.status(500).json({
            success: false,
            message: "Failed to submit contributor application. Please try again."
        });
    }
});

// PUT /contributors/:id/status - Update contributor status (admin only)
app.put("/contributors/:id/status", authenticateToken, async (req, res) => {
    const { id } = req.params;
    const { status, adminNotes } = req.body;
    
    // Basic admin check - you might want to implement proper admin roles
    const { userId } = req.user;
    const adminUser = await User.findById(userId);
    
    if (!adminUser || adminUser.email !== 'sahilk64555@gmail.com') {
        return res.status(403).json({
            success: false,
            message: "Access denied. Admin privileges required."
        });
    }
    
    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({
            success: false,
            message: "Status must be either 'approved' or 'rejected'"
        });
    }
    
    try {
        const contributor = await Contributor.findById(id);
        if (!contributor) {
            return res.status(404).json({
                success: false,
                message: "Contributor not found"
            });
        }
        
        contributor.status = status;
        contributor.adminNotes = adminNotes;
        contributor.reviewedAt = new Date();
        contributor.reviewedBy = userId;
        
        await contributor.save();
        
        // Send email notification to contributor
        try {
            const transporter = nodemailer.createTransport({
                service: 'gmail',
                auth: {
                    user: process.env.EMAIL_USER,
                    pass: process.env.EMAIL_PASSWORD
                }
            });
            
            const statusText = status === 'approved' ? 'Approved' : 'Not Approved';
            const statusColor = status === 'approved' ? '#28a745' : '#dc3545';
            
            const contributorMailOptions = {
                from: `"Travel Book Team" <${process.env.EMAIL_USER}>`,
                to: contributor.email,
                subject: `Contributor Application ${statusText} - Travel Book`,
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <div style="text-align: center; margin-bottom: 20px;">
                            <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png" alt="Travel Book Logo" style="max-width: 150px;">
                        </div>
                        <h2 style="color: ${statusColor};">Application ${statusText}</h2>
                        <p>Dear ${contributor.fullName},</p>
                        <p>Thank you for your interest in contributing to Travel Book!</p>
                        <div style="background: #f8f9fa; padding: 20px; border-left: 4px solid ${statusColor}; margin: 20px 0;">
                            <p style="margin: 0;"><strong>Status:</strong> Your application has been <span style="color: ${statusColor}; font-weight: bold;">${statusText}</span></p>
                            ${adminNotes ? `<p style="margin: 10px 0 0 0;"><strong>Notes:</strong> ${adminNotes}</p>` : ''}
                        </div>
                        ${status === 'approved' ? 
                            '<p>Welcome to the Travel Book contributor community! We\'ll be in touch with next steps soon.</p>' :
                            '<p>We appreciate your interest in contributing. Please feel free to apply again in the future or reach out if you have any questions.</p>'
                        }
                        <p>Best regards,<br>The Travel Book Team</p>
                    </div>
                `
            };
            
            await transporter.sendMail(contributorMailOptions);
            console.log('Contributor notification email sent successfully');
        } catch (emailError) {
            console.error('Failed to send contributor notification email:', emailError);
            // Continue execution even if email fails
        }
        
        res.status(200).json({
            success: true,
            message: `Contributor application ${status} successfully`,
            contributor
        });
    } catch (error) {
        console.error("Error updating contributor status:", error);
        res.status(500).json({
            success: false,
            message: "Failed to update contributor status"
        });
    }
});

// DELETE /contributors/:id - Delete contributor (admin only)
app.delete("/contributors/:id", authenticateToken, async (req, res) => {
    const { id } = req.params;
    
    // Basic admin check - you might want to implement proper admin roles
    const { userId } = req.user;
    const adminUser = await User.findById(userId);
    
    if (!adminUser || adminUser.email !== 'sahilk64555@gmail.com') {
        return res.status(403).json({
            success: false,
            message: "Access denied. Admin privileges required."
        });
    }
    
    try {
        const contributor = await Contributor.findById(id);
        if (!contributor) {
            return res.status(404).json({
                success: false,
                message: "Contributor not found"
            });
        }
        
        await Contributor.findByIdAndDelete(id);
        
        res.status(200).json({
            success: true,
            message: "Contributor deleted successfully"
        });
    } catch (error) {
        console.error("Error deleting contributor:", error);
        res.status(500).json({
            success: false,
            message: "Failed to delete contributor"
        });
    }
});

// GET /contributors/stats - Get contributor statistics
app.get("/contributors/stats", async (req, res) => {
    try {
        const stats = await Contributor.aggregate([
            {
                $group: {
                    _id: null,
                    total: { $sum: 1 },
                    approved: {
                        $sum: { $cond: [{ $eq: ["$status", "approved"] }, 1, 0] }
                    },
                    pending: {
                        $sum: { $cond: [{ $eq: ["$status", "pending"] }, 1, 0] }
                    },
                    rejected: {
                        $sum: { $cond: [{ $eq: ["$status", "rejected"] }, 1, 0] }
                    }
                }
            }
        ]);
        
        // Get contribution type breakdown
        const typeStats = await Contributor.aggregate([
            { $match: { status: 'approved' } },
            {
                $group: {
                    _id: "$contributionType",
                    count: { $sum: 1 }
                }
            }
        ]);
        
        res.status(200).json({
            success: true,
            stats: stats[0] || { total: 0, approved: 0, pending: 0, rejected: 0 },
            contributionTypes: typeStats
        });
    } catch (error) {
        console.error("Error fetching contributor stats:", error);
        res.status(500).json({
            success: false,
            message: "Failed to fetch contributor statistics"
        });
    }
});

// ========================
// CHATBOT ROUTES
// ========================

/**
 * POST /chat
 * Handle chatbot requests
 * Body: { message: string, conversationHistory?: Array }
 * Response: { error: boolean, message: string, conversationHistory: Array }
 */
app.post("/chat", handleChatRequest);

/**
 * GET /chat-status
 * Get chatbot operational status
 */
app.get("/chat-status", getChatbotStatus);

// Add a health check endpoint that Render can use to verify the app is running
app.get("/health", (req, res) => {
    res.status(200).send("OK");
});

// Make sure the port is properly set from environment variables
const port = process.env.PORT || 3000;

// Start the server with proper error handling
const server = app.listen(port, '0.0.0.0', () => {
    console.log(`Server is running on port ${port}`);
    console.log(`Server URL: http://localhost:${port}`);
});

// Handle server errors
server.on('error', (error) => {
    console.error('Server error:', error);
   
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use. Try using a different port.`);
    }
});

// Handle process termination gracefully
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully');
    server.close(() => {
        console.log('Server closed');
        process.exit(0);
    });
});

module.exports = app;
