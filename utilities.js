const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
// Import the login notification function
const { sendLoginNotification } = require('./sendLoginNotification');

// Middleware to authenticate JWT tokens
function authenticateToken(req,res,next)
{
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];   

    // No token -> unauthorized;  
    if(!token)
    {
        return res.sendStatus(401);
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user)=>{
        // Token invalid -> forbidden
        if(err)
        {
            return res.sendStatus(401);
        }

        req.user = user;
        next();
    });
}

// Generate a random 6-digit OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP via email
async function sendOTP(email, otp) {
    try {
        // Create a transporter using SMTP
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD
            }
        });

        // Email content
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: email,
            subject: 'Your Travel Book OTP Code',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png" alt="Travel Book Logo" style="max-width: 150px;">
                    </div>
                    <h2 style="color: #3498db; text-align: center;">Your One-Time Password</h2>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">Hello,</p>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">You've requested to access your Travel Book account. Please use the following OTP code to complete your verification:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; padding: 15px; background-color: #f7f7f7; border-radius: 5px; display: inline-block;">${otp}</div>
                    </div>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">This code will expire in 10 minutes for security reasons.</p>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">If you didn't request this code, please ignore this email.</p>
                    <p style="font-size: 14px; color: #888; text-align: center; margin-top: 30px;">© ${new Date().getFullYear()} Travel Book. All rights reserved.</p>
                </div>
            `
        };

        // Send email
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Error sending OTP email:', error);        return false;
    }
}

// Send password reset confirmation email
async function sendPasswordResetConfirmation(email, deviceInfo = {}) {
    try {
        // Check if environment variables are set
        if (!process.env.EMAIL_USER || !process.env.EMAIL_PASSWORD) {
            console.error('EMAIL_USER or EMAIL_PASSWORD environment variables are not set');
            return false;
        }

        // Get current date and time in Indian Standard Time (UTC+5:30)
        const now = new Date();
        const formattedDate = now.toLocaleDateString('en-US', { 
            weekday: 'long', 
            year: 'numeric', 
            month: 'long', 
            day: 'numeric',
            timeZone: 'Asia/Kolkata' // Set to IST
        });
        
        // Format time in IST
        const formattedTime = now.toLocaleTimeString('en-US', { 
            hour: '2-digit', 
            minute: '2-digit', 
            hour12: true,
            timeZone: 'Asia/Kolkata' // Set to IST
        });

        // Create a transporter using SMTP
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            }
        });

        // Email content
        const mailOptions = {
            from: `"Travel Book Security" <${process.env.EMAIL_USER}>`,
            to: email,
            subject: 'Password Reset Confirmation - Travel Book',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png" alt="Travel Book Logo" style="max-width: 150px;">
                    </div>
                    <h2 style="color: #3498db; text-align: center;">Password Reset Successful</h2>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">Hello,</p>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">Your Travel Book account password has been successfully reset.</p>
                      <div style="background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px;">
                        <p style="margin: 5px 0; font-size: 14px;"><strong>Date:</strong> ${formattedDate}</p>
                        <p style="margin: 5px 0; font-size: 14px;"><strong>Time (IST):</strong> ${formattedTime}</p>
                        ${deviceInfo.ip && deviceInfo.ip !== '127.0.0.1' && deviceInfo.ip !== '::1' ? 
                            `<p style="margin: 5px 0; font-size: 14px;"><strong>IP Address:</strong> ${deviceInfo.ip}</p>` : ''}
                        ${deviceInfo.browser ? `<p style="margin: 5px 0; font-size: 14px;"><strong>Browser:</strong> ${deviceInfo.browser}</p>` : ''}
                        ${deviceInfo.os ? `<p style="margin: 5px 0; font-size: 14px;"><strong>Device:</strong> ${deviceInfo.os}</p>` : ''}
                    </div>
                    
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">If you did not request this password reset, please contact our support team immediately as your account may be compromised.</p>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <a href="https://travelbook.sahilfolio.live/login" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Log In</a>
                    </div>
                    
                    <p style="font-size: 14px; color: #888; text-align: center; margin-top: 30px;">© ${new Date().getFullYear()} Travel Book. All rights reserved.</p>
                </div>
            `
        };

        // Send email
        await transporter.sendMail(mailOptions);
        console.log(`Password reset confirmation sent successfully to ${email}`);
        return true;
    } catch (error) {
        console.error('Error sending password reset confirmation email:', error);
        return false;
    }
}

module.exports = {
    authenticateToken,
    generateOTP,
    sendOTP,
    sendPasswordResetConfirmation
}