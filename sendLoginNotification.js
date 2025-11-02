const nodemailer = require('nodemailer');

// Send login notification email with authentication method
async function sendLoginNotification(email, ip, device, authMethod = 'password') {
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

        // Get auth method icon and color
        let authIcon = '🔑';
        let authColor = '#3498db';
        
        switch(authMethod.toLowerCase()) {
            case 'google':
                authIcon = '<svg width="14" height="14" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 5px;"><path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" /><path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" /><path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" /><path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" /></svg>';
                authColor = '#4285F4';
                break;
            case 'github':
                authIcon = '<svg width="14" height="14" viewBox="0 0 24 24" style="vertical-align: middle; margin-right: 5px;"><path fill="#181717" d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.885 1.845 1.245 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>';
                authColor = '#181717';
                break;
            case 'otp':
                authIcon = '📱';
                authColor = '#e67e22';
                break;
            default:
                authIcon = '🔑';
                authColor = '#3498db';
        }

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
            subject: 'New Login Detected - Travel Book',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                    <div style="text-align: center; margin-bottom: 20px;">
                        <img src="https://raw.githubusercontent.com/Sahilll94/Travel-Book/main/src/assets/images/logo.png" alt="Travel Book Logo" style="max-width: 150px;">
                    </div>
                    <h2 style="color: #3498db; text-align: center;">New Login Detected</h2>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">Hello,</p>
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">We detected a new login to your Travel Book account.</p>
                    
                    <div style="background-color: #f8f9fa; border-radius: 5px; padding: 15px; margin-bottom: 20px;">
                        <p style="margin: 5px 0; font-size: 14px;"><strong>Date:</strong> ${formattedDate}</p>
                        <p style="margin: 5px 0; font-size: 14px;"><strong>Time (IST):</strong> ${formattedTime}</p>
                        <p style="margin: 10px 0; font-size: 14px; color: ${authColor};">
                            <strong>Sign-in method:</strong> ${authIcon} ${authMethod.charAt(0).toUpperCase() + authMethod.slice(1)}
                        </p>
                        ${ip && ip !== '127.0.0.1' && ip !== '::1' ? 
                            `<p style="margin: 5px 0; font-size: 14px;"><strong>IP Address:</strong> ${ip}</p>` : ''}
                        ${device ? `<p style="margin: 5px 0; font-size: 14px;"><strong>Device:</strong> ${device}</p>` : ''}
                    </div>
                    
                    <p style="font-size: 16px; color: #555; margin-bottom: 20px;">If this was you, no further action is required. If you did not log in recently, please secure your account by changing your password immediately.</p>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <a href="https://travelbook.sahilfolio.live/login" style="background-color: #3498db; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;">Secure Your Account</a>
                    </div>
                    
                    <p style="font-size: 14px; color: #888; text-align: center; margin-top: 30px;">© ${new Date().getFullYear()} Travel Book. All rights reserved.</p>
                </div>
            `
        };

        // Send email
        await transporter.sendMail(mailOptions);
        return true;
    } catch (error) {
        console.error('Error sending login notification email:', error);        return false;
    }
}

module.exports = { sendLoginNotification };
