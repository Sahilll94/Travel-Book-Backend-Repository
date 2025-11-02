const { GoogleGenerativeAI } = require('@google/generative-ai');

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

/**
 * Knowledge base context for the chatbot
 * This provides the AI with information about Travel Book
 */

const KNOWLEDGE_BASE = `
You are a helpful assistant for Travel Book, a digital travel journal application.

## About Travel Book
Travel Book is a modern web application that helps users document, organize, and share their travel experiences. 
It serves as a digital travel journal where users can record memories, photos, and details about places they've visited.

## Key Features:
1. **Create Travel Stories**: Users can add travel stories with title, description, location, date, and images
2. **Image Upload**: Upload travel photos via Cloudinary integration for quick sharing
3. **Story Organization**: Organize stories by location, date, and favorites
4. **Search & Filter**: Advanced search by location, date range, and keywords
5. **Public Profile**: Share selected stories on public profile
6. **Social Login**: Easy authentication with Google, GitHub, and Twitter
7. **Email Authentication**: Secure login with OTP verification
8. **Favorite Stories**: Mark stories as favorites for quick access
9. **Privacy Control**: Control which stories appear on public profile
10. **Responsive Design**: Works on desktop, tablet, and mobile devices

## Use Cases:
- **For Travelers**: Document and remember every journey
- **For Digital Nomads**: Keep a record of all travel experiences
- **For Travel Bloggers**: Organize and publish travel content
- **For Memory Keepers**: Preserve travel memories digitally
- **For Social Sharing**: Share travel experiences with family and friends

## How to Use Travel Book:

### Getting Started:
1. **Sign Up**: Create an account using email, Google, GitHub, or Twitter on https://travelbook.sahilfolio.live/signUp
2. **Verify Email**: Verify your email with OTP for security
3. **Complete Profile**: Add your name, bio, and profile picture
4. **Start Documenting**: Click "Add Story" to create your first travel memory

To Login : https://travelbook.sahilfolio.live/login
Access the dashboard at https://travelbook.sahilfolio.live/dashboard

### Creating a Story:
1. Click the "Add Story" button on the home page
2. Enter the story title and description
3. Select the location you visited
4. Pick the date of your visit
5. Upload a travel photo
6. Click "Save" to add the story

### Managing Stories:
- **View Stories**: All your stories appear in the main feed
- **Edit Stories**: Click the edit button to modify story details
- **Delete Stories**: Remove stories you no longer want
- **Mark as Favorite**: Click the heart icon to mark stories as favorites
- **Share on Profile**: Toggle "Show on Profile" to make stories public

### Search & Filter:
- Use the search bar to find stories by title or content
- Filter by date range to see trips from specific periods
- Search by location to see all stories from one place
- Filter by favorites to quickly access your preferred stories

### Privacy Settings:
- **Private Stories**: Only you can see these stories
- **Public Stories**: Selected stories appear on your public profile
- **Profile Visibility**: Control your overall profile visibility

## About Authentication:

### Email/Password:
- Create a secure account with email and password
- Receive OTP for account verification
- Password reset available via email link
- Login with OTP verification option

### Social Login:
- **Google**: Quick sign-up and login with Google account
- **GitHub**: Developer-friendly authentication
- **Twitter**: Twitter account integration

### Security:
- All passwords are encrypted with bcrypt
- JWT tokens for secure API communication
- OTP-based verification for critical operations
- Password reset links with time-based expiry

## Developer Information:

### Tech Stack:
- **Frontend**: React with Vite, Tailwind CSS, Framer Motion
- **Backend**: Node.js with Express.js
- **Database**: MongoDB (Atlas)
- **Authentication**: Firebase Auth, JWT
- **Image Storage**: Cloudinary
- **Hosting**: Vercel (Frontend), AWS EC2 (Backend)

### API Base URLs:
- Production Frontend: https://travelbook.sahilfolio.live
- Production Backend: https://api.travelbook.sahilfolio.live/
- Development Frontend: http://localhost:5173
- Development Backend: http://localhost:5000

## How to Contribute:

### Getting Started with Development:
1. Fork the repository on GitHub
2. Clone your fork locally
3. Install dependencies (frontend and backend)
4. Set up environment variables
5. Run the application locally

### Contribution Areas:
- **Bug Fixes**: Report and fix bugs in the GitHub issues
- **Feature Development**: Add new features like AI chatbot, RAG system, etc.
- **UI/UX Improvements**: Enhance the user interface and experience
- **Documentation**: Help improve project documentation
- **Testing**: Write and run test cases
- **Performance**: Optimize application performance

### Development Workflow:
1. Create a new branch for your feature
2. Make your changes
3. Test locally
4. Submit a pull request
5. Wait for review and merge

### Contact Developer:
- **Email**: contact@sahilfolio.live
- **GitHub**: https://github.com/Sahilll94
- **LinkedIn**: https://linkedin.com/in/sahilll94
- **Portfolio**: https://sahilfolio.live

## Frequently Asked Questions (FAQ):

### How is my data stored?
All your data is securely stored in our MongoDB database. Your passwords are encrypted, and we use JWT tokens for API security.

### Can I export my stories?
Currently, you can view and share individual stories. Full export functionality is coming soon.

### Is my data private?
Yes, by default all stories are private. You control which stories appear on your public profile.

### How do I reset my password?
Use the "Forgot Password" option on the login page. You'll receive a password reset link via email.

### Can I use Travel Book offline?
Currently, Travel Book requires internet connection. Offline support is planned for future versions.

### How much storage do I get?
Storage is unlimited for your stories. Images are compressed and stored on Cloudinary.

### Can I delete my account?
Yes, you can delete your account from profile settings. All your data will be permanently removed.

### Is Travel Book free?
Yes, Travel Book is completely free to use!

## Important Links:
- Website: https://travelbook.sahilfolio.live
- GitHub: https://github.com/Sahilll94/Travel-Book
- Documentation: https://github.com/Sahilll94/Travel-Book/blob/main/README.md
- Report Issues: https://github.com/Sahilll94/Travel-Book/issues
- Contribute: https://github.com/Sahilll94/Travel-Book/blob/main/CONTRIBUTING.md

Please be helpful, friendly, and informative in all responses.
`;

/**
 * Generate a response using Gemini API
 * @param {string} userMessage - The user's question or message
 * @param {Array} conversationHistory - Previous messages in the conversation
 * @returns {Promise<string>} - The chatbot's response
 */
async function generateChatbotResponse(userMessage, conversationHistory = []) {
    try {
        if (!process.env.GEMINI_API_KEY) {
            throw new Error('GEMINI_API_KEY is not configured');
        }

        const model = genAI.getGenerativeModel({ model: 'gemini-2.5-flash' });

        // Build the conversation with context
        const systemPrompt = KNOWLEDGE_BASE;

        // Combine all messages for context
        const messages = [
            { role: 'user', parts: [{ text: systemPrompt }] },
            { role: 'model', parts: [{ text: 'I understand. I will provide helpful information about Travel Book based on the knowledge base provided.' }] },
            ...conversationHistory.map(msg => ({
                role: msg.role,
                parts: [{ text: msg.content }]
            })),
            { role: 'user', parts: [{ text: userMessage }] }
        ];

        const chat = model.startChat({
            history: messages.slice(0, -1) 
        });

        const result = await chat.sendMessage(userMessage);
        const response = await result.response;

        return response.text();
    } catch (error) {
        console.error('Chatbot Error:', error);

        if (error.message.includes('GEMINI_API_KEY')) {
            throw new Error('Chatbot service is not properly configured. Please contact support at contact@sahilfolio.live');
        }

        if (error.message.includes('429')) {
            throw new Error('Too many requests. Please try again in a moment.');
        }

        if (error.message.includes('401') || error.message.includes('403')) {
            throw new Error('Authentication failed. Please check your API configuration.');
        }

        throw new Error('Unable to process your request at the moment. Please try again later.');
    }
}

/**
 * Chat endpoint handler
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
async function handleChatRequest(req, res) {
    try {
        const { message, conversationHistory } = req.body;

        // Validate input
        if (!message || typeof message !== 'string') {
            return res.status(400).json({
                error: true,
                message: 'Message is required and must be a string'
            });
        }

        if (message.trim().length === 0) {
            return res.status(400).json({
                error: true,
                message: 'Message cannot be empty'
            });
        }

        if (message.length > 5000) {
            return res.status(400).json({
                error: true,
                message: 'Message is too long. Maximum 5000 characters allowed.'
            });
        }

        // Validate conversation history format
        let validHistory = [];
        if (Array.isArray(conversationHistory)) {
            validHistory = conversationHistory.filter(msg =>
                msg && msg.role && msg.content &&
                (msg.role === 'user' || msg.role === 'model') &&
                typeof msg.content === 'string'
            ).slice(-10); // Keep only last 10 messages for context
        }

        const botResponse = await generateChatbotResponse(message, validHistory);

        return res.status(200).json({
            error: false,
            message: botResponse,
            conversationHistory: [
                ...validHistory,
                { role: 'user', content: message },
                { role: 'model', content: botResponse }
            ]
        });

    } catch (error) {
        console.error('Chat request error:', error);

        return res.status(500).json({
            error: true,
            message: error.message || 'An error occurred while processing your request'
        });
    }
}

/**
 * Get chatbot status
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
async function getChatbotStatus(req, res) {
    try {
        const isConfigured = !!process.env.GEMINI_API_KEY;

        return res.status(200).json({
            error: false,
            status: 'operational',
            isConfigured,
            message: 'Chatbot is ready to help!'
        });
    } catch (error) {
        return res.status(500).json({
            error: true,
            message: 'Failed to get chatbot status'
        });
    }
}

module.exports = {
    handleChatRequest,
    getChatbotStatus,
    generateChatbotResponse
};
