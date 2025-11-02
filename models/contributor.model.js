const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const contributorSchema = new Schema({
    fullName: { 
        type: String, 
        required: true 
    },
    githubUsername: { 
        type: String, 
        required: true, 
        unique: true 
    },
    email: { 
        type: String,
        validate: {
            validator: function(v) {
                return !v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
            },
            message: 'Please enter a valid email address'
        }
    },
    linkedinProfile: { 
        type: String 
    },
    portfolioWebsite: { 
        type: String 
    },
    contributionDescription: { 
        type: String, 
        required: true 
    },
    contributionType: { 
        type: String, 
        required: true,
        enum: ['Bug Fix', 'Feature', 'UI/UX Improvement', 'Documentation', 'Testing', 'Performance Optimization', 'Code Refactoring', 'Security Enhancement', 'Other']
    },
    prLinks: [{ 
        type: String 
    }],
    issuesWorkedOn: { 
        type: String 
    },
    country: { 
        type: String 
    },
    bio: { 
        type: String, 
        maxlength: 200 
    },
    profilePicture: { 
        type: String 
    },
    consentToDisplay: { 
        type: Boolean, 
        required: true,
        default: false 
    },
    status: {
        type: String,
        enum: ['pending', 'approved', 'rejected'],
        default: 'pending'
    },
    submittedAt: { 
        type: Date, 
        default: Date.now 
    },
    reviewedAt: { 
        type: Date 
    },
    reviewedBy: { 
        type: String 
    }, // Email of the person who reviewed
    rejectionReason: { 
        type: String 
    }
});

// Index for better query performance
contributorSchema.index({ status: 1 });
contributorSchema.index({ githubUsername: 1 });
contributorSchema.index({ submittedAt: -1 });

module.exports = mongoose.model("Contributor", contributorSchema);
