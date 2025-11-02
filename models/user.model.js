const mongoose = require("mongoose");
const Schema = mongoose.Schema;


const userSchema = new Schema({
    fullName: {type:String, required:true},
    email: {type:String, required:true, unique:true},    password: {type:String, required: function() {
        // Password is required only if neither googleId nor githubId nor twitterId is provided
        return !this.googleId && !this.githubId && !this.twitterId;
    }},
    googleId: {type:String},
    githubId: {type:String},
    twitterId: {type:String},
    createdOn: {type:Date, default: Date.now},    otp: {type:String},
    otpExpiry: {type:Date},
    isVerified: {type:Boolean, default:false},
    emailVerified: {type:Boolean, default:false}, // Used for OAuth verified emails
    resetPasswordToken: {type:String},
    resetPasswordExpiry: {type:Date},    loginActivity: [{
        timestamp: {type: Date, default: Date.now},
        ipAddress: {type: String},
        device: {type: String},
        method: {type: String, enum: ['password', 'otp', 'google', 'github', 'twitter'], default: 'password'}
    }],// New profile fields
    profileImage: {type:String, default: "https://res.cloudinary.com/travel-book/image/upload/v1720536854/travel_book/default-avatar.png"},
    profilePicture: {type:String}, // For Google profile picture
    bio: {type:String, default: ""},
    location: {type:String, default: ""},
    phone: {type:String, default: ""},
    website: {type:String, default: ""},
    socialLinks: {
        facebook: {type:String, default: ""},
        twitter: {type:String, default: ""},
        instagram: {type:String, default: ""},
        linkedin: {type:String, default: ""}
    },
    preferences: {
        notificationsEnabled: {type:Boolean, default: true},
        privacySettings: {
            showEmail: {type:Boolean, default: false},
            showPhone: {type:Boolean, default: false},
            profileVisibility: {type:String, enum: ['public', 'private'], default: 'public'}
        },
        theme: {type:String, enum: ['light', 'dark', 'system'], default: 'system'}
    }
});

module.exports = mongoose.model("User", userSchema);