const admin = require('firebase-admin');
const config = require('./config.json');

// You'll need to create a service account in the Firebase console and download the JSON file
// Then add these details to your config.json file
const serviceAccount = config.firebaseAdmin;

// Initialize Firebase Admin
admin.initializeApp({
  credential: admin.credential.cert(serviceAccount)
});

module.exports = admin;
