// Firebase Configuration for CyberForensics Pro
const firebaseConfig = {
    apiKey: "AIzaSyBYour-API-Key-Here",
    authDomain: "cyber-a0318.firebaseapp.com",
    projectId: "cyber-a0318",
    storageBucket: "cyber-a0318.appspot.com",
    messagingSenderId: "123456789",
    appId: "1:123456789:web:abcdef123456",
    measurementId: "G-XXXXXXXXXX"
};

// Initialize Firebase
firebase.initializeApp(firebaseConfig);

// Initialize services
const auth = firebase.auth();
const db = firebase.firestore();
const analytics = firebase.analytics();

// Export for use in other files
window.firebaseServices = {
    auth,
    db,
    analytics
};