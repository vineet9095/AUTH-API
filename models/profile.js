// models/profile.js
const mongoose = require('mongoose');

const profileSchema = new mongoose.Schema({
    name:{  
        type: String, 
        required: true,
    },
    age: { 
        type: Number, 
        required: true, 
    },
    mobile: { 
        type: String, 
        required: true, 
    },
    email: { 
        type: String, 
        required: true, 
    },
    dob:{
        type: Date, 
        required: true, 
    },
});

const Profile = mongoose.model('Profile', profileSchema);

module.exports = Profile;
