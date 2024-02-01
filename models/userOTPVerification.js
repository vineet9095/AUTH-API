const mongoose = require('mongoose');

const UserOTPverificationSchema = new mongoose.Schema({
    userId: {
        type: String,
        required: true
    },
    otp: {
        type: String,
        required: true
    },
    createAt: {
        type: Date,
        required: true
    },
    expireAt: {
        type: Date,
        required: true
    },
});

const UserOTPVerification = mongoose.model('UserOTPVerification', UserOTPverificationSchema);
module.exports = UserOTPVerification;