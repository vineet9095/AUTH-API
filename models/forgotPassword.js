const mongoose = require('mongoose');

const forgotPasswordSchema = new mongoose.Schema({
  resetPasswordOTP: {
    type: String,
    required: true,
  },

  resetPasswordExpires: {
    type: Date,
    required: true,
  },

  forgotEmail:{
    type: String,
    required: true,
  },

});

const ForgotPassword = mongoose.model('ForgotPassword', forgotPasswordSchema);

module.exports = ForgotPassword;

