const nodemailer = require('nodemailer');
const UserOTPVerification = require('../models/userOTPVerification');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const transporter = nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: {
          user: 'vineet.sen@indicchain.com',
          pass: 'sbey odeu qqqj dodc'
        }
})

transporter.verify((error, success) => {
        if (error) {
          console.log(error)
        } else {
          console.log('Ready For messages')
          console.log(success)
        }
})

function generateOTP () {
        let random = Math.random()
        let OTP = Math.floor(random * 900000) + 100000
        return OTP
}

const sendOTPVerificationEmail = async ({ _id, email }, res) => {
        try {
          const otp = generateOTP()
          const otpString = otp.toString()
          const saltRounds = 10
          const hashedOTP = await bcrypt.hash(otpString, saltRounds)
      
          const newOTPVerification = new UserOTPVerification({
            userId: _id,
            otp: hashedOTP,
            createAt: Date.now(),
            expireAt: Date.now() + 120000
          })
      
          await newOTPVerification.save()
      
          const mailOptions = {
            from: 'vineet.sen@indicchain.com',
            to: email,
            subject: 'Verify Your email',
            html: `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Email Verification</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        margin: 0;
                        padding: 0;
                        background-color: #f4f4f4;
                    }
            
                    .container {
                        max-width: 600px;
                        margin: 20px auto;
                        padding: 20px;
                        background-color: #ffffff;
                        border-radius: 8px;
                        box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                    }
            
                    h2 {
                        color: #333333;
                    }
            
                    p {
                        color: #666666;
                    }
            
                    .code {
                        font-size: 1.2em;
                        font-weight: bold;
                        background-color: #e6e6e6;
                        padding: 8px;
                        border-radius: 4px;
                        margin: 10px 0;
                        display: inline-block;
                    }
            
                    .expiration {
                        color: #ff0000;
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <h2>Email Verification</h2>
                    <p>Enter the following code in the app to verify your email address and complete the signup process:</p>
                    <p class="code"><b>${otp}</b></p>
                    <p>This code expires in <span class="expiration">2 minutes</span> only.</p>
                </div>
            </body>
            </html>
            `
          }
      
          await transporter.sendMail(mailOptions)
      
          res.json({
            status: 'pending',
            message: 'Verification OTP email sent',
            data: {
              userId: _id,
              email: email
            }
          })
        } catch (error) {
          console.log('Error:', error.message)
          res.json({
            status: 'FAILED',
            message: error.message
          })
        }
}

const verifyToken = (req, res, next) => {
        const token = req.headers['token']
        if (!token) {
          return res
            .status(403)
            .json({ status: 'FAILED', message: 'Token not provided' })
        }
      
        jwt.verify(token, 'abc', (err, decoded) => {
          if (err) {
            return res
              .status(403)
              .json({ status: 'FAILED', message: 'Failed to authenticate token' })
          }
          req.userId = decoded.userId
          next()
        })
}

module.exports = {transporter, generateOTP,sendOTPVerificationEmail,verifyToken};