const express = require('express')
const nodemailer = require('nodemailer')
const bcrypt = require('bcrypt')
const router = express.Router()
const User = require('../models/users')
const UserOTPVerification = require('../models/userOTPVerification')
const ForgotPassword = require('../models/forgotPassword')
const Product = require('../models/productModel');
const jwt = require('jsonwebtoken')
const Joi = require('joi')
const { transporter, generateOTP, sendOTPVerificationEmail, verifyToken } = require('../controllers/services');


/**
* @swagger
* /api/user/signup:
*   post:
*     tags:
*       - Authentication
*     description: User signup
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: User signup information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             name:
*               type: string
*               description: User's name
*               required: true
*             email:
*               type: string
*               description: User's email
*               required: true
*             password:
*               type: string
*               description: User's password
*               required: true
*             dateOfBirth:
*               type: string
*               description: User's date of birth (YYYY-MM-DD)
*               required: true
*     responses:
*       200:
*         description: User registered successfully.
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       409:
*         description: Conflict - User with the provided email already exists.
*       500:
*         description: Internal Server Error - Something went wrong during signup.
*/

router.post('/signup', async (req, res) => {
  const signUpSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().required(),
    password: Joi.string().required(),
    dateOfBirth: Joi.string()
      .pattern(new RegExp(/^\d{4}-\d{2}-\d{2}$/))
      .required()
      .custom((value, helpers) => {
        const birthYear = new Date(value).getFullYear();
        const currentYear = new Date().getFullYear();
        if (birthYear > 2000 && birthYear < currentYear) {
          return value;
        } else {
          return helpers.error('dateOfBirth must be after 2000 and before the current year');
        }
      })
  });

  try {
    const validationResult = signUpSchema.validate(req.body);

    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const existingUser = await User.findOne({ email: validationResult.value.email.toLowerCase(), })

    if (existingUser) {
      throw new Error('User with the provided email already exists')
    }
    const saltRounds = 10
    const hashedPassword = await bcrypt.hash(validationResult.value.password, saltRounds
    )
    const newUser = new User({
      name: validationResult.value.name,
      email: validationResult.value.email.toLowerCase(),
      password: hashedPassword,
      dateOfBirth: validationResult.value.dateOfBirth,
      verified: false
    })

    const savedUser = await newUser.save()
    await sendOTPVerificationEmail(savedUser, res)
  } catch (error) {
    console.log('Error:', error.message)
    res.json({
      status: 'FAILED',
      message: error.message
    })
  }
})

// {  
//   "name": "vineetSen",
//   "email": "vineet91@gmail.com",
//   "password": "Vineet@9095",
//   "dateOfBirth": "2002-01-06"
// }

/**
* @swagger
* /api/user/verifyOTP/{_id}:
*   put:
*     tags:
*       - Authentication
*     description: Verify user OTP
*     produces:
*       - application/json
*     parameters:
*       - name: _id
*         in: path
*         description: User ID
*         required: true
*         type: string
*       - name: body
*         description: OTP verification information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             otp:
*               type: string
*               description: OTP for verification
*               required: true
*     responses:
*       200:
*         description: User email verified successfully.
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - Account record doesn't exist or has been verified already. Please login.
*       403:
*         description: Forbidden - OTP hash expired. Please request again or Invalid OTP passed. Check your inbox.
*       500:
*         description: Internal Server Error - Something went wrong during OTP verification.
*/

router.put('/verifyOTP/:_id', async (req, res) => {
  const verifyOTPSchema = Joi.object({
    otp: Joi.string().required(),
  });

  try {
    const validationResult = verifyOTPSchema.validate(req.body);

    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }
    const id = req.params._id;

    const UserOTPVerificationRecords = await UserOTPVerification.find({ userId: id });

    if (UserOTPVerificationRecords.length <= 0) {
      throw new Error(
        "Account record doesn't exist or has been verified already. Please login."
      )
    } else {
      const { expireAt } = UserOTPVerificationRecords[0]
      const hashedOTP = UserOTPVerificationRecords[0].otp

      if (expireAt < Date.now()) {
        throw new Error('OTP hash expired. Please request again.')
      } else {
        const validOTP = await bcrypt.compare(validationResult.value.otp, hashedOTP)

        if (!validOTP) {
          throw new Error('Invalid OTP passed. Check your inbox.')
        } else {
          await User.updateOne({ _id: id }, { verified: true })
          await UserOTPVerification.deleteMany({ userId: id })
          res.json({
            status: 'Verified', message: 'User email verified successfully'
          })
        }
      }
    }
  } catch (error) {
    res.json({ status: 'Failed', message: error.message })
  }
})

// {
//     "userId": "6576b2055e47d212f0821763",
//     "otp": "628537"
// }


/**
* @swagger
* /api/user/resendOTP:
*   post:
*     tags:
*       - Authentication
*     description: Resend OTP for user verification
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: Resend OTP information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             email:
*               type: string
*               description: User's email
*               required: true
*     responses:
*       200:
*         description: OTP resent successfully. Check your email for the new OTP.
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - User not found with the provided email.
*       403:
*         description: Forbidden - Provided email does not match the existing email or User is Already Verified Please login or You cannot resend mail until the previous OTP is expired.
*       500:
*         description: Internal Server Error - Something went wrong during OTP resend.
*/

router.post('/resendOTP', async (req, res) => {

  const resendOTPSchema = Joi.object({
    email: Joi.string().required(),
  });

  try {
    const validationResult = resendOTPSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }
    console.log("Heloo", validationResult);

    const existingUser = await User.findOne({ email: validationResult.value.email });
    if (!existingUser) {
      throw new Error('User not found with the provided email');
    }
    const userId = existingUser._id;

    const userVerificationRecord = await UserOTPVerification.findOne({ userId })

    if (existingUser.email !== validationResult.value.email) {
      throw new Error('Provided email does not match the existing email')
    }

    if (existingUser.verified) {
      throw new Error('User is Already Verified Please login')
    }

    if (userVerificationRecord.expireAt < Date.now()) {
      await UserOTPVerification.deleteMany({ userId })
      await sendOTPVerificationEmail({ _id: userId, email }, res)
    } else {
      throw new Error(
        'You cannot resend mail until the previous OTP is expired'
      )
    }
  } catch (error) {
    console.log('Error:', error.message)
    res.json({
      status: 'FAILED',
      message: error.message
    })
  }
})

// {
//     "email": "Vineet9165@gmail.com"
// }


/**
* @swagger
* /api/user/login:
*   post:
*     tags:
*       - Authentication
*     description: User login
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: User login information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             email:
*               type: string
*               description: User's email
*               required: true
*             password:
*               type: string
*               description: User's password
*               required: true
*     responses:
*       200:
*         description: Login successful. Returns a token and user information.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Login successful
*             data:
*               type: object
*               properties:
*                 token:
*                   type: string
*                   example: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
*                 user:
*                   type: object
*                   properties:
*                     _id:
*                       type: string
*                       example: 1234567890abcdef12345678
*                     name:
*                       type: string
*                       example: John Doe
*                     email:
*                       type: string
*                       example: john.doe@example.com
*                     dateOfBirth:
*                       type: string
*                       example: 1990-01-01
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - User not found. Please check your credentials.
*       403:
*         description: Forbidden - Invalid password or User email is not verified. Please complete the verification process.
*       500:
*         description: Internal Server Error - Something went wrong during login.
*/

router.post('/login', async (req, res) => {

  const logInSchema = Joi.object({
    email: Joi.string().required(),
    password: Joi.string().required(),
  });

  try {
    const validationResult = logInSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }
    const user = await User.findOne({ email: validationResult.value.email.toLowerCase(), })

    if (!user) {
      throw new Error('User not found. Please check your credentials.')
    }

    const passwordMatch = await bcrypt.compare(validationResult.value.password, user.password)

    if (!passwordMatch) {
      throw new Error('Invalid password. Please check your credentials.')
    }

    if (!user.verified) {
      throw new Error(
        'User email is not verified. Please complete the verification process.'
      )
    }

    const token = jwt.sign({ userId: user._id }, 'abc', { expiresIn: '1h' })

    user.token = token
    await user.save()

    res.json({
      status: 'success',
      message: 'Login successful',
      data: {
        token,
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          dateOfBirth: user.dateOfBirth
        }
      }
    })
  } catch (error) {
    console.log('Error:', error.message)
    res.json({
      status: 'FAILED',
      message: error.message
    })
  }
})

// {
//     "email": "Vineet9165@gmail.com",
//     "password": "Vineet@9095"
// }


/**
* @swagger
* /api/user/forgotPassword:
*   patch:
*     tags:
*       - Authentication
*     description: Initiate password reset process
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: Password reset information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             email:
*               type: string
*               description: User's email
*               required: true
*     responses:
*       200:
*         description: Reset password email sent successfully. Check your email for the OTP.
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - User with the provided email does not exist or User email is not verified. Please complete the verification process.
*       500:
*         description: Internal Server Error - Something went wrong during the password reset process.
*/

router.patch('/forgotPassword', async (req, res) => {

  const forgotPasswordSchema = Joi.object({
    email: Joi.string().required(),
  });

  try {
    const validationResult = forgotPasswordSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const forgotRecord = await ForgotPassword.findOne({ forgotEmail: validationResult.value.email })
    console.log('Hello', forgotRecord)

    if (forgotRecord) {
      await ForgotPassword.deleteOne({ forgotEmail: validationResult.value.email })
    }

    const user = await User.findOne({ email: validationResult.value.email })

    if (!user) {
      throw new Error('User with the provided email does not exist')
    }

    if (!user.verified) {
      throw new Error(
        'User email is not verified. Please complete the verification process.'
      )
    }

    const resetcode = generateOTP()
    const otpString = resetcode.toString()

    const forgotPassword = new ForgotPassword({
      resetPasswordOTP: otpString,
      resetPasswordExpires: Date.now() + 300000, // 5 minutes
      forgotEmail: validationResult.value.email
    })

    await forgotPassword.save()

    const mailOptions = {
      from: 'vineet.sen@indicchain.com',
      to: validationResult.value.email,
      subject: 'Reset Your Password',
      html: `<p>Your Forgot OTP code is <b>${otpString}</b> to reset your password.</p>`
    }

    await transporter.sendMail(mailOptions)

    res.json({
      status: 'success',
      message: 'Reset password email sent successfully'
    })
  } catch (error) {
    console.log('Error:', error.message)
    res.json({
      status: 'FAILED',
      message: error.message
    })
  }
})

// {
//     "email": "vineet9165@gmail.com"
// }


/**
* @swagger
* /api/user/resetPassword:
*   post:
*     tags:
*       - Authentication
*     description: Reset user password using OTP
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: Password reset information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             resetPasswordOTP:
*               type: string
*               description: OTP received for password reset
*               required: true
*             newPassword:
*               type: string
*               description: User's new password
*               required: true
*     responses:
*       200:
*         description: Password reset successful.
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - Invalid resetPassword OTP or Reset password OTP has expired. Please reset the password again.
*       500:
*         description: Internal Server Error - Something went wrong during the password reset process.
*/

router.post('/resetPassword', async (req, res) => {
  const resetPasswordSchema = Joi.object({
    resetPasswordOTP: Joi.string().required(),
    newPassword: Joi.string().required(),
  });

  try {
    const validationResult = resetPasswordSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const resetRecord = await ForgotPassword.findOne({ resetPasswordOTP: validationResult.value.resetPasswordOTP });

    if (!resetRecord) {
      throw new Error('Invalid resetPassword OTP Please Forgot Password first')
    }

    if (resetRecord.resetPasswordExpires < Date.now()) {
      await ForgotPassword.deleteOne({ resetPasswordOTP: validationResult.value.resetPasswordOTP })
      throw new Error(
        'Reset password OTP has expired. Please reset the password again'
      )
    }

    const hashedPassword = await bcrypt.hash(validationResult.value.newPassword, 10)

    const user = await User.findOne({ email: resetRecord.forgotEmail })
    console.log(user)

    if (!user) {
      throw new Error('Data not found. Please reset the password again')
    }

    user.password = hashedPassword
    await user.save()
    await ForgotPassword.deleteOne({ resetPasswordOTP: validationResult.value.resetPasswordOTP })

    res.json({
      status: 'success',
      message: 'Password reset successful'
    })
  } catch (error) {
    console.error('Error:', error.message)
    res.json({
      status: 'FAILED',
      message: error.message
    })
  }
})

// {
//     "resetPasswordOTP": "477068",
//     "newPassword": "Vineet@9995"
// }

/**
* @swagger
* /api/user/updateProfile:
*   put:
*     tags:
*       - Authentication
*     description: Update user profile
*     produces:
*       - application/json
*     parameters:
*       - name: token
*         in: header
*         description: User Token
*         required: true
*         type: string
*       - name: body
*         description: Updated user profile information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             name:
*               type: string
*               description: User's updated name
*               required: true
*             dateOfBirth:
*               type: string
*               description: User's updated date of birth (YYYY-MM-DD)
*               required: true
*     security:
*       - BearerAuth: []
*     responses:
*       200:
*         description: User profile updated successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: User profile updated successfully
*             data:
*               type: object
*               properties:
*                 _id:
*                   type: string
*                   example: 1234567890abcdef12345678
*                 name:
*                   type: string
*                   example: John Doe
*                 email:
*                   type: string
*                   example: john.doe@example.com
*                 dateOfBirth:
*                   type: string
*                   example: 1990-01-01
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       404:
*         description: Not Found - User not found.
*       403:
*         description: Forbidden - User not authorized to update the profile.
*       500:
*         description: Internal Server Error - Something went wrong during profile update.
*/

router.put('/updateProfile', verifyToken, async (req, res) => {
  const updateProSchema = Joi.object({
    name: Joi.string().required(),
    dateOfBirth: Joi.string()
      .pattern(new RegExp(/^\d{4}-\d{2}-\d{2}$/))
      .required()
      .custom((value, helpers) => {
        const birthYear = new Date(value).getFullYear();
        const currentYear = new Date().getFullYear();
        if (birthYear > 2000 && birthYear < currentYear) {
          return value;
        } else {
          return helpers.error('dateOfBirth must be after 2000 and before the current year');
        }
      })
  });

  try {
    console.log("hii", req.userId); // Access the user ID from req.userId
    console.log("hello", req.body);
    const validationResult = updateProSchema.validate(req.body);
    const userId = req.userId; // Use req.userId instead of req.params.userId

    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const user = await User.findById(userId);

    if (!user) {
      throw new Error('User not found');
    }

    user.name = validationResult.value.name;
    user.dateOfBirth = validationResult.value.dateOfBirth;

    const updatedUser = await user.save();

    res.json({
      status: 'success',
      message: 'User profile updated successfully',
      data: updatedUser
    });
  } catch (error) {
    console.log('Error:', error.message);
    res.json({
      status: 'FAILED',
      message: error.message
    });
  }
});


// {
//   "name": "Alok AgniHotri",
//   "dateOfBirth": "2001-02-23"
// }

/**
* @swagger
* /api/user/createProduct:
*   post:
*     tags:
*       - Product
*     description: Create a new product
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: Product information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             name:
*               type: string
*               description: Product name
*               required: true
*             quantity:
*               type: number
*               description: Quantity of the product
*               required: true
*             price:
*               type: number
*               description: Price of the product
*               required: true
*             description:
*               type: string
*               description: Description of the product
*               required: false
*     responses:
*       200:
*         description: Product created successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Product created successfully
*             data:
*               type: object
*               properties:
*                 _id:
*                   type: string
*                   example: 1234567890abcdef12345678
*                 name:
*                   type: string
*                   example: ProductName
*                 quantity:
*                   type: number
*                   example: 10
*                 price:
*                   type: number
*                   example: 19.99
*                 description:
*                   type: string
*                   example: Product description
*       400:
*         description: Bad Request - Invalid input or missing required fields.
*       409:
*         description: Conflict - Product with the provided name already exists.
*       500:
*         description: Internal Server Error - Something went wrong during product creation.
*/

router.post('/createProduct', async (req, res) => {

  const createProductSchema = Joi.object({
    name: Joi.string().required(),
    quantity: Joi.number().required(),
    price: Joi.number().required(),
    description: Joi.string().optional(),
  });

  try {
    const validationResult = createProductSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const ProductDetails = await Product.findOne({ name: validationResult.value.name });
    if (ProductDetails) {
      throw new Error('This Product name already exists');
    }

    const product = await Product.create(req.body);
    res.json({
      status: 'success',
      message: 'Product created successfully',
      data: product
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// {
//   "name": "Shampu",
//   "quantity": "5",
//   "price": "20",
//   "description": "Hii Hello byy"
// }

/**
* @swagger
* /api/user/readAllProducts:
*   get:
*     tags:
*       - Product
*     description: Retrieve all products
*     produces:
*       - application/json
*     responses:
*       200:
*         description: Products retrieved successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Product retrieve successfully
*             data:
*               type: array
*               items:
*                 type: object
*                 properties:
*                   _id:
*                     type: string
*                     example: 1234567890abcdef12345678
*                   name:
*                     type: string
*                     example: ProductName
*                   quantity:
*                     type: number
*                     example: 10
*                   price:
*                     type: number
*                     example: 19.99
*                   description:
*                     type: string
*                     example: Product description
*       500:
*         description: Internal Server Error - Something went wrong during product retrieval.
*/

router.get('/readAllProducts', async (req, res) => {
  try {
    const products = await Product.find({})
    res.status(200).json({
      status: 'success',
      message: 'Product retrieve successfully',
      data: products
    });
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

/**
* @swagger
* /api/user/readProductsById/{_id}:
*   get:
*     tags:
*       - Product
*     description: Retrieve a product by ID
*     produces:
*       - application/json
*     parameters:
*       - name: _id
*         in: path
*         description: Product ID
*         required: true
*         type: string
*     responses:
*       200:
*         description: Product retrieved successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Product retrieve successfully
*             data:
*               type: object
*               properties:
*                 _id:
*                   type: string
*                   example: 1234567890abcdef12345678
*                 name:
*                   type: string
*                   example: ProductName
*                 quantity:
*                   type: number
*                   example: 10
*                 price:
*                   type: number
*                   example: 19.99
*                 description:
*                   type: string
*                   example: Product description
*       400:
*         description: Bad Request - Invalid id.
*       404:
*         description: Not Found - Product not found with the provided ID.
*       500:
*         description: Internal Server Error - Something went wrong during product retrieval.
*/

router.get('/readProductsById/:_id', async (req, res) => {
  try {
    const id = req.params._id;

    if (id.length !== 24) {
      throw new Error('Invalid id');
    }

    const product = await Product.findById(id)
    if (!product) {
      throw new error('Product not Found of this id');
    }
    res.status(200).json({
      status: 'success',
      message: 'Product retrieve successfully',
      data: product
    });
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

/**
* @swagger
* /api/user/UpdateProducts/{_id}:
*   put:
*     tags:
*       - Product
*     description: Update a product by ID
*     produces:
*       - application/json
*     parameters:
*       - name: _id
*         in: path
*         description: Product ID
*         required: true
*         type: string
*       - name: body
*         description: Updated product information
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             name:
*               type: string
*               description: Updated product name
*               required: true
*             quantity:
*               type: number
*               description: Updated quantity of the product
*               required: true
*             price:
*               type: number
*               description: Updated price of the product
*               required: true
*             description:
*               type: string
*               description: Updated description of the product
*               required: false
*     responses:
*       200:
*         description: Product updated successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Product Updated successfully
*             data:
*               type: object
*               properties:
*                 _id:
*                   type: string
*                   example: 1234567890abcdef12345678
*                 name:
*                   type: string
*                   example: UpdatedProductName
*                 quantity:
*                   type: number
*                   example: 20
*                 price:
*                   type: number
*                   example: 24.99
*                 description:
*                   type: string
*                   example: Updated product description
*       400:
*         description: Bad Request - Invalid id or invalid input.
*       404:
*         description: Not Found - Product not found with the provided ID or Product name already exists.
*       500:
*         description: Internal Server Error - Something went wrong during product update.
*/

router.put('/UpdateProducts/:_id', async (req, res) => {

  const UpdateProductsSchema = Joi.object({
    name: Joi.string().required(),
    quantity: Joi.number().required(),
    price: Joi.number().required(),
    description: Joi.string().optional(),
  });

  try {
    const validationResult = UpdateProductsSchema.validate(req.body);
    if (validationResult.error) {
      throw new Error(validationResult.error.details[0].message);
    }

    const id = req.params._id;
    console.log("id", id);

    if (id.length !== 24) {
      throw new Error('Invalid id');
    }
    const ProductDetails = await Product.findOne({ name: validationResult.value.name });
    if (ProductDetails) {
      throw new Error('This Product name already exists');
    }

    const product = await Product.findByIdAndUpdate(id, req.body)

    if (!product) {
      throw new Error('Product not Found of this id');
    }
    const updatedProduct = await Product.findById(id)
    res.status(200).json({
      status: 'success',
      message: 'Product Updated successfully',
      data: updatedProduct
    });
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

// {
//   "name": "Samosha",
//   "quantity": "2",
//   "price": "40",
//   "description": "Hii Hello byy good night"
// }

/**
* @swagger
* /api/user/deleteProducts/{_id}:
*   delete:
*     tags:
*       - Product
*     description: Delete a product by ID
*     produces:
*       - application/json
*     parameters:
*       - name: _id
*         in: path
*         description: Product ID
*         required: true
*         type: string
*     responses:
*       200:
*         description: Product deleted successfully.
*         schema:
*           type: object
*           properties:
*             status:
*               type: string
*               example: success
*             message:
*               type: string
*               example: Product Deleted successfully
*             data:
*               type: object
*               properties:
*                 _id:
*                   type: string
*                   example: 1234567890abcdef12345678
*                 name:
*                   type: string
*                   example: DeletedProductName
*                 quantity:
*                   type: number
*                   example: 20
*                 price:
*                   type: number
*                   example: 24.99
*                 description:
*                   type: string
*                   example: Deleted product description
*       400:
*         description: Bad Request - Invalid id.
*       404:
*         description: Not Found - Product not found with the provided ID.
*       500:
*         description: Internal Server Error - Something went wrong during product deletion.
*/

router.delete('/deleteProducts/:_id', async (req, res) => {
  try {
    const id = req.params._id;

    if (id.length !== 24) {
      throw new Error('Invalid id');
    }

    const product = await Product.findByIdAndDelete(id);

    console.log("product", product);
    if (!product) {
      throw new Error('cannot find any product with this ID');
    }
    res.status(200).json({
      status: 'success',
      message: 'Product Delted successfully',
      data: product
    });
  } catch (error) {
    res.status(500).json({ message: error.message })
  }
})

module.exports = router
