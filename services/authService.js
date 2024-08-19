const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { PrismaClient } = require('@prisma/client');
import { withOptimize } from "@prisma/extension-optimize";
const util = require("util");
const crypto = require('crypto');

// Prisma Client
const prisma = new PrismaClient().$extends(withOptimize());

// JWT Token Generation
const signToken = (user) => {
    return jwt.sign({ user_id: user.id }, process.env.JWT_SECRET_TOKEN, {
        expiresIn: process.env.JWT_EXPIRES_IN,
    });
};

// JWT Token Verification
const verifyToken = async (token) => {
    return await util.promisify(jwt.verify)(token, process.env.JWT_SECRET_TOKEN);;
};

// Create JWT and Send Response
const createSendToken = (res, user, statusCode) => {
    const token = signToken(user);

    // Setup cookie options
    const cookieOptions = {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'None',
    };

    res.cookie('templete_token', JSON.stringify(token), cookieOptions);

    // Clear the password from the user object before sending it back
    user.password = undefined;

    res.status(statusCode).json({
        status: 'success',
        token,
        data: { user },
    });
};

// Password Hashing
const hashPassword = async (password) => {
    return await bcrypt.hash(password, 12);
};

// Password Comparison
const comparePassword = async (candidatePassword, userPassword) => {
    return await bcrypt.compare(candidatePassword, userPassword);
};

// Find User by Email
const findUserByEmail = async (email) => {
    return await prisma.user.findUnique({
        where: { email },
    });
};

// Find User by ID
const findUserById = async (id) => {
    return await prisma.user.findUnique({
        where: { id },
    });
};

const registerUser = async (userData) => {
    // Hash the user's password before saving
    userData.password = await hashPassword(userData.password);

    // Create a new user in the database
    const newUser = await prisma.user.create({
        data: userData,
    });

    return newUser;
};

const generateEmailVerificationToken = async (user) => {
    const verifyEmailToken = generateToken();
    const hashedToken = hashToken(verifyEmailToken);
    const expiresIn = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
    
    await prisma.user.update({
        where: { id: user.id },
        data: {
          emailVerificationToken: hashedToken,
          emailVerificationTokenExpires: expiresIn,
        },
      });
    
      return verifyEmailToken;
};

const generateToken = () => crypto.randomBytes(20).toString('hex');

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const createPasswordResetToken = async (user) => {
    const resetToken = generateToken();
    const hashedToken = hashToken(resetToken);
  
    const expiresIn = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
  
    await prisma.user.update({
      where: { id: user.id },
      data: {
        passwordResetToken: hashedToken,
        passwordResetExpires: expiresIn,
      },
    });
  
    return resetToken;
};


const resetPassword = async (user, newPassword) => {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: newPassword,
        passwordResetToken: null,
        passwordResetExpires: null,
        passwordChangedAt: new Date(),
      },
    });
};

const verifyAccount =  async (user, emailVerfiyStatus) => {
    await prisma.user.update({
        where: { id: user.id },
        data: {
            emailVerified: true,
            emailVerificationToken: null,
            emailVerificationTokenExpires: null,
        },
    });
};
  

module.exports = {
    signToken,
    hashPassword,
    comparePassword,
    findUserByEmail,
    findUserById,
    createSendToken,
    verifyToken,
    registerUser,
    createPasswordResetToken,
    resetPassword,
    generateEmailVerificationToken,
    hashToken
};
