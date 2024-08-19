const express = require('express');
const authController = require('../controllers/authController');
const { authValidations } = require('../validators/validation');
const validationMiddleware = require('../middlewares/validationMiddleware');
const authMiddleware = require('../middlewares/authMiddleware');

const router = express.Router();

router.post('/register', authValidations.register, validationMiddleware.validate, authController.register);
router.post('/login', authValidations.login, validationMiddleware.validate, authController.login);
router.post('/forgotPassword', authValidations.forgotPassword, validationMiddleware.validate, authController.forgotPassword);
router.post('/resetPassword/:token', authValidations.resetPassword, validationMiddleware.validate, authController.resetPassword);
router.post('/logout', authMiddleware.protect, authController.logout);
router.post('/resendVerificationEmail', authMiddleware.protect, authController.resendVerificationEmail);
router.get('/verifyEmail/:token', authMiddleware.protect, authController.verifyEmail);

module.exports = router;
