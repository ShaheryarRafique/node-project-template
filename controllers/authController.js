const authService = require('../services/authService');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const logger = require('../utils/logger');
const EmailService = require('../services/EmailService');

exports.register = catchAsync(async (req, res, next) => {
    const { email, password, name } = req.body;

    // Check if the user already exists
    const existingUser = await authService.findUserByEmail(email);
    if (existingUser) {
        logger.error(`Registration attempt with existing email: ${email}`);
        return next(new AppError('Email already in use.', 409));
    }

    // Register the user
    const newUser = await authService.registerUser({ email, password, name });

    // Generate email verification token
    const verificationToken = await authService.generateEmailVerificationToken(newUser);

    // Create verification URL
    const verificationUrl = `${req.protocol}://${req.get('host')}/api/v1/auth/verifyEmail/${verificationToken}`;

    // Send verification email in the background
    setImmediate(async () => {
        const emailService = new EmailService(newUser, verificationUrl);
        try {
            await emailService.sendVerificationEmail();
            logger.info(`Verification email sent to: ${newUser.email}`);
        } catch (err) {
            logger.error(`Failed to send verification email to: ${newUser.email}`, err);
            await authService.verifyAccount(newUser, true);
            return next(new AppError('There was an error sending the email. Try again later!', 500));
        }
    });

    // Send JWT token
    authService.createSendToken(res, newUser, 201);

    logger.info(`User registered: ${newUser.email}`);
});

exports.verifyEmail = catchAsync(async (req, res, next) => {
    const { token } = req.params;
    const hashedToken = authService.hashToken(token);

    const user = await prisma.user.findFirst({
        where: {
            emailVerificationToken: hashedToken,
            emailVerificationTokenExpires: {
                gt: new Date(),
            },
        },
    });

    if (!user) {
        return next(new AppError('Token is invalid or has expired', 400));
    }

    await authService.verifyAccount(user, true);

    // Redirect or respond depending on your flow
    res.status(200).send('Email verified successfully! You can now log in.');
});

exports.resendVerificationEmail = catchAsync(async (req, res, next) => {
    const user = await prisma.user.findUnique({
        where: { id: req.user.id, emailVerified: false },
    });

    if (!user) {
        return next(new AppError('No unverified user found or email already verified.', 404));
    }

    // Check if the token is null or expired
    if (!user.emailVerificationToken || new Date() > user.emailVerificationTokenExpires) {
        const verificationToken = await authService.generateEmailVerificationToken(user);
        const verificationUrl = `${req.protocol}://${req.get('host')}/api/users/verifyEmail/${verificationToken}`;
        
        const emailService = new EmailService(user, verificationUrl);
        try {
            await emailService.sendVerificationEmail();
            logger.info(`Verification email resent to: ${user.email}`);
            res.status(200).json({ message: 'Verification email resent successfully!' });
        } catch (err) {
            logger.error(`Failed to resend verification email to: ${user.email}`, err);
            return next(new AppError('Failed to send verification email.', 500));
        }
    } else {
        res.status(400).json({ message: 'A verification email was already sent recently. Please check your email or try again later.' });
    }
});


exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;

    const user = await authService.findUserByEmail(email);

    if (!user || !(await authService.comparePassword(password, user.password))) {
        logger.error(`Invalid login attempt for email: ${email}`);
        return next(new AppError('Incorrect email or password.', 401));
    }

    authService.createSendToken(res, user, 200);
});

exports.logout = catchAsync(async (req, res) => {
    res.cookie('templete_token', 'loggedout', {
        expires: new Date(Date.now() + 10 * 1000),
        httpOnly: true,
    });
    logger.info('User logged out');
    res.status(200).json({ status: 'success' });
});

exports.forgotPassword = catchAsync(async (req, res, next) => {
    const { ip, userAgent } = req;
    const { email } = req.body;
    // 1) Get user based on POSTed email
    const user = await authService.findUserByEmail(email);
    if (!user) {
        logger.error(`Password reset requested for non-existent email: ${email}`);
        return next(new AppError('There is no user with that email address.', 404));
    }

    // 2) Generate the random reset token
    const resetToken = await authService.createPasswordResetToken(user);

    // 3) Send it to user's email
    const resetURL = `${req.protocol}://${req.get('host')}/api/v1/auth/resetPassword/${resetToken}`;
    const emailService = new Email(user, resetURL, ip, userAgent);

    try {
        await emailService.sendPasswordReset();
        res.status(200).json({
            status: 'success',
            message: 'Token sent to email!',
        });
    } catch (err) {
        logger.error(`Error sending password reset email to: ${user.email}`, err);

        // Clear the reset token and expiration fields if email sending fails
        await prisma.user.update({
            where: { id: user.id },
            data: {
                passwordResetToken: null,
                passwordResetExpires: null,
            },
        });

        return next(new AppError('There was an error sending the email. Try again later!', 500));
    }
});

exports.resetPassword = catchAsync(async (req, res, next) => {
    // 1) Get user based on the token
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await prisma.user.findFirst({
        where: {
            passwordResetToken: hashedToken,
            passwordResetExpires: { gt: new Date() },
        },
    });

    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
        logger.error(`Invalid or expired password reset token used.`);
        return next(new AppError('Token is invalid or has expired', 400));
    }

    // 3) Update password and clear reset fields
    const hashedPassword = await authService.hashPassword(req.body.password);
    await authService.resetPassword(user, hashedPassword);

    // 4) Log the user in, send JWT
    authService.createSendToken(res, user, 200);
    logger.info(`Password reset successfully for user: ${user.email}`);
});
