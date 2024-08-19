const authService = require('../services/authService');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/appError');
const logger = require('../utils/logger');

exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    } else if (req.cookies.templete_token) {
        token = JSON.parse(req.cookies.templete_token);
    }

    if (!token) {
        logger.error('No token provided');
        return next(new AppError('You are not logged in! Please log in to get access.', 401));
    }

    const decoded = await authService.verifyToken(token);

    const user = await authService.findUserById(decoded.user_id);

    if (!user) {
        logger.error('Token does not belong to a valid user');
        return next(new AppError('The user belonging to this token no longer exists.', 401));
    }

    logger.info(`Authenticated user: ${user.email}`);
    res.locals.user = user;
    next();
});

exports.restrictTo = (...roles) => {
    return (req, res, next) => {
      // roles is an array like ['admin', 'moderator']. role might be 'user' or something else
      if (!roles.includes(req.user.role)) {
        logger.error('You do not have permission to perform this action');
        return next(
          new AppError('You do not have permission to perform this action', 403)
        );
      }
  
      next();
    };
};