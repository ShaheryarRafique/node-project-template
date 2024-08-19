const { Prisma } = require('@prisma/client');
const logger = require('../utils/logger');

const sendDevError = (res, err) => {
    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
        error: err,
        stack: err.stack
    });
};

const sendProdError = (res, err) => {
    if (err.isOperation) {
        return res.status(err.statusCode).json({
            status: err.status,
            message: err.message,
        });
    }

    let message = 'Something went very wrong.';
    let statusCode = 500;

    if (err.message && err.message.includes("Can't reach database server at")) {
        message = `Can't reach database server at ${err.message.split(' ')[4]}:${err.message.split(' ')[5].split('\n')[0]}. Please make sure your database server is running.`;
    }

    return res.status(statusCode).json({
        status: 'error',
        message,
    });
};

module.exports = (err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    // Log the error using logger instance
    logger.error(err.message);
    logger.debug(err.stack);

    if (process.env.NODE_ENV === 'development') {
        sendDevError(res, err);
    }
    if (process.env.NODE_ENV === 'production') {
        // console.log('Handling production error:', err.response); // Add this line
        if (err instanceof Prisma.PrismaClientKnownRequestError) {
            // console.log('Handling Prisma error:', err.code);
            switch (err.code) {
                case 'P1000':
                    return res.status(401).json({
                        status: 'fail',
                        message: "Authentication failed against database server."
                    });
                case 'P2001':
                    return res.status(404).json({
                        status: 'fail',
                        message: `The record searched for in the where condition does not exist.`
                    });
                case 'P2002':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Unique constraint failed.'
                    });
                case 'P2003':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Foreign key constraint failed.'
                    });
                case 'P2004':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'A constraint failed on the database.'
                    });
                case 'P2005':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'The value stored in the database is invalid for the field\'s type.'
                    });
                case 'P2006':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'The provided value for the field is not valid.'
                    });
                case 'P2007':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'Data validation error.'
                    });
                case 'P2015':
                    return res.status(400).json({
                        status: 'fail',
                        message: 'A related record could not be found.'
                    });
                default:
                    return sendProdError(res, err);
            }
        }
         else {
            return sendProdError(res, err);
        }
    }
};
