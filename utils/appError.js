class AppError extends Error {

    constructor(message, statusCode) {
        super(message)
        this.statusCode = statusCode || 500;
        this.status = this.statusCode < 500 ? 'fail' : 'error';
        this.isOperation = true;

        Error.captureStackTrace(this, this.constructor);
    }

}

module.exports = AppError;