const winston = require('winston');
const fs = require('fs');
const path = require('path');

// Define log file and log level
const logFile = path.join('tmp', 'development.log');
const logLevel = 'debug'; // Set log level to the lowest level (debug)

// Ensure the log file directory exists
const logFileDir = path.dirname(logFile);
if (!fs.existsSync(logFileDir)) {
  fs.mkdirSync(logFileDir, { recursive: true });
}

// Ensure the log file exists
if (!fs.existsSync(logFile)) {
  fs.writeFileSync(logFile, '');
}

// Create a logger instance
const logger = winston.createLogger({
  level: logLevel,
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ level, message, timestamp, requestId, ...metadata }) => {
      // Include log level, timestamp, message, and any additional metadata
      const logObject = {
        level,
        timestamp,
        message,
        requestId,
        ...metadata
      };
      return JSON.stringify(logObject);
    })
  ),
  transports: [
    new winston.transports.File({ filename: logFile }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
  ],
});

module.exports = logger;
