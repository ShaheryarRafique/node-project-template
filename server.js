const dotenv = require("dotenv");
const path = require("path");
const { connection, closeConnection } = require("./db.js"); // Assuming closeConnection is a function to close the database
const logger = require('./utils/logger');

//Env Variables
dotenv.config({
    path: path.join(__dirname, ".env"),
});

const app = require('./app.js');
require('./db');

const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  logger.info('Server is listening on port ' + port);
});

connection();

// Function to handle graceful shutdown
const gracefulShutdown = () => {
  logger.error("Gracefully shutting down...");

  // Close the database connection
  closeConnection().then(() => {
    logger.error("Database connection closed.");

    // Close the server
    server.close(() => {
      logger.error("Server shut down gracefully.");
      process.exit(0);
    });
  });
};

// Handle termination signals
process.on("SIGTERM", gracefulShutdown);
process.on("SIGINT", gracefulShutdown);

process.on("uncaughtException", (err) => {
  logger.error("Uncaught Exception:", err);
  gracefulShutdown();
});

process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
  gracefulShutdown();
});