//Required Packages
const express = require("express");
const morgan = require("morgan");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const xss = require('xss-clean');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');

//Routes Paths
const routes = require("./routes/index");

// Controller Path
const globalErrorHandler = require("./controllers/errorController");
const AppError = require("./utils/appError");


//Express APP
const app = express();

// Pug View 
app.enable('trust proxy');

app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));


// Enable CORS for all routes
const corsOption = {
  origin: true,
  credentials: true,
};
app.use(cors(corsOption));

// Cookie Parser
app.use(cookieParser());

//Third party Middlewares
app.use(helmet());

//compression
app.use(compression());

// Limit requests from same API
const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: 'Too many requests from this IP, please try again in an hour!'
});

app.use('/api', limiter);

// Parse incoming JSON payloads
app.use(
  express.json({
    verify: (req, res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);

// Parse incoming URL-encoded payloads
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Data sanitization against XSS
app.use(xss());

//view the request url
if (process.env.NODE_ENV === "development") {
  app.use(
    morgan(
      ":method :url :status :res[content-length] bytes - :response-time ms"
    )
  );
}

//Routes Middleware
app.use("/api/v1", routes);

//Unknown API endpoint
app.use((req, res, next) => {
  next(new AppError(`Requested URL (${req.originalUrl}) does not exist`, 404));
});

//Global Error Handler
app.use(globalErrorHandler);

//Export File
module.exports = app;
