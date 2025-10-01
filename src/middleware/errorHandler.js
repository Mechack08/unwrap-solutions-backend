const { logger } = require("../utils/logger");

// Custom error class
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.status = `${statusCode}`.startsWith("4") ? "fail" : "error";
    this.isOperational = true;

    Error.captureStackTrace(this, this.constructor);
  }
}

// Handle Prisma errors
const handlePrismaError = (err) => {
  switch (err.code) {
    case "P2002":
      return new AppError("Duplicate field value entered", 400);
    case "P2014":
      return new AppError("Invalid ID", 400);
    case "P2003":
      return new AppError("Invalid input data", 400);
    case "P2025":
      return new AppError("Record not found", 404);
    default:
      return new AppError("Database error", 500);
  }
};

// Handle JWT errors
const handleJWTError = () =>
  new AppError("Invalid token. Please log in again!", 401);

const handleJWTExpiredError = () =>
  new AppError("Your token has expired! Please log in again.", 401);

// Handle validation errors
const handleValidationError = (err) => {
  const errors = err.details.map((el) => el.message);
  const message = `Invalid input data. ${errors.join(". ")}`;
  return new AppError(message, 400);
};

// Send error response in development
const sendErrorDev = (err, res) => {
  res.status(err.statusCode).json({
    status: err.status,
    error: err,
    message: err.message,
    stack: err.stack,
  });
};

// Send error response in production
const sendErrorProd = (err, res) => {
  // Operational, trusted error: send message to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      status: err.status,
      message: err.message,
    });
  } else {
    // Programming or other unknown error: don't leak error details
    logger.error("ERROR:", err);

    res.status(500).json({
      status: "error",
      message: "Something went wrong!",
    });
  }
};

// Main error handler
const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "error";

  if (process.env.NODE_ENV === "development") {
    sendErrorDev(err, res);
  } else {
    let error = { ...err };
    error.message = err.message;

    // Handle specific error types
    if (err.code?.startsWith("P2")) error = handlePrismaError(error);
    if (err.name === "JsonWebTokenError") error = handleJWTError();
    if (err.name === "TokenExpiredError") error = handleJWTExpiredError();
    if (err.name === "ValidationError") error = handleValidationError(err);

    sendErrorProd(error, res);
  }
};

module.exports = {
  AppError,
  errorHandler,
};
