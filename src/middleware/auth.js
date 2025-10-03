const jwt = require("jsonwebtoken");
const prisma = require("../../prisma");
const { AppError } = require("./errorHandler");
const { asyncHandler } = require("./asyncHandler");
const { logger } = require("../utils/logger");

const verifyToken = (request) => {
  let token;

  // Check if token exists in Authorization header
  if (
    request.headers.authorization &&
    request.headers.authorization.startsWith("Bearer")
  ) {
    token = request.headers.authorization.split(" ")[1];
  }

  return token;
};

const decodToken = (token) => jwt.verify(token, process.env.JWT_SECRET);

// Verify JWT token and attach user to the request
const protect = asyncHandler(async (req, res, next) => {
  let token;

  // Check if token exists in Authorization header
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  if (!token) {
    throw new AppError(
      "You are not logged in. Please log in to access this ressource.",
      401
    );
  }

  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // Check if user still exists
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        email: true,
        username: true,
        firstName: true,
        lastName: true,
        role: true,
        status: true,
        isVerified: true,
        avatar: {
          select: {
            url: true,
            alt: true,
          },
        },
      },
    });

    if (!user) {
      throw new AppError(
        "The user belonging to this token no longer exists.",
        401
      );
    }

    // Check if user is active
    if (user.status !== "ACTIVE") {
      throw new AppError(
        "Your account has been deactivated. Please contact support.",
        403
      );
    }

    // Check if user is verified (optional - comment out if not needed)
    // if (!user.isVerified) {
    //   throw new AppError('Please verify your email address to access this resource.', 403);
    // }

    // Grand access to protected route
    req.user = user;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Inavlid token. Please log in again.", 401);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError("Your token has expired. Please log in again.", 401);
    }
  }
});

// Restrict access to specific roles
const restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      throw new AppError(
        "You are not logged in. Please log in to access this resource.",
        401
      );
    }

    if (!roles.includes(req.user.role)) {
      logger.warn(
        `Access denied for user ${req.user.id} with role ${req.user.role} to ${req.path}`
      );
      throw new AppError(
        "You do not have permission to perform this action.",
        403
      );
    }

    next();
  };
};

// Restrict access to specific roles
const checkOwnership = (modelName) => {
  return asyncHandler(async (req, res, next) => {
    const resourceId = req.params.id;
    const userId = req.user.id;

    // Admin can access any resource
    if (req.user.role === "ADMIN") {
      return next();
    }

    // Check ownership based on model
    let resource;
    switch (modelName) {
      case "post":
        resource = await prisma.post.findUnique({
          where: { id: resourceId },
          select: { authorId: true },
        });
        if (!resource || resource.authorId !== userId) {
          throw new AppError(
            "You do not have permission to access this resource.",
            403
          );
        }
        break;

      case "user":
        if (resourceId !== userId) {
          throw new AppError(
            "You do not have permission to access this resource.",
            403
          );
        }
        break;

      default:
        throw new AppError("Invalid resource type.", 400);
    }

    next();
  });
};

// Optional authentification (user data if logged in, but not required)
const optionalAuth = asyncHandler(async (req, res, next) => {
  const token = verifyToken(req);

  if (token) {
    try {
      const decoded = decodToken(token);
      const user = await prisma.user.findUnique({
        where: { id: decoded.id },
        select: {
          id: true,
          email: true,
          username: true,
          firstName: true,
          lastName: true,
          role: true,
          status: true,
        },
      });

      if (user && user.status === "ACTIVE") {
        req.user = user;
      }
    } catch (error) {
      logger.debug("Optional auth failed:", error.message);
    }
  }

  next();
});

// Verify email token
const verifyEmailToken = asyncHandler(async (req, res, next) => {
  const { token } = req.params;

  if (!token) {
    throw new AppError("Email verification token is required.", 400);
  }

  try {
    const decoded = decodToken(token);

    if (decoded.type !== "email-verification") {
      throw new AppError("Invalid token type.", 400);
    }

    req.tokenData = decoded;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid verification token.", 400);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError(
        "Verification token has expired. Please request a new one.",
        400
      );
    }
    throw error;
  }
});

// Verify password reset token
const verifyResetToken = asyncHandler(async (req, res, next) => {
  const { token } = req.body;

  if (!token) {
    throw new AppError("Password reset token is required.", 400);
  }

  try {
    const decoded = decodToken(token);

    if (decoded.type !== "email-verification") {
      throw new AppError("Invalid token type.", 400);
    }

    req.tokenData = decoded;
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid Reset token.", 400);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError(
        "Reset token has expired. Please request a new one.",
        400
      );
    }
    throw error;
  }
});

module.exports = {
  protect,
  restrictTo,
  checkOwnership,
  optionalAuth,
  verifyEmailToken,
  verifyResetToken,
};
