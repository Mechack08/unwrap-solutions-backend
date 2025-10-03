const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const prisma = require("../../prisma");
const { AppError } = require("../middleware/errorHandler");
const { logger } = require("../utils/logger");

// Generate JWT token
const generateToken = (
  payload,
  expiresIn = process.env.JWT_EXPIRES_IN || "7d"
) => {
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn });
};

// Generate refresh token
const generateRefreshToken = (payload) => {
  return jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "30d" }
  );
};

// Hash password
const hashPassword = async (password) => {
  return await bcrypt.hash(password, 12);
};

// Compare password
const comparePassword = async (candidatePassword, userPassword) => {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Register new user
const register = async (userData) => {
  const { email, username, password, firstName, lastName } = userData;

  // Check if user already exists
  const existingUser = await prisma.user.findFirst({
    where: {
      OR: [{ email }, { username }],
    },
  });

  if (existingUser) {
    if (existingUser.email === email) {
      throw new AppError("Email already in use", 400);
    }
    if (existingUser.username === username) {
      throw new AppError("Username already taken");
    }
  }

  // Hash password
  const hashedPassword = await hashPassword(password);

  // Create user
  const user = await prisma.user.create({
    data: {
      email,
      username,
      password: hashedPassword,
      firstName,
      lastName,
      role: "READER", // Default role
      status: "ACTIVE",
    },
    select: {
      id: true,
      email: true,
      username: true,
      firstName: true,
      lastName: true,
      role: true,
      status: true,
      isVerified: true,
      createdAt: true,
    },
  });

  // Generate tokens
  const accessToken = generateToken({ id: user.id, role: user.role });
  const refreshToken = generateRefreshToken({ id: user.id });

  logger.info(`New user registered: ${user.email}`);

  return {
    user,
    accessToken,
    refreshToken,
  };
};

// Login user
const login = async (identifier, password) => {
  // Find user by email or username
  const user = await prisma.user.findFirst({
    where: {
      OR: [{ email: identifier }, { username: identifier }],
    },
    include: {
      avatar: {
        select: {
          url: true,
          alt: true,
        },
      },
    },
  });

  if (!user) {
    throw new AppError("Invalid credentials.", 401);
  }

  // Check password
  const isPasswordValid = await comparePassword(password, user.password);

  if (!isPasswordValid) {
    logger.warn(`Failed login attempt for user: ${identifier}`);
    throw new AppError("Invalid credentials.", 401);
  }

  // Check if user is active
  if (user.status !== "ACTIVE") {
    throw new AppError(
      "Your account has been deactivated. Please contact support.",
      403
    );
  }

  // Generate tokens
  const accessToken = generateToken({ id: user.id, role: user.role });
  const refreshToken = generateRefreshToken({ id: user.id });

  // Remove password from response
  const { password: _, ...userWithoutPassword } = user;

  logger.info(`User logged in: ${user.email}`);

  return {
    user: userWithoutPassword,
    accessToken,
    refreshToken,
  };
};

// Refresh access token
const refreshAccessToken = async (refreshToken) => {
  if (!refreshToken) {
    throw new AppError("Refresh token is required", 400);
  }

  try {
    // Verify refresh token
    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET
    );

    // Check if user still exists
    const user = await prisma.user.findUnique({
      where: { id: decoded.id },
      select: {
        id: true,
        role: true,
        status: true,
      },
    });

    if (!user) {
      throw new AppError("User no longer exists", 401);
    }

    if (user.status !== "ACTIVE") {
      throw new AppError("User account is not active", 403);
    }

    // Generate new access token
    const newAccessToken = generateToken({ id: user.id, role: user.role });

    return {
      accessToken: newAccessToken,
    };
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid refresh token", 401);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError(
        "Refresh token has expired. Please log in again.",
        401
      );
    }
    throw error;
  }
};

// Change password (authenticated user)
const changePassword = async (userId, currentPassword, newPassword) => {
  // Get user with password
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new AppError("User not found", 404);
  }

  // Verify current password
  const isPasswordValid = await comparePassword(currentPassword, user.password);

  if (!isPasswordValid) {
    throw new AppError("Current password is incorrect", 401);
  }

  // Hash new password
  const hashedPassword = await hashPassword(newPassword);

  // Update password
  await prisma.user.update({
    where: { id: userId },
    data: { password: hashedPassword },
  });

  logger.info(`Password changed for user: ${user.email}`);

  return true;
};

// Request password reset
const requestPasswordReset = async (email) => {
  // Find user
  const user = await prisma.user.findUnique({
    where: { email },
  });

  if (!user) {
    // Don't reveal if user exists for security
    logger.warn(`Password reset requested for non-existent email: ${email}`);
    return true;
  }

  // Generate reset token (valid for 1 hour)
  const resetToken = jwt.sign(
    {
      id: user.id,
      type: "password-reset",
      email: user.email,
    },
    process.env.JWT_SECRET,
    { expiresIn: "1h" }
  );

  logger.info(`Password reset token generated for user: ${user.email}`);

  // TODO: Send email with reset token
  // await emailService.sendPasswordResetEmail(user.email, resetToken);

  return {
    resetToken, // Remove this in production, send via email only
    message: "Password reset instructions have been sent to your email",
  };
};

// Reset password with token
const resetPassword = async (token, newPassword) => {
  try {
    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.type !== "password-reset") {
      throw new AppError("Invalid token type", 400);
    }

    // Hash new password
    const hashedPassword = await hashPassword(newPassword);

    // Update password
    await prisma.user.update({
      where: { id: decoded.id },
      data: { password: hashedPassword },
    });

    logger.info(`Password reset completed for user: ${decoded.email}`);

    return true;
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid or expired reset token", 400);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError(
        "Reset token has expired. Please request a new one.",
        400
      );
    }
    throw error;
  }
};

// Verify email
const verifyEmail = async (token) => {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.type !== "email-verification") {
      throw new AppError("Invalid token type", 400);
    }

    // Update user verification status
    const user = await prisma.user.update({
      where: { id: decoded.id },
      data: { isVerified: true },
      select: {
        id: true,
        email: true,
        username: true,
        isVerified: true,
      },
    });

    logger.info(`Email verified for user: ${user.email}`);

    return user;
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      throw new AppError("Invalid verification token", 400);
    } else if (error.name === "TokenExpiredError") {
      throw new AppError(
        "Verification token has expired. Please request a new one.",
        400
      );
    }
    throw error;
  }
};

// Request email verification
const requestEmailVerification = async (userId) => {
  const user = await prisma.user.findUnique({
    where: { id: userId },
  });

  if (!user) {
    throw new AppError("User not found", 404);
  }

  if (user.isVerified) {
    throw new AppError("Email is already verified", 400);
  }

  // Generate verification token (valid for 24 hours)
  const verificationToken = jwt.sign(
    {
      id: user.id,
      type: "email-verification",
      email: user.email,
    },
    process.env.JWT_SECRET,
    { expiresIn: "24h" }
  );

  logger.info(`Email verification token generated for user: ${user.email}`);

  // TODO: Send verification email
  // await emailService.sendVerificationEmail(user.email, verificationToken);

  return {
    verificationToken, // Remove this in production, send via email only
    message: "Verification email has been sent",
  };
};

module.exports = {
  register,
  login,
  refreshAccessToken,
  changePassword,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
  requestEmailVerification,
  generateToken,
  hashPassword,
  comparePassword,
};
