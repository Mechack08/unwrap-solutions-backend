const authService = require("../services/authService");
const { asyncHandler } = require("../middleware/asyncHandler");
const { logger } = require("../utils/logger");

/**
 * @desc    Register a new user
 * @route   POST /api/auth/register
 * @access  Public
 */
const register = asyncHandler(async (req, res) => {
  const { email, username, password, firstName, lastName } = req.body;

  const result = await authService.register({
    email,
    username,
    password,
    firstName,
    lastName,
  });

  res.status(201).json({
    status: true,
    message: "Registration successful",
    data: {
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    },
  });
});

/**
 * @desc    Login user
 * @route   POST /api/auth/login
 * @access  Public
 */
const login = asyncHandler(async (req, res) => {
  const { identifier, password } = req.body;

  const result = await authService.login(identifier, password);

  res.status(200).json({
    success: true,
    message: "Login successful",
    data: {
      user: result.user,
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
    },
  });
});

/**
 * @desc    Get current user profile
 * @route   GET /api/auth/me
 * @access  Private
 */
const getMe = asyncHandler(async (req, res) => {
  res.status(200).json({
    success: true,
    data: {
      user: req.user,
    },
  });
});

/**
 * @desc    Logout user
 * @route   POST /api/auth/logout
 * @access  Private
 */
const logout = asyncHandler(async (req, res) => {
  // In a stateless JWT setup, logout is handled client-side by removing the token
  // If using refresh tokens with a database, you would invalidate them here

  logger.info(`User logged out: ${req.user.email}`);

  res.status(200).json({
    success: true,
    message: "Logout successful",
  });
});

/**
 * @desc    Refresh access token
 * @route   POST /api/auth/refresh
 * @access  Public
 */
const refreshToken = asyncHandler(async (req, res) => {
  const { refreshToken } = req.body;

  const result = await authService.refreshAccessToken(refreshToken);

  res.status(200).json({
    success: true,
    message: "Token refreshed successfully",
    data: {
      accessToken: result.accessToken,
    },
  });
});

/**
 * @desc    Change password
 * @route   POST /api/auth/change-password
 * @access  Private
 */
const changePassword = asyncHandler(async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  await authService.changePassword(req.user.id, currentPassword, newPassword);

  res.status(200).json({
    success: true,
    message: "Password changed successfully",
  });
});

/**
 * @desc    Request password reset
 * @route   POST /api/auth/forgot-password
 * @access  Public
 */
const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  const result = await authService.requestPasswordReset(email);

  res.status(200).json({
    success: true,
    message: result.message,
    // Include token only in development for testing
    ...(process.env.NODE_ENV === "development" && {
      resetToken: result.resetToken,
    }),
  });
});

/**
 * @desc    Reset password with token
 * @route   POST /api/auth/reset-password
 * @access  Public
 */
const resetPassword = asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body;

  await authService.resetPassword(token, newPassword);

  res.status(200).json({
    success: true,
    message:
      "Password reset successful. You can now login with your new password.",
  });
});

/**
 * @desc    Verify email address
 * @route   GET /api/auth/verify-email/:token
 * @access  Public
 */
const verifyEmail = asyncHandler(async (req, res) => {
  const { token } = req.params;

  const user = await authService.verifyEmail(token);

  res.status(200).json({
    success: true,
    message: "Email verified successfully",
    data: {
      user,
    },
  });
});

/**
 * @desc    Request email verification
 * @route   POST /api/auth/request-verification
 * @access  Private
 */
const requestEmailVerification = asyncHandler(async (req, res) => {
  const result = await authService.requestEmailVerification(req.user.id);

  res.status(200).json({
    success: true,
    message: result.message,
    // Include token only in development for testing
    ...(process.env.NODE_ENV === "development" && {
      verificationToken: result.verificationToken,
    }),
  });
});

module.exports = {
  register,
  login,
  getMe,
  logout,
  refreshToken,
  changePassword,
  forgotPassword,
  resetPassword,
  verifyEmail,
  requestEmailVerification,
};
