const express = require("express");
const authController = require("../controllers/authController");
const { protect } = require("../middleware/auth");
const {
  validateRegister,
  validateLogin,
  validateChangePassword,
  validateRequestPasswordReset,
  validateResetPassword,
  validateRefreshToken,
} = require("../validators/authValidators");

const router = express.Router();

// Public routes
router.post("/register", validateRegister, authController.register);
router.post("/login", validateLogin, authController.login);
router.post("/refresh", validateRefreshToken, authController.refreshToken);
router.post(
  "/forgot-password",
  validateRequestPasswordReset,
  authController.forgotPassword
);
router.post(
  "/reset-password",
  validateResetPassword,
  authController.resetPassword
);
router.get("/verify-email/:token", authController.verifyEmail);

// Protected routes (require authentication)
router.use(protect); // All routes after this require authentication

router.get("/me", authController.getMe);
router.post("/logout", authController.logout);
router.post(
  "/change-password",
  validateChangePassword,
  authController.changePassword
);
router.post("/request-verification", authController.requestEmailVerification);

module.exports = router;
