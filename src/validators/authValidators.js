const Joi = require("joi");
const { AppError } = require("../middleware/errorHandler");

// Validation middleware wrapper
const validate = (schema) => {
  return (req, res, next) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
    });

    if (error) {
      const errorMessage = error.details
        .map((detail) => detail.message)
        .join(", ");
      throw new AppError(errorMessage, 400);
    }

    req.body = value;
    next();
  };
};

// Register validation schema
const registerSchema = Joi.object({
  email: Joi.string().email().required().lowercase().trim().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),

  username: Joi.string()
    .alphanum()
    .min(3)
    .max(24)
    .required()
    .lowercase()
    .trim()
    .messages({
      "string.alphanum": "Username must contain only letters and numbers",
      "string.min": "Username must be at least 3 characters long",
      "string.max": "Username cannot exceed 24 characters",
      "any.required": "Username is required",
    }),

  password: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])"))
    .messages({
      "string.min": "Password must be at least 8 characters long",
      "string.max": "Password cannot exceed 128 characters",
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one lowercase letter, and one number",
      "any.required": "Password is required",
    }),

  confirmPassword: Joi.string().valid(Joi.ref("password")).required().messages({
    "any.only": "Passwords do not match",
    "any.required": "Please confirm your password",
  }),

  firstName: Joi.string().min(2).max(50).required().trim().messages({
    "string.min": "First name must be at least 2 characters long",
    "string.max": "First name cannot exceed 50 characters",
    "any.required": "First name is required",
  }),

  lastName: Joi.string().min(2).max(50).required().trim().messages({
    "string.min": "Last name must be at least 2 characters long",
    "string.max": "Last name cannot exceed 50 characters",
    "any.required": "Last name is required",
  }),
});

// Login validation schema
const loginSchema = Joi.object({
  identifier: Joi.string().required().trim().messages({
    "any.required": "Email or username is required",
  }),

  password: Joi.string().required().messages({
    "any.required": "Password is required",
  }),
});

// Change password validation schema
const changePasswordSchema = Joi.object({
  currentPassword: Joi.string().required().messages({
    "any.required": "Current password is required",
  }),

  newPassword: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])"))
    .invalid(Joi.ref("currentPassword"))
    .messages({
      "string.min": "New password must be at least 8 characters long",
      "string.max": "New password cannot exceed 128 characters",
      "string.pattern.base":
        "New password must contain at least one uppercase letter, one lowercase letter, and one number",
      "any.invalid": "New password must be different from current password",
      "any.required": "New password is required",
    }),

  confirmNewPassword: Joi.string()
    .valid(Joi.ref("newPassword"))
    .required()
    .messages({
      "any.only": "Passwords do not match",
      "any.required": "Please confirm your new password",
    }),
});

// Request password reset validation schema
const requestPasswordResetSchema = Joi.object({
  email: Joi.string().email().required().lowercase().trim().messages({
    "string.email": "Please provide a valid email address",
    "any.required": "Email is required",
  }),
});

// Reset password validation schema
const resetPasswordSchema = Joi.object({
  token: Joi.string().required().messages({
    "any.required": "Reset token is required",
  }),

  newPassword: Joi.string()
    .min(8)
    .max(128)
    .required()
    .pattern(new RegExp("^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])"))
    .messages({
      "string.min": "Password must be at least 8 characters long",
      "string.max": "Password cannot exceed 128 characters",
      "string.pattern.base":
        "Password must contain at least one uppercase letter, one lowercase letter, and one number",
      "any.required": "New password is required",
    }),

  confirmNewPassword: Joi.string()
    .valid(Joi.ref("newPassword"))
    .required()
    .messages({
      "any.only": "Passwords do not match",
      "any.required": "Please confirm your new password",
    }),
});

// Refresh token validation schema
const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string().required().messages({
    "any.required": "Refresh token is required",
  }),
});

// Verify email token validation
const verifyEmailSchema = Joi.object({
  token: Joi.string().required().messages({
    "any.required": "Verification token is required",
  }),
});

module.exports = {
  validate,
  validateRegister: validate(registerSchema),
  validateLogin: validate(loginSchema),
  validateChangePassword: validate(changePasswordSchema),
  validateRequestPasswordReset: validate(requestPasswordResetSchema),
  validateResetPassword: validate(resetPasswordSchema),
  validateRefreshToken: validate(refreshTokenSchema),
  validateVerifyEmail: validate(verifyEmailSchema),
};
