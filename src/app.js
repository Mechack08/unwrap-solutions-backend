const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const prisma = require("../prisma");

// Import middleware
const { errorHandler } = require("./middleware/errorHandler");
const { logger } = require("./utils/logger");

// Import routes
// const authRoutes = require("./routes/auth");
// const postRoutes = require("./routes/posts");
// const categoryRoutes = require("./routes/categories");
// const tagRoutes = require("./routes/tags");
// const commentRoutes = require("./routes/comments");
// const userRoutes = require("./routes/users");

const app = express();

// Trust proxy for proper IP detection behind load balancers
app.set("trust proxy", 1);

// Enhanced Security Headers with Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: ["'self'", "data:", "https:"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    noSniff: true,
    frameguard: { action: "deny" },
    xssFilter: true,
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
  })
);

// CORS Configuration with Security
const corsOptions = {
  origin: function (origin, callback) {
    const allowedOrigins = [
      process.env.FRONTEND_URL,
      "http://localhost:3001",
      "http://localhost:3000",
      "https://unwrapsolutions.dev",
      "https://www.unwrapsolutions.dev",
      "https://blog.unwrapsolutions.dev",
    ].filter(Boolean);

    // Allow requests with no origin (mobile apps, etc.)
    if (!origin) return callback(null, true);

    if (allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      logger.warn(`Blocked CORS request from origin: ${origin}`);
      callback(new Error("Not allowed by CORS"));
    }
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
  allowedHeaders: [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
    "X-API-Key",
  ],
  exposedHeaders: ["X-Total-Count", "X-Page-Count"],
  maxAge: 86400, // 24 hours
};

app.use(cors(corsOptions));

// Rate Limiting with different limits for different endpoints
const createRateLimit = (
  windowMs,
  max,
  message,
  skipSuccessfulRequests = false
) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      error: message,
      retryAfter: Math.ceil(windowMs / 1000),
    },
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests,
    keyGenerator: (req) => {
      return rateLimit.ipKeyGenerator(req.ip) || req.connection.remoteAddress;
    },
    handler: (req, res) => {
      logger.warn(
        `Rate limit exceeded for IP: ${rateLimit.ipKeyGenerator(req.ip)} on ${req.path}`
      );
      res.status(429).json({
        error: "Too many requests",
        message: "Rate limit exceeded. Please try again later.",
        retryAfter: Math.ceil(windowMs / 1000),
      });
    },
  });
};

// General API rate limiting
const generalLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  100, // limit each IP to 100 requests per windowMs
  "Too many requests from this IP, please try again later."
);

// Strict rate limiting for authentication routes
const authLimiter = createRateLimit(
  15 * 60 * 1000, // 15 minutes
  5, // limit each IP to 5 auth requests per windowMs
  "Too many authentication attempts, please try again later.",
  true // skip successful requests
);

// Moderate rate limiting for write operations
const writeLimiter = createRateLimit(
  60 * 1000, // 1 minute
  10, // limit each IP to 10 write requests per minute
  "Too many write requests, please try again later."
);

// Apply rate limiting
app.use("/api", generalLimiter);
app.use("/api/auth", authLimiter);

// Body parsing middleware with size limits
app.use(
  express.json({
    limit: "10mb",
    verify: (req, res, buf) => {
      // Store raw body for webhook verification if needed
      req.rawBody = buf;
    },
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "10mb",
    parameterLimit: 100, // Limit number of parameters
  })
);

// Security middleware for file uploads
app.use(
  "/uploads",
  express.static(path.join(__dirname, "../uploads"), {
    maxAge: "1d",
    setHeaders: (res, path) => {
      // Prevent execution of uploaded files
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("Content-Disposition", "inline");

      // Only allow image files to be displayed
      const ext = path.split(".").pop().toLowerCase();
      const allowedImageTypes = ["jpg", "jpeg", "png", "gif", "webp", "svg"];

      if (!allowedImageTypes.includes(ext)) {
        res.setHeader("Content-Type", "application/octet-stream");
        res.setHeader("Content-Disposition", "attachment");
      }
    },
  })
);

// Request sanitization middleware
app.use((req, res, next) => {
  // Remove any potential script tags from request body
  if (req.body && typeof req.body === "object") {
    const sanitizeObject = (obj) => {
      for (const key in obj) {
        if (typeof obj[key] === "string") {
          // Basic XSS protection - remove script tags
          obj[key] = obj[key].replace(
            /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
            ""
          );
        } else if (typeof obj[key] === "object" && obj[key] !== null) {
          sanitizeObject(obj[key]);
        }
      }
    };
    sanitizeObject(req.body);
  }
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - start;
    const logData = {
      method: req.method,
      url: req.originalUrl,
      status: res.statusCode,
      ip: req.ip,
      userAgent: req.get("User-Agent"),
      duration: `${duration}ms`,
      contentLength: res.get("Content-Length") || 0,
    };

    if (res.statusCode >= 400) {
      logger.warn("HTTP Request", logData);
    } else {
      logger.info("HTTP Request", logData);
    }
  });

  next();
});

// Security headers middleware
app.use((req, res, next) => {
  // Additional security headers
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "geolocation=(), microphone=(), camera=()"
  );

  // Remove potentially sensitive headers
  res.removeHeader("X-Powered-By");
  res.removeHeader("Server");

  next();
});

// Health check endpoint (before authentication)
app.get("/health", async (req, res) => {
  try {
    // Check database connection
    await prisma.$queryRaw`SELECT 1`;

    res.status(200).json({
      status: "healthy",
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || "development",
      version: process.env.npm_package_version || "1.0.0",
      database: "connected",
    });
  } catch (error) {
    logger.error("Health check failed:", error);
    res.status(503).json({
      status: "unhealthy",
      timestamp: new Date().toISOString(),
      error: "Database connection failed",
    });
  }
});

// Security info endpoint (for security.txt)
app.get("/.well-known/security.txt", (req, res) => {
  res.type("text/plain");
  res.send(`Contact: security@unwrapsolutions.dev
Expires: ${new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString()}
Preferred-Languages: en
Policy: https://unwrapsolutions.dev/security-policy`);
});

// API routes with appropriate rate limiting
// app.use("/api/auth", authRoutes);
// app.use("/api/posts", postRoutes);
// app.use("/api/categories", categoryRoutes);
// app.use("/api/tags", tagRoutes);
// app.use("/api/comments", writeLimiter, commentRoutes);
// app.use("/api/users", userRoutes);

// API documentation route
app.get("/api", (req, res) => {
  res.json({
    message: "Welcome to Unwrap Solutions Blog API",
    version: "1.0.0",
    documentation: "https://docs.unwrapsolutions.dev/api",
    endpoints: {
      auth: {
        path: "/api/auth",
        methods: ["POST"],
        description: "Authentication endpoints",
      },
      posts: {
        path: "/api/posts",
        methods: ["GET", "POST", "PUT", "DELETE"],
        description: "Blog posts management",
      },
      categories: {
        path: "/api/categories",
        methods: ["GET", "POST", "PUT", "DELETE"],
        description: "Category management",
      },
      tags: {
        path: "/api/tags",
        methods: ["GET", "POST", "PUT", "DELETE"],
        description: "Tag management",
      },
      comments: {
        path: "/api/comments",
        methods: ["GET", "POST", "PUT", "DELETE"],
        description: "Comment management",
      },
      users: {
        path: "/api/users",
        methods: ["GET", "PUT", "DELETE"],
        description: "User management",
      },
    },
    rateLimit: {
      general: "100 requests per 15 minutes",
      auth: "5 requests per 15 minutes",
      writes: "10 requests per minute",
    },
    security: {
      https: process.env.NODE_ENV === "production",
      cors: "Configured for specific origins",
      headers: "Security headers enabled",
      rateLimiting: "Multiple tiers active",
    },
  });
});

// robots.txt
app.get("/robots.txt", (req, res) => {
  res.type("text/plain");
  res.send(`User-agent: *
Disallow: /api/
Disallow: /uploads/private/
Allow: /uploads/public/

Sitemap: ${process.env.FRONTEND_URL || "https://blog.unwrapsolutions.dev"}/sitemap.xml`);
});

// Handle preflight requests
app.options(/.*/, cors(corsOptions));

// 404 handler for API routes
app.use(/^\/api\/.*/, (req, res) => {
  logger.warn(
    `404 - API endpoint not found: ${req.method} ${req.originalUrl} - IP: ${req.ip}`
  );
  res.status(404).json({
    error: "API endpoint not found",
    message: `Cannot ${req.method} ${req.originalUrl}`,
    availableEndpoints: [
      "/api/auth",
      "/api/posts",
      "/api/categories",
      "/api/tags",
      "/api/comments",
      "/api/users",
    ],
  });
});

// 404 handler for all other routes
app.use(/.*/, (req, res) => {
  res.status(404).json({
    error: "Resource not found",
    message: `Cannot ${req.method} ${req.originalUrl}`,
  });
});

// Global error handler (must be last middleware)
app.use(errorHandler);

// Graceful shutdown handling
process.on("SIGTERM", async () => {
  logger.info("SIGTERM received, shutting down gracefully");
  await prisma.$disconnect();
  process.exit(0);
});

process.on("SIGINT", async () => {
  logger.info("SIGINT received, shutting down gracefully");
  await prisma.$disconnect();
  process.exit(0);
});

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  logger.error("Uncaught Exception:", error);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on("unhandledRejection", (reason, promise) => {
  logger.error("Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});

module.exports = app;
