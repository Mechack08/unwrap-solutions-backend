require("dotenv").config();
const app = require("./src/app");
const prisma = require("./prisma");

const PORT = process.env.PORT || 4000;

async function startServer() {
  try {
    // Test database connection
    await prisma.$connect();
    console.log("✅ Database connected successfully");

    // Start server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on port ${PORT}`);
      console.log(`📝 Blog API available at http://localhost:${PORT}/api`);
      console.log(`📚 Environment: ${process.env.NODE_ENV || "development"}`);
    });
  } catch (error) {
    console.error("❌ Failed to start server:", error);
    process.exit(1);
  }
}

startServer();
