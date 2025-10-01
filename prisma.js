// PRISMA CLIENT SETUP
const { PrismaClient } = require("./src/generated/prisma/client");
const prisma = new PrismaClient();

// EXPORTING THE PRISMA CLIENT INSTANCE
module.exports = prisma;
