const { PrismaClient } = require('@prisma/client');
const prisma = new PrismaClient();
const logger = require('./utils/logger');

const connection = () => {
  if (prisma.$connect) {
    logger.info('Database is connected.');
  } else {
    logger.error('Database connection failed.');
  }
}

const closeConnection = () => {
  return prisma.$disconnect();
};

module.exports = { connection, closeConnection, prisma };