const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcrypt');

const prisma = new PrismaClient();

const userData = [
  {
    email: 'accountant@example.com',
    password: 'password123',
    name: 'Accountant User',
    role: 'ACCOUNTANT',
  },
  {
    email: 'manager@example.com',
    password: 'password123',
    name: 'Manager User',
    role: 'MANAGER',
  },
  {
    email: 'cashier@example.com',
    password: 'password123',
    name: 'Cashier User',
    role: 'CASHIER',
  },
  {
    email: 'director@example.com',
    password: 'password123',
    name: 'Director User',
    role: 'DIRECTOR',
  },
];

async function main() {
  console.log(`Start seeding ...`);
  for (const u of userData) {
    const hashedPassword = await bcrypt.hash(u.password, 10);
    const user = await prisma.user.create({
      data: {
        email: u.email,
        password: hashedPassword,
        name: u.name,
        role: u.role,
      },
    });
    console.log(`Created user with id: ${user.id}`);
  }
  console.log(`Seeding finished.`);
}

main()
  .catch((e) => {
    console.error(e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
