You must have installed postgres and node.js 
Change the Database Url in env file according to your postgres username and password
sample url : DATABASE_URL="postgresql://postgres:sherry123@localhost:5432/accounts"
in this username = postgresql ::: where it might be different based on your postgres username
in this password = sherry123 ::: where it might be different based on your postgres password


Initialize a new Node.js project:
npm init -y

Install Node Modules
npm i

Install Prisma CLI as a dev dependency:
npm install prisma --save-dev

Install Prisma Client:
npm install @prisma/client

Initialize Prisma in your project:
npx prisma init

Generate Prisma Client:
npx prisma generate

Create and Run a Migration:
npx prisma migrate dev --name init

Run the seed file for sample data for each type of role:
npm run prisma:seed

You can watch your database enteries using the prisma studio too alternatively you can watch your data on postgresql window app as well:
npx prisma studio