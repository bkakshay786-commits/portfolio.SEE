# LearnFlow – Study Planner with Accounts

LearnFlow can run locally as a zero-dependency Node.js app or deploy to Vercel
with a Neon PostgreSQL database.

## Run locally

    node learnflow/server.js

Open http://localhost:3000, create an account, and your plan, tasks, quiz results,
weak topics, focus stats, settings and assistant notes are saved automatically.

## Deploy to Vercel

1. Create a PostgreSQL database with [Neon](https://neon.tech/) and copy its
   connection string.
2. In the Vercel project, set `DATABASE_URL` to that connection string.
3. Set `SESSION_SECRET` to a unique random value of at least 32 characters.
   For example, generate one with `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`.
4. Set both variables for Production (and Preview if needed), then redeploy.

Vercel creates the required `users` table automatically on the first API request.
The database connection and session secret are required for sign-up, login, and
saved progress. Do not commit either value.

## Project files

- `index.html`, `login.html` - Vercel static pages
- `api/[...path].js` - Vercel serverless API backed by Neon
- `learnflow/server.js` - local Node.js HTTP server
- `learnflow/public/` - local app pages
- `learnflow/data/` - local account storage (not committed)

## API

- `POST /api/register` - create account (name, email, password)
- `POST /api/login` - sign in
- `POST /api/logout` - sign out
- `GET /api/me` - current user
- `GET /api/state` - load saved progress
- `PUT /api/state` - save progress
- `DELETE /api/account` - delete account (requires password)

Passwords use scrypt with a per-user salt, and sessions use signed HttpOnly
cookies. Auth endpoints are rate-limited, and cross-origin writes are blocked.
