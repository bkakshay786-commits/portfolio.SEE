# LearnFlow – Study Planner with Accounts

Zero-dependency Node.js app (Node 18+). No `npm install` needed.

## Run
    node server.js

Open http://localhost:3000, create an account, and your plan, tasks, quiz results,
weak topics, focus stats, settings and assistant notes are saved automatically
and restored on any device you sign in from.

## Files
- `server.js`         - HTTP server, auth, per-user storage
- `public/login.html` - sign in / create account page
- `public/index.html` - the planner (loads and autosaves your progress)
- `data/db.json`      - created automatically; holds all accounts (back this up)

## API
- POST   /api/register  create account (name, email, password)
- POST   /api/login     sign in
- POST   /api/logout    sign out
- GET    /api/me        current user
- GET    /api/state     load saved progress
- PUT    /api/state     save progress
- DELETE /api/account   delete account (needs password)

## Config (environment variables)
- PORT (default 3000)
- DATA_DIR (default ./data)
- SESSION_SECRET (default: auto-generated into data/secret.key)
- NODE_ENV=production adds the Secure flag to cookies (use behind HTTPS)

## Security notes
Passwords are hashed with scrypt and a per-user salt, sessions are signed HttpOnly
cookies, auth endpoints are rate-limited, and cross-origin writes are blocked.
For public hosting, put it behind HTTPS and back up data/.
