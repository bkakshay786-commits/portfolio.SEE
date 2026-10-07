# LearnFlow – Study Planner with Accounts

LearnFlow can run locally as a zero-dependency Node.js app with accounts or
deploy to Vercel as a static study planner that stores progress in the current
browser.

## Run locally

    node learnflow/server.js

Open http://localhost:3000, create an account, and your plan, tasks, quiz results,
weak topics, focus stats, settings and assistant notes are saved automatically.

## Deploy to Vercel

Import this GitHub repository in Vercel or connect it to the existing Vercel
project. Pushes to `main` deploy the static app automatically; no environment
variables or database setup are required.

The Vercel version opens directly into the planner and saves data in the
browser's local storage. It works without accounts or a backend; saved progress
is limited to that browser and device. To sync accounts across devices, run the
local Node.js app with its API or configure a persistent database separately.

## Project files

- `index.html`, `login.html` - Vercel static pages
- `api/[...path].js` - optional API source backed by Neon (not deployed by the static Vercel config)
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

The local API stores accounts in `learnflow/data/` and must only be used with
appropriate protections for a public deployment. The static Vercel app does not
send account data to a server.
