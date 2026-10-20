# OFAuth Express example

Run a small app that connects with OFAuth, saves tokens, lets you choose a linked account, reads its profile, and reconnects an account when needed.

The app uses the V4 TypeScript SDK and PostgreSQL. Tokens, pending callbacks, browser sessions, and your account choice survive app restarts.

## Run locally

Use Node.js 22 or later, npm, and Docker. Create a Sandbox integration in the [OFAuth dashboard](https://app.ofauth.com). Add `http://127.0.0.1:3000` as your app origin. Register both return URLs exactly:

```text
http://127.0.0.1:3000/oauth/ofauth/callback
http://127.0.0.1:3000/oauth/ofauth/reconnect
```

Clone and install the example:

```bash
git clone https://github.com/OFAuth-source/example-express-oauth.git
cd example-express-oauth
npm ci
cp .env.example .env
docker compose up -d --wait
```

Set `OFAUTH_CLIENT_ID` and `OFAUTH_CLIENT_SECRET` in `.env` to your Sandbox credentials. Generate a session secret:

```bash
node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("hex"))'
```

Paste the result into `SESSION_SECRET` in `.env`. Keep `.env` out of version control. Then create the tables and start the app:

```bash
npm run db:setup
npm start
```

Open **http://127.0.0.1:3000**. Use `127.0.0.1` throughout the flow so the browser keeps the same app session.

1. Select **Sign in to the demo**, then **Connect with OFAuth**.
2. Complete authorization. The SDK checks the callback against your app session and saves the tokens.
3. On **Choose an account**, select **Use this account** for the account you want.
4. Select **Read profile**. You should see that account's name and username. Sandbox uses sample data.
5. Restart the app and open the home page. Your session and selected account remain available.

The demo sign-in always uses the app user `demo-customer`. Replace that route with your app's authentication before you deploy.

## Try cancellation and reconnect

Start authorization and cancel it. The app shows **Authorization canceled**. A used callback cannot be replayed.

App sessions expire after 30 minutes. If a return arrives after your session ends, the app shows **Your app session ended**. Sign in and start again. The app does not attach an old return to a new session.

For an account that needs reconnect, select **Reconnect account**. The app creates a journey for the selected account and saves a one-use state value tied to your browser session. Its return handler handles `completed`, `canceled`, `expired`, and `denied`, then fetches the original account's current status. A `completed` return alone does not prove the account is connected. The app never replays a failed action.

Sandbox accounts use the dashboard's reconnect controls. To try the hosted reconnect journey locally, use a Test integration and an account whose status is `needs_reconnect`. Update the credentials in `.env`, and register the same local return URLs for that integration. Live integrations require HTTPS: use a deployed app origin and register its HTTPS return URLs instead. If the account is already connected, the app offers a profile request instead.

## Keep each authorization separate

The SDK stores one authorization per key. This app uses:

```js
const tokenKey = appUserId => JSON.stringify([clientId, appUserId])
```

That exact key is passed as `userId` when authorization starts and completes, and when tokens or user clients are loaded. The client ID identifies the environment, so two clients can share a database without overwriting the same app user's tokens. Account choices use the same key. A new authorization for the same key replaces its stored tokens.

If one app user can connect several OFAuth identities through the same client, add an app-owned identity-slot ID to this key. Never use a linked-account ID as the authorization key: one authorization can grant several linked accounts.

## Recover safely

`PostgresTokenStore` coordinates refreshes across app processes and saves rotated tokens. Use a direct PostgreSQL connection or session-mode pool that supports session advisory locks.

If a refresh outcome cannot be confirmed, the SDK throws `refresh_recovery_required`. The app stops API calls and shows **Connect again to continue** with a new authorization button. It does not delete the refresh journal or send the previous refresh token again. If the original process still has a known replacement, the SDK can retry saving it before a new authorization is needed.

The reconnect return state lasts 30 minutes so the app can receive an expired 15-minute journey. Each callback consumes its state once, including cancellation and expiry. Invalid, replayed, or expired state returns an error without resuming work.

## Before deployment

Replace the demo sign-in with your app's authentication. Keep the user ID and session ID server-controlled. Use HTTPS, secure cookies, your deployment's proxy configuration, and the deployed registered return URLs. The included server binds to loopback for local use.

Keep credentials and the database private. Restrict access to token and session tables. Run `schema.sql` as part of your database setup. The PostgreSQL session adapter creates its session table on first use. Remove expired pending and reconnect rows with a scheduled database cleanup job.

[TypeScript SDK guide](https://github.com/ofauth-source/public-docs/blob/docs/v3-docs-port/v3/sdk/typescript/index.mdx) · [Reconnect guide](https://github.com/ofauth-source/public-docs/blob/docs/v3-docs-port/v3/guides/reconnect.mdx)
