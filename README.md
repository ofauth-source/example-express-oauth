# OFAuth Express example

Run a small app that connects with OFAuth, saves tokens, lets you choose a linked account, reads its profile, and reconnects an account when needed.

The app uses the V4 TypeScript SDK and PostgreSQL. Tokens, pending callbacks, browser sessions, and your account choice survive app restarts. Sandbox, Test, and Live all use the same code and S256 PKCE flow; no Sandbox client-credentials shortcut is used.

## Run locally

Use Node.js 22 or later, npm, Docker, and an active OFAuth Operator plan. You do not need to register an app or copy OFAuth credentials.

Clone and install the example:

```bash
git clone https://github.com/OFAuth-source/example-express-oauth.git
cd example-express-oauth
npm ci
cp .env.example .env
docker compose up -d --wait
```

Generate a session secret:

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
2. Complete authorization. The application checks the callback against your app session and saves the tokens.
3. On **Choose an account**, select **Use this account** for the account you want.
4. Select **Read profile**. You should see that account's name and username. Requests use the approving workspace’s Operator allowance.
5. Restart the app and open the home page. Your session and selected account remain available.

The demo sign-in always uses the app user `demo-customer`. Replace that route with your app's authentication before you deploy.

## Automatic Operator setup

Operator mode is the default. The server discovers OFAuth’s registration endpoint and creates credentials for this deployment. It stores them in its own PostgreSQL database, and reuses them after restart. No client secret is shipped in this repository or copied by the user. The app requests `access:read connections:manage`.

Select **Connect with OFAuth**, sign in to OFAuth, choose the accounts to share, and approve. Approval binds this private deployment to your subscribing workspace. Registration alone grants no account access and uses no allowance. The app then discovers the exact granted accounts. Apps in the OFAuth Operator sidebar lets you disconnect access; Usage shows the app’s usage.

An unused registration expires after 24 hours. On a later app start, an expired, unapproved registration is replaced automatically. Preserve the application database so approved client credentials, sessions, tokens and account choices survive restart. The app’s database user must be private to the application.

This example reads profiles. Other Access operations keep their existing confirmation rules. Operator apps do not include Realtime, Vault+, or webhooks.

For a local OFAuth server, set `OFAUTH_API_URL=http://127.0.0.1:8787` and `OFAUTH_AUTH_URL=http://localhost:8788`. These are server configuration values. Production uses the standard OFAuth origins. The automatic registration endpoint must be deployed before this example’s Operator mode is used.

## Developer integrations

A product onboarding other people’s accounts still uses its Developer integration, entitlement and billing. Set `OFAUTH_MODE=developer`, `OFAUTH_CLIENT_ID` and `OFAUTH_CLIENT_SECRET` from that integration in the private `.env`. Register the exact callback `${APP_ORIGIN}/oauth/ofauth/callback`. Developer mode requests `profile:read` and keeps the same OAuth, discovery and account-selection flow. An account owner does not need an Operator plan to use a Developer integration.

## Try cancellation and reconnect

Start authorization and cancel it. The app shows **Authorization canceled**. A used callback cannot be replayed.

App sessions expire after 30 minutes. If a return arrives after your session ends, the app shows **Your app session ended**. Sign in and start again. The app does not attach an old return to a new session.

For an account that needs reconnect, select **Reconnect account**. The app creates a journey for the selected account and saves a one-use state value tied to your browser session. Its return handler handles `completed`, `canceled`, `expired`, and `denied`, then fetches the original account's current status. A `completed` return alone does not prove the account is connected. The app never replays a failed action.

Sandbox accounts use the dashboard's reconnect controls. To try the hosted reconnect journey locally, use a Test integration and an account whose status is `needs_reconnect`. Update the credentials in `.env`, and register the same local return URL for that integration. Live integrations require HTTPS: use a deployed app origin and register its HTTPS return URL instead. If the account is already connected, the app offers a profile request instead.

## Keep token ownership in your application

`oauth.js` uses the SDK’s `OFAuthLink` for standard protocol requests. The application stores tokens, pending callbacks, and selected account in PostgreSQL. The resource SDK receives an access-token getter and never independently refreshes or persists credentials.

Storage keys include the client ID and application user. Add a tenant or identity-slot ID if your application needs one. The browser session and initiating user are checked before a callback state is consumed. Only the current registration version can save exchanged or refreshed tokens and account selections.

Access tokens last 15 minutes. Use the returned `expires_in`; the refresh token stays the same. Independent app instances can refresh concurrently. A lost refresh response or failed access-token save can be retried after restart without a distributed lock or refresh journal. `invalid_grant` requires a new authorization, while temporary failures remain retriable.

## Revoke the registration

Send a session-authenticated, CSRF-protected `POST /disconnect` with the current form token. It disables local token use before revoking the refresh token through RFC 7009. A failed upstream revocation stays pending for a later retry. This ends one renewable credential and its access tokens; it does not erase the owner's durable consent or revoke independent credentials.

To end the entire authorization, call `DELETE /v3/authorization` with a current bearer before disabling local use, or disconnect the application from the OFAuth dashboard. Removing an account and reconnecting its provider session are separate operations.

## Verify the consumer behavior

```bash
npm run check
npm run test:e2e
```

Use a disposable database: the E2E run clears the example tables. The run starts two Express processes sharing PostgreSQL, tests concurrent refresh, loses a refresh response, restarts a process, checks account isolation and selection during a callback, and retries revocation after an outage. It writes a redacted `artifacts/oauth-e2e.json`. See [TESTING.md](TESTING.md) for failure expectations and simulation limits. This fixture is not actual OFAuth or staging provider evidence.

## Before deployment

Replace the demo sign-in with your app's authentication. Keep the user ID and session ID server-controlled. Use HTTPS, secure cookies, your deployment's proxy configuration, and the deployed registered return URLs. The included server binds to loopback for local use.

Keep credentials and the database private. Restrict access to token and session tables. Run `schema.sql` as part of your database setup. The PostgreSQL session adapter creates its session table on first use. Remove expired `app_pending` and reconnect rows with a scheduled database cleanup job.

[TypeScript SDK guide](https://github.com/ofauth-source/public-docs/blob/docs/v3-docs-port/v3/sdk/typescript/index.mdx) · [Reconnect guide](https://github.com/ofauth-source/public-docs/blob/docs/v3-docs-port/v3/guides/reconnect.mdx)
