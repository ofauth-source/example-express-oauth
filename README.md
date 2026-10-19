# OFAuth Express OAuth example

Connect an account through OFAuth and display its profile in a local Express app. The example uses OAuth authorization code flow with state, PKCE, and a session-bound callback.

## Run locally

Use Node.js 22 or later and npm. Create an OFAuth integration with this exact redirect URI:

```text
http://127.0.0.1:3000/oauth/ofauth/callback
```

Start with your Sandbox integration credentials. The app requests `profile:read offline_access` and reads a profile. It does not send messages or publish content.

```bash
git clone https://github.com/ofauth-source/example-express-oauth.git
cd example-express-oauth
npm ci
cp .env.example .env
```

Edit `.env` and replace the client ID and client secret. Generate a session secret:

```bash
node --input-type=module -e 'import { randomBytes } from "node:crypto"; console.log(randomBytes(32).toString("hex"))'
```

Paste the generated value into `SESSION_SECRET` in `.env`. Keep `.env` out of version control.

```bash
npm start
```

Expect `Open http://127.0.0.1:3000`. Open that address, select **Connect account**, and complete OFAuth authorization. Use `127.0.0.1` throughout the flow so the callback receives the same browser session.

After authorization, the page title is **Connected profile**. The page displays the first granted linked account's profile name and username. A null name displays **Connected account**; a null username displays an empty line. Sandbox returns mock account data.

If authorization expires, is denied, or fails, return to the local home page and start again. An authorization attempt expires after five minutes and its state can be used only once.

## Before production

This app binds to loopback and uses HTTP with `secure: false` cookies. Express's default in-memory session store and the pending-authorization map are local to one process. Restarting the app loses them.

For production, use HTTPS, secure cookies, a production session store, and shared expiring authorization-attempt storage. Configure proxy trust only for your deployment. Register the deployed redirect URI and update `redirectUri` in `app.js` to match it exactly.

Keep OAuth credentials and tokens on your backend. The example validates the token response, uses ten-second upstream request timeouts, and escapes profile text before rendering HTML. It selects the first granted linked account; add account selection when your app supports several accounts.

The example reads the profile immediately and does not persist or refresh tokens, despite requesting `offline_access`. Add durable token storage, token-expiry handling, rotating refresh-token handling, and recovery for lost account access before you build a long-running integration.
