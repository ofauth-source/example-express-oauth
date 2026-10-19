import express from "express"
import session from "express-session"
import { createHash, randomBytes } from "node:crypto"

const { OFAUTH_CLIENT_ID, OFAUTH_CLIENT_SECRET, SESSION_SECRET } = process.env
if (!OFAUTH_CLIENT_ID || !OFAUTH_CLIENT_SECRET || !SESSION_SECRET) {
	throw new Error("Set OFAUTH_CLIENT_ID, OFAUTH_CLIENT_SECRET, and SESSION_SECRET")
}

const app = express()
const redirectUri = "http://127.0.0.1:3000/oauth/ofauth/callback"
const pending = new Map()
const credentials = Buffer.from(
	`${encodeURIComponent(OFAUTH_CLIENT_ID)}:${encodeURIComponent(OFAUTH_CLIENT_SECRET)}`
).toString("base64")

app.disable("x-powered-by")
app.use((req, res, next) => {
	res.set("Cache-Control", "no-store")
	res.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	res.set("Referrer-Policy", "no-referrer")
	next()
})
app.use(session({
	secret: SESSION_SECRET,
	resave: false,
	saveUninitialized: false,
	cookie: { httpOnly: true, sameSite: "lax", secure: false, maxAge: 30 * 60_000 }
}))

const saveSession = req => new Promise((resolve, reject) => {
	req.session.save(error => error ? reject(error) : resolve())
})
const escapeHtml = value => String(value).replace(/[&<>"']/g, char => ({
	"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
})[char])

app.get("/", (req, res) => {
	res.type("html").send('<!doctype html><html lang="en"><title>OFAuth profile</title><h1>OFAuth profile</h1><a href="/connect">Connect account</a></html>')
})

app.get("/connect", async (req, res, next) => {
	try {
		const state = randomBytes(32).toString("base64url")
		const verifier = randomBytes(32).toString("base64url")
		const attempt = { sessionId: req.sessionID, verifier, expiresAt: Date.now() + 5 * 60_000 }
		pending.set(state, attempt)
		setTimeout(() => pending.delete(state), 5 * 60_000).unref()
		req.session.started = true
		await saveSession(req)

		const url = new URL("https://auth.ofauth.com/link/authorize")
		url.search = new URLSearchParams({
			response_type: "code",
			client_id: OFAUTH_CLIENT_ID,
			redirect_uri: redirectUri,
			scope: "profile:read offline_access",
			state,
			code_challenge: createHash("sha256").update(verifier).digest("base64url"),
			code_challenge_method: "S256"
		}).toString()
		res.redirect(url.toString())
	} catch (error) { next(error) }
})

app.get("/oauth/ofauth/callback", async (req, res, next) => {
	const { state, code, error } = req.query
	const attempt = typeof state === "string" ? pending.get(state) : undefined
	if (!attempt || attempt.sessionId !== req.sessionID || attempt.expiresAt <= Date.now()) {
		return res.status(400).send("Authorization expired or invalid. Start again.")
	}
	pending.delete(state)
	if (error !== undefined) {
		return res.status(400).send("Authorization was not completed. Start again.")
	}
	if (typeof code !== "string" || !code) {
		return res.status(400).send("Missing authorization code. Start again.")
	}

	try {
		const tokenResponse = await fetch("https://api.ofauth.com/v3/link/token", {
			method: "POST",
			headers: {
				authorization: `Basic ${credentials}`,
				"content-type": "application/x-www-form-urlencoded"
			},
			body: new URLSearchParams({
				grant_type: "authorization_code",
				code,
				redirect_uri: redirectUri,
				code_verifier: attempt.verifier
			}),
			signal: AbortSignal.timeout(10_000)
		})
		if (!tokenResponse.ok) throw new Error("Token exchange failed")
		const tokens = await tokenResponse.json()
		const account = tokens?.linked_accounts?.data?.[0]
		if (typeof tokens?.access_token !== "string" || !tokens.access_token ||
			tokens.token_type !== "Bearer" || typeof tokens.authorization_id !== "string" ||
			typeof tokens.expires_in !== "number" || tokens.expires_in <= 0 ||
			typeof tokens.scope !== "string" || !tokens.scope.split(" ").includes("profile:read") ||
			typeof account?.id !== "string" || !account.id) {
			throw new Error("Profile access was not granted")
		}

		const profileResponse = await fetch("https://api.ofauth.com/v3/access/profile", {
			headers: {
				authorization: `Bearer ${tokens.access_token}`,
				"x-linked-account-id": account.id
			},
			signal: AbortSignal.timeout(10_000)
		})
		if (!profileResponse.ok) throw new Error("Profile request failed")
		const profile = await profileResponse.json()
		if (!profile || !["name", "username"].every(key =>
			profile[key] === null || typeof profile[key] === "string")) {
			throw new Error("Invalid profile response")
		}
		res.type("html").send(`<!doctype html><html lang="en"><title>Connected profile</title><h1>${escapeHtml(profile.name ?? "Connected account")}</h1><p>${escapeHtml(profile.username ?? "")}</p></html>`)
	} catch (error) { next(error) }
})

app.use((error, req, res, next) => {
	res.status(502).send("Could not load the profile. Start authorization again.")
})

app.listen(3000, "127.0.0.1", () => {
	console.log("Open http://127.0.0.1:3000")
})
