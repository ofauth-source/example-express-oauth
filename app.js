import express from "express"
import session from "express-session"
import connectPgSimple from "connect-pg-simple"
import pg from "pg"
import { randomBytes } from "node:crypto"
import { pathToFileURL } from "node:url"
import { OFAuthClient } from "@ofauth/onlyfans-sdk"

import { createOAuth } from "./oauth.js"

const escape = value => String(value ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c])
const saveSession = req => new Promise((resolve, reject) => req.session.save(error => error ? reject(error) : resolve()))

export function createApp(config) {
	const { clientId, clientSecret, sessionSecret, pool, origin, apiUrl, authUrl } = config
	const ofauth = createOAuth({ clientId, clientSecret, pool, origin, apiUrl, authUrl })
	const tokenKey = ofauth.key
	const discovery = req => new OFAuthClient({ baseUrl: apiUrl, accessToken: () => ofauth.accessToken(req.session.userId) })
	const selection = async req => (await ofauth.load(req.session.userId))?.selected_account_id
	const app = express()
	app.disable("x-powered-by")
	app.use((req, res, next) => {
		res.set({ "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'self'; frame-ancestors 'none'", "Referrer-Policy": "no-referrer" })
		next()
	})
	app.get("/style.css", (req, res) => res.type("css").send("body{font:17px/1.6 system-ui;max-width:720px;margin:60px auto;padding:0 24px;color:#182338;background:#fafbfd}h1{font-size:36px;line-height:1.2}h2{font-size:23px}button{font:inherit;background:#087da6;border:0;border-radius:7px;padding:9px 16px;color:white;cursor:pointer}a{color:#086b99}article{background:white;border:1px solid #dce4ec;padding:24px;border-radius:12px;margin:20px 0}small{color:#526174}form{display:inline-block;margin:8px 8px 8px 0}code{overflow-wrap:anywhere}label{display:block;margin:12px 0}"))
	app.use(express.urlencoded({ extended: false }))
	app.use(session({ store: new (connectPgSimple(session))({ pool, createTableIfMissing: true }), secret: sessionSecret, resave: false, saveUninitialized: false, cookie: { httpOnly: true, sameSite: "lax", secure: origin.startsWith("https:"), maxAge: 30 * 60_000 } }))
	app.use((req, res, next) => {
		req.session.csrfToken ??= randomBytes(32).toString("base64url")
		res.locals.form = (action, label, fields = "") => `<form method="post" action="${action}"><input type="hidden" name="csrf" value="${escape(req.session.csrfToken)}">${fields}<button>${escape(label)}</button></form>`
		next()
	})
	const page = (res, title, body, status = 200) => res.status(status).type("html").send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escape(title)} · OFAuth example</title><link rel="stylesheet" href="/style.css"></head><body><small>OFAuth / Express example</small><h1>${escape(title)}</h1>${body}<p><a href="/">Home</a></p></body></html>`)
	const signedIn = (req, res, next) => req.session.userId ? next() : page(res, "Your app session ended", '<p>Sign in, then start again. This return cannot complete an earlier session.</p>', 401)
	const csrf = (req, res, next) => req.body.csrf === req.session.csrfToken ? next() : page(res, "Request expired", "<p>Reload the page and try again.</p>", 403)
	app.get("/", async (req, res) => {
		if (!req.session.userId) return page(res, "Try OFAuth", `<p>Connect linked accounts, choose an account, and read its profile.</p>${res.locals.form("/signin", "Sign in to the demo")}`)
		const selected = await selection(req)
		page(res, "Your linked accounts", `${res.locals.form("/connect", "Connect with OFAuth")}<p><a href="/accounts">Choose an account</a></p>${selected ? `<article><h2>Selected account</h2><code>${escape(selected)}</code><p><a href="/profile">Read profile</a></p>${res.locals.form("/reconnect", "Reconnect account")}</article>` : ""}${res.locals.form("/signout", "Sign out")}`)
	})
	// Replace this demo sign-in with your app's real authentication.
	app.post("/signin", csrf, async (req, res) => {
		await new Promise((resolve, reject) => req.session.regenerate(error => error ? reject(error) : resolve()))
		req.session.userId = "demo-customer"
		req.session.csrfToken = randomBytes(32).toString("base64url")
		await saveSession(req)
		res.redirect("/")
	})
	app.post("/signout", signedIn, csrf, async (req, res) => {
		await new Promise((resolve, reject) => req.session.destroy(error => error ? reject(error) : resolve()))
		res.clearCookie("connect.sid").redirect("/")
	})
	app.post("/connect", signedIn, csrf, async (req, res) => {
		await saveSession(req)
		const url = await ofauth.start(req.session.userId, req.sessionID)
		res.redirect(url)
	})
	app.get("/oauth/ofauth/callback", signedIn, async (req, res, next) => {
		try {
			await ofauth.complete(req.originalUrl, req.session.userId, req.sessionID)
			res.redirect("/accounts")
		} catch (error) {
			if (error.code === "access_denied") return page(res, "Authorization canceled", '<p>No new access was saved. You can connect again from home.</p>')
			if (["invalid_state", "invalid_session"].includes(error.code)) return page(res, "Authorization expired", '<p>Start a new authorization from home.</p>', 400)
			next(error)
		}
	})
	app.get("/accounts", signedIn, async (req, res) => {
		const accounts = []
		for await (const account of discovery(req).linkedAccounts.iterate()) accounts.push(account)
		page(res, "Choose an account", accounts.map(account => `<article><h2>${escape(account.display_name ?? account.username ?? account.id)}</h2><p>${escape(account.status)}</p>${res.locals.form("/accounts", "Use this account", `<input type="hidden" name="id" value="${escape(account.id)}">`)}</article>`).join("") || '<p>No accounts were granted. Connect again from home.</p>')
	})
	app.post("/accounts", signedIn, csrf, async (req, res) => {
		if (typeof req.body.id !== "string" || !req.body.id) return page(res, "Choose an account", "<p>Select an account from the list.</p>", 400)
		const registration = await ofauth.load(req.session.userId)
		const account = await discovery(req).linkedAccounts.get({ id: req.body.id })
		await ofauth.select(req.session.userId, account.id, registration?.version)
		res.redirect("/")
	})
	app.get("/profile", signedIn, async (req, res) => {
		const id = await selection(req)
		if (!id) return res.redirect("/accounts")
		const account = await discovery(req).linkedAccounts.get({ id })
		if (account.status !== "connected") return page(res, "Reconnect your account", `<p>${escape(account.status)}</p>${res.locals.form("/reconnect", "Reconnect account")}`)
		const client = discovery(req).withLinkedAccount(id)
		const profile = await client.access.profile.get()
		page(res, "Connected profile", `<article><h2>${escape(profile.name ?? "Connected account")}</h2><p>${escape(profile.username)}</p><code>${escape(id)}</code></article>`)
	})
	app.post("/reconnect", signedIn, csrf, async (req, res) => {
		const id = await selection(req)
		if (!id) return res.redirect("/accounts")
		const state = randomBytes(32).toString("base64url")
		await pool.query("INSERT INTO app_reconnect VALUES($1,$2,$3,$4,now()+interval '30 minutes')", [state, req.sessionID, tokenKey(req.session.userId), id])
		try {
			const journey = await discovery(req).linkedAccounts.createReconnect({ id, body: { state, redirect_uri: `${origin}/oauth/ofauth/reconnect` } })
			res.redirect(journey.url)
		} catch (error) { await pool.query("DELETE FROM app_reconnect WHERE state=$1", [state]); throw error }
	})
	app.get("/oauth/ofauth/reconnect", signedIn, async (req, res) => {
		const { state, reconnect } = req.query
		if (typeof state !== "string") return page(res, "Invalid return", "<p>Start a new reconnect from home.</p>", 400)
		const { rows: [attempt] } = await pool.query("DELETE FROM app_reconnect WHERE state=$1 AND session_id=$2 AND user_key=$3 RETURNING *", [state, req.sessionID, tokenKey(req.session.userId)])
		if (!attempt || new Date(attempt.expires_at) <= new Date()) return page(res, "Reconnect expired", "<p>Start a new reconnect from home.</p>", 400)
		const messages = { completed: "Reconnect finished", canceled: "Reconnect canceled", expired: "Reconnect expired", denied: "Reconnect denied" }
		if (typeof reconnect !== "string" || !Object.hasOwn(messages, reconnect)) return page(res, "Invalid return", "<p>Start a new reconnect from home.</p>", 400)
		const account = await discovery(req).linkedAccounts.get({ id: attempt.linked_account_id })
		page(res, messages[reconnect], `<p>Current account status: <strong>${escape(account.status)}</strong>.</p>${account.status === "connected" ? '<p>You can read this account’s profile.</p>' : '<p>The account still needs attention. Return home to try again.</p>'}`)
	})
	app.post("/disconnect", signedIn, csrf, async (req, res) => {
		await ofauth.disconnect(req.session.userId)
		res.sendStatus(204)
	})
	app.use((error, req, res, next) => {
		if (error.needsReauthorization) return page(res, "Connect with OFAuth", `<p>Your authorization needs to be renewed.</p>${res.locals.form("/connect", "Connect with OFAuth")}`, 401)
		if (error.recoveryAction === "reconnect_linked_account") return page(res, "Reconnect your account", res.locals.form("/reconnect", "Reconnect account"), 409)
		if (error.code === "linked_account_reconnect_not_required") return page(res, "Account already connected", '<p><a href="/profile">Read profile</a></p>')
		console.error("OFAuth request failed:", error.name, error.code ?? error.status ?? "unknown")
		page(res, "Request could not finish", "<p>Return home and try again.</p>", 502)
	})
	return app
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const { OFAUTH_CLIENT_ID: clientId, OFAUTH_CLIENT_SECRET: clientSecret, SESSION_SECRET: sessionSecret, DATABASE_URL: connectionString, APP_ORIGIN: origin = "http://127.0.0.1:3000" } = process.env
	if (!clientId || !clientSecret || !sessionSecret || !connectionString) throw new Error("Set OFAUTH_CLIENT_ID, OFAUTH_CLIENT_SECRET, SESSION_SECRET, and DATABASE_URL in .env")
	const pool = new pg.Pool({ connectionString })
	const app = createApp({ clientId, clientSecret, sessionSecret, pool, origin })
	app.listen(Number(new URL(origin).port || 3000), "127.0.0.1", () => console.log(`Open ${origin}`))
}
