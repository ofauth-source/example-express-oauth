// Public HTTP consumer test. The issuer simulates OFAuth and cannot certify it.
import assert from "node:assert/strict"
import { createServer } from "node:http"
import { createHash } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import pg from "pg"
import { execFileSync } from "node:child_process"
import { createApp } from "./app.js"

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const checks = []
const codes = new Map(), bearers = new Set(), refreshes = new Set()
let issued = 0, loseRefresh = false, revokeUnavailable = false, refreshEntered, releaseRefresh, refreshGate
const listen = server => new Promise(resolve => server.listen(0, "127.0.0.1", () => resolve(`http://127.0.0.1:${server.address().port}`)))
const close = server => new Promise(resolve => server.close(resolve))
const fixture = createServer(async (req, res) => {
	const url = new URL(req.url, "http://fixture")
	const json = (status, value) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(value)) }
	if (url.pathname === "/v3/link/token") {
		assert.equal(req.headers.authorization, `Basic ${Buffer.from("ofauth_test_fixture:fixture-secret").toString("base64")}`)
		let body = ""; for await (const part of req) body += part
		const form = new URLSearchParams(body)
		let refresh
		if (form.get("grant_type") === "authorization_code") {
			const code = codes.get(form.get("code")); if (!code) return json(400, { error: "invalid_grant" })
			assert.equal(createHash("sha256").update(form.get("code_verifier")).digest("base64url"), code.challenge)
			assert.equal(form.get("redirect_uri"), code.redirect)
			codes.delete(form.get("code")); refresh = `fixture-refresh-${++issued}`; refreshes.add(refresh)
		} else {
			refresh = form.get("refresh_token")
			if (!refreshes.has(refresh)) return json(400, { error: "invalid_grant" })
			if (loseRefresh) { loseRefresh = false; req.socket.destroy(); return }
			if (refreshGate) { refreshEntered(); await refreshGate; refreshGate = undefined }
		}
		const bearer = `fixture-access-${++issued}`; bearers.add(bearer)
		return json(200, { access_token: bearer, refresh_token: refresh, expires_in: 900, token_type: "Bearer", scope: "profile:read" })
	}
	if (url.pathname === "/v3/link/revoke") {
		if (revokeUnavailable) return json(503, { error: "server_error" })
		let body = ""; for await (const part of req) body += part
		refreshes.delete(new URLSearchParams(body).get("token")); bearers.clear()
		res.writeHead(200); return res.end()
	}
	if (!bearers.has(req.headers.authorization?.slice(7))) return json(401, { error: "invalid_token" })
	if (url.pathname === "/v3/linked-accounts") return json(200, { data: [{ id: "conn_a", status: "connected", display_name: "Account A" }, { id: "conn_b", status: "connected", display_name: "Account B" }], has_more: false, next_cursor: null })
	if (url.pathname === "/v3/linked-accounts/conn_a") return json(200, { id: "conn_a", status: "connected" })
	if (url.pathname === "/v3/linked-accounts/foreign") return json(403, { error: "linked_account_not_granted" })
	if (url.pathname === "/v3/access/profile") {
		assert.equal(req.headers["x-linked-account-id"], "conn_a")
		return json(200, { id: 12, name: "Account A", username: "account-a" })
	}
	json(404, { error: "not_found" })
})
let servers = []
try {
	await pool.query(await readFile(new URL("schema.sql", import.meta.url), "utf8"))
	await pool.query("TRUNCATE app_oauth, app_pending, app_reconnect")
	const apiUrl = await listen(fixture)
	// Open two independently constructed application instances with shared DB/session state.
	servers = [createServer(), createServer()]
	for (let i = 0; i < servers.length; i++) {
		servers[i] = createServer(createApp({ pool, clientId: "ofauth_test_fixture", clientSecret: "fixture-secret", sessionSecret: "test-session-secret-at-least-32-bytes", origin: "http://127.0.0.1:3000", apiUrl, authUrl: apiUrl }))
	}
	const origins = await Promise.all(servers.map(listen))
	let cookie = ""
	const call = async (path, options = {}, instance = 0, browserCookie = cookie) => {
		const response = await fetch(origins[instance] + path, { redirect: "manual", ...options, headers: { cookie: browserCookie, ...options.headers } })
		const updated = response.headers.get("set-cookie"); if (updated && browserCookie === cookie) cookie = updated.split(";")[0]
		return response
	}
	let html = await (await call("/")).text()
	let csrf = html.match(/name="csrf" value="([^"]+)"/)[1]
	const post = (path, fields = {}, instance = 0) => call(path, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf, ...fields }) }, instance)
	assert.equal((await post("/signin")).status, 302)
	html = await (await call("/")).text(); csrf = html.match(/name="csrf" value="([^"]+)"/)[1]
	const connect = await post("/connect")
	const authorization = new URL(connect.headers.get("location")); const state = authorization.searchParams.get("state")
	codes.set("fixture-code", { challenge: authorization.searchParams.get("code_challenge"), redirect: authorization.searchParams.get("redirect_uri") })
	const callback = `/oauth/ofauth/callback?state=${state}&code=fixture-code&iss=${encodeURIComponent(apiUrl+"/v3/link")}`
	const foreignHome = await fetch(origins[1]+"/", { redirect: "manual" })
	let foreignCookie = foreignHome.headers.get("set-cookie").split(";")[0]
	const foreignCsrf = (await foreignHome.text()).match(/name="csrf" value="([^"]+)"/)[1]
	const foreignSignin = await fetch(origins[1]+"/signin", { method: "POST", redirect: "manual", headers: { cookie: foreignCookie, "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ csrf: foreignCsrf }) })
	foreignCookie = foreignSignin.headers.get("set-cookie").split(";")[0]
	assert.equal((await call(callback, {}, 1, foreignCookie)).status, 400)
	assert.equal((await call(callback, {}, 1)).status, 302)
	assert.equal((await call(callback)).status, 400)
	checks.push("session-bound single-use callback across instances")
	assert.equal((await call("/accounts")).status, 200)
	assert.equal((await post("/accounts", { id: "foreign" })).status, 502)
	assert.equal((await post("/accounts", { id: "conn_a" })).status, 302)
	const before = (await pool.query("SELECT tokens FROM app_oauth")).rows[0].tokens.refresh_token
	await pool.query("UPDATE app_oauth SET tokens=jsonb_set(tokens,'{expires_at}','0')")
	const profiles = await Promise.all([call("/profile", {}, 0), call("/profile", {}, 1)])
	assert.deepEqual(profiles.map(r => r.status), [200, 200])
	assert.equal((await pool.query("SELECT tokens FROM app_oauth")).rows[0].tokens.refresh_token, before)
	checks.push("concurrent refresh with stable refresh token and explicit account isolation")
	await pool.query("UPDATE app_oauth SET tokens=jsonb_set(tokens,'{expires_at}','0')")
	loseRefresh = true; assert.equal((await call("/profile")).status, 502)
	await close(servers[0])
	servers[0] = createServer(createApp({ pool, clientId: "ofauth_test_fixture", clientSecret: "fixture-secret", sessionSecret: "test-session-secret-at-least-32-bytes", origin: "http://127.0.0.1:3000", apiUrl, authUrl: apiUrl }))
	origins[0] = await listen(servers[0])
	assert.equal((await call("/profile")).status, 200)
	checks.push("lost refresh response retry after application restart")
	await pool.query("UPDATE app_oauth SET tokens=jsonb_set(tokens,'{expires_at}','0')")
	const started = new Promise(resolve => { refreshEntered = resolve })
	refreshGate = new Promise(resolve => { releaseRefresh = resolve })
	const staleProfile = call("/profile", {}, 1)
	await started
	const newer = new URL((await post("/connect")).headers.get("location"))
	releaseRefresh()
	assert.equal((await staleProfile).status, 401)
	codes.set("fixture-new-code", { challenge: newer.searchParams.get("code_challenge"), redirect: newer.searchParams.get("redirect_uri") })
	assert.equal((await call(`/oauth/ofauth/callback?state=${newer.searchParams.get("state")}&code=fixture-new-code&iss=${encodeURIComponent(apiUrl+"/v3/link")}`)).status, 302)
	assert.notEqual((await pool.query("SELECT tokens FROM app_oauth")).rows[0].tokens.refresh_token, before)
	assert.equal((await post("/accounts", { id: "conn_a" })).status, 302)
	checks.push("stale in-flight refresh cannot overwrite a newer registration")
	revokeUnavailable = true; assert.equal((await post("/disconnect")).status, 502)
	assert.equal((await call("/accounts", {}, 1)).status, 401)
	assert.ok((await pool.query("SELECT revocation_token FROM app_oauth")).rows[0].revocation_token)
	revokeUnavailable = false; assert.equal((await post("/disconnect")).status, 204)
	assert.equal(refreshes.size, 1)
	assert.ok(refreshes.has(before))
	checks.push("local disconnect fails closed and preserves upstream revocation retry")
	await mkdir("artifacts", { recursive: true })
	await writeFile("artifacts/oauth-e2e.json", JSON.stringify({ result: "pass", revision: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(), sourceDigest: createHash("sha256").update(await readFile("oauth.js")).digest("hex"), runtime: process.version, sdk: JSON.parse(await readFile("node_modules/@ofauth/onlyfans-sdk/package.json", "utf8")).version, database: "PostgreSQL", issuer: "simulated OAuth fixture; not OFAuth certification", checks }, null, 2)+"\n")
	console.log(`PASS ${checks.length} scenarios; artifacts/oauth-e2e.json`)
} finally {
	await Promise.all(servers.filter(s => s.listening).map(close)); await close(fixture); await pool.end()
}
