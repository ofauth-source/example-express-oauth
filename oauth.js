import { randomUUID } from "node:crypto"
import { OFAuthLink } from "@ofauth/onlyfans-sdk"

export function createOAuth({ pool, clientId, clientSecret, origin, apiUrl, authUrl, scopes = ['profile:read'] }) {
	const link = new OFAuthLink({ clientId, clientSecret, redirectUri: `${origin}/oauth/ofauth/callback`, apiUrl, authUrl })
	const key = userId => JSON.stringify([clientId, userId])
	const invalid = () => Object.assign(new Error("Authorization is unavailable"), { code: "invalid_grant", needsReauthorization: true })
	const load = async userId => (await pool.query("SELECT * FROM app_oauth WHERE user_key=$1", [key(userId)])).rows[0]
	const stored = tokens => ({ ...tokens, expires_at: Date.now() + tokens.expires_in * 1000 })
	return {
		key,
		load,
		async start(userId, sessionId) {
			const previous = await load(userId)
			if (previous?.revocation_token) {
				await link.revoke({ token: previous.revocation_token, tokenTypeHint: "refresh_token" })
				await pool.query("UPDATE app_oauth SET revocation_token=NULL WHERE user_key=$1 AND revocation_token=$2", [key(userId), previous.revocation_token])
			}
			const request = await link.createAuthorizationUrl({ scopes })
			const version = randomUUID()
			const db = await pool.connect()
			try {
				await db.query("BEGIN")
				// Changing registrations invalidates in-flight writes without locking refresh requests.
				const registration = await db.query("INSERT INTO app_oauth(user_key,version) VALUES($1,$2) ON CONFLICT(user_key) DO UPDATE SET version=$2 WHERE app_oauth.revocation_token IS NULL RETURNING version", [key(userId), version])
				if (!registration.rowCount) throw Object.assign(new Error("Retry pending revocation"), { code: "server_error" })
				await db.query("INSERT INTO app_pending VALUES($1,$2,$3,$4,$5,now()+interval '10 minutes')", [request.state, sessionId, key(userId), version, request.codeVerifier])
				await db.query("COMMIT")
			} catch (error) { await db.query("ROLLBACK"); throw error } finally { db.release() }
			return request.url
		},
		async complete(callback, userId, sessionId) {
			const params = new URL(callback, origin).searchParams
			if (params.getAll("state").length !== 1) throw invalid()
			const state = params.get("state")
			const { rows: [pending] } = await pool.query("DELETE FROM app_pending WHERE state=$1 AND user_key=$2 AND session_id=$3 AND expires_at>now() RETURNING *", [state, key(userId), sessionId])
			if (!pending) throw Object.assign(invalid(), { code: "invalid_state" })
			const { code } = link.parseCallback(callback, state)
			const tokens = await link.exchangeCode({ code, codeVerifier: pending.verifier })
			const result = await pool.query("UPDATE app_oauth SET tokens=$3,selected_account_id=NULL WHERE user_key=$1 AND version=$2 AND revocation_token IS NULL", [key(userId), pending.version, stored(tokens)])
			if (!result.rowCount) { await link.revoke({ token: tokens.refresh_token }); throw invalid() }
		},
		async accessToken(userId, request = {}) {
			const row = await load(userId)
			if (!row?.tokens) throw invalid()
			if (row.tokens.expires_at > Date.now() + 60_000 && (!request.forceRefresh || row.tokens.access_token !== request.rejectedAccessToken)) return row.tokens.access_token
			const tokens = stored(await link.refresh({ refreshToken: row.tokens.refresh_token }))
			const result = await pool.query("UPDATE app_oauth SET tokens=$3 WHERE user_key=$1 AND version=$2 AND tokens->>'refresh_token'=$4", [key(userId), row.version, tokens, row.tokens.refresh_token])
			if (!result.rowCount) throw invalid()
			return tokens.access_token
		},
		async select(userId, accountId, version, refreshToken) {
			const result = await pool.query("UPDATE app_oauth SET selected_account_id=$3 WHERE user_key=$1 AND version=$2 AND tokens->>'refresh_token'=$4", [key(userId), version, accountId, refreshToken])
			if (!result.rowCount) throw invalid()
		},
		async disconnect(userId) {
			const { rows: [row] } = await pool.query("UPDATE app_oauth SET version=$2,revocation_token=COALESCE(tokens->>'refresh_token',revocation_token),tokens=NULL,selected_account_id=NULL WHERE user_key=$1 RETURNING revocation_token", [key(userId), randomUUID()])
			if (!row?.revocation_token) return
			await link.revoke({ token: row.revocation_token, tokenTypeHint: "refresh_token" })
			await pool.query("UPDATE app_oauth SET revocation_token=NULL WHERE user_key=$1 AND revocation_token=$2", [key(userId), row.revocation_token])
		}
	}
}
