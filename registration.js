// Deployment credentials stay in this app's private database, never in user setup.
export async function operatorRegistration({ pool, origin, apiUrl = 'https://api.ofauth.com' }) {
	const api = new URL(apiUrl)
	if (api.pathname !== '/' || api.search || api.hash || api.username || api.password ||
		(api.protocol !== 'https:' && !(api.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(api.hostname))))
		throw new Error('OFAUTH_API_URL must be an HTTPS origin or a local HTTP origin')
	const issuer = `${api.origin}/v3/link`
	const redirectUri = `${origin}/oauth/ofauth/callback`
	const { rows: [stored] } = await pool.query('SELECT * FROM app_operator_registration WHERE issuer=$1 AND redirect_uri=$2', [issuer, redirectUri])
	if (stored) {
		// An approved deployment persists across app disconnects and restarts.
		const connected = await pool.query("SELECT 1 FROM app_oauth WHERE (user_key::jsonb)->>0=$1 AND tokens IS NOT NULL LIMIT 1", [stored.client_id])
		if (stored.activated || connected.rowCount) {
			if (!stored.activated) await pool.query('UPDATE app_operator_registration SET activated=true WHERE issuer=$1 AND redirect_uri=$2 AND client_id=$3', [issuer, redirectUri, stored.client_id])
			return { clientId: stored.client_id, clientSecret: stored.client_secret }
		}
		if (Date.now() - new Date(stored.created_at).getTime() < 24 * 60 * 60_000)
			return { clientId: stored.client_id, clientSecret: stored.client_secret }
	}
	const metadataResponse = await fetch(`${api.origin}/.well-known/oauth-authorization-server/v3/link`, { redirect: 'error', signal: AbortSignal.timeout(10_000) })
	if (!metadataResponse.ok) throw new Error('OFAuth discovery failed')
	const metadata = await metadataResponse.json()
	if (metadata.issuer !== issuer || metadata.registration_endpoint !== `${issuer}/register`)
		throw new Error('OFAuth discovery does not advertise the expected API registration endpoint')
	const response = await fetch(metadata.registration_endpoint, {
		method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10_000), headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ client_name: 'Express example', redirect_uris: [redirectUri],
			token_endpoint_auth_method: 'client_secret_basic', grant_types: ['authorization_code', 'refresh_token'],
			response_types: ['code'], application_type: 'web', scope: 'access:read connections:manage' })
	})
	if (response.status !== 201) throw new Error(`OFAuth automatic registration failed (${response.status})`)
	const registration = await response.json()
	if (typeof registration.client_id !== 'string' || !/^oa_[a-f0-9-]{36}$/.test(registration.client_id) ||
		typeof registration.client_secret !== 'string' || registration.client_secret.length < 32 ||
		registration.redirect_uris?.length !== 1 || registration.redirect_uris[0] !== redirectUri ||
		registration.token_endpoint_auth_method !== 'client_secret_basic') throw new Error('OFAuth registration response is invalid')
	// Concurrent starts choose one persisted registration; unused losers expire at OFAuth.
	await pool.query(`INSERT INTO app_operator_registration(issuer,redirect_uri,client_id,client_secret)
		VALUES($1,$2,$3,$4) ON CONFLICT(issuer,redirect_uri) DO UPDATE SET
		client_id=EXCLUDED.client_id,client_secret=EXCLUDED.client_secret,created_at=now()
		WHERE NOT app_operator_registration.activated AND app_operator_registration.created_at < now()-interval '24 hours'
		AND NOT EXISTS (SELECT 1 FROM app_oauth WHERE (user_key::jsonb)->>0=app_operator_registration.client_id AND tokens IS NOT NULL)`,
		[issuer, redirectUri, registration.client_id, registration.client_secret])
	const { rows: [winner] } = await pool.query('SELECT client_id,client_secret FROM app_operator_registration WHERE issuer=$1 AND redirect_uri=$2', [issuer, redirectUri])
	if (!winner) throw new Error('OFAuth registration could not be persisted')
	return { clientId: winner.client_id, clientSecret: winner.client_secret }
}
