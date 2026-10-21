import pg from "pg"
import { createApp } from "./app.js"

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL })
const apiUrl = process.env.OFAUTH_E2E_API_URL
const app = createApp({ pool, clientId: "ofauth_test_fixture", clientSecret: "fixture-secret", sessionSecret: "test-session-secret-at-least-32-bytes", origin: "http://127.0.0.1:3000", apiUrl, authUrl: apiUrl })
const server = app.listen(0, "127.0.0.1", () => process.send({ origin: `http://127.0.0.1:${server.address().port}` }))

process.on("message", message => {
	if (message !== "close") return
	server.close(async () => { await pool.end(); process.disconnect() })
})
