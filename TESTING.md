# Behavior evidence

Before implementation, these failure expectations define the HTTP checks:

- A callback from another user or session must not consume the legitimate pending state. Expired and replayed callbacks fail.
- A newer connection attempt prevents an older callback or refresh from overwriting customer credentials or account selection.
- Two independent application instances can refresh concurrently. A lost refresh response remains retryable after process restart.
- Account discovery and selection remain within the current authorization. A changed registration rejects an in-flight account selection.
- Disconnect invalidates local registration before upstream revocation, preserves a retryable revocation when the issuer is unavailable, and prevents stale writes from restoring tokens.
- Authenticated resource redirects never forward bearer tokens. Invalid grants require authorization; transport failures remain retriable.

`npm run check` validates source syntax. `npm run test:e2e` exercises two real Express instances sharing PostgreSQL against a simulated OAuth server and writes `artifacts/oauth-e2e.json`. The fixture proves the consumer integration only. Actual OFAuth issuer and staging provider callback evidence belongs to the coordinated monorepo release validation.
