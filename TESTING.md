# Behavior evidence

Before implementation, these failure expectations define the HTTP checks:

- A callback from another user or session must not consume the legitimate pending state. Expired and replayed callbacks fail.
- A newer connection attempt prevents an older callback or refresh from overwriting customer credentials or account selection.
- Two independent application instances can refresh concurrently. A lost refresh response remains retryable after process restart.
- Account discovery and selection remain within the current authorization. A changed registration rejects an in-flight account selection.
- If account selection starts while a new authorization is pending, completing that callback must reject the old selection without replacing the new registration's account choice.
- Application instances run in separate OS processes with independent connection pools. Restart kills one process and launches a new one while preserving the browser session, selected account, and stable refresh credential in PostgreSQL.
- Disconnect invalidates local registration before upstream revocation, preserves a retryable revocation when the issuer is unavailable, and prevents stale writes from restoring tokens.
- Authenticated resource redirects never forward bearer tokens. Invalid grants require authorization; transport failures remain retriable.

`npm run check` validates source syntax. `npm run test:e2e` exercises two Express processes with independent connection pools sharing PostgreSQL against a simulated OAuth server. It stops and replaces one process and writes `artifacts/oauth-e2e.json`. Failed runs write `artifacts/oauth-e2e-failure.json`. The fixture proves the consumer integration only. Actual OFAuth issuer and staging provider callback evidence belongs to the coordinated monorepo release validation.

`artifacts/account-selection-before.json` records the selection race before the fix: the stale request returned `302` and replaced the newer choice. The passing run rejects it with `401` and retains the new choice.
