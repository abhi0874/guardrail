# Deployment status

The public dashboard presents recorded synthetic evidence. Its optional local lab runs four fixed scenarios against disposable state on loopback. The public build has no account pages, OAuth callback, account API or password-recovery handlers. Account environment variables cannot activate those features. Its backend readiness integration has no live upstream binding. Historical hosted latency and release measures describe previously recorded runs.

The separately operated [hosted Guardrail dashboard](https://mcp-agent-security.vercel.app) includes live managed sign-in, Profile, Settings and account deletion. Disposable password and Google accounts were used to verify hosted deletion. Enrolled MFA factors prevent the existing deletion path. Registered email is read-only in the app. Provider-level email changes are outside that guarantee. Dashboard accounts confer no operator privileges on the separate restricted MCP backend.

## Privately operated account-enabled edition

The private deployment requires `RECRUITER_CAPTCHA_MODE=required` and `RECRUITER_TURNSTILE_SITE_KEY` bound to the approved public Turnstile widget key. Independently verify provider-side CAPTCHA enforcement and permitted origins on the designated Auth instance, including rejection of missing or invalid challenges. Keep the widget secret with the provider and all administrative credentials in authorized server-side bindings. Configure the canonical origin and account service privately.

The inherited verifier timing defect can interrupt legitimate password recovery on the private service. It remains unresolved. Keep account identity data, codes, links and tokens out of recorded automation. The recorded edition carries no hosted production configuration, account data or service-level guarantees.
