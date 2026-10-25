# Email Lookup — AWS WAF + Bedrock Demo

An innovation-sprint demo: **AWS WAF** shielding a genuinely public, student-facing
**email lookup** app, with **Amazon Bedrock** acting as a live AI security analyst on top.

The app is modeled on a real public university email-lookup tool — you enter a last name,
a date of birth, and a Student/HR ID, and it returns your campus email. Because that kind
of endpoint is **public and returns personal data (emails)**, it is a textbook target for
scraping. This demo shows the attack happening and the WAF stopping it — narrated in plain
English by Bedrock.

> **All data here is 100% fake.** The student directory is generated
> (`data/generate-seed.mjs`) with invented names, a tidy block of fake IDs, synthetic
> birthdays, and `@demo.edu` emails. Branding is a neutral "Demo University" — this is not
> a clone of any real institution's site, and no real records are ever used.

## The story (why it lands)

- **Public page (`/`)** — the student-facing lookup. It has **zero** security presence by
  design: no firewall banner, a generic error if a request is blocked. The attacker and
  the student both just see a plain form.
- **Security dashboard (`/security`)** — the internal ops view (unlinked from the public
  page). Live metrics, **"Launch an attack"** buttons (harvest / SQL injection / exploit
  probe — each hits a different WAF rule), a **live AI triage feed** (Claude) narrating
  each attack, an **"Ask the Firewall"** chat panel, and a **Toolbox** of copy-to-clipboard
  AWS commands for this deployment.
- Run the demo **shield OFF** first: the directory gets scraped wide open. Then flip the
  **shield ON** live: the WAF rate limit cuts the scrape off at the edge. Bedrock explains
  both.

### Where this lives in "real" AWS (talk track)
The Ask-the-Firewall chat is embedded here so the whole story is on one screen. In
production, the native equivalent is **Amazon Q in CloudWatch** (natural-language queries
over the WAF log group) or **CloudWatch Logs Insights**. Keep a console window open on the
`aws-waf-logs-email-demo` log group if you want to show the native version.

## Architecture

```
app/        Vite + React + Mantine — public lookup page (/) + security dashboard (/security)
api/        Lambda handlers (nodejs22.x): lookup, stats, reset, seed, analyst (Bedrock)
infra/      AWS CDK (TypeScript): DynamoDB, REST API, WAF web ACL + logging, Bedrock IAM
data/       fake-student seed generator -> students.json (copied into api/)
scripts/    enumerate (attack sim) + waf-on / waf-off toggles
```

- `POST /email-lookup` — `{ last, birthday, student_id, emplid }` -> `{ email, email_type, result_code }`
- `GET  /stats` — counters for the dashboard
- `POST /reset` — zero the counters
- `POST /analyst` — Bedrock triage / chat (`{ mode, context, question }`)
- `POST /report` — the attack script reports its edge-block tally (`{ blocked, harvested }`)
  so the dashboard + triage can surface blocks (which never reach the backend)
- `GET  /waf` — live WAF association state (`{ associated }`) for the dashboard shield light
- `POST /waf` — `{ on: true|false }` actually associates / disassociates the web ACL
- `POST /attack` — `{ attack: "harvest" | "sqli" | "exploit" }` fires a real attack at the
  endpoint from a Lambda (the dashboard "Launch an attack" buttons); each type trips a
  different WAF rule
- **WAF**: rate limit **100 req / 5 min per IP + User-Agent** (the hero — mirrors prod's
  `rate-limit-apis-by-ip-useragent` rule) + AWS managed rule groups (SQLi, CommonRuleSet,
  KnownBadInputs, IpReputation). Deployed **unassociated** — the demo starts unprotected,
  and the dashboard toggle arms it live.
- **API Gateway throttle**: an always-on burst throttle on the prod stage (**10 req/s,
  burst 20**), independent of the WAF shield. This is what 429s a *fast* scrape on the spot
  — the WAF rate rule's ~1-min window lets the first burst overshoot, so the two layers
  complement each other. Dashboard polling stays well under the limit.

## Prerequisites (one-time)

1. AWS CLI configured for your **personal sandbox** account `438920434591`, `us-east-1`.
2. **Anthropic API key for the AI analyst.** This sandbox AWS account can't get Bedrock
   model access (AWS gates it behind billing-history maturity), so the live analyst runs
   on the **direct Claude API** instead. Grab a key from console.anthropic.com and set it
   in your deploy shell — it's read into the Lambda env at deploy time, so it never lands
   in source or git:
   ```powershell
   $env:ANTHROPIC_API_KEY = "sk-ant-..."   # then cdk deploy
   ```
   The default model is `claude-haiku-5-5` (cheapest/fastest; override with
   `ANTHROPIC_MODEL`). Triage is **event-driven** (fires only on an attack or a shield
   toggle, not on a timer) and `max_tokens` is small, so a few dollars of credit lasts
   many demos. *Leave the key unset to build/test on the deterministic fallback — the demo
   still works, just without live AI. In production the native equivalent is Amazon Bedrock
   (same Claude models, in your VPC).*
3. Bootstrap CDK (the sandbox was previously de-bootstrapped):
   ```bash
   cd infra
   CDK_DEFAULT_REGION=us-east-1 CDK_DEFAULT_ACCOUNT=438920434591 \
     npx cdk bootstrap aws://438920434591/us-east-1
   ```

## Deploy

```bash
# 1. Infra
cd infra
npm install
npx tsc
CDK_DEFAULT_REGION=us-east-1 CDK_DEFAULT_ACCOUNT=438920434591 npx cdk deploy
#   (optional) BEDROCK_MODEL_ID=... CDK_DEFAULT_... npx cdk deploy

# 2. Point the app at the deployed API (use the ApiUrl output, including /prod)
#    edit app/.env -> VITE_API_BASE=https://XXXX.execute-api.us-east-1.amazonaws.com/prod

# 3. App
cd ../app
npm install
npm run dev          # http://localhost:5173  (/ = public, /security = dashboard)

# 4. Wire the WAF toggle scripts
cd ../scripts
cp arns.env.example arns.env   # fill WEBACL_ARN + STAGE_ARN from the cdk outputs
```

## 5-minute demo script

> **Prep before the room (do this once, not on stage):** arm the shield ahead of time so
> nobody waits on WAF propagation. Flip the dashboard toggle to **ON** (or run `waf-on.sh`)
> and give it ~60s to settle green. The demo then *starts* protected, like production.

**Fastest path:** on `/security`, click **▶ Run demo storm** — it plays the whole story
(the stakes, then real blocks) in one go, narrated. Or walk it manually:

1. **Set the scene.** Open `/` (public lookup). Do one legitimate lookup with a seeded
   student (last `Ivanov`, DOB `10/20/2002`, Student ID `10000000`) → it returns the email.
   "This is public. Anyone on the internet can use it — and it returns personal data."
2. **The stakes.** On `/security`, click **Simulate unprotected** in the Attacker console.
   Fake student emails stream out and the **Estimated breach exposure** counter climbs into
   the thousands. "With no firewall, a scraper empties the directory in seconds — here's the
   exposure." (A local dramatization — it never touches the live WAF, so there's no waiting.)
3. **The defense (real, instant).** The shield is already **ON**. Click **SQL Injection**,
   then **Exploit Probe** — both are blocked **instantly** (managed rules match per request,
   no rate threshold), so the Attacker console flips to green `BLOCKED` lines, the **"Blocked
   at the edge"** tile climbs, and the **AI triage feed** (Claude) names the rule that
   stopped each one. (Then **Directory Harvest** — the API Gateway burst throttle 429s the
   flood on the **first** click: "Blocked at the edge" jumps to ~280 while "emails exposed"
   barely moves. The WAF's IP+User-Agent rate rule is the slower second layer behind it.)
4. **Prove it's real.** Point at the **Real WAF blocks** panel — it lists the actual requests
   AWS WAF sampled and blocked (`GetSampledRequests`): source IP, path, and the rule. "This
   isn't a mock — that's AWS WAF's own record of dropping the attack." (Samples take up to
   ~a minute to appear.)
5. **Ask the Firewall.** Type *"What just happened and are we safe now?"* into the chat — the
   analyst (Claude) summarizes the incident for the room.
6. **Close.** Mention the native mapping (Amazon Q in CloudWatch over `aws-waf-logs-*`) and
   that this rule set — rate-limiting by IP + User-Agent plus managed groups (SQLi etc.) —
   mirrors the real production ACL. "Same pattern; prod dials it up."

The shield toggle is **live** (it really associates/disassociates the web ACL via `POST
/waf`), so you *can* flip it off to show the raw difference — but turning it back **on**
takes ~60s to propagate, so keep it armed during the talk and use **Simulate unprotected**
for the "danger" beat.

Use `Reset` on the dashboard between runs, and flip the shield back **OFF** to re-arm the demo.

## Cost / cleanup

- The WAF web ACL costs roughly **$5–11/mo while the stack exists** (prorated hourly),
  regardless of whether it's associated — so **`cdk destroy` between sprints** for a $0
  footprint. Lambda / API Gateway / DynamoDB are pay-per-request pennies at demo volume.
- The **Claude API** is the only per-call cost: triage is event-driven and uses the
  cheapest model with a small `max_tokens`, so a full demo run is a fraction of a cent and
  a few dollars of credit lasts many runs.
- Tear down everything: `cd infra && npx cdk destroy` (also in the dashboard **Toolbox**).
- Reminder: if you created a **root access key** for this sandbox, delete it after the sprint.
