// Attack simulator — POST /attack
//
// Fires REAL requests at the public /email-lookup endpoint from THIS Lambda (a stable
// source IP), so every request is genuinely evaluated by the WAF. Three attack types,
// each aimed at a different WAF rule so the demo can show distinct blocks:
//   harvest  -> high-volume directory scrape        -> rate-limit rule (IP + User-Agent)
//   sqli     -> SQL-injection payloads in the fields -> AWS managed SQLi rule set
//   exploit  -> Log4Shell / path-traversal probes    -> Known Bad Inputs + Common Rule Set
//
// Shield OFF: everything reaches the backend. Shield ON: the WAF rejects at the edge
// (403/429); we report the block tally to /report so the dashboard + AI triage can see
// blocks (which never reach the backend to be counted normally).
//
// Body: { attack: "harvest" | "sqli" | "exploit" }
// Runtime: nodejs22.x (global fetch)
import { readFileSync } from "node:fs";

const API_BASE = (process.env.API_BASE ?? "").replace(/\/$/, "");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

// Lazy-load the bundled fake directory for realistic harvest payloads (NOT real data).
let directory = null;
const loadDirectory = () => {
  if (directory) return directory;
  directory = JSON.parse(
    readFileSync(new URL("./students.json", import.meta.url), "utf8"),
  );
  return directory;
};

// ---- Attack catalog: each builder returns a list of { ua, body } descriptors -------

const buildHarvest = () => {
  const students = loadDirectory();
  const reqs = [];
  // The real harvest: every known combo (returns an email while the shield is off).
  for (const s of students) {
    reqs.push({
      ua: "directory-harvester/1.0",
      body: {
        last: s.last,
        birthday: s.birthday,
        student_id: String(s.id),
        emplid: "",
      },
    });
  }
  // Brute-force filler so the volume clearly clears the 100 req / 5 min rate limit.
  for (let i = 0; i < 300; i++) {
    reqs.push({
      ua: "directory-harvester/1.0",
      body: {
        last: "Zzzz",
        birthday: "01/01/1990",
        student_id: String(19000000 + i),
        emplid: "",
      },
    });
  }
  // Shuffle so the valid records aren't all front-loaded — the throttle / rate limit then
  // catches most of them and only a fraction of the directory leaks (the honest result).
  for (let i = reqs.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [reqs[i], reqs[j]] = [reqs[j], reqs[i]];
  }
  return reqs;
};

const SQLI_PAYLOADS = [
  "' OR '1'='1",
  "' OR 1=1--",
  "admin'--",
  "1' UNION SELECT username, password FROM users--",
  "'; DROP TABLE students;--",
  "') OR ('1'='1",
  '" OR ""="',
];
const buildSqli = () => {
  const reqs = [];
  for (let i = 0; i < 40; i++) {
    const p = SQLI_PAYLOADS[i % SQLI_PAYLOADS.length];
    reqs.push({
      ua: "sqlmap/1.5#demo",
      body: { last: p, birthday: "01/01/2000", student_id: p, emplid: "" },
    });
  }
  return reqs;
};

const EXPLOIT_PAYLOADS = [
  "${jndi:ldap://127.0.0.1/a}", // Log4Shell
  "../../../../../../etc/passwd", // path traversal
  "..%2f..%2f..%2fetc%2fpasswd",
  "<script>alert(1)</script>", // reflected XSS
  "() { :; }; echo vulnerable", // Shellshock
];
const buildExploit = () => {
  const reqs = [];
  for (let i = 0; i < 40; i++) {
    const p = EXPLOIT_PAYLOADS[i % EXPLOIT_PAYLOADS.length];
    reqs.push({
      // Log4Shell in the User-Agent too — Known Bad Inputs inspects headers.
      ua: "${jndi:ldap://127.0.0.1/ua}",
      body: { last: p, birthday: "01/01/2000", student_id: p, emplid: p },
    });
  }
  return reqs;
};

const CATALOG = {
  harvest: buildHarvest,
  sqli: buildSqli,
  exploit: buildExploit,
};

const sendOne = async (r, tally) => {
  try {
    const res = await fetch(`${API_BASE}/email-lookup`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": r.ua },
      body: JSON.stringify(r.body),
    });
    if (res.status === 403 || res.status === 429) {
      tally.blocked++;
      return;
    }
    if (!res.ok) {
      tally.errors++;
      return;
    }
    const j = await res.json().catch(() => ({}));
    if (j.result_code === "0") tally.harvested++;
    else tally.notFound++;
  } catch {
    tally.errors++;
  }
};

export const handler = async (event) => {
  const method = event?.requestContext?.http?.method ?? event?.httpMethod;
  if (method === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders, body: "" };
  }

  let body = {};
  try {
    body = event?.body ? JSON.parse(event.body) : {};
  } catch {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({ error: "Body must be a JSON object" }),
    };
  }

  const attack = body.attack;
  const build = CATALOG[attack];
  if (!build) {
    return {
      statusCode: 400,
      headers: corsHeaders,
      body: JSON.stringify({
        error: `Unknown attack "${attack}". Use harvest | sqli | exploit.`,
      }),
    };
  }
  if (!API_BASE) {
    return {
      statusCode: 500,
      headers: corsHeaders,
      body: JSON.stringify({ error: "API_BASE not configured" }),
    };
  }

  const reqs = build();
  const tally = { blocked: 0, harvested: 0, notFound: 0, errors: 0 };
  const start = Date.now();

  const CONCURRENCY = 10;
  for (let i = 0; i < reqs.length; i += CONCURRENCY) {
    await Promise.all(reqs.slice(i, i + CONCURRENCY).map((r) => sendOne(r, tally)));
  }
  const durationMs = Date.now() - start;

  // Report the edge-block tally (best-effort — never fail the attack over reporting).
  try {
    await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blocked: tally.blocked, harvested: tally.harvested }),
    });
  } catch {
    /* ignore */
  }

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({
      attack,
      sent: reqs.length,
      harvested: tally.harvested,
      blocked: tally.blocked,
      notFound: tally.notFound,
      errors: tally.errors,
      durationMs,
    }),
  };
};
