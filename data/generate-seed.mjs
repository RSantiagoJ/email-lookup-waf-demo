// Generates 50 completely fake students for the demo directory.
//
// NOTHING here is real. Names are drawn from generic word lists, IDs are a tidy
// sequential block, birthdays are synthetic, and every email is on the fake
// `@demo.edu` domain. This file (and the students.json it writes) is the ONLY
// source of "student" data in the project — no real records are ever used.
//
// Run: node data/generate-seed.mjs   (writes data/students.json)

import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

const FIRST = [
  "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Avery",
  "Quinn", "Reese", "Rowan", "Sage", "Drew", "Hayden", "Emerson", "Finley",
  "Harper", "Kendall", "Logan", "Parker", "Skyler", "Blake", "Cameron", "Dakota",
  "Elliot",
];
const LAST = [
  "Rivera", "Chen", "Patel", "Nguyen", "Garcia", "Okafor", "Kim", "Silva",
  "Haddad", "Novak", "Larsen", "Mbeki", "Ivanov", "Rossi", "Yamamoto", "Dubois",
  "Costa", "Fisher", "Walsh", "Romano", "Tanaka", "Brooks", "Ferreira", "Olsen",
  "Khan",
];
// Two fake campuses, mirroring the real tool's "email type" idea.
const EMAIL_TYPES = [
  { type: "DemoU-Student", domain: "students.demo.edu" },
  { type: "DemoU-Grad", domain: "grad.demo.edu" },
];

// Deterministic pseudo-random so re-running gives a stable directory.
let seed = 42;
const rand = () => {
  seed = (seed * 1103515245 + 12345) & 0x7fffffff;
  return seed / 0x7fffffff;
};
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const pad2 = (n) => String(n).padStart(2, "0");

const students = [];
const usedEmails = new Set();

for (let i = 0; i < 50; i++) {
  const id = String(10000000 + i); // 10000000 .. 10000049
  const first = pick(FIRST);
  const last = pick(LAST);
  const et = pick(EMAIL_TYPES);

  // Synthetic birthday: year 1996..2005, valid month/day.
  const year = 1996 + Math.floor(rand() * 10);
  const month = 1 + Math.floor(rand() * 12);
  const day = 1 + Math.floor(rand() * 28);
  const birthday = `${pad2(month)}/${pad2(day)}/${year}`;

  // Build a unique fake email.
  let n = 1;
  let local = `${first}.${last}`.toLowerCase();
  while (usedEmails.has(`${local}${pad2(n)}`)) n++;
  const email = `${local}${pad2(n)}@${et.domain}`;
  usedEmails.add(`${local}${pad2(n)}`);

  students.push({
    id,
    last,
    first,
    birthday, // MM/DD/YYYY, matches the request payload format
    email,
    email_type: et.type,
  });
}

const outPath = join(here, "students.json");
writeFileSync(outPath, JSON.stringify(students, null, 2));
console.log(`Wrote ${students.length} fake students -> ${outPath}`);
console.log("Sample:", students[0], students[1]);
