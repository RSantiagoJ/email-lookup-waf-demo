// Mock public "Email Lookup" endpoint — POST /email-lookup
//
// Clones the behavior of the real student email lookup: given a last name, a date
// of birth, and ONE id (student_id OR emplid), it returns the matching campus email.
// All data is fake (see data/generate-seed.mjs). AWS WAF sits IN FRONT of this.
//
// Request body (JSON object, mirrors the real payload):
//   { last, birthday, student_id, emplid }   // one of student_id/emplid populated
// Response:
//   { email, email_type, result_code }       // result_code "0" = found, "1" = not found
//
// With WAF off, a scripted attacker can walk the id space and read result_code/email to
// harvest the whole directory (PII). With WAF on, the rate limit blocks the scrape at
// the edge before it ever reaches this function.
//
// Runtime: nodejs22.x
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient,
  ScanCommand,
  UpdateCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const STUDENTS_TABLE = process.env.STUDENTS_TABLE;
const STATS_TABLE = process.env.STATS_TABLE;

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

// Load the fake directory once per warm container, keyed by id.
let cache = null;
const loadDirectory = async () => {
  if (cache) return cache;
  const out = await ddb.send(new ScanCommand({ TableName: STUDENTS_TABLE }));
  cache = new Map((out.Items ?? []).map((r) => [String(r.id), r]));
  return cache;
};

// requests = lookups that reached the directory; emailsFound = PII rows actually returned.
const bumpStats = async (requests, emailsFound) => {
  await ddb.send(
    new UpdateCommand({
      TableName: STATS_TABLE,
      Key: { id: "counters" },
      UpdateExpression: "ADD requests :r, emailsFound :e",
      ExpressionAttributeValues: { ":r": requests, ":e": emailsFound },
    }),
  );
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

  const last = String(body.last ?? "").trim();
  const birthday = String(body.birthday ?? "").trim();
  const id = String(body.student_id || body.emplid || "").trim();

  const directory = await loadDirectory();
  const rec = directory.get(id);

  // A match requires id + last name + birthday to all line up (case-insensitive last).
  const matched =
    rec &&
    rec.last.toLowerCase() === last.toLowerCase() &&
    rec.birthday === birthday;

  // Every call that reaches here is one request against the directory.
  await bumpStats(1, matched ? 1 : 0);

  if (matched) {
    return {
      statusCode: 200,
      headers: corsHeaders,
      body: JSON.stringify({
        email: rec.email,
        email_type: rec.email_type,
        result_code: "0",
      }),
    };
  }

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({ email: "", email_type: "", result_code: "1" }),
  };
};
