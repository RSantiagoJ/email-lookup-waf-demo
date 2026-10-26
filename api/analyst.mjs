// AI security analyst — POST /analyst  (Amazon Bedrock)
//
// Two modes in one handler, both fed a small JSON context computed by the dashboard
// (current counters, request rate, and whether the WAF shield is on):
//   mode "triage" -> one or two sentences narrating what's happening right now
//                    (drives the live triage feed on the security dashboard).
//   mode "chat"   -> answers a free-text question an exec types into the
//                    "Ask the Firewall" panel, grounded in the same context.
//
// AI provider order: the direct Anthropic Claude API (preferred — this sandbox AWS
// account can't get Bedrock model access due to a billing-history gate) -> Amazon
// Bedrock (if ever unblocked) -> a deterministic rule-based fallback so the demo never
// hard-fails. In production the native equivalent is Bedrock (same Claude models,
// in-VPC); only the hosting differs here.
//
// Runtime: nodejs22.x (global fetch is available for the Anthropic call).
import {
  BedrockRuntimeClient,
  ConverseCommand,
} from "@aws-sdk/client-bedrock-runtime";
import { SSMClient, GetParameterCommand } from "@aws-sdk/client-ssm";

const client = new BedrockRuntimeClient({});
const MODEL_ID = process.env.BEDROCK_MODEL_ID; // Bedrock model (fallback provider)

// Preferred provider — direct Anthropic Claude API. The key is optional and injected at
// deploy time (empty when unset -> we fall through to Bedrock, then offline text). The
// default model is the cheapest tier and max_tokens is small, so a triage line costs a
// fraction of a cent and a few dollars of credit lasts many demos.
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY; // optional direct override
const ANTHROPIC_KEY_PARAM = process.env.ANTHROPIC_API_KEY_PARAM; // SSM SecureString name
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL ?? "claude-haiku-5-5";
// Output budget per mode: triage is a one/two-sentence feed line (tiny, cheap), while an
// "Ask the Firewall" chat answer needs room to finish a thought without clipping.
const TRIAGE_MAX_TOKENS = 160;
const CHAT_MAX_TOKENS = 700;

// Resolve the Claude key from SSM Parameter Store at runtime so deploys never touch it.
// An ANTHROPIC_API_KEY env var, if set, wins as a direct override. Cache only a real key
// so a `put-parameter` done after deploy is picked up on the next call.
const ssm = new SSMClient({});
let cachedKey = ANTHROPIC_API_KEY ? ANTHROPIC_API_KEY.trim() : null;
const getAnthropicKey = async () => {
  if (cachedKey) return cachedKey;
  if (!ANTHROPIC_KEY_PARAM) return "";
  try {
    const out = await ssm.send(
      new GetParameterCommand({ Name: ANTHROPIC_KEY_PARAM, WithDecryption: true }),
    );
    const v = (out.Parameter?.Value ?? "").trim();
    if (v) cachedKey = v;
    return v;
  } catch {
    return ""; // not set yet / no access -> fall through to the offline fallback
  }
};

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
};

const SYSTEM = `You are a concise security analyst watching live traffic to a PUBLIC
student "email lookup" API. The API returns a student's email given a last name, date of
birth, and an ID. Because it is public and returns personal data, the main threat is
ENUMERATION: a script walking the ID space to harvest the student email directory. An AWS
WAF with an IP rate limit sits in front of it.

You are given a JSON snapshot: wafOn (shield on/off), requests (total lookups that reached
the backend), emailsFound (emails actually returned), blocked (requests the WAF rejected at
the EDGE, which never reached the backend), directorySize (total students), requestsPerMin
and blockedPerMin (recent rates). It may also include an "event" object describing the
most recent simulated attack: attack (harvest | sqli | exploit), rule (the control that
targets it — a WAF rule or the API Gateway throttle), sent, blocked, and harvested. When
an event is present, name the attack in plain terms and say whether it was stopped: if
blocked>0, the named control dropped it at the edge (whether or not the shield is on); if
blocked is 0 and wafOn is false, it reached the application unfiltered.
A rising "blocked" with the shield ON means the firewall is stopping the attack at the
edge before it reaches the directory. Interpret it for a non-technical executive. Be
specific and calm. No markdown, no preamble.`;

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

// Deterministic narration used when the AI provider is unavailable (keeps the demo alive).
const fallbackTriage = (c) => {
  const rate = Math.round(c.requestsPerMin ?? 0);
  const blocked = Math.round(c.blocked ?? 0);
  const bRate = Math.round(c.blockedPerMin ?? 0);

  // Attack-specific narration when the dashboard reports a just-run attack.
  if (c.event) {
    const e = c.event;
    const names = {
      harvest: "a directory harvest",
      sqli: "a SQL-injection attack",
      exploit: "an exploit probe",
    };
    const name = names[e.attack] ?? "an attack";
    if (e.blocked > 0) {
      return `${cap(name)} was stopped at the edge: ${e.blocked} of ${e.sent} requests blocked by the ${e.rule} before reaching the directory.${e.attack === "harvest" ? " The email harvest was cut off." : " The malicious payloads never touched the application."}`;
    }
    if (!c.wafOn) {
      if (e.attack === "harvest") {
        return `Shield is OFF — ${name} just walked the ID space and pulled ${c.emailsFound} student emails straight from the backend. Nothing stopped it.`;
      }
      return `Shield is OFF — ${e.sent} requests from ${name} reached the application unfiltered. With the shield on, the ${e.rule} would drop them at the edge.`;
    }
    return `Shield is ON but ${name} was not blocked this run${e.attack === "harvest" ? " — the rate rule is still propagating; expect blocks within about a minute" : ""}.`;
  }

  // Shield ON and the edge is rejecting the scrape (the hero moment).
  if (c.wafOn && (blocked > 0 || bRate > 30)) {
    return `Shield is ON and the firewall is stopping the scrape at the edge: ${blocked} request${blocked === 1 ? "" : "s"} blocked before reaching the directory${bRate > 30 ? ` (~${bRate}/min right now)` : ""}. The harvest is being cut off at the firewall.`;
  }
  // Shield ON but the rate rule hasn't started enforcing yet (propagation window).
  if (c.wafOn && rate > 60 && blocked === 0) {
    return `Shield is ON but ~${rate}/min is still reaching the directory — the IP+User-Agent rate rule is propagating at the edge and has not started enforcing yet. Expect blocks within about a minute.`;
  }
  // Open scrape in progress, no shield.
  if (!c.wafOn && rate > 60) {
    return `High lookup volume (~${rate}/min) from a narrow source with few valid matches — consistent with someone enumerating the directory to harvest emails. ${c.emailsFound} emails returned so far. The shield is OFF.`;
  }
  return `Traffic is light (~${rate}/min). Shield ${c.wafOn ? "ON" : "OFF"}. ${c.emailsFound} of ${c.directorySize} emails returned, ${blocked} blocked at the edge.`;
};

const fallbackChat = (c, q) =>
  `(offline analyst) Right now: shield ${c.wafOn ? "ON" : "OFF"}, ${c.requests} total lookups, ${c.emailsFound} emails exposed, ${Math.round(c.blocked ?? 0)} blocked at the edge, ~${Math.round(c.requestsPerMin ?? 0)}/min. Enable Bedrock model access to get a full answer to: "${q}".`;

// One call to the Anthropic Messages API. Returns the concatenation of ALL text blocks
// (not just the first — a leading empty/non-text block must not drop a valid completion).
// maxTokens is caller-supplied so triage stays tiny while an exec chat answer has room to
// finish a thought (see askClaude / the handler).
const anthropicOnce = async (userText, apiKey, maxTokens) => {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      model: ANTHROPIC_MODEL,
      max_tokens: maxTokens,
      // Haiku 5.5 runs adaptive thinking ON by default, and thinking tokens are drawn
      // from max_tokens — which starves (and clips) the visible answer. This is a plain
      // narration/Q&A task that needs no reasoning, so disable thinking: every token goes
      // to the answer, and it's cheaper and faster for a live demo. "disabled" is accepted
      // on Haiku 5.5 at effort "high" or below; "low" is the cheapest.
      thinking: { type: "disabled" },
      output_config: { effort: "low" },
      system: SYSTEM,
      messages: [{ role: "user", content: userText }],
    }),
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => "");
    const err = new Error(`anthropic ${res.status}: ${detail.slice(0, 200)}`);
    // 429 (rate limit) and 5xx (incl. 529 overloaded) are worth one retry; 4xx auth/
    // request errors are not.
    err.retryable = res.status === 429 || res.status >= 500;
    throw err;
  }
  const j = await res.json();
  return (j?.content ?? [])
    .filter((b) => b?.type === "text" && typeof b.text === "string")
    .map((b) => b.text)
    .join("")
    .trim();
};

// Call Claude, retrying ONCE on an empty completion or a transient (429/5xx) error, so a
// one-off blip doesn't drop us to the offline fallback. A hard failure (auth/bad request)
// is not retried. Throws after the second miss -> the handler serves the fallback.
const askClaude = async (userText, apiKey, maxTokens) => {
  let lastErr;
  for (let attempt = 1; attempt <= 2; attempt++) {
    try {
      const text = await anthropicOnce(userText, apiKey, maxTokens);
      if (text) return text;
      lastErr = new Error("empty response");
    } catch (err) {
      lastErr = err;
      if (err?.retryable === false) break; // don't retry a hard failure
    }
  }
  throw lastErr ?? new Error("empty response");
};

const askBedrock = async (userText) => {
  const out = await client.send(
    new ConverseCommand({
      modelId: MODEL_ID,
      system: [{ text: SYSTEM }],
      messages: [{ role: "user", content: [{ text: userText }] }],
      inferenceConfig: { maxTokens: 300, temperature: 0.2 },
    }),
  );
  return out.output?.message?.content?.[0]?.text?.trim() ?? "";
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

  const mode = body.mode === "chat" ? "chat" : "triage";
  const ctx = body.context ?? {};
  const question = String(body.question ?? "").slice(0, 500);

  const userText =
    mode === "chat"
      ? `Live snapshot: ${JSON.stringify(ctx)}\n\nExecutive question: ${question}\n\nAnswer in at most 4 short sentences of plain prose — no bullet points, no headings. Finish every sentence.`
      : `Live snapshot: ${JSON.stringify(ctx)}\n\nNarrate what is happening in one or two sentences.`;

  let text = "";
  let source = "fallback";
  try {
    const apiKey = await getAnthropicKey();
    const maxTokens = mode === "chat" ? CHAT_MAX_TOKENS : TRIAGE_MAX_TOKENS;
    if (apiKey) {
      source = "claude";
      text = await askClaude(userText, apiKey, maxTokens);
    } else if (MODEL_ID) {
      source = "bedrock";
      text = await askBedrock(userText);
    } else {
      throw new Error("no AI provider configured");
    }
    if (!text) throw new Error("empty response");
  } catch (err) {
    console.error("AI analyst unavailable, using fallback:", err?.message ?? err);
    source = "fallback";
    text = mode === "chat" ? fallbackChat(ctx, question) : fallbackTriage(ctx);
  }

  return {
    statusCode: 200,
    headers: corsHeaders,
    body: JSON.stringify({ text, source, mode }),
  };
};
