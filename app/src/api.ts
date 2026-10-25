import { API_BASE } from "./config";

// ---- Public email lookup -------------------------------------------------

export type IdType = "student_id" | "emplid";

export type LookupPayload = {
  last: string;
  birthday: string; // MM/DD/YYYY
  student_id: string;
  emplid: string;
};

export type LookupResponse = {
  email: string;
  email_type: string;
  result_code: string; // "0" = found, "1" = not found
};

export type WafBlockedError = { blocked: true; status: number };

// POST the lookup form. A 403/429 means the WAF blocked the request at the edge.
export async function emailLookup(
  payload: LookupPayload,
): Promise<LookupResponse> {
  const res = await fetch(`${API_BASE}/email-lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (res.status === 403 || res.status === 429) {
    const err: WafBlockedError = { blocked: true, status: res.status };
    throw err;
  }
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return (await res.json()) as LookupResponse;
}

// ---- Stats (security dashboard) ------------------------------------------

export type Stats = {
  requests: number;
  emailsFound: number;
  blocked: number;
  directorySize: number;
  updatedAt: number;
};

export async function getStats(): Promise<Stats> {
  const res = await fetch(`${API_BASE}/stats`);
  if (!res.ok) throw new Error(`stats error: ${res.status}`);
  return (await res.json()) as Stats;
}

export async function resetStats(): Promise<void> {
  await fetch(`${API_BASE}/reset`, { method: "POST" });
}

// ---- WAF control (dashboard shield toggle) -------------------------------

export type WafStatus = { associated: boolean };

// Is the web ACL currently attached to the live API endpoint?
export async function getWafStatus(): Promise<WafStatus> {
  const res = await fetch(`${API_BASE}/waf`);
  if (!res.ok) throw new Error(`waf status error: ${res.status}`);
  return (await res.json()) as WafStatus;
}

// Actually associate (on=true) or disassociate (on=false) the WAF.
export async function setWaf(on: boolean): Promise<WafStatus> {
  const res = await fetch(`${API_BASE}/waf`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ on }),
  });
  if (!res.ok) throw new Error(`waf set error: ${res.status}`);
  return (await res.json()) as WafStatus;
}

// ---- AI analyst (Claude API; prod = Bedrock) -----------------------------

// Describes the most recent simulated attack so the analyst can name it and say
// whether the shield stopped it. Omitted for idle / shield-toggle narration.
export type AnalystEvent = {
  attack: string;
  rule: string;
  sent: number;
  blocked: number;
  harvested: number;
};

export type AnalystContext = {
  wafOn: boolean;
  requests: number;
  emailsFound: number;
  blocked: number;
  directorySize: number;
  requestsPerMin: number;
  blockedPerMin: number;
  event?: AnalystEvent;
};

export type AnalystResponse = {
  text: string;
  source: "claude" | "bedrock" | "fallback";
  mode: "triage" | "chat";
};

export async function askAnalyst(
  mode: "triage" | "chat",
  context: AnalystContext,
  question?: string,
): Promise<AnalystResponse> {
  const res = await fetch(`${API_BASE}/analyst`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mode, context, question }),
  });
  if (!res.ok) throw new Error(`analyst error: ${res.status}`);
  return (await res.json()) as AnalystResponse;
}

// ---- Attack simulator (dashboard "launch attack" buttons) ----------------

export type AttackId = "harvest" | "sqli" | "exploit";

export type AttackResult = {
  attack: AttackId;
  sent: number;
  harvested: number;
  blocked: number;
  notFound: number;
  errors: number;
  durationMs: number;
};

// The catalog the dashboard renders. `rule` names the WAF rule each attack targets,
// which the analyst uses to narrate the block. Add an entry to grow the playground.
export const ATTACKS: {
  id: AttackId;
  label: string;
  rule: string;
  blurb: string;
}[] = [
  {
    id: "harvest",
    label: "Directory Harvest",
    rule: "rate-limit rule (IP + User-Agent)",
    blurb:
      "Walks the ID space to scrape the whole student email directory. Trips the rate limit.",
  },
  {
    id: "sqli",
    label: "SQL Injection",
    rule: "AWS managed SQLi rule set",
    blurb:
      "Sends SQL-injection payloads in the lookup fields. Dropped at the edge on sight.",
  },
  {
    id: "exploit",
    label: "Exploit Probe",
    rule: "Known Bad Inputs + Common Rule Set",
    blurb:
      "Log4Shell and path-traversal signatures. Caught by the managed exploit rules.",
  },
];

export async function launchAttack(attack: AttackId): Promise<AttackResult> {
  const res = await fetch(`${API_BASE}/attack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ attack }),
  });
  if (!res.ok) throw new Error(`attack error: ${res.status}`);
  return (await res.json()) as AttackResult;
}

// ---- Real WAF proof (sampled blocked requests) ---------------------------

export type WafSample = {
  ip: string;
  uri: string;
  method: string;
  rule: string;
  at: string | null;
};

// Actual blocked requests sampled by AWS WAF — proof the blocks are real.
export async function getWafSamples(): Promise<{
  samples: WafSample[];
  count?: number;
  error?: string;
}> {
  const res = await fetch(`${API_BASE}/waf-samples`);
  if (!res.ok) throw new Error(`waf-samples error: ${res.status}`);
  return (await res.json()) as {
    samples: WafSample[];
    count?: number;
    error?: string;
  };
}
