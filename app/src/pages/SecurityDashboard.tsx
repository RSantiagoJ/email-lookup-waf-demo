import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ActionIcon,
  Badge,
  Box,
  Button,
  Card,
  Container,
  CopyButton,
  Group,
  Loader,
  Progress,
  ScrollArea,
  SimpleGrid,
  Stack,
  Switch,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import {
  IconShieldCheck,
  IconShieldOff,
  IconRobot,
  IconSend,
  IconSwords,
  IconMailSearch,
  IconSql,
  IconBug,
  IconTerminal2,
  IconCopy,
  IconCheck,
  IconPlayerPlay,
  IconReportMoney,
  IconActivity,
  IconAlertTriangle,
} from "@tabler/icons-react";
import {
  askAnalyst,
  getStats,
  getWafStatus,
  getWafSamples,
  launchAttack,
  resetStats,
  setWaf,
  ATTACKS,
  type AnalystContext,
  type AnalystEvent,
  type AttackId,
  type Stats,
  type WafSample,
} from "../api";
import { API_BASE } from "../config";

type FeedItem = { id: number; text: string; source: string; at: string };
type ChatItem = { role: "user" | "analyst"; text: string; source?: string };
type TickerLine = { id: number; kind: "leak" | "block" | "info"; text: string };

// The shield's real lifecycle: off -> arming (associating) -> on, and on ->
// disarming -> off. "arming"/"disarming" are the in-flight states while we wait
// for the live WAF association poll to confirm.
type ShieldState = "off" | "arming" | "on" | "disarming";

const STATS_POLL_MS = 2000;
const WAF_POLL_MS = 3000;

// Derive the REST API id + region from the live API base so the Toolbox commands
// always match this deployment.
const REST_API_ID = (() => {
  try {
    return new URL(API_BASE).hostname.split(".")[0];
  } catch {
    return "<rest-api-id>";
  }
})();
const REGION = (() => {
  try {
    return new URL(API_BASE).hostname.split(".")[2];
  } catch {
    return "us-east-1";
  }
})();
const DEPLOY_ENV = `$env:CDK_DEFAULT_REGION="${REGION}"; $env:CDK_DEFAULT_ACCOUNT="438920434591"`;

// Copy-paste terminal commands (PowerShell). These buttons only copy to the clipboard —
// they never touch your stack. Run them yourself in a terminal.
const TOOLBOX: { label: string; desc: string; cmd: string }[] = [
  {
    label: "Deploy",
    desc: "Build + deploy the stack (offline AI fallback).",
    cmd: `cd infra; npx tsc; ${DEPLOY_ENV}; npx cdk deploy`,
  },
  {
    label: "Deploy with live AI",
    desc: "Same, plus your Claude API key for live triage.",
    cmd: `cd infra; npx tsc; $env:ANTHROPIC_API_KEY="sk-ant-REPLACE_ME"; ${DEPLOY_ENV}; npx cdk deploy`,
  },
  {
    label: "Refresh API routes",
    desc: "Force the prod stage to the latest routes (after adding endpoints).",
    cmd: `aws apigateway create-deployment --rest-api-id ${REST_API_ID} --stage-name prod --region ${REGION}`,
  },
  {
    label: "Tear down ($0)",
    desc: "Destroy everything when you're done to stop all cost.",
    cmd: `cd infra; npx cdk destroy`,
  },
];

const SAMPLES_POLL_MS = 8000;
const COST_PER_RECORD = 164; // ~ IBM avg cost per breached record (USD)
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Synthetic directory for the "unprotected" leak dramatization — client-side only, it
// NEVER touches the API or the WAF. Deliberately fake demo emails.
const DEMO_FIRST = [
  "emerson", "avery", "jordan", "riley", "casey", "morgan",
  "quinn", "sawyer", "reese", "rowan", "harper", "elliot",
];
const DEMO_LAST = [
  "ivanov", "chen", "okafor", "nguyen", "santos", "kowalski",
  "ahmed", "delgado", "park", "mori", "haddad", "novak",
];
const LEAK_EMAILS = Array.from({ length: 50 }, (_, i) => {
  const f = DEMO_FIRST[i % DEMO_FIRST.length];
  const l = DEMO_LAST[(i * 7) % DEMO_LAST.length];
  return {
    email: `${f}.${l}${String(i).padStart(2, "0")}@demo.edu`,
    id: String(10000000 + i),
  };
});

export function SecurityDashboard() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [rpm, setRpm] = useState(0);
  const [bpm, setBpm] = useState(0);
  const [shield, setShield] = useState<ShieldState>("off");

  const [feed, setFeed] = useState<FeedItem[]>([]);
  const [chat, setChat] = useState<ChatItem[]>([]);
  const [question, setQuestion] = useState("");
  const [chatBusy, setChatBusy] = useState(false);
  const [attackBusy, setAttackBusy] = useState<AttackId | null>(null);
  const [storming, setStorming] = useState(false);
  const [ticker, setTicker] = useState<TickerLine[]>([]);
  const [simRunning, setSimRunning] = useState(false);
  const [simLeaked, setSimLeaked] = useState(0);
  const [samples, setSamples] = useState<WafSample[]>([]);

  // Refs so the polling closures always see current values.
  const prevSample = useRef<{
    requests: number;
    blocked: number;
    t: number;
  } | null>(null);
  const lastFeedText = useRef<string>("");
  const feedId = useRef(0);
  const prevShield = useRef<ShieldState>("off");
  const tickerId = useRef(0);
  const mounted = useRef(true);
  const ctxRef = useRef<AnalystContext>({
    wafOn: false,
    requests: 0,
    emailsFound: 0,
    blocked: 0,
    directorySize: 50,
    requestsPerMin: 0,
    blockedPerMin: 0,
  });

  // Poll stats; derive requests-per-minute from the delta between samples.
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s = await getStats();
        if (!alive) return;
        const now = Date.now();
        if (prevSample.current) {
          const dSec = (now - prevSample.current.t) / 1000;
          if (dSec > 0) {
            const dReq = s.requests - prevSample.current.requests;
            const dBlk = s.blocked - prevSample.current.blocked;
            setRpm(Math.max(0, (dReq / dSec) * 60));
            setBpm(Math.max(0, (dBlk / dSec) * 60));
          }
        }
        prevSample.current = { requests: s.requests, blocked: s.blocked, t: now };
        setStats(s);
      } catch {
        /* keep last known values */
      }
    };
    tick();
    const h = setInterval(tick, STATS_POLL_MS);
    return () => {
      alive = false;
      clearInterval(h);
    };
  }, []);

  // Keep the analyst context ref current for the triage/chat calls.
  useEffect(() => {
    ctxRef.current = {
      wafOn: shield === "on",
      requests: stats?.requests ?? 0,
      emailsFound: stats?.emailsFound ?? 0,
      blocked: stats?.blocked ?? 0,
      directorySize: stats?.directorySize ?? 50,
      requestsPerMin: rpm,
      blockedPerMin: bpm,
    };
  }, [shield, stats, rpm, bpm]);

  // Poll the REAL WAF association state and settle the shield lifecycle.
  // While arming, stay "arming" until the association actually shows up; while
  // disarming, stay "disarming" until it's actually gone. Also picks up changes
  // made outside the UI (e.g. the waf-on / waf-off scripts).
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const { associated } = await getWafStatus();
        if (!alive) return;
        setShield((cur) => {
          if (associated) return cur === "disarming" ? "disarming" : "on";
          return cur === "arming" ? "arming" : "off";
        });
      } catch {
        /* keep last known state */
      }
    };
    tick();
    const h = setInterval(tick, WAF_POLL_MS);
    return () => {
      alive = false;
      clearInterval(h);
    };
  }, []);

  // AI triage is EVENT-DRIVEN, not polled — a paid model call only fires on a real
  // event (an attack launch or a shield settle), never on a timer, so a few dollars of
  // API credit lasts many demos. `narrate` prepends one line to the feed.
  const narrate = async (event?: AnalystEvent) => {
    const ctx: AnalystContext = { ...ctxRef.current, event };
    if (!event && ctx.requests === 0 && ctx.blocked === 0) return;
    try {
      const r = await askAnalyst("triage", ctx);
      if (!r.text) return;
      if (!event && r.text === lastFeedText.current) return; // de-dupe idle re-narration
      lastFeedText.current = r.text;
      feedId.current += 1;
      setFeed((f) =>
        [
          {
            id: feedId.current,
            text: r.text,
            source: r.source,
            at: new Date().toLocaleTimeString(),
          },
          ...f,
        ].slice(0, 20),
      );
    } catch {
      /* non-fatal: skip this narration */
    }
  };

  // Narrate once when the shield finishes arming or disarming (a settled transition).
  useEffect(() => {
    const prev = prevShield.current;
    prevShield.current = shield;
    if (
      (prev === "arming" && shield === "on") ||
      (prev === "disarming" && shield === "off")
    ) {
      narrate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [shield]);

  // Poll the REAL blocked-request samples from AWS WAF for the proof panel (free).
  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await getWafSamples();
        if (alive) setSamples(r.samples ?? []);
      } catch {
        /* keep last known */
      }
    };
    tick();
    const h = setInterval(tick, SAMPLES_POLL_MS);
    return () => {
      alive = false;
      clearInterval(h);
    };
  }, []);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  async function onAsk(e: FormEvent) {
    e.preventDefault();
    const q = question.trim();
    if (!q || chatBusy) return;
    setChat((c) => [...c, { role: "user", text: q }]);
    setQuestion("");
    setChatBusy(true);
    try {
      const r = await askAnalyst("chat", ctxRef.current, q);
      setChat((c) => [
        ...c,
        { role: "analyst", text: r.text, source: r.source },
      ]);
    } catch {
      setChat((c) => [
        ...c,
        { role: "analyst", text: "Analyst is unavailable right now." },
      ]);
    } finally {
      setChatBusy(false);
    }
  }

  async function onReset() {
    await resetStats();
    prevSample.current = null;
    lastFeedText.current = "";
    setRpm(0);
    setBpm(0);
    setFeed([]);
    setTicker([]);
    setSimLeaked(0);
  }

  // --- Attacker console (leaked-email ticker) ------------------------
  const pushTicker = (kind: TickerLine["kind"], text: string) => {
    tickerId.current += 1;
    setTicker((t) => [{ id: tickerId.current, kind, text }, ...t].slice(0, 80));
  };

  // Simulate the directory leaking with NO firewall — pure client-side dramatization
  // (no WAF touched, instant), so the "danger" beat never waits on AWS.
  async function simulateLeak() {
    if (simRunning) return;
    setSimRunning(true);
    setSimLeaked(0);
    pushTicker("info", "harvesting directory with no firewall in front…");
    for (let i = 0; i < LEAK_EMAILS.length; i++) {
      if (!mounted.current) break;
      const e = LEAK_EMAILS[i];
      pushTicker("leak", `LEAKED  ${e.email}  (student_id ${e.id})`);
      setSimLeaked(i + 1);
      await sleep(90);
    }
    pushTicker(
      "info",
      `directory emptied: ${LEAK_EMAILS.length} student emails harvested.`,
    );
    setSimRunning(false);
  }

  // Launch a REAL attack via the backend attack Lambda, update the console, narrate.
  async function onAttack(id: AttackId) {
    if (attackBusy) return;
    setAttackBusy(id);
    try {
      const r = await launchAttack(id);
      // Pull fresh stats right away so the tiles jump without waiting for the poll.
      try {
        const s = await getStats();
        setStats(s);
        prevSample.current = {
          requests: s.requests,
          blocked: s.blocked,
          t: Date.now(),
        };
      } catch {
        /* the poll will catch up */
      }
      const meta = ATTACKS.find((a) => a.id === id);
      // Reflect the result in the attacker console.
      if (r.blocked > 0) {
        const n = Math.min(8, r.blocked);
        for (let k = 0; k < n; k++) {
          pushTicker(
            "block",
            `403  POST /email-lookup  BLOCKED — ${meta?.rule ?? "WAF"}`,
          );
        }
        pushTicker(
          "info",
          `BLOCKED AT THE EDGE: ${r.blocked} request${r.blocked === 1 ? "" : "s"} stopped by the WAF.`,
        );
      } else if (r.harvested > 0) {
        pushTicker("leak", `${r.harvested} emails harvested — nothing stopped this.`);
      }
      await narrate({
        attack: id,
        rule: meta?.rule ?? "",
        sent: r.sent,
        blocked: r.blocked,
        harvested: r.harvested,
      });
      // Nudge the real-WAF proof panel to refresh.
      try {
        const sr = await getWafSamples();
        setSamples(sr.samples ?? []);
      } catch {
        /* the poll will catch up */
      }
    } catch {
      feedId.current += 1;
      setFeed((f) =>
        [
          {
            id: feedId.current,
            text: `Attack "${id}" could not be launched — the /attack route may need a refresh (see the Toolbox).`,
            source: "fallback",
            at: new Date().toLocaleTimeString(),
          },
          ...f,
        ].slice(0, 20),
      );
    } finally {
      setAttackBusy(null);
    }
  }

  // One-click demo storm. Assumes the shield is ALREADY ON (pre-armed) — it never arms
  // the WAF, so nobody waits on propagation. Danger (simulated leak) -> real instant
  // blocks (SQLi + exploit), narrated as it goes.
  async function onStorm() {
    if (storming || attackBusy || simRunning) return;
    setStorming(true);
    try {
      pushTicker(
        "info",
        shield === "on"
          ? "shield is ON (production config) — running the storm."
          : "shield is OFF — arm it first for the blocked beat.",
      );
      await simulateLeak();
      await sleep(900);
      await onAttack("sqli");
      await sleep(700);
      await onAttack("exploit");
    } finally {
      setStorming(false);
    }
  }

  // Flip the REAL firewall. Go to a transitional state immediately; the WAF
  // status poll confirms the association and settles to on/off.
  async function onToggle(next: boolean) {
    if (shield === "arming" || shield === "disarming") return;
    setShield(next ? "arming" : "disarming");
    try {
      await setWaf(next);
    } catch {
      setShield(next ? "off" : "on"); // revert on failure
    }
  }

  const requests = stats?.requests ?? 0;
  const emailsFound = stats?.emailsFound ?? 0;
  const blocked = stats?.blocked ?? 0;
  const directorySize = stats?.directorySize ?? 50;
  const exposed = Math.max(emailsFound, simLeaked);
  const breachCost = exposed * COST_PER_RECORD;
  const exposedPct = Math.min(
    100,
    Math.round((emailsFound / directorySize) * 100),
  );

  const transitioning = shield === "arming" || shield === "disarming";
  const shieldLabel =
    shield === "on"
      ? "ON"
      : shield === "off"
        ? "OFF"
        : shield === "arming"
          ? "ARMING…"
          : "DISARMING…";
  const shieldColor =
    shield === "on" ? "teal" : shield === "off" ? "red" : "yellow";
  const shieldBg =
    shield === "on" ? "teal.0" : shield === "off" ? "red.0" : "yellow.0";
  const shieldBorder =
    shield === "on"
      ? "var(--mantine-color-teal-4)"
      : shield === "off"
        ? "var(--mantine-color-red-4)"
        : "var(--mantine-color-yellow-4)";
  const shieldNote =
    shield === "arming"
      ? "Associating WAF — blocking ramps up over ~60s."
      : shield === "disarming"
        ? "Removing the WAF from the live endpoint…"
        : shield === "on"
          ? "WAF is attached to the live API endpoint."
          : "Endpoint is unprotected. Flip to arm the firewall.";

  const liveSource = feed[0]?.source;
  const aiBadge =
    liveSource === "claude"
      ? { label: "Claude", color: "blue" }
      : liveSource === "bedrock"
        ? { label: "Bedrock", color: "blue" }
        : liveSource === "fallback"
          ? { label: "offline", color: "yellow" }
          : { label: "idle", color: "gray" };

  return (
    <Box bg="gray.0" mih="100vh">
      <Box bg="blue.8" py="md">
        <Container size="lg">
          <Group justify="space-between">
            <Group gap="xs">
              <IconShieldCheck size={22} color="white" />
              <Text c="white" fw={700}>
                Directory Security — Operations
              </Text>
            </Group>
            <Group>
              <Switch
                checked={shield === "on" || shield === "arming"}
                onChange={(e) => onToggle(e.currentTarget.checked)}
                disabled={transitioning}
                onLabel="SHIELD ON"
                offLabel="SHIELD OFF"
                size="lg"
                color="teal"
              />
              <Button variant="white" size="xs" onClick={onReset}>
                Reset
              </Button>
            </Group>
          </Group>
        </Container>
      </Box>

      <Container size="lg" py="xl">
        {/* --- Metric tiles ------------------------------------------- */}
        <SimpleGrid cols={{ base: 1, sm: 2, lg: 4 }} mb="xl">
          <Card withBorder bg="white" radius="md" padding="lg">
            <Text size="sm" c="dimmed">
              Lookup traffic hitting the directory
            </Text>
            <Text fw={700} fz={36}>
              {requests.toLocaleString()}
            </Text>
            <Text size="sm" fw={600} c={rpm > 60 ? "red.7" : "dimmed"}>
              ~{Math.round(rpm)} / min
            </Text>
          </Card>

          <Card withBorder bg="white" radius="md" padding="lg">
            <Text size="sm" c="dimmed">
              Student emails exposed
            </Text>
            <Text
              fw={700}
              fz={36}
              c={emailsFound > 0 ? "red.7" : "teal.7"}
            >
              {emailsFound} / {directorySize}
            </Text>
            <Progress
              value={exposedPct}
              color={exposedPct > 0 ? "red" : "teal"}
              mt="xs"
            />
          </Card>

          <Card withBorder bg="white" radius="md" padding="lg">
            <Text size="sm" c="dimmed">
              Blocked at the edge
            </Text>
            <Text fw={700} fz={36} c={blocked > 0 ? "teal.7" : "dimmed"}>
              {blocked.toLocaleString()}
            </Text>
            <Text size="sm" fw={600} c={blocked > 0 ? "teal.7" : "dimmed"}>
              {blocked > 0 ? "stopped by the WAF" : "no blocks yet"}
            </Text>
          </Card>

          <Card
            withBorder
            radius="md"
            padding="lg"
            bg={shieldBg}
            style={{ borderColor: shieldBorder }}
          >
            <Text size="sm" c="dimmed">
              Firewall shield
            </Text>
            <Group gap="xs" mt={4}>
              {shield === "on" ? (
                <IconShieldCheck size={32} color="var(--mantine-color-teal-7)" />
              ) : shield === "off" ? (
                <IconShieldOff size={32} color="var(--mantine-color-red-7)" />
              ) : (
                <Loader size={28} color="yellow" />
              )}
              <Badge color={shieldColor} size="lg">
                {shieldLabel}
              </Badge>
            </Group>
            <Text size="xs" c="dimmed" mt="xs">
              {shieldNote}
            </Text>
          </Card>
        </SimpleGrid>

        {/* --- Attacks + Toolbox ------------------------------------- */}
        <SimpleGrid cols={{ base: 1, md: 2 }} mb="xl">
          <Card withBorder bg="white" radius="md" padding="lg">
            <Group gap="xs" mb="xs">
              <IconSwords size={20} />
              <Text fw={600}>Launch an attack</Text>
            </Group>
            <Text size="xs" c="dimmed" mb="md">
              Each button fires REAL requests at the live endpoint from the attack
              Lambda, so the WAF genuinely evaluates them. Shield OFF: they land. Shield
              ON: each trips a different rule and is blocked at the edge.
            </Text>
            <Button
              fullWidth
              color="grape"
              mb="md"
              leftSection={<IconPlayerPlay size={18} />}
              loading={storming}
              disabled={attackBusy !== null || simRunning}
              onClick={onStorm}
            >
              Run demo storm
            </Button>
            <Stack gap="sm">
              {ATTACKS.map((a) => (
                <Button
                  key={a.id}
                  variant="light"
                  color="red"
                  justify="flex-start"
                  leftSection={
                    a.id === "harvest" ? (
                      <IconMailSearch size={18} />
                    ) : a.id === "sqli" ? (
                      <IconSql size={18} />
                    ) : (
                      <IconBug size={18} />
                    )
                  }
                  loading={attackBusy === a.id}
                  disabled={attackBusy !== null && attackBusy !== a.id}
                  onClick={() => onAttack(a.id)}
                  h="auto"
                  py="sm"
                  styles={{
                    label: { whiteSpace: "normal", textAlign: "left" },
                    inner: { justifyContent: "flex-start" },
                  }}
                >
                  <Box>
                    <Text fw={600} size="sm">
                      {a.label}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {a.blurb}
                    </Text>
                  </Box>
                </Button>
              ))}
            </Stack>
          </Card>

          <Card withBorder bg="white" radius="md" padding="lg">
            <Group gap="xs" mb="xs">
              <IconTerminal2 size={20} />
              <Text fw={600}>Toolbox</Text>
              <Badge variant="light" color="gray" size="sm">
                copy &amp; paste
              </Badge>
            </Group>
            <Text size="xs" c="dimmed" mb="md">
              Copy the AWS commands for this deployment to your clipboard, then run them
              in your terminal. These buttons never touch your stack on their own.
            </Text>
            <Stack gap="xs">
              {TOOLBOX.map((t) => (
                <Group key={t.label} justify="space-between" wrap="nowrap" gap="sm">
                  <Box style={{ minWidth: 0 }}>
                    <Text fw={600} size="sm">
                      {t.label}
                    </Text>
                    <Text size="xs" c="dimmed">
                      {t.desc}
                    </Text>
                  </Box>
                  <CopyButton value={t.cmd} timeout={1500}>
                    {({ copied, copy }) => (
                      <Tooltip label={copied ? "Copied!" : "Copy command"} withArrow>
                        <ActionIcon
                          variant={copied ? "filled" : "light"}
                          color={copied ? "teal" : "blue"}
                          onClick={copy}
                          size="lg"
                          aria-label={`Copy: ${t.label}`}
                        >
                          {copied ? <IconCheck size={18} /> : <IconCopy size={18} />}
                        </ActionIcon>
                      </Tooltip>
                    )}
                  </CopyButton>
                </Group>
              ))}
            </Stack>
          </Card>
        </SimpleGrid>

        {/* --- Attacker console + real WAF proof --------------------- */}
        <SimpleGrid cols={{ base: 1, md: 2 }} mb="xl">
          {/* Leaked-email ticker + breach-cost counter */}
          <Card withBorder radius="md" padding="lg" bg="dark.8">
            <Group justify="space-between" mb="xs">
              <Group gap="xs">
                <IconAlertTriangle size={20} color="var(--mantine-color-red-5)" />
                <Text fw={600} c="white">
                  Attacker console
                </Text>
              </Group>
              <Button
                size="xs"
                variant="light"
                color="red"
                loading={simRunning}
                disabled={storming}
                onClick={simulateLeak}
              >
                Simulate unprotected
              </Button>
            </Group>
            <Group justify="space-between" align="flex-end" mb="sm">
              <Box>
                <Group gap={6} mb={2}>
                  <IconReportMoney size={14} color="var(--mantine-color-red-4)" />
                  <Text size="xs" c="gray.5">
                    Estimated breach exposure
                  </Text>
                </Group>
                <Text fw={800} fz={32} c="red.4">
                  ${breachCost.toLocaleString()}
                </Text>
              </Box>
              <Text size="xs" c="gray.5">
                {exposed} records × ${COST_PER_RECORD}
              </Text>
            </Group>
            <ScrollArea h={220}>
              <Stack gap={2}>
                {ticker.length === 0 && (
                  <Text size="xs" c="gray.6" ff="monospace">
                    idle — "Simulate unprotected" streams the directory leaking, or launch
                    an attack with the shield on to watch it get blocked.
                  </Text>
                )}
                {ticker.map((l) => (
                  <Text
                    key={l.id}
                    size="xs"
                    ff="monospace"
                    c={
                      l.kind === "leak"
                        ? "red.4"
                        : l.kind === "block"
                          ? "teal.4"
                          : "gray.5"
                    }
                  >
                    {l.kind === "leak" ? "✖ " : l.kind === "block" ? "✔ " : "› "}
                    {l.text}
                  </Text>
                ))}
              </Stack>
            </ScrollArea>
          </Card>

          {/* Real WAF proof panel */}
          <Card withBorder bg="white" radius="md" padding="lg">
            <Group gap="xs" mb="xs">
              <IconActivity size={20} />
              <Text fw={600}>Real WAF blocks</Text>
              <Badge variant="light" color="teal" size="sm">
                live from AWS
              </Badge>
            </Group>
            <Text size="xs" c="dimmed" mb="sm">
              Actual requests AWS WAF sampled and <b>blocked</b> (GetSampledRequests, last
              10 min) — proof the blocks are real. Samples can take ~a minute to appear.
            </Text>
            <ScrollArea h={220}>
              <Stack gap="xs">
                {samples.length === 0 && (
                  <Text size="sm" c="dimmed">
                    No blocked samples yet. With the shield ON, launch an attack — blocked
                    requests show up here within about a minute.
                  </Text>
                )}
                {samples.map((s, i) => (
                  <Group key={i} justify="space-between" wrap="nowrap" gap="xs">
                    <Box style={{ minWidth: 0 }}>
                      <Text size="xs" ff="monospace" truncate>
                        {s.method} {s.uri} — {s.ip}
                      </Text>
                      <Text size="xs" c="dimmed">
                        {s.rule}
                        {s.at ? ` · ${new Date(s.at).toLocaleTimeString()}` : ""}
                      </Text>
                    </Box>
                    <Badge color="red" variant="light" size="sm">
                      BLOCK
                    </Badge>
                  </Group>
                ))}
              </Stack>
            </ScrollArea>
          </Card>
        </SimpleGrid>

        <SimpleGrid cols={{ base: 1, md: 2 }}>
          {/* --- Live AI triage feed ---------------------------------- */}
          <Card withBorder bg="white" radius="md" padding="lg">
            <Group gap="xs" mb="sm">
              <IconRobot size={20} />
              <Text fw={600}>Live AI Triage</Text>
              <Badge variant="light" color={aiBadge.color} size="sm">
                {aiBadge.label}
              </Badge>
            </Group>
            <ScrollArea h={320}>
              <Stack gap="sm">
                {feed.length === 0 && (
                  <Text c="dimmed" size="sm">
                    Waiting for traffic. Launch an attack above (or flip the shield)
                    to see the analyst narrate it in real time.
                  </Text>
                )}
                {feed.map((item) => (
                  <Card
                    key={item.id}
                    withBorder
                    bg="gray.0"
                    radius="sm"
                    padding="sm"
                  >
                    <Group justify="space-between" mb={4}>
                      <Text size="xs" c="dimmed">
                        {item.at}
                      </Text>
                      {item.source === "fallback" && (
                        <Badge size="xs" color="yellow" variant="light">
                          offline
                        </Badge>
                      )}
                    </Group>
                    <Text size="sm">{item.text}</Text>
                  </Card>
                ))}
              </Stack>
            </ScrollArea>
          </Card>

          {/* --- Ask the Firewall chat -------------------------------- */}
          <Card withBorder bg="white" radius="md" padding="lg">
            <Group gap="xs" mb="sm">
              <IconRobot size={20} />
              <Text fw={600}>Ask the Firewall</Text>
            </Group>
            <ScrollArea h={260} mb="sm">
              <Stack gap="sm">
                {chat.length === 0 && (
                  <Text c="dimmed" size="sm">
                    Ask things like "what's attacking us right now?" or "should I
                    turn the shield on?"
                  </Text>
                )}
                {chat.map((m, i) => (
                  <Box
                    key={i}
                    style={{
                      alignSelf:
                        m.role === "user" ? "flex-end" : "flex-start",
                      maxWidth: "90%",
                    }}
                  >
                    <Card
                      withBorder={m.role !== "user"}
                      bg={m.role === "user" ? "blue.7" : "gray.0"}
                      radius="md"
                      padding="sm"
                    >
                      <Text size="sm" c={m.role === "user" ? "white" : undefined}>
                        {m.text}
                      </Text>
                    </Card>
                  </Box>
                ))}
              </Stack>
            </ScrollArea>
            <form onSubmit={onAsk}>
              <Group gap="xs">
                <TextInput
                  flex={1}
                  placeholder="Ask the analyst…"
                  value={question}
                  onChange={(e) => setQuestion(e.currentTarget.value)}
                  disabled={chatBusy}
                />
                <Button type="submit" loading={chatBusy} px="sm">
                  <IconSend size={16} />
                </Button>
              </Group>
            </form>
          </Card>
        </SimpleGrid>
      </Container>
    </Box>
  );
}
