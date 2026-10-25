import { useState, type FormEvent } from "react";
import {
  Alert,
  Anchor,
  Box,
  Button,
  Card,
  Container,
  Divider,
  Group,
  Loader,
  Radio,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { IconInfoCircle } from "@tabler/icons-react";
import { emailLookup, type IdType, type LookupResponse } from "../api";

// Convert the native date input (YYYY-MM-DD) to the MM/DD/YYYY the API expects.
function toMMDDYYYY(iso: string): string {
  const [y, m, d] = iso.split("-");
  if (!y || !m || !d) return "";
  return `${m}/${d}/${y}`;
}

type View =
  | { kind: "form" }
  | { kind: "loading" }
  | { kind: "found"; last: string; res: LookupResponse }
  | { kind: "notfound" }
  | { kind: "error" };

export function EmailLookup() {
  const [lastName, setLastName] = useState("");
  const [dob, setDob] = useState("");
  const [idType, setIdType] = useState<IdType>("student_id");
  const [idVal, setIdVal] = useState("");
  const [view, setView] = useState<View>({ kind: "form" });

  async function onSubmit(e: FormEvent) {
    e.preventDefault(); // AJAX: no navigation, URL stays the same.

    if (!lastName.trim() || !dob || !idVal.trim()) {
      setView({ kind: "error" });
      return;
    }

    setView({ kind: "loading" });
    try {
      const res = await emailLookup({
        last: lastName.trim(),
        birthday: toMMDDYYYY(dob),
        student_id: idType === "student_id" ? idVal.trim() : "",
        emplid: idType === "emplid" ? idVal.trim() : "",
      });
      if (res.result_code === "0") {
        setView({ kind: "found", last: lastName.trim(), res });
      } else {
        setView({ kind: "notfound" });
      }
    } catch {
      // Includes WAF blocks (403/429). The public page shows a generic error on
      // purpose — no hint that a firewall exists.
      setView({ kind: "error" });
    }
  }

  function reset() {
    setView({ kind: "form" });
  }

  return (
    <Box bg="gray.0" mih="100vh">
      {/* Neutral demo branding — clearly a demo, not an impersonation. */}
      <Box bg="blue.8" py="md">
        <Container size="sm">
          <Text c="white" fw={700} size="lg">
            DEMO UNIVERSITY
          </Text>
        </Container>
      </Box>

      <Container size="sm" py="xl">
        <Title order={1} mb="xs">
          Email Lookup
        </Title>
        <Text c="dimmed" mb="lg">
          Look up your campus email address.
        </Text>

        <Card withBorder radius="md" padding="xl" bg="white">
          {view.kind === "loading" && (
            <Group justify="center" py="xl">
              <Loader />
              <Text>Looking up…</Text>
            </Group>
          )}

          {view.kind === "found" && (
            <Stack>
              <Title order={3}>Email Address Found</Title>
              <div>
                <Text fw={600}>Last Name</Text>
                <Text mb="sm">{view.last}</Text>
                <Text fw={600}>Email Type</Text>
                <Text mb="sm">{view.res.email_type}</Text>
                <Text fw={600}>Email Address</Text>
                <Text>{view.res.email}</Text>
              </div>
              <Button variant="light" onClick={reset} mt="md">
                Return to Email Lookup
              </Button>
            </Stack>
          )}

          {view.kind === "notfound" && (
            <Stack>
              <Title order={3}>No Match Found</Title>
              <Text>
                We couldn't find a record matching that last name, date of
                birth, and ID. Please check your entries and try again.
              </Text>
              <Button variant="light" onClick={reset} mt="md">
                Return to Email Lookup
              </Button>
            </Stack>
          )}

          {view.kind === "error" && (
            <Stack>
              <Alert color="red" title="Something went wrong">
                We're unable to process your request right now. Please try again
                later.
              </Alert>
              <Button variant="light" onClick={reset}>
                Return to Email Lookup
              </Button>
            </Stack>
          )}

          {view.kind === "form" && (
            <form onSubmit={onSubmit}>
              <Stack>
                <TextInput
                  label="Primary Last Name"
                  required
                  maxLength={64}
                  value={lastName}
                  onChange={(e) => setLastName(e.currentTarget.value)}
                />
                <TextInput
                  label="Date of Birth"
                  type="date"
                  required
                  value={dob}
                  onChange={(e) => setDob(e.currentTarget.value)}
                />
                <Radio.Group
                  label="Please select either Student ID or HR Employee ID to use for recovery"
                  required
                  value={idType}
                  onChange={(v) => setIdType(v as IdType)}
                >
                  <Group mt="xs">
                    <Radio value="student_id" label="Student ID" />
                    <Radio
                      value="emplid"
                      label="HR Employee ID (Found on Pay Advice)"
                    />
                  </Group>
                </Radio.Group>
                <TextInput
                  label="Enter Selected ID"
                  required
                  placeholder="Enter Selected ID"
                  value={idVal}
                  onChange={(e) => setIdVal(e.currentTarget.value)}
                />
                <Button type="submit" mt="sm">
                  Get Email
                </Button>
              </Stack>
            </form>
          )}
        </Card>

        <Card withBorder radius="md" padding="lg" mt="lg" bg="white">
          <Group gap="xs" mb="xs">
            <IconInfoCircle size={18} />
            <Text fw={600}>Need Help?</Text>
          </Group>
          <Text size="sm" c="dimmed">
            As a reminder, the email listed does not ensure that your account is
            active and you may need to contact your campus Help Desk.
          </Text>
          <Divider my="sm" />
          <Anchor size="sm" href="#">
            Help Desk Contact Information
          </Anchor>
        </Card>

        <Text ta="center" c="dimmed" size="xs" mt="xl">
          This is a demonstration application. All data shown is fictitious.
        </Text>
      </Container>
    </Box>
  );
}
