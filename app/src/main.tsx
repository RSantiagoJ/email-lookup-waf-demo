import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { MantineProvider, createTheme } from "@mantine/core";
import "@mantine/core/styles.css";
import { EmailLookup } from "./pages/EmailLookup";
import { SecurityDashboard } from "./pages/SecurityDashboard";

const theme = createTheme({
  primaryColor: "blue",
  fontFamily:
    "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <MantineProvider theme={theme}>
      <BrowserRouter>
        <Routes>
          {/* Public, student-facing. No security presence by design. */}
          <Route path="/" element={<EmailLookup />} />
          {/* Internal security team view. Unlinked from the public page. */}
          <Route path="/security" element={<SecurityDashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </MantineProvider>
  </StrictMode>,
);
