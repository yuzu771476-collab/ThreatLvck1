document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("scan-form");
  const input = document.getElementById("urlInput");
  const button = document.getElementById("scan-button");

  const score = document.getElementById("risk-score");
  const status = document.getElementById("status-text");
  const message = document.getElementById("result-message");
  const bar = document.getElementById("score-bar");
  const label = document.getElementById("graph-score-label");
  const dial = document.getElementById("score-dial");
  const findings = document.getElementById("findings-list");
  const scannerPanel = document.querySelector(".scanner-panel");

  const checks = {
    length: {
      card: "check-length",
      status: "length-status",
      value: "length-value",
      explanation: "length-explanation"
    },
    ip: {
      card: "check-ip",
      status: "ip-status",
      value: "ip-value",
      explanation: "ip-explanation"
    },
    at_symbol: {
      card: "check-at",
      status: "at-status",
      value: "at-value",
      explanation: "at-explanation"
    },
    https: {
      card: "check-https",
      status: "https-status",
      value: "https-value",
      explanation: "https-explanation"
    },
    domain_age: {
      card: "check-age",
      status: "age-status",
      value: "age-value",
      explanation: "age-explanation"
    },
    virustotal: {
      card: "check-vt",
      status: "vt-status",
      value: "vt-value",
      explanation: "vt-explanation"
    }
  };

  const aliases = {
    length: ["length"],
    ip: ["ip"],
    at_symbol: ["at_symbol", "at"],
    https: ["https"],
    domain_age: ["domain_age", "age"],
    virustotal: ["virustotal", "virus_total"]
  };

  function classFor(value) {
    const state = String(value || "UNKNOWN").toLowerCase();

    if (
      ["pass", "safe", "clean", "lower-risk", "secure"].includes(state)
    ) {
      return "pass";
    }

    if (
      ["warning", "suspicious", "high-risk"].includes(state)
    ) {
      return "warning";
    }

    if (
      ["error", "malicious", "danger", "failed", "rate-limited"].includes(state)
    ) {
      return "danger";
    }

    return "unknown";
  }

  function renderCheck(ids, item) {
    const card = document.getElementById(ids.card);
    const statusElement = document.getElementById(ids.status);
    const valueElement = document.getElementById(ids.value);
    const explanationElement = document.getElementById(ids.explanation);

    if (!card || !statusElement || !valueElement || !explanationElement) {
      return;
    }

    const state = item?.status || "UNKNOWN";
    const stateClass = classFor(state);

    card.classList.remove("pass", "warning", "danger", "unknown", "waiting");
    card.classList.add(stateClass);

    statusElement.textContent = state.replaceAll("_", " ");

    valueElement.textContent =
      item?.value ??
      item?.details ??
      item?.message ??
      "No additional information available";

    explanationElement.textContent =
      item?.explanation ??
      item?.description ??
      item?.reason ??
      "The analyzer did not return an explanation for this check.";
  }

  function resetChecks() {
    Object.values(checks).forEach(ids => {
      const card = document.getElementById(ids.card);
      const statusElement = document.getElementById(ids.status);
      const valueElement = document.getElementById(ids.value);
      const explanationElement = document.getElementById(ids.explanation);

      if (!card || !statusElement || !valueElement || !explanationElement) {
        return;
      }

      card.classList.remove("pass", "warning", "danger", "unknown");
      card.classList.add("waiting");

      statusElement.textContent = "WAITING";
      valueElement.textContent = "Not inspected yet";
      explanationElement.textContent = "Run a URL analysis to view this check.";
    });
  }

  function renderFindings(items) {
    findings.replaceChildren();

    if (!Array.isArray(items) || !items.length) {
      const empty = document.createElement("div");
      empty.className = "empty-state";

      const icon = document.createElement("span");
      icon.textContent = "✓";

      const paragraph = document.createElement("p");
      paragraph.textContent = "No warning findings.";

      const small = document.createElement("small");
      small.textContent = "No checks reported a warning for this scan.";

      empty.append(icon, paragraph, small);
      findings.append(empty);
      return;
    }

    items.forEach(item => {
      const row = document.createElement("div");
      row.className = "finding-row";

      const dot = document.createElement("i");
      dot.className = "finding-dot";

      const text = document.createElement("span");
      text.textContent = String(item);

      row.append(dot, text);
      findings.append(row);
    });
  }

  function renderAllChecks(data) {
    Object.entries(checks).forEach(([key, ids]) => {
      const itemKey = aliases[key].find(
        candidate => data.checks?.[candidate]
      );

      const item = itemKey
        ? data.checks[itemKey]
        : {
            status: "UNKNOWN",
            value: "No result returned",
            explanation: "The server did not return information for this check."
          };

      renderCheck(ids, item);
    });
  }

  form.addEventListener("submit", async event => {
    event.preventDefault();

    const url = input.value.trim();

    if (!url) {
      input.focus();
      message.textContent = "Enter a URL before starting the analysis.";
      return;
    }

    button.disabled = true;
    button.innerHTML = "SCANNING <span class='button-spinner'></span>";

    score.textContent = "...";
    status.textContent = "ANALYZING";
    status.className = "status-scanning";
    message.textContent = "Inspecting URL structure and reputation signals…";

    bar.style.width = "0%";
    label.textContent = "SCANNING";
    dial.style.setProperty("--score-angle", "0deg");

    if (scannerPanel) {
      scannerPanel.classList.add("is-scanning");
    }

    resetChecks();

    try {
      const response = await fetch("/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "The scan could not be completed.");
      }

      if (!Number.isFinite(Number(data.risk_score))) {
        throw new Error("The server returned an invalid risk score.");
      }

      const value = Math.max(
        0,
        Math.min(100, Number(data.risk_score))
      );

      score.textContent = value;
      status.textContent = data.status || "UNKNOWN";
      status.className = classFor(data.status);

      message.textContent =
        value >= 40
          ? "This URL triggered multiple risk indicators. Treat it with caution."
          : value >= 15
            ? "Some signals deserve a closer look before trusting this destination."
            : "The current checks returned a comparatively low risk score. Stay cautious.";

      bar.style.width = `${value}%`;
      dial.style.setProperty("--score-angle", `${value * 3.6}deg`);
      dial.dataset.level = classFor(data.status);
      label.textContent = `${value} / 100`;

      renderAllChecks(data);
      renderFindings(data.findings);

    } catch (error) {
      status.textContent = "SCAN FAILED";
      status.className = "danger";
      message.textContent = error.message;

      score.textContent = "--";
      label.textContent = "NO RESULT";
      bar.style.width = "0%";
      dial.style.setProperty("--score-angle", "0deg");

      resetChecks();
      renderFindings([error.message]);

    } finally {
      button.disabled = false;
      button.innerHTML = "ANALYZE <span>→</span>";

      if (scannerPanel) {
        scannerPanel.classList.remove("is-scanning");
      }
    }
  });
});