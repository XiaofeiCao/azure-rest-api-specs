// Generated browser client script emitted as <work-dir>/report-html/assets/app.js
export const REPORT_PORTAL_APP_JS = `(function () {
  "use strict";

  const { document, window, fetch } = globalThis;

  const state = {
    bundle: null,
    selectedServiceId: "all",
    activeTab: "operations",
    lastDrawerTrigger: null,
  };

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function safeHttpsUrl(rawUrl) {
    if (!rawUrl || typeof rawUrl !== "string") {
      return "";
    }
    try {
      const parsed = new URL(rawUrl);
      return parsed.protocol === "https:" ? parsed.toString() : "";
    } catch {
      return "";
    }
  }

  function clampPct(value) {
    const num = Number(value);
    if (!Number.isFinite(num)) {
      return 0;
    }
    return Math.max(0, Math.min(100, Number(num.toFixed(1))));
  }

  function pct(num, den) {
    return den === 0 ? 100 : Number(((num / den) * 100).toFixed(1));
  }

  function getScopedServices() {
    if (!state.bundle) return [];
    if (state.selectedServiceId === "all") {
      return state.bundle.services;
    }
    return state.bundle.services.filter((s) => s.serviceId === state.selectedServiceId);
  }

  function computeScopeMetrics(services) {
    let totalOps = 0;
    let testedOps = 0;
    let passedClean = 0;
    let passedMismatch = 0;
    let blocked = 0;
    let failed = 0;
    let totalDisc = 0;
    let blockingDisc = 0;
    let warningDisc = 0;
    let examples = 0;

    const byLocation = {
      path: { total: 0, exercised: 0 },
      query: { total: 0, exercised: 0 },
      header: { total: 0, exercised: 0 },
      body: { total: 0, exercised: 0 },
    };
    let reqTotal = 0;
    let reqEx = 0;
    let optTotal = 0;
    let optEx = 0;

    for (const s of services) {
      totalOps += s.apiCoverage.totalOperations;
      testedOps += s.apiCoverage.testedOperations;
      passedClean += s.apiCoverage.passedClean;
      passedMismatch += s.apiCoverage.passedWithMismatch;
      blocked += s.apiCoverage.blocked;
      failed += s.apiCoverage.failedServiceError;
      totalDisc += s.discrepancySummary.total;
      blockingDisc += s.discrepancySummary.blocking;
      warningDisc += s.discrepancySummary.warning;
      examples += s.generatedExamplesCount;

      const p = s.parameterCoverage;
      reqTotal += p.requiredTotal;
      reqEx += p.requiredExercised;
      optTotal += p.optionalTotal;
      optEx += p.optionalExercised;
      for (const loc of ["path", "query", "header", "body"]) {
        byLocation[loc].total += p.byLocation[loc].total;
        byLocation[loc].exercised += p.byLocation[loc].exercised;
      }
    }

    const paramTotal = reqTotal + optTotal;
    const paramEx = reqEx + optEx;
    return {
      serviceCount: services.length,
      totalOps,
      testedOps,
      apiPct: pct(testedOps, totalOps),
      passedClean,
      passedMismatch,
      blocked,
      failed,
      paramTotal,
      paramEx,
      paramPct: pct(paramEx, paramTotal),
      reqTotal,
      reqEx,
      reqPct: pct(reqEx, reqTotal),
      optTotal,
      optEx,
      optPct: pct(optEx, optTotal),
      byLocation,
      totalDisc,
      blockingDisc,
      warningDisc,
      examples,
    };
  }

  function statusBadgeHtml(status) {
    if (status === "passed") {
      return '<span class="badge badge-passed">passed</span>';
    }
    if (status === "passed_with_mismatch") {
      return '<span class="badge badge-mismatch">mismatch</span>';
    }
    if (status === "blocked") {
      return '<span class="badge badge-blocked">blocked</span>';
    }
    if (status === "failed_service_error") {
      return '<span class="badge badge-blocking">failed</span>';
    }
    return \`<span class="badge badge-neutral">\${esc(status)}</span>\`;
  }

  function renderEndpointBadge(armBaseUrl) {
    if (!armBaseUrl || armBaseUrl.toLowerCase() === "https://management.azure.com") {
      return "";
    }
    let label = armBaseUrl;
    try {
      const u = new URL(armBaseUrl);
      label = \`\${u.host}\${u.pathname && u.pathname !== "/" ? u.pathname : ""}\`;
    } catch {
      // Keep raw string if not parseable.
    }
    return \`<span class="canary-pill" title="Custom / Canary ARM endpoint">\${esc(label)}</span>\`;
  }

  function renderServicesGrid() {
    const grid = document.getElementById("servicesGrid");
    const allBtn = document.getElementById("selectAllServicesBtn");
    const multiService = state.bundle.services.length > 1;
    allBtn.classList.toggle("hidden", !multiService);
    allBtn.classList.toggle("active", state.selectedServiceId === "all");
    allBtn.setAttribute("aria-pressed", String(state.selectedServiceId === "all"));

    grid.innerHTML = state.bundle.services
      .map((svc) => {
        const isSelected = state.selectedServiceId === svc.serviceId || !multiService;
        const specUrl = safeHttpsUrl(svc.githubSpecUrl);
        const specHtml = specUrl
          ? \`<a href="\${esc(specUrl)}" target="_blank" rel="noopener noreferrer" data-ext-link="1">\${esc(svc.specRelativeDir)} ↗</a>\`
          : esc(svc.specRelativeDir);
        const selectBtnHtml = multiService
          ? \`<button type="button" class="btn btn-secondary btn-sm \${isSelected ? "active" : ""}" aria-pressed="\${isSelected ? "true" : "false"}" data-select-service="\${esc(svc.serviceId)}">\${isSelected ? "Selected ✓" : "Filter to Run"}</button>\`
          : "";
        return \`
          <div class="service-card \${isSelected ? "selected" : ""}" data-service-id="\${esc(svc.serviceId)}">
            <div class="service-card-top">
              <div>
                <div class="service-ns">\${esc(svc.providerNamespace)}</div>
                <div class="muted">\${specHtml}</div>
              </div>
              <div class="tag-row">
                \${renderEndpointBadge(svc.armBaseUrl)}
                <span class="version-tag">\${esc(svc.apiVersion)}</span>
                \${selectBtnHtml}
              </div>
            </div>
            <div class="service-metrics">
              <div class="mini-metric">
                <div class="mini-metric-label">API Coverage</div>
                <div class="mini-metric-val">\${clampPct(svc.apiCoverage.coveragePercent)}%</div>
                <div class="mini-metric-sub">\${Number(svc.apiCoverage.testedOperations) || 0} / \${Number(svc.apiCoverage.totalOperations) || 0} ops</div>
              </div>
              <div class="mini-metric">
                <div class="mini-metric-label">Param Coverage</div>
                <div class="mini-metric-val">\${clampPct(svc.parameterCoverage.percent)}%</div>
                <div class="mini-metric-sub">Req \${clampPct(svc.parameterCoverage.requiredPercent)}% · Opt \${clampPct(svc.parameterCoverage.optionalPercent)}%</div>
              </div>
              <div class="mini-metric">
                <div class="mini-metric-label">Discrepancies</div>
                <div class="mini-metric-val">\${Number(svc.discrepancySummary.total) || 0}</div>
                <div class="mini-metric-sub">\${Number(svc.generatedExamplesCount) || 0} live examples</div>
              </div>
            </div>
            <div class="service-footer">
              <span>Region: <strong>\${esc(svc.region || "n/a")}</strong> · Test RG: <strong>\${esc(svc.rgCleanupStatus || "n/a")}</strong></span>
              <span>Tested \${esc(String(svc.testedAt || "").slice(0, 10))}</span>
            </div>
          </div>
        \`;
      })
      .join("");

    grid.querySelectorAll("[data-ext-link]").forEach((link) => {
      link.addEventListener("click", (ev) => ev.stopPropagation());
    });

    if (multiService) {
      grid.querySelectorAll("[data-select-service]").forEach((btn) => {
        btn.addEventListener("click", (ev) => {
          ev.stopPropagation();
          const id = btn.getAttribute("data-select-service");
          state.selectedServiceId = state.selectedServiceId === id ? "all" : id;
          renderAll();
        });
      });
      grid.querySelectorAll(".service-card").forEach((card) => {
        card.addEventListener("click", () => {
          const id = card.getAttribute("data-service-id");
          state.selectedServiceId = state.selectedServiceId === id ? "all" : id;
          renderAll();
        });
      });
    }
  }

  function renderKpis(metrics) {
    const kpiGrid = document.getElementById("kpiGrid");
    kpiGrid.innerHTML = \`
      <div class="kpi-card">
        <div class="kpi-label">Validated Mgmt Services</div>
        <div class="kpi-value">\${metrics.serviceCount}</div>
        <div class="kpi-detail">\${metrics.examples} sanitized live TypeSpec examples generated</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">API Operation Coverage</div>
        <div class="kpi-value">\${clampPct(metrics.apiPct)}%</div>
        <div class="kpi-detail">
          <strong>\${metrics.testedOps} / \${metrics.totalOps}</strong> operations
          (Clean: \${metrics.passedClean} · Mismatch: \${metrics.passedMismatch} · Blocked: \${metrics.blocked})
        </div>
        <div class="progress-track">
          <div class="progress-fill green" style="width: \${clampPct(metrics.apiPct)}%"></div>
        </div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Parameter &amp; Body Coverage</div>
        <div class="kpi-value">\${clampPct(metrics.paramPct)}%</div>
        <div class="kpi-detail">
          <strong>\${metrics.paramEx} / \${metrics.paramTotal}</strong> params
          (Required: <strong>\${clampPct(metrics.reqPct)}%</strong> [\${metrics.reqEx}/\${metrics.reqTotal}] · Optional: <strong>\${clampPct(metrics.optPct)}%</strong> [\${metrics.optEx}/\${metrics.optTotal}])
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width: \${clampPct(metrics.paramPct)}%"></div>
        </div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Spec-vs-Live Discrepancies</div>
        <div class="kpi-value">\${metrics.totalDisc}</div>
        <div class="kpi-detail">
          Blocking: <strong>\${metrics.blockingDisc}</strong> · Warning: <strong>\${metrics.warningDisc}</strong>
        </div>
      </div>
    \`;
  }

  function renderOperationsTable(services) {
    const search = document.getElementById("opSearchInput").value.trim().toLowerCase();
    const statusFilter = document.getElementById("opStatusFilter").value;
    const methodFilter = document.getElementById("opMethodFilter").value;

    const rows = [];
    for (const svc of services) {
      for (const op of svc.operations) {
        if (statusFilter !== "all" && op.status !== statusFilter) continue;
        if (methodFilter !== "all" && op.method !== methodFilter) continue;
        if (search) {
          const hay =
            \`\${svc.providerNamespace} \${op.operationId} \${op.pathTemplate} \${op.sourceLabel || ""} \${op.resourceType}\`.toLowerCase();
          if (!hay.includes(search)) continue;
        }
        rows.push({ svc, op });
      }
    }

    document.getElementById("opsTabCount").textContent = String(rows.length);

    const tbody = document.getElementById("operationsTableBody");
    if (rows.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="8" class="muted">No operations match the active filters.</td></tr>';
      return;
    }

    tbody.innerHTML = rows
      .map(({ svc, op }) => {
        const lroBadge = op.observedLro?.detected
          ? \`<span class="badge badge-neutral" title="Polled \${Number(op.observedLro.pollCount) || 0}x via \${esc(op.observedLro.pollingHeaderUsed || "wire")}">LRO (\${Number(op.observedLro.pollCount) || 0} polls)</span>\`
          : op.isLroDeclared
            ? '<span class="badge badge-neutral">LRO (sync 200)</span>'
            : "";
        const srcUrl = safeHttpsUrl(op.githubSourceUrl);
        const sourceCell = srcUrl
          ? \`<a href="\${esc(srcUrl)}" target="_blank" rel="noopener noreferrer" data-ext-link="1"><code>\${esc(op.sourceLabel)}</code></a>\`
          : op.sourceLabel
            ? \`<code>\${esc(op.sourceLabel)}</code>\`
            : "-";

        return \`
          <tr class="clickable-row" data-svc="\${esc(svc.serviceId)}" data-op="\${esc(op.operationId)}">
            <td>
              <div><strong>\${esc(svc.providerNamespace.replace(/^Microsoft\\./, ""))}</strong></div>
              <div class="muted">\${esc(svc.apiVersion)}</div>
            </td>
            <td>
              <button type="button" class="op-link-btn" data-open-svc="\${esc(svc.serviceId)}" data-open-op="\${esc(op.operationId)}"><strong><code>\${esc(op.operationId)}</code></strong></button>
              \${op.blockerReason ? \`<div class="muted">\${esc(String(op.blockerReason).slice(0, 85))}</div>\` : ""}
            </td>
            <td>
              <span class="verb verb-\${esc(op.method)}">\${esc(op.method)}</span>
              <span class="route-code">\${esc(op.pathTemplate)}</span>
            </td>
            <td>\${sourceCell}</td>
            <td>\${esc(op.phase)} \${lroBadge}</td>
            <td>
              \${statusBadgeHtml(op.status)}
              \${op.lastHttpStatus ? \`<span class="muted">HTTP \${Number(op.lastHttpStatus)}</span>\` : ""}
            </td>
            <td class="param-bar-cell">
              <div><strong>\${Number(op.parameterStats.exercised) || 0}/\${Number(op.parameterStats.total) || 0}</strong> (\${clampPct(op.parameterStats.percent)}%)</div>
              <div class="progress-track">
                <div class="progress-fill" style="width: \${clampPct(op.parameterStats.percent)}%"></div>
              </div>
            </td>
            <td>\${op.discrepancyCount > 0 ? \`<span class="badge badge-warning">\${Number(op.discrepancyCount)}</span>\` : '<span class="muted">0</span>'}</td>
          </tr>
        \`;
      })
      .join("");

    tbody.querySelectorAll("[data-ext-link]").forEach((link) => {
      link.addEventListener("click", (ev) => ev.stopPropagation());
    });

    tbody.querySelectorAll("[data-open-op]").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openOperationDrawer(
          btn.getAttribute("data-open-svc"),
          btn.getAttribute("data-open-op"),
          btn,
        );
      });
    });

    tbody.querySelectorAll("tr.clickable-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        const rowBtn = tr.querySelector("[data-open-op]");
        openOperationDrawer(tr.getAttribute("data-svc"), tr.getAttribute("data-op"), rowBtn);
      });
    });
  }

  function renderParametersTable(services, metrics) {
    document.getElementById("paramsTabCount").textContent = \`\${clampPct(metrics.paramPct)}%\`;

    const locCards = document.getElementById("paramLocationCards");
    locCards.innerHTML = ["path", "query", "header", "body"]
      .map((loc) => {
        const item = metrics.byLocation[loc];
        const p = pct(item.exercised, item.total);
        return \`
          <div class="mini-metric">
            <div class="mini-metric-label">\${esc(loc)} Parameters</div>
            <div class="mini-metric-val">\${item.exercised} / \${item.total} (\${clampPct(p)}%)</div>
          </div>
        \`;
      })
      .join("");

    const locFilter = document.getElementById("paramLocationFilter").value;
    const stateFilter = document.getElementById("paramStateFilter").value;
    const search = document.getElementById("opSearchInput").value.trim().toLowerCase();

    const items = [];
    for (const svc of services) {
      for (const op of svc.operations) {
        for (const param of op.parameters) {
          if (locFilter !== "all" && param.in !== locFilter) continue;
          if (stateFilter === "untested" && param.exercised) continue;
          if (stateFilter === "exercised" && !param.exercised) continue;
          if (stateFilter === "required" && !param.required) continue;
          if (stateFilter === "optional" && param.required) continue;
          if (search) {
            const hay =
              \`\${svc.providerNamespace} \${op.operationId} \${param.name} \${param.type}\`.toLowerCase();
            if (!hay.includes(search)) continue;
          }
          items.push({ svc, op, param });
        }
      }
    }

    const tbody = document.getElementById("parametersTableBody");
    if (items.length === 0) {
      tbody.innerHTML =
        '<tr><td colspan="8" class="muted">No parameters match the active filters.</td></tr>';
      return;
    }

    tbody.innerHTML = items
      .map(
        ({ svc, op, param }) => \`
          <tr class="clickable-row" data-svc="\${esc(svc.serviceId)}" data-op="\${esc(op.operationId)}">
            <td>\${esc(svc.providerNamespace.replace(/^Microsoft\\./, ""))}</td>
            <td><button type="button" class="op-link-btn" data-open-svc="\${esc(svc.serviceId)}" data-open-op="\${esc(op.operationId)}"><code>\${esc(op.operationId)}</code></button></td>
            <td><strong><code>\${esc(param.name)}</code></strong></td>
            <td><span class="badge badge-neutral">\${esc(param.in)}</span></td>
            <td>\${param.required ? "<strong>Required</strong>" : '<span class="muted">Optional</span>'}</td>
            <td><code>\${esc(param.type)}</code></td>
            <td>
              \${
                param.exercised
                  ? '<span class="badge badge-passed">✓ Exercised</span>'
                  : '<span class="badge badge-mismatch">○ Untested</span>'
              }
            </td>
            <td><code>\${esc(param.sampleValue ?? "-")}</code></td>
          </tr>
        \`,
      )
      .join("");

    tbody.querySelectorAll("[data-open-op]").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        openOperationDrawer(
          btn.getAttribute("data-open-svc"),
          btn.getAttribute("data-open-op"),
          btn,
        );
      });
    });

    tbody.querySelectorAll("tr.clickable-row").forEach((tr) => {
      tr.addEventListener("click", () => {
        const rowBtn = tr.querySelector("[data-open-op]");
        openOperationDrawer(tr.getAttribute("data-svc"), tr.getAttribute("data-op"), rowBtn);
      });
    });
  }

  function populateDiscrepancyRuleOptions(services) {
    const select = document.getElementById("discRuleFilter");
    const prev = select.value;
    const rules = new Set();
    for (const s of services) {
      for (const d of s.discrepancies) {
        rules.add(d.ruleId);
      }
    }
    select.innerHTML =
      '<option value="all">All Rules</option>' +
      [...rules]
        .sort()
        .map((r) => \`<option value="\${esc(r)}">\${esc(r)}</option>\`)
        .join("");
    if ([...rules].includes(prev)) {
      select.value = prev;
    }
  }

  function renderDiscrepancies(services) {
    const ruleFilter = document.getElementById("discRuleFilter").value;
    const sevFilter = document.getElementById("discSeverityFilter").value;

    const list = [];
    for (const s of services) {
      for (const d of s.discrepancies) {
        if (ruleFilter !== "all" && d.ruleId !== ruleFilter) continue;
        if (sevFilter !== "all" && d.severity !== sevFilter) continue;
        list.push(d);
      }
    }

    document.getElementById("discTabCount").textContent = String(list.length);
    const container = document.getElementById("discrepanciesList");
    if (list.length === 0) {
      container.innerHTML =
        '<div class="muted">No behavioral discrepancies detected for the selected service/filter scope.</div>';
      return;
    }

    container.innerHTML = list
      .map((d) => {
        const srcUrl = safeHttpsUrl(d.githubSourceUrl);
        const srcHtml = srcUrl
          ? \`<a href="\${esc(srcUrl)}" target="_blank" rel="noopener noreferrer"><code>\${esc(d.sourceLabel)}</code> ↗</a>\`
          : d.sourceLabel
            ? \`<code>\${esc(d.sourceLabel)}</code>\`
            : "";
        return \`
          <article class="disc-card \${esc(d.severity)}">
            <div class="disc-header">
              <div>
                <span class="badge badge-\${esc(d.severity)}">\${esc(String(d.severity).toUpperCase())}</span>
                <strong><code>\${esc(d.ruleId)}</code></strong> —
                <code>\${esc(d.operationId)}</code>
                \${srcHtml ? \`(\${srcHtml})\` : ""}
              </div>
              <span class="version-tag">\${esc(d.providerNamespace)} @ \${esc(d.apiVersion)}</span>
            </div>
            <div><strong>\${esc(d.summary)}</strong></div>
            <div class="disc-grid">
              <div class="disc-box">
                <div class="mini-metric-label">TypeSpec Expectation</div>
                <div>\${esc(d.specExpectation)}</div>
              </div>
              <div class="disc-box">
                <div class="mini-metric-label">Actual Live Wire Behavior</div>
                <div>\${esc(d.actualWireBehavior)}</div>
              </div>
            </div>
          </article>
        \`;
      })
      .join("");
  }

  function openOperationDrawer(serviceId, operationId, triggerEl) {
    const svc = state.bundle.services.find((s) => s.serviceId === serviceId);
    const op = svc?.operations.find((o) => o.operationId === operationId);
    if (!svc || !op) return;
    if (triggerEl && typeof triggerEl.focus === "function") {
      state.lastDrawerTrigger = triggerEl;
    }

    document.getElementById("drawerServiceLabel").textContent =
      \`\${svc.providerNamespace} (\${svc.apiVersion})\`;
    document.getElementById("drawerOpTitle").textContent = op.operationId;

    const opDiscrepancies = svc.discrepancies.filter((d) => d.operationId === op.operationId);
    const wireHtml =
      Array.isArray(op.wireSteps) && op.wireSteps.length > 0
        ? \`
          <h4>Wire HTTP Exchanges (\${op.wireSteps.length})</h4>
          <div class="table-wrap" style="margin-bottom:18px">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Step</th>
                  <th>Verb</th>
                  <th>Status</th>
                  <th>Duration</th>
                  <th>Sanitized Target Path</th>
                </tr>
              </thead>
              <tbody>
                \${op.wireSteps
                  .map(
                    (ws) => \`
                    <tr>
                      <td><span class="badge badge-neutral">\${esc(ws.step)}</span></td>
                      <td><span class="verb verb-\${esc(ws.method)}">\${esc(ws.method)}</span></td>
                      <td><strong>HTTP \${Number(ws.status)}</strong></td>
                      <td>\${Number(ws.durationMs) || 0} ms</td>
                      <td><code class="route-code">\${esc(ws.sanitizedUrl)}</code></td>
                    </tr>
                  \`,
                  )
                  .join("")}
              </tbody>
            </table>
          </div>
        \`
        : "";

    const exampleHtml =
      op.examples.length > 0
        ? op.examples
            .map(
              (ex) => \`
                <h4>Sanitized Live Example: <code>\${esc(ex.name)}.json</code></h4>
                <pre class="code-pre">\${esc(JSON.stringify(ex.content, null, 2))}</pre>
              \`,
            )
            .join("")
        : '<p class="muted">No positive 2xx live example recorded for this operation.</p>';

    const discHtml =
      opDiscrepancies.length > 0
        ? \`
          <h4>Detected Discrepancies (\${opDiscrepancies.length})</h4>
          \${opDiscrepancies
            .map(
              (d) => \`
              <div class="disc-card \${esc(d.severity)}" style="margin-bottom:10px">
                <strong><code>\${esc(d.ruleId)}</code></strong>: \${esc(d.summary)}
                <div class="muted" style="margin-top:4px">Live: \${esc(d.actualWireBehavior)}</div>
              </div>
            \`,
            )
            .join("")}
        \`
        : "";

    document.getElementById("drawerBody").innerHTML = \`
      <div style="margin-bottom:14px">
        <span class="verb verb-\${esc(op.method)}">\${esc(op.method)}</span>
        <code class="route-code">\${esc(op.pathTemplate)}</code>
      </div>
      <div class="service-metrics" style="margin-bottom:16px">
        <div class="mini-metric">
          <div class="mini-metric-label">Execution Status</div>
          <div class="mini-metric-val">\${statusBadgeHtml(op.status)} \${op.lastHttpStatus ? \`HTTP \${Number(op.lastHttpStatus)}\` : ""}</div>
        </div>
        <div class="mini-metric">
          <div class="mini-metric-label">Parameter Coverage</div>
          <div class="mini-metric-val">\${Number(op.parameterStats.exercised) || 0}/\${Number(op.parameterStats.total) || 0} (\${clampPct(op.parameterStats.percent)}%)</div>
          <div class="mini-metric-sub">Req \${clampPct(op.parameterStats.requiredPercent)}% · Opt \${clampPct(op.parameterStats.optionalPercent)}%</div>
        </div>
        <div class="mini-metric">
          <div class="mini-metric-label">Wire LRO State</div>
          <div class="mini-metric-val">\${op.observedLro?.detected ? \`\${Number(op.observedLro.pollCount) || 0} polls\` : "Sync"}</div>
          <div class="mini-metric-sub">\${esc(op.observedLro?.pollingHeaderUsed || op.phase)}</div>
        </div>
      </div>
      \${op.blockerReason ? \`<div class="disc-card blocking" style="margin-bottom:14px"><strong>Blocker:</strong> \${esc(op.blockerReason)}</div>\` : ""}
      \${discHtml}
      \${wireHtml}
      <h4>Parameters &amp; Request Body Properties (\${op.parameters.length})</h4>
      <div class="table-wrap" style="margin-bottom:18px">
        <table class="data-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>In</th>
              <th>Req</th>
              <th>Type</th>
              <th>State</th>
              <th>Sample</th>
            </tr>
          </thead>
          <tbody>
            \${op.parameters
              .map(
                (p) => \`
                <tr>
                  <td><code>\${esc(p.name)}</code></td>
                  <td>\${esc(p.in)}</td>
                  <td>\${p.required ? "Yes" : "No"}</td>
                  <td><code>\${esc(p.type)}</code></td>
                  <td>\${p.exercised ? '<span class="badge badge-passed">✓</span>' : '<span class="badge badge-mismatch">○</span>'}</td>
                  <td><code>\${esc(p.sampleValue ?? "-")}</code></td>
                </tr>
              \`,
              )
              .join("")}
          </tbody>
        </table>
      </div>
      \${exampleHtml}
    \`;

    document.getElementById("drawerBackdrop").classList.remove("hidden");
    document.getElementById("detailDrawer").classList.remove("hidden");
    const closeBtn = document.getElementById("closeDrawerBtn");
    if (closeBtn && typeof closeBtn.focus === "function") {
      closeBtn.focus();
    }
  }

  function closeDrawer() {
    document.getElementById("drawerBackdrop").classList.add("hidden");
    document.getElementById("detailDrawer").classList.add("hidden");
    if (state.lastDrawerTrigger && typeof state.lastDrawerTrigger.focus === "function") {
      state.lastDrawerTrigger.focus();
      state.lastDrawerTrigger = null;
    }
  }

  function updateActiveTabVisibility() {
    document.querySelectorAll(".tab").forEach((btn) => {
      btn.classList.toggle("active", btn.getAttribute("data-tab") === state.activeTab);
    });
    document
      .getElementById("tab-operations")
      .classList.toggle("hidden", state.activeTab !== "operations");
    document
      .getElementById("tab-parameters")
      .classList.toggle("hidden", state.activeTab !== "parameters");
    document
      .getElementById("tab-discrepancies")
      .classList.toggle("hidden", state.activeTab !== "discrepancies");

    document
      .getElementById("operationsFilters")
      .classList.toggle("hidden", state.activeTab === "discrepancies");
    document
      .getElementById("parametersFilters")
      .classList.toggle("hidden", state.activeTab !== "parameters");
    document
      .getElementById("discrepanciesFilters")
      .classList.toggle("hidden", state.activeTab !== "discrepancies");
  }

  function renderAll() {
    const scoped = getScopedServices();
    const metrics = computeScopeMetrics(scoped);
    renderServicesGrid();
    renderKpis(metrics);
    populateDiscrepancyRuleOptions(scoped);
    renderOperationsTable(scoped);
    renderParametersTable(scoped, metrics);
    renderDiscrepancies(scoped);
    updateActiveTabVisibility();
  }

  async function bootstrap() {
    try {
      let data = window.__ARM_BLACKBOX_PORTAL_DATA__ || null;
      if (!data) {
        const resp = await fetch("./assets/portal-data.json");
        if (!resp.ok) {
          throw new Error(\`HTTP \${resp.status}\`);
        }
        data = await resp.json();
      }

      state.bundle = data;
      const customEndpoints = [
        ...new Set(
          (data.services || [])
            .map((s) => s.armBaseUrl)
            .filter((u) => u && u.toLowerCase() !== "https://management.azure.com"),
        ),
      ];
      document.getElementById("envPill").textContent =
        customEndpoints.length === 1
          ? \`Target Endpoint: \${customEndpoints[0]}\`
          : customEndpoints.length > 1
            ? \`Custom / Canary Endpoints (\${customEndpoints.length})\`
            : "Target Endpoint: https://management.azure.com";
      document.getElementById("generatedAtLabel").textContent = \`Report generated \${String(
        data.generatedAt || "",
      )
        .replace("T", " ")
        .slice(
          0,
          19,
        )} UTC · Click any operation row to inspect wire exchanges, parameters & sanitized live examples\`;

      document.getElementById("loadingState").classList.add("hidden");
      document.getElementById("dashboardContent").classList.remove("hidden");
      renderAll();
    } catch (err) {
      document.getElementById("loadingState").innerHTML =
        \`<p style="color:#b91c1c">Failed to load local blackbox report: \${esc(err?.message || err)}</p>\`;
    }
  }

  document.getElementById("selectAllServicesBtn").addEventListener("click", () => {
    state.selectedServiceId = "all";
    renderAll();
  });

  document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      state.activeTab = btn.getAttribute("data-tab");
      updateActiveTabVisibility();
    });
  });

  for (const id of [
    "opSearchInput",
    "opStatusFilter",
    "opMethodFilter",
    "paramLocationFilter",
    "paramStateFilter",
    "discRuleFilter",
    "discSeverityFilter",
  ]) {
    document.getElementById(id).addEventListener("input", () => renderAll());
    document.getElementById(id).addEventListener("change", () => renderAll());
  }

  document.getElementById("closeDrawerBtn").addEventListener("click", closeDrawer);
  document.getElementById("drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      closeDrawer();
    }
  });

  bootstrap();
})();
`;
