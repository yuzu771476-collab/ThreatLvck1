document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  const trendCanvas = $("trend-chart");
  const donutCanvas = $("distribution-chart");
  let dataState = null;

  function setupCanvas(canvas) {
    const rect = canvas.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.max(1, rect.width * dpr);
    canvas.height = Math.max(1, rect.height * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return {ctx, width: rect.width, height: rect.height};
  }
  function drawTrend(scans) {
    const {ctx, width, height} = setupCanvas(trendCanvas);
    ctx.clearRect(0, 0, width, height);
    const values = scans.slice(0, 20).reverse().map(s => Number(s.risk_score));
    $("trend-empty").style.display = values.length ? "none" : "grid";
    if (!values.length) return;
    const pad = {l: 32, r: 14, t: 18, b: 28};
    const w = width - pad.l - pad.r, h = height - pad.t - pad.b;
    ctx.font = "10px DM Mono, monospace";
    ctx.fillStyle = "#8295a9";
    [0, 25, 50, 75, 100].forEach(v => {
      const y = pad.t + h - (v / 100) * h;
      ctx.strokeStyle = "rgba(140,170,195,.13)";
      ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(width - pad.r, y); ctx.stroke();
      ctx.fillText(String(v), 4, y + 3);
    });
    const points = values.map((v, i) => ({
      x: pad.l + (values.length === 1 ? w / 2 : i * w / (values.length - 1)),
      y: pad.t + h - (v / 100) * h
    }));
    const gradient = ctx.createLinearGradient(0, pad.t, 0, height);
    gradient.addColorStop(0, "rgba(63,218,235,.23)");
    gradient.addColorStop(1, "rgba(63,218,235,0)");
    ctx.beginPath();
    points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
    if (points.length === 1) ctx.lineTo(points[0].x + 1, points[0].y);
    ctx.lineTo(points[points.length - 1].x, pad.t + h);
    ctx.lineTo(points[0].x, pad.t + h);
    ctx.closePath(); ctx.fillStyle = gradient; ctx.fill();
    ctx.beginPath();
    points.forEach((p, i) => i ? ctx.lineTo(p.x, p.y) : ctx.moveTo(p.x, p.y));
    ctx.strokeStyle = "#4bd8e8"; ctx.lineWidth = 2; ctx.stroke();
    points.forEach(p => {
      ctx.beginPath(); ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = "#9af5ff"; ctx.fill();
    });
    ctx.fillStyle = "#8295a9";
    ctx.fillText("OLDEST", pad.l, height - 7);
    ctx.textAlign = "right"; ctx.fillText("LATEST", width - pad.r, height - 7);
  }
  function drawDonut(low, medium, high) {
    const {ctx, width, height} = setupCanvas(donutCanvas);
    ctx.clearRect(0, 0, width, height);
    const values = [low, medium, high], colors = ["#48d6b0", "#e9b85f", "#f06c83"];
    const total = values.reduce((a, b) => a + b, 0);
    const cx = width / 2, cy = height / 2, radius = Math.min(width, height) * .37;
    ctx.lineWidth = 15; ctx.lineCap = "butt";
    ctx.beginPath(); ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(130,150,170,.15)"; ctx.stroke();
    if (!total) return;
    let start = -Math.PI / 2;
    values.forEach((v, i) => {
      if (!v) return;
      const end = start + (v / total) * Math.PI * 2;
      ctx.beginPath(); ctx.arc(cx, cy, radius, start, end);
      ctx.strokeStyle = colors[i]; ctx.stroke(); start = end;
    });
  }
  function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
  }
  function renderHistory(scans) {
    const body = $("history-body");
    body.replaceChildren();
    if (!scans.length) {
      const tr = document.createElement("tr"), td = document.createElement("td");
      td.colSpan = 4; td.className = "table-empty"; td.textContent = "No recorded scans yet.";
      tr.append(td); body.append(tr); return;
    }
    scans.forEach(scan => {
      const tr = document.createElement("tr");
      const date = new Date(scan.scanned_at);
      const level = Number(scan.risk_score) >= 40 ? "HIGH RISK" : Number(scan.risk_score) >= 15 ? "SUSPICIOUS" : "LOWER RISK";
      tr.innerHTML = `<td class="url-cell">${escapeHTML(scan.url)}</td><td>${escapeHTML(date.toLocaleString())}</td><td><b class="table-score">${Number(scan.risk_score)} / 100</b></td><td><span class="risk-pill ${Number(scan.risk_score) >= 40 ? "high" : Number(scan.risk_score) >= 15 ? "medium" : "low"}">${level}</span></td>`;
      body.append(tr);
    });
  }
  async function load() {
    $("refresh-analytics").disabled = true;
    try {
      const response = await fetch("/api/analytics");
      if (!response.ok) throw new Error("Could not load analytics.");
      const data = await response.json();
      dataState = data;
      $("total-scans").textContent = data.total_scans;
      $("average-score").innerHTML = `${data.average_score}<small>/100</small>`;
      $("highest-score").textContent = data.highest_score;
      $("high-risk-count").textContent = data.high_risk;
      $("lower-risk-count").textContent = data.lower_risk;
      $("suspicious-count").textContent = data.suspicious;
      $("high-risk-legend").textContent = data.high_risk;
      $("distribution-total").textContent = data.total_scans;
      drawTrend(data.scans);
      drawDonut(data.lower_risk, data.suspicious, data.high_risk);
      renderHistory(data.scans);
    } catch (error) {
      $("trend-empty").textContent = error.message;
      $("trend-empty").style.display = "grid";
    } finally {
      $("refresh-analytics").disabled = false;
    }
  }
  $("refresh-analytics").addEventListener("click", load);
  window.addEventListener("resize", () => { if (dataState) { drawTrend(dataState.scans); drawDonut(dataState.lower_risk, dataState.suspicious, dataState.high_risk); } });
  load();
});
