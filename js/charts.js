/**
 * Interactive SOC Visualizations & Charts
 * High performance Canvas & SVG implementations without external heavyweight libraries
 */

class SOCCharts {
  /**
   * Renders a glowing Donut Chart for Severity Breakdown
   */
  static renderSeverityDonut(canvas, counts) {
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width;
    const height = canvas.height;
    ctx.clearRect(0, 0, width, height);

    const data = [
      { label: 'Critical', value: counts.critical || 0, color: '#ff3366', glow: 'rgba(255, 51, 102, 0.4)' },
      { label: 'High', value: counts.high || 0, color: '#ff7828', glow: 'rgba(255, 120, 40, 0.4)' },
      { label: 'Medium', value: counts.medium || 0, color: '#f59e0b', glow: 'rgba(245, 158, 11, 0.4)' },
      { label: 'Low', value: counts.low || 0, color: '#3b82f6', glow: 'rgba(59, 130, 246, 0.4)' },
      { label: 'Info', value: counts.info || 0, color: '#06b6d4', glow: 'rgba(6, 182, 212, 0.4)' }
    ];

    const total = data.reduce((sum, item) => sum + item.value, 0);
    const centerX = width / 2;
    const centerY = height / 2;
    const radius = Math.min(centerX, centerY) - 20;
    const innerRadius = radius * 0.62;

    if (total === 0) {
      // Empty state
      ctx.beginPath();
      ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.08)';
      ctx.lineWidth = radius - innerRadius;
      ctx.stroke();

      ctx.fillStyle = '#64748b';
      ctx.font = '600 14px Outfit, sans-serif';
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      ctx.fillText('No Vulnerabilities', centerX, centerY);
      return;
    }

    let startAngle = -Math.PI / 2;

    data.forEach(item => {
      if (item.value === 0) return;
      const sliceAngle = (item.value / total) * (Math.PI * 2);
      const endAngle = startAngle + sliceAngle;

      ctx.save();
      ctx.beginPath();
      ctx.arc(centerX, centerY, (radius + innerRadius) / 2, startAngle, endAngle);
      ctx.strokeStyle = item.color;
      ctx.lineWidth = radius - innerRadius - 4;
      ctx.shadowColor = item.glow;
      ctx.shadowBlur = 12;
      ctx.stroke();
      ctx.restore();

      startAngle = endAngle;
    });

    // Center Text
    ctx.fillStyle = '#ffffff';
    ctx.font = '700 24px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total.toString(), centerX, centerY - 6);

    ctx.fillStyle = '#94a3b8';
    ctx.font = '500 11px Outfit, sans-serif';
    ctx.fillText('TOTAL VULNS', centerX, centerY + 16);
  }

  /**
   * Renders Risk Score Circular SVG Gauge
   */
  static renderRiskGauge(score) {
    const circle = document.getElementById('riskGaugeVal');
    const label = document.getElementById('riskGaugeScore');
    const badge = document.getElementById('riskGaugeBadge');

    if (!circle || !label) return;

    // Circumference for r=70 is 2 * PI * 70 = 439.8
    const maxOffset = 440;
    const offset = maxOffset - (score / 100) * maxOffset;
    circle.style.strokeDashoffset = offset;

    let color = 'rgba(56, 189, 248, 0.4)';
    let text = 'STANDBY';

    if (score > 0) {
      color = '#10b981';
      text = 'LOW RISK';
      if (score >= 80) {
        color = '#ff3366';
        text = 'CRITICAL POSTURE';
      } else if (score >= 60) {
        color = '#ff7828';
        text = 'HIGH RISK';
      } else if (score >= 40) {
        color = '#f59e0b';
        text = 'MODERATE RISK';
      }
    }

    circle.style.stroke = color;
    label.textContent = score;
    label.style.color = color;

    if (badge) {
      badge.textContent = text;
      badge.style.color = color;
    }
  }

  /**
   * Top Vulnerable Assets Chart List
   */
  static renderTopVulnerableHosts(container, hosts) {
    if (!container) return;
    if (!hosts || hosts.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); font-size:0.8rem; text-align:center; padding:2rem 1rem;">No hosts cataloged yet.</div>';
      return;
    }
    const sorted = [...hosts].sort((a, b) => b.risk_score - a.risk_score).slice(0, 5);

    let html = '';
    sorted.forEach(h => {
      let riskColor = '#10b981';
      if (h.risk_score >= 80) riskColor = '#ff3366';
      else if (h.risk_score >= 60) riskColor = '#ff7828';
      else if (h.risk_score >= 40) riskColor = '#f59e0b';

      html += `
        <div class="top-host-item" style="display:flex; flex-direction:column; gap:0.35rem; margin-bottom:0.85rem; padding:0.6rem 0.8rem; background:rgba(15,23,42,0.5); border-radius:8px; border:1px solid rgba(255,255,255,0.05); cursor:pointer;" onclick="window.dashboardApp.openHostModal('${h.id}')">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span style="font-family:var(--font-mono); font-size:0.82rem; font-weight:600; color:#fff;">${h.ip}</span>
              <span style="font-size:0.75rem; color:var(--text-muted);">(${h.hostname})</span>
            </div>
            <span style="font-family:var(--font-mono); font-size:0.8rem; font-weight:700; color:${riskColor};">Risk: ${h.risk_score}/100</span>
          </div>
          <div style="display:flex; align-items:center; gap:0.5rem;">
            <div style="flex:1; height:6px; background:rgba(255,255,255,0.08); border-radius:99px; overflow:hidden; display:flex;">
              <div style="width:${(h.vuln_counts.critical / (h.vuln_counts.critical + h.vuln_counts.high + h.vuln_counts.medium + h.vuln_counts.low + 0.01)) * 100}%; background:#ff3366;"></div>
              <div style="width:${(h.vuln_counts.high / (h.vuln_counts.critical + h.vuln_counts.high + h.vuln_counts.medium + h.vuln_counts.low + 0.01)) * 100}%; background:#ff7828;"></div>
              <div style="width:${(h.vuln_counts.medium / (h.vuln_counts.critical + h.vuln_counts.high + h.vuln_counts.medium + h.vuln_counts.low + 0.01)) * 100}%; background:#f59e0b;"></div>
            </div>
            <span style="font-size:0.7rem; color:var(--text-dim); font-family:var(--font-mono);">${h.vuln_counts.critical} Crit / ${h.vuln_counts.high} High</span>
          </div>
        </div>
      `;
    });

    container.innerHTML = html;
  }

  /**
   * Most Exposed Ports Horizontal Bar
   */
  static renderPortDistribution(container, hosts) {
    if (!container) return;
    const portFreq = {};
    hosts.forEach(h => {
      (h.ports || []).forEach(p => {
        const key = `${p.port}/${p.proto.toUpperCase()} (${p.service.toUpperCase()})`;
        portFreq[key] = (portFreq[key] || 0) + 1;
      });
    });

    const sortedPorts = Object.entries(portFreq)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    const maxCount = sortedPorts.length > 0 ? sortedPorts[0][1] : 1;

    let html = '';
    sortedPorts.forEach(([name, count]) => {
      const pct = Math.round((count / maxCount) * 100);
      html += `
        <div style="margin-bottom:0.75rem;">
          <div style="display:flex; justify-content:space-between; font-size:0.78rem; margin-bottom:0.25rem;">
            <span style="font-family:var(--font-mono); color:#fff;">${name}</span>
            <span style="color:var(--accent-cyan); font-family:var(--font-mono);">${count} ${count === 1 ? 'host' : 'hosts'}</span>
          </div>
          <div style="height:6px; background:rgba(255,255,255,0.06); border-radius:99px; overflow:hidden;">
            <div style="width:${pct}%; height:100%; background:linear-gradient(90deg, #38bdf8, #818cf8); border-radius:99px;"></div>
          </div>
        </div>
      `;
    });

    if (sortedPorts.length === 0) {
      html = '<div style="color:var(--text-dim); font-size:0.8rem; text-align:center; padding:1rem;">No open ports indexed</div>';
    }

    container.innerHTML = html;
  }
}

if (typeof window !== 'undefined') {
  window.SOCCharts = SOCCharts;
}
