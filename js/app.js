/**
 * Main Application Controller for Nessus Office Network Security Dashboard
 */

class DashboardApp {
  constructor() {
    this.apiClient = new window.NessusApiClient();
    const saved = localStorage.getItem('active_nessus_scan');
    if (saved) {
      try {
        this.data = JSON.parse(saved);
      } catch (e) {
        this.data = window.OFFICE_NETWORK_MOCK;
      }
    } else {
      this.data = window.OFFICE_NETWORK_MOCK;
    }
    this.activeTab = 'overview';
    this.filterSeverity = 'all';
    this.filterSubnet = 'all';
    this.searchQuery = '';
    this.selectedHost = null;
    this.selectedVuln = null;

    this.init();
  }

  setScanData(scanData) {
    this.data = scanData;
    try {
      localStorage.setItem('active_nessus_scan', JSON.stringify(scanData));
    } catch (e) {
      console.warn('Scan data too large for localStorage');
    }
    this.render();
  }

  clearScanData() {
    localStorage.removeItem('active_nessus_scan');
    this.data = window.OFFICE_NETWORK_MOCK;
    this.render();
    this.showToast('Scan data cleared. Dashboard in standby.', 'info');
  }

  init() {
    this.bindEvents();
    this.updateConnectionStatusBadge();
    this.render();
  }

  bindEvents() {
    // Tab switching
    document.querySelectorAll('.nav-tab-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const tab = btn.dataset.tab;
        this.switchTab(tab);
      });
    });

    // File Drag & Drop
    const dropZone = document.getElementById('fileDropZone');
    const fileInput = document.getElementById('scanFileInput');

    if (dropZone && fileInput) {
      dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--accent-cyan)';
        dropZone.style.background = 'rgba(56, 189, 248, 0.08)';
      });

      dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-glass)';
        dropZone.style.background = 'transparent';
      });

      dropZone.addEventListener('drop', async (e) => {
        e.preventDefault();
        dropZone.style.borderColor = 'var(--border-glass)';
        dropZone.style.background = 'transparent';
        if (e.dataTransfer.files.length > 0) {
          await this.handleFileUpload(e.dataTransfer.files[0]);
        }
      });

      fileInput.addEventListener('change', async (e) => {
        if (e.target.files.length > 0) {
          await this.handleFileUpload(e.target.files[0]);
        }
      });
    }

    // Network Topology Search input
    const searchInput = document.getElementById('globalSearchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderNetworkTopology();
      });
      searchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.triggerHostSearch();
        }
      });
    }

    // Vulnerability Catalog Search input
    const vulnSearchInput = document.getElementById('vulnSearchInput');
    if (vulnSearchInput) {
      vulnSearchInput.addEventListener('input', (e) => {
        this.searchQuery = e.target.value.toLowerCase().trim();
        this.renderVulnTable();
      });
      vulnSearchInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.triggerVulnSearch();
        }
      });
    }

    // Severity Filters
    document.querySelectorAll('.filter-pill[data-severity]').forEach(pill => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill[data-severity]').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        this.filterSeverity = pill.dataset.severity;
        this.renderVulnTable();
      });
    });

    // Connection Form
    const connForm = document.getElementById('nessusApiConfigForm');
    if (connForm) {
      connForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        await this.handleSaveApiConfig();
      });
    }

    // Test API button
    const testBtn = document.getElementById('btnTestConnection');
    if (testBtn) {
      testBtn.addEventListener('click', async () => {
        await this.handleTestConnection();
      });
    }

    // Close Modals when clicking outside
    document.querySelectorAll('.modal-backdrop').forEach(modal => {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.closeAllModals();
        }
      });
    });

    // ESC key closes modals
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        this.closeAllModals();
      }
    });
  }

  switchTab(tabName) {
    this.activeTab = tabName;
    document.querySelectorAll('.nav-tab-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.tab === tabName);
    });

    document.querySelectorAll('.tab-view').forEach(view => {
      view.classList.toggle('active', view.id === `tab-${tabName}`);
    });

    if (tabName === 'overview') {
      this.renderCharts();
    }
  }

  async handleFileUpload(file) {
    try {
      this.showToast(`Parsing ${file.name}...`, 'info');
      const parsedData = await window.NessusFileParser.parseFile(file);
      this.setScanData(parsedData);
      this.showToast(`Loaded ${parsedData.hosts.length} hosts & ${parsedData.vulnerabilities.length} vulnerabilities from ${file.name}`, 'success');
      this.closeModal('importModal');
    } catch (err) {
      this.showToast(`Error parsing file: ${err.message}`, 'error');
    }
  }

  async handleSaveApiConfig() {
    const url = document.getElementById('cfgServerUrl').value;
    const accessKey = document.getElementById('cfgAccessKey').value;
    const secretKey = document.getElementById('cfgSecretKey').value;
    const useProxy = document.getElementById('cfgUseProxy').checked;
    const proxyUrl = document.getElementById('cfgProxyUrl').value;

    this.apiClient.saveConfig(url, accessKey, secretKey, useProxy, proxyUrl);
    this.updateConnectionStatusBadge();
    const displayUrl = document.getElementById('apiDisplayUrl');
    if (displayUrl) displayUrl.textContent = url;
    this.showToast('Nessus API configuration saved! Connecting...', 'success');
    this.closeModal('apiSettingsModal');
    await this.fetchRemoteScans();
  }

  async handleTestConnection() {
    const btn = document.getElementById('btnTestConnection');
    btn.disabled = true;
    btn.textContent = 'Testing connection...';

    const url = document.getElementById('cfgServerUrl').value;
    const accessKey = document.getElementById('cfgAccessKey').value;
    const secretKey = document.getElementById('cfgSecretKey').value;
    const useProxy = document.getElementById('cfgUseProxy').checked;
    const proxyUrl = document.getElementById('cfgProxyUrl').value;

    this.apiClient.saveConfig(url, accessKey, secretKey, useProxy, proxyUrl);

    try {
      const status = await this.apiClient.testConnection();
      this.showToast(`Successfully connected to Nessus! Server Status: ${status.status || 'OK'}`, 'success');
      this.updateConnectionStatusBadge(true);
      await this.fetchRemoteScans();
    } catch (err) {
      this.showToast(err.message, 'error');
      this.updateConnectionStatusBadge(false);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Test Connection';
    }
  }

  async fetchRemoteScans() {
    try {
      this.showToast('Fetching available scans from Nessus API...', 'info');
      const scansResponse = await this.apiClient.getScans();
      const scansList = scansResponse.scans || [];
      const selectElem = document.getElementById('liveScanSelect');
      
      if (selectElem) {
        selectElem.innerHTML = '';
        if (scansList.length === 0) {
          selectElem.innerHTML = '<option value="">No scans found on server</option>';
        } else {
          scansList.forEach(s => {
            const opt = document.createElement('option');
            opt.value = s.id;
            opt.textContent = `${s.name} [Status: ${s.status}] (${s.id})`;
            selectElem.appendChild(opt);
          });
        }
      }
      this.renderScanListTable(scansList);
    } catch (err) {
      this.showToast(`Failed to list scans: ${err.message}`, 'error');
    }
  }

  async loadSelectedScan() {
    const selectElem = document.getElementById('liveScanSelect');
    const scanId = selectElem?.value;
    if (!scanId) {
      this.showToast('Please select a scan first.', 'error');
      return;
    }

    try {
      this.showToast(`Fetching scan #${scanId} details...`, 'info');
      const scanDetails = await this.apiClient.getScanDetails(scanId);
      const transformed = this.apiClient.transformScanData(scanDetails);
      this.setScanData(transformed);
      this.showToast(`Successfully synced scan #${scanId} with dashboard!`, 'success');
      this.switchTab('overview');
    } catch (err) {
      this.showToast(`Failed loading scan: ${err.message}`, 'error');
    }
  }

  updateConnectionStatusBadge(forceOnline = null) {
    const badge = document.getElementById('apiStatusBadge');
    const dot = document.getElementById('apiStatusDot');
    const text = document.getElementById('apiStatusText');

    if (!badge || !dot || !text) return;

    if (forceOnline === true) {
      dot.className = 'status-dot online';
      text.textContent = 'Nessus API Connected';
    } else if (forceOnline === false) {
      dot.className = 'status-dot';
      text.textContent = 'API Offline';
    } else if (this.apiClient.isConfigured()) {
      dot.className = 'status-dot online';
      text.textContent = 'Configured (Live)';
    } else {
      dot.className = 'status-dot';
      text.textContent = 'Standby (Offline)';
    }
  }

  render() {
    this.renderHeaderMeta();
    this.renderMetrics();
    this.renderCharts();
    this.renderNetworkTopology();
    this.renderVulnTable();
    this.renderPacketStream();
  }

  renderHeaderMeta() {
    const scanName = document.getElementById('hdrScanName');
    const scanMeta = document.getElementById('hdrScanMeta');
    if (scanName) scanName.textContent = this.data.info.name || 'No Scan Data Loaded';
    if (scanMeta) {
      if (!this.data.hosts || this.data.hosts.length === 0) {
        scanMeta.textContent = 'Ready for live Nessus API synchronization or .nessus file import';
      } else {
        scanMeta.textContent = `Target: ${this.data.info.targets} | Scanner: ${this.data.info.scanner_name} | Latency: ${this.data.info.network_latency_avg}`;
      }
    }
  }

  renderMetrics() {
    const totalHosts = (this.data.hosts || []).length;
    const totalVulns = (this.data.vulnerabilities || []).length;
    
    let critCount = 0;
    let highCount = 0;
    let medCount = 0;

    (this.data.hosts || []).forEach(h => {
      critCount += h.vuln_counts.critical || 0;
      highCount += h.vuln_counts.high || 0;
      medCount += h.vuln_counts.medium || 0;
    });

    const elHosts = document.getElementById('metricTotalHosts');
    const elVulns = document.getElementById('metricTotalVulns');
    const elCrit = document.getElementById('metricCritVulns');
    const elHigh = document.getElementById('metricHighVulns');
    const elPackets = document.getElementById('metricTotalPackets');

    if (elHosts) elHosts.textContent = totalHosts;
    if (elVulns) elVulns.textContent = totalVulns;
    if (elCrit) elCrit.textContent = critCount;
    if (elHigh) elHigh.textContent = highCount;
    if (elPackets) elPackets.textContent = (this.data.info.total_packets_probed || 0).toLocaleString();

    // Critical Banner alert
    const alertStrip = document.getElementById('scanAlertStrip');
    const alertTitle = document.getElementById('alertStripTitle');
    const alertMsg = document.getElementById('alertStripMsg');

    if (alertStrip && alertTitle && alertMsg) {
      if (totalHosts === 0) {
        alertStrip.className = 'scan-alert-strip healthy';
        alertTitle.textContent = 'Dashboard Ready & Standing By';
        alertMsg.textContent = 'No scan data currently loaded. Import a .nessus file or sync from the Live Nessus API tab.';
      } else if (critCount > 0) {
        alertStrip.className = 'scan-alert-strip';
        alertTitle.textContent = `CRITICAL ACTION REQUIRED: ${critCount} Exploitable Vulnerabilities Found`;
        alertMsg.textContent = 'Immediate risk of remote compromise detected on office domain endpoints. Check the remediation roadmap.';
      } else {
        alertStrip.className = 'scan-alert-strip healthy';
        alertTitle.textContent = 'Office Network Security Posture Stable';
        alertMsg.textContent = 'No active critical severity vulnerabilities currently detected across scanned segments.';
      }
    }
  }

  renderCharts() {
    let counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    this.data.hosts.forEach(h => {
      counts.critical += h.vuln_counts.critical || 0;
      counts.high += h.vuln_counts.high || 0;
      counts.medium += h.vuln_counts.medium || 0;
      counts.low += h.vuln_counts.low || 0;
      counts.info += h.vuln_counts.info || 0;
    });

    const canvas = document.getElementById('sevDonutCanvas');
    if (canvas && window.SOCCharts) {
      window.SOCCharts.renderSeverityDonut(canvas, counts);
    }

    if (window.SOCCharts) {
      window.SOCCharts.renderRiskGauge(this.data.info.risk_score || 50);
      window.SOCCharts.renderTopVulnerableHosts(document.getElementById('topHostsContainer'), this.data.hosts);
      window.SOCCharts.renderPortDistribution(document.getElementById('portDistContainer'), this.data.hosts);
    }
  }

  triggerHostSearch() {
    const input = document.getElementById('globalSearchInput');
    if (input) {
      this.searchQuery = input.value.toLowerCase().trim();
      this.renderNetworkTopology();
      if (!this.data.hosts || this.data.hosts.length === 0) {
        this.showToast('No network hosts loaded yet. Import a .nessus file or connect the API to search live assets.', 'info');
      }
    }
  }

  triggerVulnSearch() {
    const input = document.getElementById('vulnSearchInput');
    if (input) {
      this.searchQuery = input.value.toLowerCase().trim();
      this.renderVulnTable();
      if (!this.data.vulnerabilities || this.data.vulnerabilities.length === 0) {
        this.showToast('No vulnerabilities cataloged yet. Import a .nessus file or connect the API to search findings.', 'info');
      }
    }
  }

  renderNetworkTopology() {
    const container = document.getElementById('networkSubnetsContainer');
    if (!container) return;

    if (!this.data.hosts || this.data.hosts.length === 0) {
      container.innerHTML = `
        <div style="grid-column: 1 / -1; text-align:center; padding:3.5rem 1.5rem; background:rgba(15,23,42,0.4); border-radius:12px; border:1px dashed var(--border-glass);">
          <div style="font-size:3rem; margin-bottom:1rem;">🌐</div>
          <h4 style="font-size:1.15rem; font-weight:700; color:#fff; margin-bottom:0.4rem;">No Office Network Assets Loaded</h4>
          <p style="font-size:0.85rem; max-width:480px; margin:0 auto 1.5rem auto; color:var(--text-dim);">
            Connect your Nessus scanner to synchronize discovered office subnets and host machines, or import your .nessus export file.
          </p>
          <div style="display:flex; justify-content:center; gap:0.85rem; flex-wrap:wrap;">
            <button class="btn btn-primary btn-sm" onclick="window.dashboardApp.openImportModal()">📁 Import .nessus File</button>
            <button class="btn btn-secondary btn-sm" onclick="window.dashboardApp.switchTab('api-controller')">⚡ Live Nessus API</button>
          </div>
        </div>
      `;
      return;
    }

    let subnets = this.data.subnets || [];
    if (subnets.length === 0) {
      // Group dynamically if missing
      const set = {};
      this.data.hosts.forEach(h => {
        set[h.subnet] = (set[h.subnet] || 0) + 1;
      });
      subnets = Object.keys(set).map(cidr => ({ cidr, name: cidr, total_hosts: set[cidr], critical_vulns: 0 }));
    }

    let html = '';

    subnets.forEach(sub => {
      let matchingHosts = this.data.hosts.filter(h => h.subnet === sub.cidr);
      if (this.searchQuery) {
        matchingHosts = matchingHosts.filter(h => 
          h.ip.toLowerCase().includes(this.searchQuery) ||
          h.hostname.toLowerCase().includes(this.searchQuery) ||
          h.os.toLowerCase().includes(this.searchQuery)
        );
      }

      if (matchingHosts.length === 0 && this.searchQuery) return;

      const subCritCount = matchingHosts.reduce((acc, h) => acc + h.vuln_counts.critical, 0);

      html += `
        <div class="subnet-card">
          <div class="subnet-header">
            <div class="subnet-title">
              <span style="font-size:1.15rem;">🖧</span>
              <div>
                <h4>${sub.name}</h4>
                <div style="font-size:0.75rem; color:var(--text-dim);">${sub.description || ''}</div>
              </div>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span class="subnet-badge">${sub.cidr}</span>
              ${subCritCount > 0 ? `<span class="sev-badge critical">${subCritCount} CRIT</span>` : ''}
            </div>
          </div>
          <div class="host-nodes-grid">
            ${matchingHosts.map(h => this.renderHostCard(h)).join('')}
          </div>
        </div>
      `;
    });

    if (!html) {
      html = '<div style="color:var(--text-dim); padding:2rem; text-align:center;">No network hosts matching search criteria.</div>';
    }

    container.innerHTML = html;
  }

  renderHostCard(host) {
    let icon = '🖥️';
    if (host.category === 'server') icon = '🖧';
    else if (host.category === 'domain-controller') icon = '🏛️';
    else if (host.category === 'firewall') icon = '🛡️';
    else if (host.category === 'iot') icon = '🖨️';

    let cardClass = 'host-node-card clean-host';
    let vulnBadge = `<span class="host-vuln-indicator" style="background:var(--success-bg); color:var(--success-color);">Clean</span>`;

    if (host.vuln_counts.critical > 0) {
      cardClass = 'host-node-card critical-host';
      vulnBadge = `<span class="host-vuln-indicator" style="background:var(--crit-bg); color:var(--crit-color);">${host.vuln_counts.critical} Crit</span>`;
    } else if (host.vuln_counts.high > 0) {
      cardClass = 'host-node-card high-host';
      vulnBadge = `<span class="host-vuln-indicator" style="background:var(--high-bg); color:var(--high-color);">${host.vuln_counts.high} High</span>`;
    }

    const portsHtml = (host.ports || []).slice(0, 3).map(p => 
      `<span class="port-tag">:${p.port}</span>`
    ).join('');

    return `
      <div class="${cardClass}" onclick="window.dashboardApp.openHostModal('${host.id}')" title="Click to inspect ${host.ip}">
        <div class="host-icon-row">
          <span class="host-device-icon">${icon}</span>
          ${vulnBadge}
        </div>
        <div class="host-ip">${host.ip}</div>
        <div class="host-name">${host.hostname}</div>
        <div class="host-ports-snippet">${portsHtml}${(host.ports || []).length > 3 ? `<span class="port-tag">+${host.ports.length - 3}</span>` : ''}</div>
      </div>
    `;
  }

  renderVulnTable() {
    const tbody = document.getElementById('vulnTableBody');
    if (!tbody) return;

    if (!this.data.vulnerabilities || this.data.vulnerabilities.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:3.5rem 1rem; color:var(--text-dim);">
            <div style="font-size:2.5rem; margin-bottom:0.75rem;">🛡️</div>
            <div style="font-size:1.05rem; font-weight:600; color:#fff; margin-bottom:0.35rem;">No Vulnerabilities to Display</div>
            <div style="font-size:0.82rem; color:var(--text-dim); max-width:440px; margin:0 auto 1.25rem auto;">
              No vulnerabilities currently loaded. Connect your live Nessus API or import a .nessus file to catalog security findings.
            </div>
            <button class="btn btn-primary btn-sm" onclick="window.dashboardApp.openImportModal()">📁 Import .nessus File</button>
          </td>
        </tr>
      `;
      return;
    }

    let list = [...this.data.vulnerabilities];

    // Filter by severity
    if (this.filterSeverity !== 'all') {
      list = list.filter(v => v.severity.toLowerCase() === this.filterSeverity);
    }

    // Filter by search query
    if (this.searchQuery) {
      list = list.filter(v => 
        v.name.toLowerCase().includes(this.searchQuery) ||
        v.cve.toLowerCase().includes(this.searchQuery) ||
        v.family.toLowerCase().includes(this.searchQuery) ||
        v.plugin_id.toString().includes(this.searchQuery) ||
        v.affected_hosts.some(h => h.toLowerCase().includes(this.searchQuery))
      );
    }

    if (list.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:2rem; color:var(--text-dim);">No vulnerabilities found matching filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(v => {
      const exploitBadge = v.exploit_available ? 
        `<span class="exploit-badge">⚠️ EXPLOITABLE</span>` : 
        `<span style="color:var(--text-dim); font-size:0.75rem;">None</span>`;

      return `
        <tr onclick="window.dashboardApp.openVulnModal(${v.plugin_id})">
          <td><span style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${v.plugin_id}</span></td>
          <td>
            <div style="font-weight:600; color:#fff;">${v.name}</div>
            <div style="font-size:0.75rem; color:var(--text-dim);">${v.synopsis.slice(0, 90)}...</div>
          </td>
          <td><span class="sev-badge ${v.severity}">${v.severity}</span></td>
          <td><span style="font-family:var(--font-mono); font-weight:700; color:#fff;">${v.cvss3_score.toFixed(1)}</span></td>
          <td><span style="font-family:var(--font-mono); font-size:0.8rem; color:${v.cve !== 'N/A' ? 'var(--accent-purple)' : 'var(--text-dim)'};">${v.cve}</span></td>
          <td>${exploitBadge}</td>
          <td><span style="font-family:var(--font-mono); color:var(--text-muted);">${v.affected_hosts.length}</span></td>
        </tr>
      `;
    }).join('');
  }

  renderPacketStream() {
    const container = document.getElementById('packetStreamFeed');
    if (!container) return;

    const logs = this.data.packet_logs || [];
    if (logs.length === 0) {
      container.innerHTML = `
        <div style="text-align:center; color:var(--text-dim); padding:3rem 1rem; background:rgba(15,23,42,0.4); border-radius:8px; border:1px dashed var(--border-glass);">
          <div style="font-size:2rem; margin-bottom:0.5rem;">📦</div>
          <div style="font-size:0.95rem; font-weight:600; color:#fff; margin-bottom:0.35rem;">No Packet Traces Recorded</div>
          <div style="font-size:0.8rem; color:var(--text-dim);">Packet capture traces will populate once an active scan session is loaded.</div>
        </div>
      `;
      return;
    }

    container.innerHTML = logs.map(p => {
      const protoClass = p.proto === 'TCP' ? 'proto-tcp' : (p.proto === 'UDP' ? 'proto-udp' : 'proto-icmp');
      return `
        <div class="packet-card">
          <div style="display:flex; align-items:center; gap:0.75rem;">
            <span style="color:var(--text-dim); font-size:0.75rem;">${p.time}</span>
            <span class="packet-proto ${protoClass}">${p.proto}</span>
            <div class="packet-ips">
              <span>${p.src}</span>
              <span class="packet-arrow">➔</span>
              <span style="color:var(--accent-cyan); font-weight:600;">${p.dst}</span>
            </div>
          </div>
          <div style="display:flex; align-items:center; gap:0.85rem;">
            <span style="color:var(--text-muted); font-size:0.75rem;">${p.info}</span>
            <span style="padding:0.15rem 0.4rem; background:rgba(255,255,255,0.05); border-radius:4px; font-size:0.7rem; color:var(--text-dim);">${p.length}</span>
          </div>
        </div>
      `;
    }).join('');
  }

  renderScanListTable(scans) {
    const container = document.getElementById('nessusScanListTableBody');
    if (!container) return;

    if (!scans || scans.length === 0) {
      container.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:1.5rem; color:var(--text-dim);">No scans currently listed.</td></tr>`;
      return;
    }

    container.innerHTML = scans.map(s => `
      <tr>
        <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${s.id}</td>
        <td style="font-weight:600; color:#fff;">${s.name}</td>
        <td><span class="sev-badge ${s.status === 'completed' ? 'low' : 'info'}">${s.status}</span></td>
        <td style="font-size:0.75rem; color:var(--text-muted);">${s.last_modification_date ? new Date(s.last_modification_date * 1000).toLocaleString() : 'N/A'}</td>
        <td>
          <button class="btn btn-sm btn-secondary" onclick="window.dashboardApp.loadScanById(${s.id})">Load to Dashboard</button>
        </td>
      </tr>
    `).join('');
  }

  async loadScanById(scanId) {
    const selectElem = document.getElementById('liveScanSelect');
    if (selectElem) selectElem.value = scanId;
    await this.loadSelectedScan();
  }

  /* Host Modal Inspector */
  openHostModal(hostId) {
    const host = this.data.hosts.find(h => h.id === hostId);
    if (!host) return;

    this.selectedHost = host;
    const modal = document.getElementById('hostDetailModal');
    if (!modal) return;

    document.getElementById('mHostIp').textContent = host.ip;
    document.getElementById('mHostName').textContent = host.hostname;
    document.getElementById('mHostFqdn').textContent = host.fqdn || 'N/A';
    document.getElementById('mHostMac').textContent = host.mac || 'N/A';
    document.getElementById('mHostOs').textContent = host.os;
    document.getElementById('mHostSubnet').textContent = host.subnet;
    document.getElementById('mHostRisk').textContent = `${host.risk_score} / 100`;

    // Render open ports
    const portsList = document.getElementById('mHostPortsList');
    if (portsList) {
      if ((host.ports || []).length === 0) {
        portsList.innerHTML = '<div style="color:var(--text-dim); padding:0.5rem;">No open ports cataloged.</div>';
      } else {
        portsList.innerHTML = host.ports.map(p => `
          <div style="display:flex; align-items:center; justify-content:space-between; padding:0.5rem 0.75rem; background:rgba(15,23,42,0.6); border-radius:6px; margin-bottom:0.4rem; font-family:var(--font-mono); font-size:0.8rem;">
            <div>
              <span style="font-weight:700; color:#fff;">Port ${p.port}/${p.proto.toUpperCase()}</span>
              <span style="color:var(--accent-cyan); margin-left:0.5rem;">[${p.service}]</span>
            </div>
            <span style="color:var(--text-dim); font-size:0.75rem;">${p.banner || ''}</span>
          </div>
        `).join('');
      }
    }

    // Render Host Vulnerabilities
    const vulnsList = document.getElementById('mHostVulnsList');
    if (vulnsList) {
      const hostVulns = this.data.vulnerabilities.filter(v => 
        (host.vuln_ids && host.vuln_ids.includes(v.plugin_id)) ||
        v.affected_hosts.some(ah => ah.includes(host.ip))
      );

      if (hostVulns.length === 0) {
        vulnsList.innerHTML = '<div style="color:var(--success-color); padding:0.5rem;">No vulnerabilities detected on this endpoint!</div>';
      } else {
        vulnsList.innerHTML = hostVulns.map(v => `
          <div style="display:flex; align-items:center; justify-content:space-between; padding:0.6rem 0.85rem; background:rgba(15,23,42,0.6); border-radius:6px; margin-bottom:0.4rem; cursor:pointer;" onclick="window.dashboardApp.openVulnModal(${v.plugin_id})">
            <div>
              <div style="font-weight:600; color:#fff; font-size:0.85rem;">${v.name}</div>
              <div style="font-size:0.75rem; color:var(--text-dim); font-family:var(--font-mono);">Plugin #${v.plugin_id} | CVE: ${v.cve}</div>
            </div>
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span class="sev-badge ${v.severity}">${v.severity}</span>
              ${v.exploit_available ? `<span class="exploit-badge">EXPLOIT</span>` : ''}
            </div>
          </div>
        `).join('');
      }
    }

    modal.classList.add('open');
  }

  /* Vulnerability Modal Inspector */
  openVulnModal(pluginId) {
    const vuln = this.data.vulnerabilities.find(v => v.plugin_id === pluginId);
    if (!vuln) return;

    this.selectedVuln = vuln;
    const modal = document.getElementById('vulnDetailModal');
    if (!modal) return;

    document.getElementById('mVulnName').textContent = vuln.name;
    document.getElementById('mVulnPluginId').textContent = vuln.plugin_id;
    document.getElementById('mVulnSevBadge').className = `sev-badge ${vuln.severity}`;
    document.getElementById('mVulnSevBadge').textContent = vuln.severity.toUpperCase();
    document.getElementById('mVulnCvss').textContent = vuln.cvss3_score.toFixed(1);
    document.getElementById('mVulnVpr').textContent = vuln.vpr_score.toFixed(1);
    document.getElementById('mVulnCve').textContent = vuln.cve;
    document.getElementById('mVulnFamily').textContent = vuln.family;
    document.getElementById('mVulnSynopsis').textContent = vuln.synopsis;
    document.getElementById('mVulnDesc').textContent = vuln.description;
    document.getElementById('mVulnSolution').textContent = vuln.solution;

    // Exploit info
    const exploitContainer = document.getElementById('mVulnExploitInfo');
    if (exploitContainer) {
      if (vuln.exploit_available) {
        exploitContainer.innerHTML = `
          <div style="padding:0.75rem 1rem; background:rgba(255,51,102,0.12); border:1px solid rgba(255,51,102,0.4); border-radius:6px; color:#ff3366; font-size:0.85rem;">
            <strong>⚠️ Public Exploit Available!</strong> Frameworks: ${(vuln.exploit_frameworks || []).join(', ') || 'Metasploit / PoC'}
          </div>
        `;
      } else {
        exploitContainer.innerHTML = `<span style="color:var(--text-dim); font-size:0.8rem;">No known public exploit frameworks registered for this plugin.</span>`;
      }
    }

    // Packet Evidence
    const packetBox = document.getElementById('mVulnPacketEvidence');
    if (packetBox) {
      packetBox.textContent = vuln.packet_evidence || 'Standard network probe response verified.';
    }

    // Affected hosts
    const affectedContainer = document.getElementById('mVulnAffectedHosts');
    if (affectedContainer) {
      affectedContainer.innerHTML = vuln.affected_hosts.map(ah => `
        <span style="font-family:var(--font-mono); font-size:0.8rem; padding:0.25rem 0.6rem; background:rgba(255,255,255,0.06); border-radius:4px; color:#fff;">
          ${ah}
        </span>
      `).join(' ');
    }

    modal.classList.add('open');
  }

  closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) modal.classList.remove('open');
  }

  closeAllModals() {
    document.querySelectorAll('.modal-backdrop').forEach(m => m.classList.remove('open'));
  }

  openApiSettings() {
    // Populate form with current values
    document.getElementById('cfgServerUrl').value = this.apiClient.serverUrl;
    document.getElementById('cfgAccessKey').value = this.apiClient.accessKey;
    document.getElementById('cfgSecretKey').value = this.apiClient.secretKey;
    document.getElementById('cfgUseProxy').checked = this.apiClient.useProxy;
    document.getElementById('cfgProxyUrl').value = this.apiClient.proxyUrl;

    const modal = document.getElementById('apiSettingsModal');
    if (modal) modal.classList.add('open');
  }

  openImportModal() {
    const modal = document.getElementById('importModal');
    if (modal) modal.classList.add('open');
  }

  openPcapImportModal() {
    const modal = document.getElementById('pcapImportModal');
    if (modal) modal.classList.add('open');
  }

  exportReport() {
    window.print();
  }

  exportCSV() {
    const headers = ['Plugin ID', 'Name', 'Severity', 'CVSS', 'CVE', 'Exploit Available', 'Affected Hosts'];
    const rows = this.data.vulnerabilities.map(v => [
      v.plugin_id,
      `"${v.name.replace(/"/g, '""')}"`,
      v.severity,
      v.cvss3_score,
      v.cve,
      v.exploit_available ? 'YES' : 'NO',
      `"${v.affected_hosts.join('; ')}"`
    ]);

    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `nessus_office_report_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }

  showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    let icon = 'ℹ️';
    if (type === 'success') icon = '✅';
    if (type === 'error') icon = '❌';

    toast.innerHTML = `<span>${icon}</span><span>${message}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }
}

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
  window.dashboardApp = new DashboardApp();
  if (window.WiresharkViewer) {
    window.wiresharkViewer = new window.WiresharkViewer();
  }
});
