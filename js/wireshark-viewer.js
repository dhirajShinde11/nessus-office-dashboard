/**
 * Wireshark Packet Capture & Web/User Intelligence Module
 * 
 * Features:
 * 1. Track which websites & applications are being visited across the office network
 * 2. Attribute traffic to specific users/devices (Source IP & Hostname)
 * 3. Categorize web traffic & applications (Media, Developer, O365, Cloud, Social, Finance)
 * 4. Human-readable easy-to-read recorded activity cards & bandwidth distribution meters
 * 5. User-to-Site Matrix & Deep Dives
 * 6. Wireshark 3-Pane Dissector (Packet Grid, Protocol Tree, Hex Dump)
 * 7. Native binary .pcap / .pcapng file parsing with DNS & TLS SNI extraction
 * 8. Live network sniffing simulation & packet tracking
 */

class WiresharkViewer {
  constructor() {
    this.packets = [];
    this.selectedPacket = null;
    this.activeFilter = '';
    this.activeSubtab = 'web'; // 'web', 'matrix', or 'dissector'
    this.appViewMode = 'cards'; // 'cards' or 'table'
    this.streamViewMode = 'cards'; // 'cards' or 'table'
    this.isCapturing = false;
    this.captureInterval = null;

    // Web & User Intelligence Aggregates
    this.siteStats = new Map(); // domain -> { domain, category, hits, bytes, users: Set, lastSeen }
    this.userStats = new Map(); // ip -> { ip, hostname, totalHits, totalBytes, sites: Map, apps: Map, lastSeen }
    this.appStats = new Map();  // appKey -> { key, name, domain, icon, color, category, isWork, totalBytes, totalHits, users: Map, lastSeen }
    this.webLogs = [];          // list of { id, pktNum, time, userIp, userName, domain, app, humanDesc, impact, category, proto, bytes, info }

    this.filterUser = 'all';
    this.filterDomain = 'all';
    this.filterApp = 'all';
    this.webSearchQuery = '';

    this.init();
  }

  init() {
    this.bindEvents();
    // Default to clean zero-state standby mode
    this.renderWebActivityView();
    this.renderPacketList();
  }

  bindEvents() {
    // Filter input for raw packet dissector
    const filterInput = document.getElementById('wsFilterInput');
    if (filterInput) {
      filterInput.addEventListener('input', (e) => {
        this.activeFilter = e.target.value.toLowerCase().trim();
        this.renderPacketList();
      });
      filterInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.applyFilter(filterInput.value);
        }
      });
    }

    // Web Activity Search
    const webSearch = document.getElementById('wsWebSearchInput');
    if (webSearch) {
      webSearch.addEventListener('input', (e) => {
        this.webSearchQuery = e.target.value.toLowerCase().trim();
        this.renderWebActivityView();
        if (this.activeSubtab === 'matrix') {
          this.renderUserMatrixTable();
        }
      });
      webSearch.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          this.triggerWebSearch();
        }
      });
    }

    // Wireshark PCAP File Drag and Drop
    const pcapDrop = document.getElementById('wsPcapDropZone');
    const pcapFile = document.getElementById('wsPcapFileInput');

    if (pcapDrop && pcapFile) {
      pcapDrop.addEventListener('dragover', (e) => {
        e.preventDefault();
        pcapDrop.style.borderColor = 'var(--accent-cyan)';
      });
      pcapDrop.addEventListener('dragleave', (e) => {
        e.preventDefault();
        pcapDrop.style.borderColor = 'var(--border-glass)';
      });
      pcapDrop.addEventListener('drop', async (e) => {
        e.preventDefault();
        pcapDrop.style.borderColor = 'var(--border-glass)';
        if (e.dataTransfer.files.length > 0) {
          await this.loadPcapFile(e.dataTransfer.files[0]);
        }
      });
      pcapFile.addEventListener('change', async (e) => {
        if (e.target.files.length > 0) {
          await this.loadPcapFile(e.target.files[0]);
        }
      });
    }
  }

  toggleAppViewMode(mode) {
    this.appViewMode = mode;
    const btnApps = document.getElementById('btnViewApps');
    const btnSites = document.getElementById('btnViewSites');
    const containerCards = document.getElementById('wsAppCardsContainer');
    const containerTable = document.getElementById('wsSitesTableContainer');

    if (btnApps && btnSites && containerCards && containerTable) {
      btnApps.classList.toggle('active', mode === 'cards');
      btnSites.classList.toggle('active', mode === 'table');
      containerCards.style.display = mode === 'cards' ? 'flex' : 'none';
      containerTable.style.display = mode === 'table' ? 'block' : 'none';
    }
  }

  toggleStreamViewMode(mode) {
    this.streamViewMode = mode;
    const btnCards = document.getElementById('btnStreamCards');
    const btnTable = document.getElementById('btnStreamTable');
    const containerCards = document.getElementById('wsReadableCardsContainer');
    const containerTable = document.getElementById('wsWebLogsTableContainer');

    if (btnCards && btnTable && containerCards && containerTable) {
      btnCards.className = mode === 'cards' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
      btnTable.className = mode === 'table' ? 'btn btn-sm btn-primary' : 'btn btn-sm btn-secondary';
      containerCards.style.display = mode === 'cards' ? 'flex' : 'none';
      containerTable.style.display = mode === 'table' ? 'block' : 'none';
    }
  }

  switchSubtab(tabName) {
    this.activeSubtab = tabName;
    const btnWeb = document.getElementById('wsSubtabWeb');
    const btnMatrix = document.getElementById('wsSubtabMatrix');
    const btnDissector = document.getElementById('wsSubtabDissector');
    const viewWeb = document.getElementById('wsViewWeb');
    const viewMatrix = document.getElementById('wsViewMatrix');
    const viewDissector = document.getElementById('wsViewDissector');

    if (btnWeb) btnWeb.classList.toggle('active', tabName === 'web');
    if (btnMatrix) btnMatrix.classList.toggle('active', tabName === 'matrix');
    if (btnDissector) btnDissector.classList.toggle('active', tabName === 'dissector');

    if (viewWeb) viewWeb.style.display = tabName === 'web' ? 'block' : 'none';
    if (viewMatrix) viewMatrix.style.display = tabName === 'matrix' ? 'block' : 'none';
    if (viewDissector) viewDissector.style.display = tabName === 'dissector' ? 'block' : 'none';

    if (tabName === 'web') {
      this.renderWebActivityView();
    } else if (tabName === 'matrix') {
      this.renderUserMatrixTable();
    } else {
      this.renderPacketList();
    }
  }

  /**
   * Application Recognition Engine
   * Maps domain names and protocols to recognizable apps and human-readable descriptions
   */
  resolveApplication(domain, pktInfo = '') {
    const clean = (domain || '').replace(/^https?:\/\//i, '').split('/')[0].split(':')[0].trim();
    const d = clean.toLowerCase();
    
    if (d.includes('youtube') || d.includes('googlevideo') || d.includes('ytimg')) {
      return {
        key: 'youtube',
        name: 'YouTube',
        subtitle: 'Video & Audio Streaming',
        icon: '▶️',
        color: '#ff0000',
        category: 'Media & Streaming',
        isWork: false,
        describe: (b) => `Streaming high-definition video segment (${this.formatBytes(b)} via TLSv1.3)`
      };
    }
    if (d.includes('github') || d.includes('gitlab')) {
      return {
        key: 'github',
        name: 'GitHub',
        subtitle: 'Source Code & DevOps',
        icon: '💻',
        color: '#818cf8',
        category: 'Developer & Code',
        isWork: true,
        describe: (b) => `Git repository commit synchronization & code push (${this.formatBytes(b)})`
      };
    }
    if (d.includes('mail.google.com') || d.includes('gmail') || (d.includes('google.com') && !d.includes('video'))) {
      return {
        key: 'google-workspace',
        name: 'Google Workspace & Gmail',
        subtitle: 'Corporate Email & Cloud Docs',
        icon: '📧',
        color: '#38bdf8',
        category: 'Google Workspace',
        isWork: true,
        describe: (b) => `Checking corporate Gmail & synchronizing Google Workspace documents`
      };
    }
    if (d.includes('microsoft') || d.includes('office') || d.includes('live.com') || d.includes('outlook')) {
      return {
        key: 'microsoft-365',
        name: 'Microsoft 365',
        subtitle: 'Office Cloud & Outlook SSO',
        icon: '🟦',
        color: '#0284c7',
        category: 'Office 365 / Cloud',
        isWork: true,
        describe: (b) => `Authenticating to Microsoft 365 cloud portal & OneDrive sync`
      };
    }
    if (d.includes('slack') || d.includes('teams') || d.includes('zoom') || d.includes('discord')) {
      return {
        key: 'slack-teams',
        name: 'Slack / Microsoft Teams',
        subtitle: 'Team Collaboration & Chat',
        icon: '💬',
        color: '#06b6d4',
        category: 'Chat & Meetings',
        isWork: true,
        describe: (b) => `Sending real-time team chat messages & channel presence heartbeat`
      };
    }
    if (d.includes('aws') || d.includes('amazon') || d.includes('azure') || d.includes('cloudflare')) {
      return {
        key: 'aws-cloud',
        name: 'AWS Cloud Console',
        subtitle: 'Cloud Infrastructure & API',
        icon: '☁️',
        color: '#f59e0b',
        category: 'Cloud Infrastructure',
        isWork: true,
        describe: (b) => `Querying AWS cloud management console & cloud infrastructure APIs`
      };
    }
    if (d.includes('netflix') || d.includes('spotify') || d.includes('twitch') || d.includes('prime')) {
      return {
        key: 'netflix',
        name: 'Netflix / Entertainment',
        subtitle: 'Ultra-HD Video Streaming',
        icon: '🎬',
        color: '#e50914',
        category: 'Media & Streaming',
        isWork: false,
        describe: (b) => `Streaming Ultra-HD high-bandwidth media content buffer`
      };
    }
    if (d.includes('quickbooks') || d.includes('chase') || d.includes('bank') || d.includes('stripe')) {
      return {
        key: 'finance-banking',
        name: 'QuickBooks & Corporate Banking',
        subtitle: 'Finance, Ledger & Invoicing',
        icon: '💳',
        color: '#10b981',
        category: 'Finance & Banking',
        isWork: true,
        describe: (b) => `Accessing secure corporate accounting ledger & banking portal`
      };
    }
    if (d.includes('linkedin') || d.includes('twitter') || d.includes('facebook') || d.includes('instagram')) {
      return {
        key: 'linkedin-social',
        name: 'LinkedIn / Social Media',
        subtitle: 'Professional Social Network',
        icon: '📱',
        color: '#0a66c2',
        category: 'Social & Marketing',
        isWork: false,
        describe: (b) => `Social feed browsing & networking profile synchronization`
      };
    }
    if (d.includes('8834') || d.includes('nessus')) {
      return {
        key: 'nessus-scanner',
        name: 'Tenable Nessus Scanner',
        subtitle: 'Security Vulnerability Engine',
        icon: '🛡️',
        color: '#a855f7',
        category: 'Nessus Telemetry',
        isWork: true,
        describe: (b) => `Tenable Nessus vulnerability scan probe & REST API sync on port 8834`
      };
    }
    if (d.includes('stackoverflow') || d.includes('npm') || d.includes('docker')) {
      return {
        key: 'dev-tools',
        name: 'Developer Community & NPM',
        subtitle: 'Package Downloads & Q&A',
        icon: '⚙️',
        color: '#6366f1',
        category: 'Developer & Code',
        isWork: true,
        describe: (b) => `Developer documentation query & node module package download`
      };
    }

    // Default Web Destination
    const displayName = clean || domain || 'Unknown Host';
    return {
      key: clean || domain,
      name: displayName,
      subtitle: 'Web Destination',
      icon: '🌐',
      color: '#94a3b8',
      category: 'General Web',
      isWork: true,
      describe: (b) => `Web traffic session to ${displayName} (${this.formatBytes(b)})`
    };
  }

  categorizeDomain(domain) {
    const app = this.resolveApplication(domain);
    return { name: app.category, color: app.color, icon: app.icon };
  }

  resolveUser(ip) {
    if (ip === '10.101.133.29') return 'My PC (Hotspot Client)';
    if (ip === '10.101.133.176') return 'Mobile Hotspot Gateway';
    if (ip === '10.101.133.45') return 'Dev Lead (Ubuntu Linux)';
    if (ip === '10.101.133.88') return 'Finance Admin (Win 11)';
    if (ip === '10.101.133.112') return 'Marketing Mac (macOS Sonoma)';
    if (ip === '127.0.0.1') return 'Localhost Scanner';
    
    // Correlate with active Nessus scan data if loaded
    if (window.dashboardApp?.data?.hosts) {
      const match = window.dashboardApp.data.hosts.find(h => h.ip === ip);
      if (match) return `${match.hostname} (${match.category || 'Asset'})`;
    }
    return `Client (${ip})`;
  }

  formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    else if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    else if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
    return (bytes / 1073741824).toFixed(2) + ' GB';
  }

  /**
   * Load realistic office multi-user trace on-demand
   */
  loadSampleOfficeTrace() {
    this.clearPackets(false);

    const sampleUsers = [
      { ip: '10.101.133.29', name: 'My PC (Hotspot Client)' },
      { ip: '10.101.133.45', name: 'Dev Lead (Ubuntu Linux)' },
      { ip: '10.101.133.88', name: 'Finance Admin (Win 11)' },
      { ip: '10.101.133.112', name: 'Marketing Mac (macOS Sonoma)' },
      { ip: '10.101.133.176', name: 'Mobile Hotspot Gateway' },
      { ip: '127.0.0.1', name: 'Localhost Scanner' }
    ];

    const sampleFlows = [
      { user: sampleUsers[0], domain: 'youtube.com', proto: 'TLS', len: 1420, hits: 32, info: 'ClientHello SNI: youtube.com [Video Stream Segment]' },
      { user: sampleUsers[0], domain: 'github.com', proto: 'TLS', len: 840, hits: 24, info: 'Application Data [TLSv1.3 Encrypted Session: github.com]' },
      { user: sampleUsers[0], domain: 'mail.google.com', proto: 'TLS', len: 620, hits: 18, info: 'ClientHello SNI: mail.google.com [Gmail Sync]' },
      { user: sampleUsers[0], domain: 'localhost:8834', proto: 'TLS', len: 320, hits: 28, info: 'Tenable Nessus REST API [/scans/7/export]' },
      
      { user: sampleUsers[1], domain: 'stackoverflow.com', proto: 'TLS', len: 540, hits: 22, info: 'ClientHello SNI: stackoverflow.com' },
      { user: sampleUsers[1], domain: 'github.com', proto: 'TLS', len: 980, hits: 36, info: 'git push origin main [TLSv1.3 github.com]' },
      { user: sampleUsers[1], domain: 'aws.amazon.com', proto: 'TLS', len: 1200, hits: 15, info: 'ClientHello SNI: console.aws.amazon.com' },
      { user: sampleUsers[1], domain: 'registry.npmjs.org', proto: 'TLS', len: 480, hits: 40, info: 'npm install payload download [registry.npmjs.org]' },

      { user: sampleUsers[2], domain: 'login.microsoftonline.com', proto: 'TLS', len: 610, hits: 25, info: 'ClientHello SNI: login.microsoftonline.com [O365 Auth]' },
      { user: sampleUsers[2], domain: 'quickbooks.intuit.com', proto: 'TLS', len: 890, hits: 19, info: 'ClientHello SNI: quickbooks.intuit.com' },
      { user: sampleUsers[2], domain: 'chase.com', proto: 'TLS', len: 740, hits: 8, info: 'ClientHello SNI: secure.chase.com [Corporate Banking]' },

      { user: sampleUsers[3], domain: 'canva.com', proto: 'TLS', len: 1400, hits: 30, info: 'ClientHello SNI: canva.com [Asset Download]' },
      { user: sampleUsers[3], domain: 'linkedin.com', proto: 'TLS', len: 720, hits: 14, info: 'ClientHello SNI: www.linkedin.com' },
      { user: sampleUsers[3], domain: 'slack.com', proto: 'TLS', len: 380, hits: 42, info: 'WebSocket Heartbeat [wss://slack.com]' },
      { user: sampleUsers[3], domain: 'youtube.com', proto: 'TLS', len: 1350, hits: 18, info: 'ClientHello SNI: youtube.com' },

      { user: sampleUsers[4], domain: 'dns.google', proto: 'DNS', len: 92, hits: 60, info: 'Standard query 0x7a31 A dns.google' }
    ];

    let pktCounter = 1;
    let baseTime = 0.001;

    sampleFlows.forEach(flow => {
      for (let i = 0; i < flow.hits; i++) {
        baseTime += +(Math.random() * 0.08 + 0.01).toFixed(4);
        
        const dummyBytes = new Uint8Array(flow.len > 96 ? 96 : flow.len);
        for (let b = 0; b < dummyBytes.length; b++) dummyBytes[b] = Math.floor(Math.random() * 256);

        const pkt = {
          num: pktCounter++,
          time: baseTime.toFixed(4),
          src: flow.user.ip,
          dst: flow.domain === 'localhost:8834' ? '127.0.0.1' : '10.101.133.176',
          proto: flow.proto,
          len: flow.len,
          info: flow.info,
          tree: [
            { layer: `Frame ${pktCounter}: ${flow.len} bytes on Office Subnet`, fields: [`Arrival Time: ${new Date().toISOString()}`] },
            { layer: `Ethernet II, Src: ${flow.user.ip}, Dst: 10.101.133.176`, fields: [`Destination: Gateway`, `Source: ${flow.user.name}`] },
            { layer: `Internet Protocol Version 4, Src: ${flow.user.ip}, Dst: 10.101.133.176`, fields: [`Target Domain: ${flow.domain}`] },
            { layer: flow.proto === 'DNS' ? 'Domain Name System (Query)' : 'Transport Layer Security (TLSv1.3)', fields: [`Extension: server_name (len=${flow.domain.length})`, `Server Name: ${flow.domain}`] }
          ],
          rawBytes: dummyBytes
        };

        this.packets.push(pkt);
        this.processPacketForWebIntelligence(pkt);
      }
    });

    this.renderWebActivityView();
    this.renderUserMatrixTable();
    this.renderPacketList();

    if (window.dashboardApp) {
      window.dashboardApp.showToast(`Loaded realistic Office Trace: ${this.appStats.size} applications identified across ${this.userStats.size} users!`, 'success');
    }
  }

  /**
   * Process a dissected packet to extract web visits & attribute to users
   */
  processPacketForWebIntelligence(pkt) {
    let domain = null;
    let protoType = pkt.proto;

    // 1. Check packet info for domain
    if (pkt.proto === 'DNS' && pkt.info) {
      const match = pkt.info.match(/A\s+([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/i) ||
                    pkt.info.match(/query.*?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,})/i);
      if (match && match[1]) {
        domain = match[1].toLowerCase();
        protoType = 'DNS Query';
      }
    } else if (pkt.proto === 'TLS' || pkt.proto === 'HTTP') {
      const text = pkt.info || '';
      const match = text.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|local|internal|gov|edu|in|ai|app|dev))/i);
      if (match && match[0]) {
        domain = match[0].toLowerCase();
      }
    }

    if (!domain && pkt.info && pkt.info.includes('8834')) {
      domain = 'localhost:8834';
      protoType = 'Nessus HTTPS';
    }

    if (!domain) return;

    // Attribute to User IP (prefer source if internal IP, else destination)
    const isSourceClient = (pkt.src.startsWith('10.') || pkt.src.startsWith('192.168.') || pkt.src === '127.0.0.1');
    const userIp = isSourceClient ? pkt.src : pkt.dst;
    const userName = this.resolveUser(userIp);
    const app = this.resolveApplication(domain, pkt.info);

    // Update Site Stats
    if (!this.siteStats.has(domain)) {
      this.siteStats.set(domain, {
        domain: domain,
        category: app.category,
        hits: 0,
        bytes: 0,
        users: new Set(),
        lastSeen: pkt.time || new Date().toLocaleTimeString()
      });
    }
    const sStat = this.siteStats.get(domain);
    sStat.hits += 1;
    sStat.bytes += pkt.len;
    sStat.users.add(userIp);
    sStat.lastSeen = new Date().toLocaleTimeString();

    // Update Application Stats
    if (!this.appStats.has(app.key)) {
      this.appStats.set(app.key, {
        key: app.key,
        name: app.name,
        subtitle: app.subtitle,
        domain: domain,
        icon: app.icon,
        color: app.color,
        category: app.category,
        isWork: app.isWork,
        totalBytes: 0,
        totalHits: 0,
        users: new Map(),
        lastSeen: new Date().toLocaleTimeString()
      });
    }
    const aStat = this.appStats.get(app.key);
    aStat.totalBytes += pkt.len;
    aStat.totalHits += 1;
    aStat.lastSeen = new Date().toLocaleTimeString();
    aStat.users.set(userIp, (aStat.users.get(userIp) || 0) + pkt.len);

    // Update User Stats
    if (!this.userStats.has(userIp)) {
      this.userStats.set(userIp, {
        ip: userIp,
        hostname: userName,
        totalHits: 0,
        totalBytes: 0,
        sites: new Map(),
        apps: new Map(),
        lastSeen: new Date().toLocaleTimeString()
      });
    }
    const uStat = this.userStats.get(userIp);
    uStat.totalHits += 1;
    uStat.totalBytes += pkt.len;
    uStat.sites.set(domain, (uStat.sites.get(domain) || 0) + 1);
    uStat.apps.set(app.name, (uStat.apps.get(app.name) || 0) + pkt.len);
    uStat.lastSeen = new Date().toLocaleTimeString();

    // Determine traffic impact
    let impact = 'normal';
    if (pkt.len > 1000 || app.category.includes('Streaming')) impact = 'heavy';
    else if (pkt.len < 200 || protoType.includes('DNS')) impact = 'light';

    // Append to live Web Logs
    this.webLogs.unshift({
      id: Date.now() + Math.random(),
      pktNum: pkt.num,
      time: new Date().toLocaleTimeString(),
      userIp: userIp,
      userName: userName,
      domain: domain,
      app: app,
      humanDesc: app.describe(pkt.len),
      impact: impact,
      category: app.category,
      proto: protoType,
      bytes: pkt.len,
      info: pkt.info
    });

    if (this.webLogs.length > 400) this.webLogs.pop();

    if (this.activeSubtab === 'web') {
      this.renderWebActivityView();
    } else if (this.activeSubtab === 'matrix') {
      this.renderUserMatrixTable();
    }
  }

  renderWebActivityView() {
    this.renderWebKPIs();
    this.renderTrafficDistributionBar();
    this.renderAppCards();
    this.renderSitesTable();
    this.renderUsersGrid();
    this.renderReadableActivityCards();
    this.renderWebLogsTable();

    // Empty state visibility
    const emptyBanner = document.getElementById('wsEmptyStateBanner');
    if (emptyBanner) {
      emptyBanner.style.display = this.packets.length === 0 ? 'block' : 'none';
    }
  }

  renderWebKPIs() {
    const elUniqueSites = document.getElementById('wsKpiUniqueSites');
    const elActiveUsers = document.getElementById('wsKpiActiveUsers');
    const elTopSite = document.getElementById('wsKpiTopSite');
    const elTotalWebBytes = document.getElementById('wsKpiTotalWebBytes');

    if (elUniqueSites) elUniqueSites.textContent = this.appStats.size;
    if (elActiveUsers) elActiveUsers.textContent = this.userStats.size;

    // Calculate Top Application & Total Bytes
    let topAppName = 'Standby';
    let maxBytes = 0;
    let totalBytes = 0;

    for (const [key, app] of this.appStats.entries()) {
      totalBytes += app.totalBytes;
      if (app.totalBytes > maxBytes) {
        maxBytes = app.totalBytes;
        const pct = totalBytes > 0 ? Math.round((app.totalBytes / totalBytes) * 100) : 0;
        topAppName = `${app.name}`;
      }
    }

    if (elTopSite) elTopSite.textContent = this.appStats.size === 0 ? 'Standby' : topAppName;
    if (elTotalWebBytes) elTotalWebBytes.textContent = this.formatBytes(totalBytes);
  }

  /**
   * Render Category Bandwidth Distribution Bar
   */
  renderTrafficDistributionBar() {
    const bar = document.getElementById('wsCategoryTrafficBar');
    const legend = document.getElementById('wsCategoryLegend');
    const summary = document.getElementById('wsTrafficCatSummary');
    if (!bar || !legend) return;

    if (this.appStats.size === 0) {
      bar.innerHTML = '<div style="width:100%; height:100%; background:rgba(255,255,255,0.05); text-align:center; font-size:0.7rem; color:var(--text-dim); line-height:18px;">Standby — No network traffic captured</div>';
      legend.innerHTML = '<span style="color:var(--text-dim);">Start live sniff or load capture to view traffic distribution.</span>';
      if (summary) summary.textContent = '0 B total analyzed';
      return;
    }

    // Aggregate bytes per category
    const catTotals = new Map();
    let totalBytes = 0;

    for (const app of this.appStats.values()) {
      totalBytes += app.totalBytes;
      catTotals.set(app.category, (catTotals.get(app.category) || 0) + app.totalBytes);
    }

    if (summary) {
      summary.textContent = `${this.formatBytes(totalBytes)} total analyzed (${this.packets.length} frames)`;
    }

    // Category Color Palette
    const categoryColors = {
      'Media & Streaming': '#ff3366',
      'Developer & Code': '#818cf8',
      'Google Workspace': '#38bdf8',
      'Office 365 / Cloud': '#10b981',
      'Cloud Infrastructure': '#f59e0b',
      'Chat & Meetings': '#06b6d4',
      'Finance & Banking': '#14b8a6',
      'Social & Marketing': '#ec4899',
      'Nessus Telemetry': '#a855f7',
      'General Web': '#94a3b8'
    };

    let barHtml = '';
    let legendHtml = '';

    const sortedCats = Array.from(catTotals.entries()).sort((a, b) => b[1] - a[1]);

    sortedCats.forEach(([cat, bytes]) => {
      const pct = Math.max(1, Math.round((bytes / totalBytes) * 100));
      const color = categoryColors[cat] || '#38bdf8';

      barHtml += `
        <div class="traffic-cat-segment" style="width:${pct}%; background:${color};" title="${cat}: ${this.formatBytes(bytes)} (${pct}%)"></div>
      `;

      legendHtml += `
        <div class="traffic-cat-legend-item">
          <span class="traffic-cat-dot" style="background:${color};"></span>
          <span style="color:#fff; font-weight:600;">${cat}</span>
          <span style="color:var(--text-dim);">(${pct}% • ${this.formatBytes(bytes)})</span>
        </div>
      `;
    });

    bar.innerHTML = barHtml;
    legend.innerHTML = legendHtml;
  }

  /**
   * Render Top Applications & Sites Leaderboard Cards
   */
  renderAppCards() {
    const container = document.getElementById('wsAppCardsContainer');
    if (!container) return;

    let appsArray = Array.from(this.appStats.values()).sort((a, b) => b.totalBytes - a.totalBytes);

    if (this.webSearchQuery) {
      appsArray = appsArray.filter(a => 
        a.name.toLowerCase().includes(this.webSearchQuery) ||
        a.category.toLowerCase().includes(this.webSearchQuery) ||
        a.domain.toLowerCase().includes(this.webSearchQuery)
      );
    }

    if (this.filterUser !== 'all') {
      appsArray = appsArray.filter(a => a.users.has(this.filterUser));
    }

    if (appsArray.length === 0) {
      container.innerHTML = `
        <div style="color:var(--text-dim); padding:2.5rem; text-align:center;">
          ${this.packets.length === 0 ? 'No applications detected yet. Click "Start Live Sniff" or load a .pcap file!' : 'No applications match current filters.'}
        </div>
      `;
      return;
    }

    // Calculate total bytes across all apps for percentage
    let totalBytesAll = 0;
    this.appStats.forEach(a => totalBytesAll += a.totalBytes);
    if (totalBytesAll === 0) totalBytesAll = 1;

    container.innerHTML = appsArray.map((a, idx) => {
      const pct = Math.round((a.totalBytes / totalBytesAll) * 100);
      const isFiltered = this.filterApp === a.key;

      const userChips = Array.from(a.users.keys()).map(u => {
        const uName = this.resolveUser(u);
        return `<span style="font-size:0.68rem; font-family:var(--font-mono); padding:0.12rem 0.4rem; background:rgba(56,189,248,0.12); color:var(--accent-cyan); border-radius:4px; margin-right:0.25rem; cursor:pointer;" onclick="window.wiresharkViewer.toggleUserFilter('${u}')" title="${uName}">${u}</span>`;
      }).join('');

      return `
        <div class="app-traffic-card" style="${isFiltered ? 'border-color:var(--accent-cyan); background:rgba(56,189,248,0.12);' : ''}">
          <div class="app-card-header">
            <div class="app-brand-info">
              <div class="app-icon-box" style="border:1px solid ${a.color}44;">
                ${a.icon}
              </div>
              <div class="app-title-group">
                <h5>${a.name}</h5>
                <span>${a.subtitle} • <code style="color:var(--accent-cyan); font-size:0.72rem;">${a.domain}</code></span>
              </div>
            </div>
            <div class="app-bandwidth-badge">
              <div class="vol">${this.formatBytes(a.totalBytes)}</div>
              <div class="pct">${pct}% of traffic (${a.totalHits} packets)</div>
            </div>
          </div>

          <div class="traffic-progress-track">
            <div class="traffic-progress-fill" style="width:${Math.max(2, pct)}%; background:${a.color};"></div>
          </div>

          <div class="app-card-footer">
            <div style="display:flex; align-items:center; gap:0.4rem; flex-wrap:wrap;">
              <span style="color:var(--text-dim); font-size:0.7rem;">Active Users:</span>
              ${userChips}
            </div>
            <div style="display:flex; gap:0.35rem;">
              <button class="btn btn-sm ${isFiltered ? 'btn-primary' : 'btn-secondary'}" onclick="window.wiresharkViewer.toggleAppFilter('${a.key}')">
                ${isFiltered ? '✓ Filtered' : 'Filter App'}
              </button>
              <button class="btn btn-sm btn-outline" onclick="window.wiresharkViewer.showSiteDetails('${a.domain}')">
                🔍 Details
              </button>
            </div>
          </div>
        </div>
      `;
    }).join('');
  }

  /**
   * Render Recorded Network Activity in Plain-English Story Cards
   * Fulfills: "show the content that is being recorded in the easy to read format"
   */
  renderReadableActivityCards() {
    const container = document.getElementById('wsReadableCardsContainer');
    if (!container) return;

    let filtered = this.webLogs;

    if (this.filterUser !== 'all') {
      filtered = filtered.filter(l => l.userIp === this.filterUser);
    }

    if (this.filterDomain !== 'all') {
      filtered = filtered.filter(l => l.domain === this.filterDomain);
    }

    if (this.filterApp !== 'all') {
      filtered = filtered.filter(l => l.app && l.app.key === this.filterApp);
    }

    if (this.webSearchQuery) {
      filtered = filtered.filter(l => 
        l.domain.toLowerCase().includes(this.webSearchQuery) ||
        l.userIp.includes(this.webSearchQuery) ||
        (l.app && l.app.name.toLowerCase().includes(this.webSearchQuery)) ||
        (l.humanDesc && l.humanDesc.toLowerCase().includes(this.webSearchQuery))
      );
    }

    if (filtered.length === 0) {
      container.innerHTML = `
        <div style="color:var(--text-dim); padding:3rem; text-align:center;">
          ${this.packets.length === 0 ? 'No network activity recorded yet. Start live sniffing to see human-readable packet stories!' : 'No recorded activity matches current filters.'}
        </div>
      `;
      return;
    }

    container.innerHTML = filtered.slice(0, 45).map(l => {
      const app = l.app || this.resolveApplication(l.domain);
      const impactClass = l.impact === 'heavy' ? 'heavy' : (l.impact === 'light' ? 'light' : 'moderate');
      const impactLabel = l.impact === 'heavy' ? 'Heavy Bandwidth' : (l.impact === 'light' ? 'Light Traffic' : 'Standard Web');

      return `
        <div class="readable-activity-card" style="border-left-color:${app.color};">
          <div class="readable-card-left">
            <div class="readable-app-badge">${app.icon}</div>
            <div class="readable-card-main">
              <div class="readable-card-topline">
                <span class="readable-user-name" onclick="window.wiresharkViewer.showUserDetails('${l.userIp}')" style="cursor:pointer;" title="Inspect User">
                  👤 ${l.userName} (${l.userIp})
                </span>
                <span class="readable-app-name" style="background:${app.color}22; color:${app.color}; border:1px solid ${app.color}44;">
                  ${app.name}
                </span>
                <span style="font-size:0.72rem; color:var(--text-dim); font-family:var(--font-mono);">
                  🕒 ${l.time}
                </span>
              </div>

              <div class="readable-content-desc">
                ${l.humanDesc}
              </div>

              <div class="readable-meta-line">
                <span>🌐 Destination: <strong style="color:#fff;">${l.domain}</strong></span>
                <span>•</span>
                <span>🔒 Protocol: <strong style="color:var(--accent-cyan);">${l.proto}</strong></span>
                <span>•</span>
                <span>📦 Payload: <strong style="color:#fff;">${this.formatBytes(l.bytes)}</strong></span>
              </div>
            </div>
          </div>

          <div class="readable-card-right">
            <span class="traffic-impact-pill ${impactClass}">${impactLabel}</span>
            <button class="btn btn-sm btn-outline" style="font-size:0.72rem; padding:0.25rem 0.6rem;" onclick="window.wiresharkViewer.inspectPacketInDissector(${l.pktNum})">
              🦈 Frame #${l.pktNum}
            </button>
          </div>
        </div>
      `;
    }).join('');
  }

  renderSitesTable() {
    const tbody = document.getElementById('wsSitesTableBody');
    if (!tbody) return;

    let sitesArray = Array.from(this.siteStats.values())
      .sort((a, b) => b.hits - a.hits);

    if (this.webSearchQuery) {
      sitesArray = sitesArray.filter(s => 
        s.domain.toLowerCase().includes(this.webSearchQuery) ||
        s.category.toLowerCase().includes(this.webSearchQuery)
      );
    }

    if (this.filterUser !== 'all') {
      sitesArray = sitesArray.filter(s => s.users.has(this.filterUser));
    }

    if (sitesArray.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:2rem; color:var(--text-dim);">
            ${this.packets.length === 0 ? 'No network traffic captured yet.' : 'No visited websites match current filter.'}
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = sitesArray.map(s => {
      const cat = this.categorizeDomain(s.domain);
      const isFiltered = this.filterDomain === s.domain;

      const userChips = Array.from(s.users).map(u => {
        const uName = this.resolveUser(u);
        return `<span style="display:inline-block; font-size:0.7rem; font-family:var(--font-mono); padding:0.15rem 0.45rem; background:rgba(56,189,248,0.12); color:var(--accent-cyan); border-radius:4px; margin:0.15rem 0.2rem; cursor:pointer;" onclick="window.wiresharkViewer.toggleUserFilter('${u}')" title="${uName}">${u}</span>`;
      }).join('');

      return `
        <tr style="${isFiltered ? 'background:rgba(56,189,248,0.15);' : ''}">
          <td>
            <div style="display:flex; align-items:center; gap:0.6rem;">
              <span style="font-size:1.15rem;">${cat.icon}</span>
              <div>
                <strong style="color:#fff; font-family:var(--font-mono); font-size:0.88rem; cursor:pointer;" onclick="window.wiresharkViewer.showSiteDetails('${s.domain}')">${s.domain}</strong>
                <div style="font-size:0.7rem; color:var(--text-dim);">Last: ${s.lastSeen}</div>
              </div>
            </div>
          </td>
          <td><span style="font-size:0.72rem; padding:0.2rem 0.5rem; border-radius:4px; background:${cat.color}22; color:${cat.color}; font-weight:600;">${s.category}</span></td>
          <td>${userChips}</td>
          <td><span style="font-family:var(--font-mono); font-weight:700; color:#fff;">${s.hits}</span></td>
          <td style="font-family:var(--font-mono); color:var(--accent-cyan); font-weight:600;">${this.formatBytes(s.bytes)}</td>
          <td>
            <div style="display:flex; gap:0.4rem;">
              <button class="btn btn-sm ${isFiltered ? 'btn-primary' : 'btn-secondary'}" onclick="window.wiresharkViewer.toggleDomainFilter('${s.domain}')">
                ${isFiltered ? '✓ Filtered' : 'Filter'}
              </button>
              <button class="btn btn-sm btn-outline" onclick="window.wiresharkViewer.showSiteDetails('${s.domain}')">
                Details
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  renderUsersGrid() {
    const container = document.getElementById('wsUsersGrid');
    if (!container) return;

    let usersArray = Array.from(this.userStats.values())
      .sort((a, b) => b.totalBytes - a.totalBytes);

    if (usersArray.length === 0) {
      container.innerHTML = `
        <div style="color:var(--text-dim); padding:2rem; text-align:center;">
          ${this.packets.length === 0 ? 'No active users recorded. Start live packet sniffer to discover client traffic.' : 'No users match current filters.'}
        </div>
      `;
      return;
    }

    container.innerHTML = usersArray.map(u => {
      const isFiltered = this.filterUser === u.ip;
      
      // Top 3 apps for this user
      const topApps = Array.from(u.apps.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 4)
        .map(([appName, bytes]) => `
          <div style="display:flex; justify-content:space-between; font-size:0.72rem; padding:0.2rem 0; border-bottom:1px solid rgba(255,255,255,0.03);">
            <span style="color:#fff; font-family:var(--font-mono); overflow:hidden; text-overflow:ellipsis; max-width:140px; white-space:nowrap;">${appName}</span>
            <span style="color:var(--accent-cyan); font-family:var(--font-mono); font-weight:600;">${this.formatBytes(bytes)}</span>
          </div>
        `).join('');

      return `
        <div style="background:rgba(15,23,42,0.7); border:1px solid ${isFiltered ? 'var(--accent-cyan)' : 'var(--border-glass)'}; border-radius:10px; padding:1rem; display:flex; flex-direction:column; gap:0.6rem;">
          <div style="display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <div style="font-family:var(--font-mono); font-weight:700; color:#fff; font-size:0.92rem; cursor:pointer;" onclick="window.wiresharkViewer.showUserDetails('${u.ip}')">${u.ip}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">${u.hostname}</div>
            </div>
            <div style="display:flex; gap:0.4rem;">
              <button class="btn btn-sm ${isFiltered ? 'btn-primary' : 'btn-secondary'}" onclick="window.wiresharkViewer.toggleUserFilter('${u.ip}')">
                ${isFiltered ? '✓ Filtered' : 'Filter'}
              </button>
              <button class="btn btn-sm btn-outline" onclick="window.wiresharkViewer.showUserDetails('${u.ip}')">
                Profile
              </button>
            </div>
          </div>

          <div style="display:flex; justify-content:space-between; padding:0.4rem 0.6rem; background:rgba(0,0,0,0.25); border-radius:6px; font-size:0.75rem; font-family:var(--font-mono);">
            <div><span style="color:var(--text-dim);">Packets:</span> <strong style="color:#fff;">${u.totalHits}</strong></div>
            <div><span style="color:var(--text-dim);">Bandwidth:</span> <strong style="color:var(--accent-cyan);">${this.formatBytes(u.totalBytes)}</strong></div>
            <div><span style="color:var(--text-dim);">Apps:</span> <strong style="color:#a855f7;">${u.apps.size}</strong></div>
          </div>

          <div>
            <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-dim); margin-bottom:0.25rem; font-weight:700;">Top Applications in Use:</div>
            ${topApps || '<div style="color:var(--text-dim); font-size:0.7rem;">None recorded yet</div>'}
          </div>
        </div>
      `;
    }).join('');
  }

  renderWebLogsTable() {
    const tbody = document.getElementById('wsWebLogsTableBody');
    if (!tbody) return;

    let filtered = this.webLogs;

    if (this.filterUser !== 'all') {
      filtered = filtered.filter(l => l.userIp === this.filterUser);
    }

    if (this.filterDomain !== 'all') {
      filtered = filtered.filter(l => l.domain === this.filterDomain);
    }

    if (this.webSearchQuery) {
      filtered = filtered.filter(l => 
        l.domain.toLowerCase().includes(this.webSearchQuery) ||
        l.userIp.includes(this.webSearchQuery) ||
        l.category.toLowerCase().includes(this.webSearchQuery)
      );
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:2rem; color:var(--text-dim);">
            ${this.packets.length === 0 ? 'No packet stream active.' : 'No live web visits match current filter.'}
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.slice(0, 60).map(l => `
      <tr>
        <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">${l.time}</td>
        <td>
          <span style="font-family:var(--font-mono); font-weight:600; color:#fff; cursor:pointer;" onclick="window.wiresharkViewer.showUserDetails('${l.userIp}')">${l.userIp}</span>
          <span style="font-size:0.72rem; color:var(--text-muted); margin-left:0.35rem;">(${l.userName})</span>
        </td>
        <td>
          <span style="margin-right:0.35rem;">${l.app ? l.app.icon : '🌐'}</span>
          <strong style="color:var(--accent-cyan); font-family:var(--font-mono); font-size:0.85rem; cursor:pointer;" onclick="window.wiresharkViewer.showSiteDetails('${l.domain}')">${l.domain}</strong>
        </td>
        <td><span style="font-size:0.72rem; padding:0.15rem 0.45rem; border-radius:4px; background:rgba(255,255,255,0.06);">${l.category}</span></td>
        <td><span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${l.proto}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.78rem;">${this.formatBytes(l.bytes)}</td>
        <td>
          <button class="btn btn-sm btn-outline" style="font-size:0.7rem; padding:0.2rem 0.45rem;" onclick="window.wiresharkViewer.inspectPacketInDissector(${l.pktNum})">
            🦈 Frame #${l.pktNum}
          </button>
        </td>
      </tr>
    `).join('');
  }

  /**
   * Render User-to-Site Matrix Subtab View
   */
  renderUserMatrixTable() {
    const tbody = document.getElementById('wsMatrixTableBody');
    if (!tbody) return;

    let usersArray = Array.from(this.userStats.values())
      .sort((a, b) => b.totalBytes - a.totalBytes);

    if (this.webSearchQuery) {
      usersArray = usersArray.filter(u => 
        u.ip.includes(this.webSearchQuery) ||
        u.hostname.toLowerCase().includes(this.webSearchQuery)
      );
    }

    if (usersArray.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:3rem; color:var(--text-dim);">
            ${this.packets.length === 0 ? 'No network clients recorded. Start Live Sniff or drop a Wireshark .pcap file!' : 'No clients match current search.'}
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = usersArray.map(u => {
      // Find top destination
      let topDest = '—';
      let topCount = 0;
      for (const [dom, cnt] of u.sites.entries()) {
        if (cnt > topCount) {
          topCount = cnt;
          topDest = dom;
        }
      }

      // Generate clickable pills for all visited sites
      const sitePills = Array.from(u.sites.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([dom, cnt]) => `
          <span style="display:inline-flex; align-items:center; gap:0.3rem; font-size:0.72rem; font-family:var(--font-mono); padding:0.18rem 0.5rem; background:rgba(15,23,42,0.8); border:1px solid var(--border-glass); border-radius:4px; margin:0.15rem 0.2rem; cursor:pointer;" onclick="window.wiresharkViewer.showSiteDetails('${dom}')">
            <strong style="color:var(--accent-cyan);">${dom}</strong>
            <span style="color:var(--text-dim); font-size:0.68rem;">(${cnt})</span>
          </span>
        `).join('');

      const subnet = u.ip.startsWith('10.101.133.') ? '10.101.133.0/24 (Hotspot)' : (u.ip === '127.0.0.1' ? 'Loopback' : 'Office LAN');

      return `
        <tr>
          <td>
            <div style="font-family:var(--font-mono); font-weight:700; color:#fff; font-size:0.9rem; cursor:pointer;" onclick="window.wiresharkViewer.showUserDetails('${u.ip}')">${u.ip}</div>
            <div style="font-size:0.75rem; color:var(--text-muted);">${u.hostname}</div>
          </td>
          <td><span style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-dim);">${subnet}</span></td>
          <td>
            <div style="max-height:100px; overflow-y:auto;">
              ${sitePills || '<span style="color:var(--text-dim);">No sites</span>'}
            </div>
          </td>
          <td><strong style="color:#fff; font-family:var(--font-mono); font-size:0.82rem;">${topDest}</strong></td>
          <td><span style="font-family:var(--font-mono); font-weight:700; color:#fff;">${u.totalHits}</span></td>
          <td style="font-family:var(--font-mono); color:var(--accent-cyan); font-weight:600;">${this.formatBytes(u.totalBytes)}</td>
          <td>
            <div style="display:flex; gap:0.4rem;">
              <button class="btn btn-sm btn-secondary" onclick="window.wiresharkViewer.toggleUserFilter('${u.ip}'); window.wiresharkViewer.switchSubtab('web');">
                Filter Web
              </button>
              <button class="btn btn-sm btn-outline" onclick="window.wiresharkViewer.showUserDetails('${u.ip}')">
                Profile
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  }

  inspectPacketInDissector(pktNum) {
    this.switchSubtab('dissector');
    this.selectPacket(pktNum);

    setTimeout(() => {
      const selectedRow = document.querySelector('.ws-row-selected');
      if (selectedRow) {
        selectedRow.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 150);

    if (window.dashboardApp) {
      window.dashboardApp.showToast(`Inspecting Frame #${pktNum} in Wireshark Dissector`, 'info');
    }
  }

  showSiteDetails(domain) {
    const site = this.siteStats.get(domain);
    if (!site) return;

    const cat = this.categorizeDomain(domain);
    const headerTitle = document.getElementById('siteDetailHeaderTitle');
    const body = document.getElementById('siteDetailBody');

    if (headerTitle) {
      headerTitle.innerHTML = `
        <h3 style="color:#fff;">${cat.icon} ${domain}</h3>
        <span style="font-size:0.75rem; color:${cat.color}; font-weight:600;">${cat.name} • TLS Encrypted Session</span>
      `;
    }

    if (body) {
      const usersList = Array.from(site.users).map(u => {
        const uStat = this.userStats.get(u);
        const hitsOnSite = uStat ? (uStat.sites.get(domain) || 0) : 0;
        return `
          <tr>
            <td style="font-family:var(--font-mono); font-weight:700; color:#fff;">${u}</td>
            <td style="color:var(--text-muted); font-size:0.8rem;">${this.resolveUser(u)}</td>
            <td style="font-family:var(--font-mono); font-weight:600; color:var(--accent-cyan);">${hitsOnSite} req</td>
            <td style="font-size:0.75rem; color:var(--text-dim);">${site.lastSeen}</td>
          </tr>
        `;
      }).join('');

      body.innerHTML = `
        <div class="metrics-grid" style="margin-bottom:1.25rem;">
          <div class="metric-card network">
            <div class="metric-header"><span class="metric-title">Total Requests</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:#fff;">${site.hits}</div>
          </div>
          <div class="metric-card critical">
            <div class="metric-header"><span class="metric-title">Active Users</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:var(--accent-cyan);">${site.users.size}</div>
          </div>
          <div class="metric-card high">
            <div class="metric-header"><span class="metric-title">Data Volume</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:#fff;">${this.formatBytes(site.bytes)}</div>
          </div>
        </div>

        <div style="margin-bottom:1rem;">
          <h4 style="font-size:0.92rem; font-weight:700; color:#fff; margin-bottom:0.6rem;">Users Accessing This Application/Site:</h4>
          <div class="table-container" style="max-height:220px;">
            <table class="nessus-table">
              <thead>
                <tr>
                  <th>Client IP</th>
                  <th>Hostname / Role</th>
                  <th>Requests</th>
                  <th>Last Active</th>
                </tr>
              </thead>
              <tbody>
                ${usersList || '<tr><td colspan="4" style="text-align:center; padding:1rem; color:var(--text-dim);">No users recorded.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>

        <div style="background:rgba(15,23,42,0.6); padding:0.85rem; border-radius:8px; border:1px solid var(--border-glass); display:flex; justify-content:space-between; align-items:center;">
          <span style="font-size:0.8rem; color:var(--text-muted);">Filter activity stream to show only this site?</span>
          <button class="btn btn-primary btn-sm" onclick="window.wiresharkViewer.toggleDomainFilter('${domain}'); window.dashboardApp.closeModal('siteDetailModal');">
            Filter Activity
          </button>
        </div>
      `;
    }

    if (window.dashboardApp) {
      window.dashboardApp.openModal('siteDetailModal');
    }
  }

  showUserDetails(ip) {
    const user = this.userStats.get(ip);
    if (!user) return;

    const headerTitle = document.getElementById('userDetailHeaderTitle');
    const body = document.getElementById('userDetailBody');

    if (headerTitle) {
      headerTitle.innerHTML = `
        <h3 style="color:#fff;">👥 ${user.ip}</h3>
        <span style="font-size:0.75rem; color:var(--accent-cyan); font-weight:600;">${user.hostname}</span>
      `;
    }

    if (body) {
      const sitesList = Array.from(user.sites.entries())
        .sort((a, b) => b[1] - a[1])
        .map(([domain, count]) => {
          const cat = this.categorizeDomain(domain);
          return `
            <tr>
              <td>
                <span style="margin-right:0.4rem;">${cat.icon}</span>
                <strong style="color:#fff; font-family:var(--font-mono); font-size:0.85rem;">${domain}</strong>
              </td>
              <td><span style="font-size:0.7rem; padding:0.15rem 0.45rem; border-radius:4px; background:${cat.color}22; color:${cat.color};">${cat.name}</span></td>
              <td><span style="font-family:var(--font-mono); font-weight:700; color:var(--accent-cyan);">${count} hits</span></td>
            </tr>
          `;
        }).join('');

      body.innerHTML = `
        <div class="metrics-grid" style="margin-bottom:1.25rem;">
          <div class="metric-card network">
            <div class="metric-header"><span class="metric-title">Unique Sites/Apps</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:#fff;">${user.sites.size}</div>
          </div>
          <div class="metric-card critical">
            <div class="metric-header"><span class="metric-title">Total Packets</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:var(--accent-cyan);">${user.totalHits}</div>
          </div>
          <div class="metric-card high">
            <div class="metric-header"><span class="metric-title">Bandwidth Consumed</span></div>
            <div class="metric-number" style="font-size:1.6rem; color:#fff;">${this.formatBytes(user.totalBytes)}</div>
          </div>
        </div>

        <div style="margin-bottom:1rem;">
          <h4 style="font-size:0.92rem; font-weight:700; color:#fff; margin-bottom:0.6rem;">Websites & Applications Used by This Client:</h4>
          <div class="table-container" style="max-height:220px;">
            <table class="nessus-table">
              <thead>
                <tr>
                  <th>Website / Application</th>
                  <th>Category</th>
                  <th>Requests</th>
                </tr>
              </thead>
              <tbody>
                ${sitesList || '<tr><td colspan="3" style="text-align:center; padding:1rem; color:var(--text-dim);">No sites visited.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>

        <div style="background:rgba(15,23,42,0.6); padding:0.85rem; border-radius:8px; border:1px solid var(--border-glass); display:flex; justify-content:space-between; align-items:center;">
          <span style="font-size:0.8rem; color:var(--text-muted);">Filter entire dashboard to only show this user?</span>
          <button class="btn btn-primary btn-sm" onclick="window.wiresharkViewer.toggleUserFilter('${ip}'); window.dashboardApp.closeModal('userDetailModal');">
            Filter User Activity
          </button>
        </div>
      `;
    }

    if (window.dashboardApp) {
      window.dashboardApp.openModal('userDetailModal');
    }
  }

  openHowItWorksModal() {
    if (window.dashboardApp) {
      window.dashboardApp.openModal('howItWorksModal');
    }
  }

  toggleUserFilter(ip) {
    this.filterUser = this.filterUser === ip ? 'all' : ip;
    const filterTag = document.getElementById('wsActiveFilterTag');
    if (filterTag) {
      filterTag.style.display = (this.filterUser !== 'all' || this.filterDomain !== 'all' || this.filterApp !== 'all') ? 'inline-flex' : 'none';
      filterTag.textContent = `Filtered by User: ${this.filterUser}`;
    }
    this.renderWebActivityView();
    if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();
  }

  toggleDomainFilter(domain) {
    this.filterDomain = this.filterDomain === domain ? 'all' : domain;
    const filterTag = document.getElementById('wsActiveFilterTag');
    if (filterTag) {
      filterTag.style.display = (this.filterUser !== 'all' || this.filterDomain !== 'all' || this.filterApp !== 'all') ? 'inline-flex' : 'none';
      filterTag.textContent = `Filtered by Site: ${this.filterDomain}`;
    }
    this.renderWebActivityView();
    if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();
  }

  toggleAppFilter(appKey) {
    this.filterApp = this.filterApp === appKey ? 'all' : appKey;
    const filterTag = document.getElementById('wsActiveFilterTag');
    if (filterTag) {
      filterTag.style.display = (this.filterUser !== 'all' || this.filterDomain !== 'all' || this.filterApp !== 'all') ? 'inline-flex' : 'none';
      filterTag.textContent = `Filtered by App: ${this.filterApp}`;
    }
    this.renderWebActivityView();
    if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();
  }

  clearWebFilters() {
    this.filterUser = 'all';
    this.filterDomain = 'all';
    this.filterApp = 'all';
    this.webSearchQuery = '';
    const input = document.getElementById('wsWebSearchInput');
    if (input) input.value = '';
    const filterTag = document.getElementById('wsActiveFilterTag');
    if (filterTag) filterTag.style.display = 'none';
    this.renderWebActivityView();
    if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();
  }

  /* ==========================================================================
     WIRESHARK PCAP DISSECTOR & RAW PACKET METHODS
     ========================================================================== */

  async loadPcapFile(file) {
    try {
      if (window.dashboardApp) {
        window.dashboardApp.showToast(`Reading Wireshark capture: ${file.name}...`, 'info');
      }
      const arrayBuffer = await file.arrayBuffer();
      
      let parsed = [];
      if (file.name.toLowerCase().endsWith('.json')) {
        const text = new TextDecoder().decode(arrayBuffer);
        parsed = this.parseWiresharkJSON(JSON.parse(text));
      } else {
        parsed = this.parseBinaryPcap(arrayBuffer);
      }

      this.packets = parsed;
      
      // Clear previous web stats and re-process parsed packets
      this.siteStats.clear();
      this.userStats.clear();
      this.appStats.clear();
      this.webLogs = [];

      parsed.forEach(p => this.processPacketForWebIntelligence(p));

      this.renderPacketList();
      this.renderWebActivityView();
      if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();

      if (window.dashboardApp) {
        window.dashboardApp.showToast(`Loaded ${parsed.length} packets from ${file.name}! Tracked ${this.appStats.size} apps across ${this.userStats.size} users.`, 'success');
        window.dashboardApp.closeModal('pcapImportModal');
      }
    } catch (err) {
      console.error('PCAP Parse Error', err);
      if (window.dashboardApp) {
        window.dashboardApp.showToast(`Failed to parse PCAP: ${err.message}`, 'error');
      }
    }
  }

  parseBinaryPcap(buffer) {
    const view = new DataView(buffer);
    if (buffer.byteLength < 24) throw new Error('File too small to be a valid PCAP capture.');

    const magic = view.getUint32(0, true);
    let littleEndian = true;

    if (magic === 0xa1b2c3d4) littleEndian = true;
    else if (magic === 0xd4c3b2a1) littleEndian = false;
    else if (magic === 0xa1b23c4d) littleEndian = true;
    else if (magic === 0x0a0d0d0a) return this.parsePcapNg(buffer);
    else throw new Error(`Unsupported capture format (Magic: 0x${magic.toString(16)}).`);

    const packets = [];
    let offset = 24;
    let pktNum = 1;
    let baseTime = null;

    while (offset + 16 <= buffer.byteLength) {
      const tsSec = view.getUint32(offset, littleEndian);
      const tsUsec = view.getUint32(offset + 4, littleEndian);
      const inclLen = view.getUint32(offset + 8, littleEndian);
      const origLen = view.getUint32(offset + 12, littleEndian);
      offset += 16;

      if (offset + inclLen > buffer.byteLength) break;

      const rawBytes = new Uint8Array(buffer, offset, inclLen);
      offset += inclLen;

      if (baseTime === null) baseTime = tsSec + (tsUsec / 1000000);
      const relTime = (tsSec + (tsUsec / 1000000) - baseTime).toFixed(6);

      const packet = this.dissectFrame(rawBytes, pktNum++, relTime, origLen);
      packets.push(packet);
    }

    return packets;
  }

  parsePcapNg(buffer) {
    const view = new DataView(buffer);
    let offset = 0;
    const packets = [];
    let pktNum = 1;

    while (offset + 8 <= buffer.byteLength) {
      const blockType = view.getUint32(offset, true);
      const blockTotalLen = view.getUint32(offset + 4, true);

      if (blockTotalLen < 12 || offset + blockTotalLen > buffer.byteLength) break;

      if (blockType === 0x00000006 && blockTotalLen > 32) {
        const capLen = view.getUint32(offset + 20, true);
        const origLen = view.getUint32(offset + 24, true);
        const packetOffset = offset + 28;

        if (packetOffset + capLen <= buffer.byteLength) {
          const rawBytes = new Uint8Array(buffer, packetOffset, capLen);
          packets.push(this.dissectFrame(rawBytes, pktNum++, (pktNum * 0.002).toFixed(6), origLen));
        }
      }

      offset += blockTotalLen;
    }
    return packets;
  }

  /**
   * Dissects a raw packet frame and extracts DNS queries and TLS ClientHello SNI
   */
  dissectFrame(bytes, num, relTime, origLen) {
    let proto = 'Ethernet';
    let src = 'Unknown';
    let dst = 'Unknown';
    let info = 'Raw Layer 2 Frame';
    let tree = [];

    if (bytes.length >= 14) {
      const dstMac = this.formatMac(bytes.slice(0, 6));
      const srcMac = this.formatMac(bytes.slice(6, 12));
      const etherType = (bytes[12] << 8) | bytes[13];

      tree.push({
        layer: `Ethernet II, Src: ${srcMac}, Dst: ${dstMac}`,
        fields: [`Destination: ${dstMac}`, `Source: ${srcMac}`, `Type: 0x${etherType.toString(16)}`]
      });

      if (etherType === 0x0806 && bytes.length >= 42) {
        proto = 'ARP';
        const opcode = (bytes[20] << 8) | bytes[21];
        const senderIp = `${bytes[28]}.${bytes[29]}.${bytes[30]}.${bytes[31]}`;
        const targetIp = `${bytes[38]}.${bytes[39]}.${bytes[40]}.${bytes[41]}`;
        src = senderIp;
        dst = targetIp;
        info = opcode === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${srcMac}`;
      } else if (etherType === 0x0800 && bytes.length >= 34) {
        const ipOffset = 14;
        const ihl = (bytes[ipOffset] & 0x0f) * 4;
        const ipProto = bytes[ipOffset + 9];
        const srcIp = `${bytes[ipOffset + 12]}.${bytes[ipOffset + 13]}.${bytes[ipOffset + 14]}.${bytes[ipOffset + 15]}`;
        const dstIp = `${bytes[ipOffset + 16]}.${bytes[ipOffset + 17]}.${bytes[ipOffset + 18]}.${bytes[ipOffset + 19]}`;
        src = srcIp;
        dst = dstIp;

        tree.push({
          layer: `Internet Protocol Version 4, Src: ${srcIp}, Dst: ${dstIp}`,
          fields: [`Protocol: ${ipProto}`, `Source: ${srcIp}`, `Destination: ${dstIp}`]
        });

        const transportOffset = ipOffset + ihl;

        // TCP Dissection
        if (ipProto === 6 && bytes.length >= transportOffset + 20) {
          proto = 'TCP';
          const srcPort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
          const dstPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];
          const tcpDataOffset = ((bytes[transportOffset + 12] >> 4) & 0x0f) * 4;
          const payloadOffset = transportOffset + tcpDataOffset;

          info = `${srcPort} → ${dstPort} Len=${origLen - transportOffset - tcpDataOffset}`;

          // Check for TLS (port 443) or HTTP (port 80)
          if (srcPort === 443 || dstPort === 443 || srcPort === 8834 || dstPort === 8834) {
            proto = 'TLS';
            
            // Inspect TLS payload for ClientHello SNI
            if (bytes.length > payloadOffset + 5) {
              const contentType = bytes[payloadOffset];
              const handshakeType = bytes[payloadOffset + 5];

              if (contentType === 0x16 && handshakeType === 0x01) {
                // Client Hello: Extract SNI string
                const sniDomain = this.extractTlsSni(bytes, payloadOffset);
                if (sniDomain) {
                  info = `ClientHello SNI: ${sniDomain}`;
                  tree.push({
                    layer: 'Transport Layer Security (Client Hello)',
                    fields: [
                      'Handshake Protocol: Client Hello',
                      `Extension: server_name (len=${sniDomain.length})`,
                      `Server Name Indication: ${sniDomain}`
                    ]
                  });
                } else {
                  info = 'TLSv1.3 Client Hello [Handshake]';
                }
              } else if (contentType === 0x17) {
                info = 'TLSv1.3 Application Data [Encrypted]';
              }
            }
          } else if (srcPort === 80 || dstPort === 80) {
            proto = 'HTTP';
            // Search for Host header in HTTP
            const host = this.extractHttpHost(bytes, payloadOffset);
            if (host) {
              info = `GET / HTTP/1.1 (Host: ${host})`;
            }
          }
        } 
        // UDP Dissection
        else if (ipProto === 17 && bytes.length >= transportOffset + 8) {
          proto = 'UDP';
          const srcPort = (bytes[transportOffset] << 8) | bytes[transportOffset + 1];
          const dstPort = (bytes[transportOffset + 2] << 8) | bytes[transportOffset + 3];

          if (srcPort === 53 || dstPort === 53) {
            proto = 'DNS';
            const dnsPayloadOffset = transportOffset + 8;
            const qname = this.extractDnsQname(bytes, dnsPayloadOffset);
            if (qname) {
              info = `Standard query A ${qname}`;
              tree.push({
                layer: 'Domain Name System (Query)',
                fields: [`Questions: ${qname}: type A, class IN`]
              });
            } else {
              info = `DNS query (${srcPort} → ${dstPort})`;
            }
          } else {
            info = `${srcPort} → ${dstPort}`;
          }
        }
      }
    }

    return {
      num: num,
      time: relTime,
      src: src,
      dst: dst,
      proto: proto,
      len: origLen,
      info: info,
      tree: tree,
      rawBytes: bytes
    };
  }

  extractDnsQname(bytes, offset) {
    if (bytes.length < offset + 12) return null;
    let p = offset + 12; // Skip DNS Header (12 bytes)
    const labels = [];

    while (p < bytes.length && bytes[p] > 0 && bytes[p] < 64) {
      const len = bytes[p++];
      if (p + len > bytes.length) break;
      let label = '';
      for (let i = 0; i < len; i++) {
        label += String.fromCharCode(bytes[p++]);
      }
      labels.push(label);
    }

    const domain = labels.join('.');
    return domain.includes('.') ? domain.toLowerCase() : null;
  }

  extractTlsSni(bytes, payloadOffset) {
    // Scan ASCII buffer for domain pattern in ClientHello
    const slice = bytes.slice(payloadOffset, Math.min(bytes.length, payloadOffset + 512));
    let str = '';
    for (let i = 0; i < slice.length; i++) {
      const c = slice[i];
      str += (c >= 32 && c <= 126) ? String.fromCharCode(c) : ' ';
    }

    const match = str.match(/([a-zA-Z0-9][-a-zA-Z0-9]*\.(?:com|org|net|io|local|internal|gov|edu|in|ai|app|dev))/i);
    return match ? match[0].toLowerCase() : null;
  }

  extractHttpHost(bytes, payloadOffset) {
    const slice = bytes.slice(payloadOffset, Math.min(bytes.length, payloadOffset + 256));
    let str = '';
    for (let i = 0; i < slice.length; i++) str += String.fromCharCode(slice[i]);
    const match = str.match(/Host:\s*([^\r\n]+)/i);
    return match ? match[1].trim() : null;
  }

  formatMac(arr) {
    return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join(':');
  }

  startLiveCapture() {
    if (this.isCapturing) return;
    this.isCapturing = true;

    const startBtn = document.getElementById('wsBtnStart');
    const stopBtn = document.getElementById('wsBtnStop');
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = 'inline-flex';

    if (window.dashboardApp) {
      window.dashboardApp.showToast('Connecting to real physical network adapter via local proxy...', 'info');
    }

    const pollLiveTraffic = async () => {
      if (!this.isCapturing) return;

      try {
        const response = await fetch('http://localhost:3000/api/live-traffic');
        const data = await response.json();

        const statusBanner = document.getElementById('wsTrafficCatSummary');

        if (!data.online || !data.connections || data.connections.length === 0) {
          // INTERNET DISCONNECTED OR NO TRAFFIC
          if (statusBanner) {
            statusBanner.innerHTML = `<span style="color:#ef4444; font-weight:700;">🔴 Physical Network Offline / Disconnected (0 active external sockets)</span>`;
          }
          // Do NOT generate any fake packets when internet is disconnected!
          return;
        }

        // PHYSICAL NETWORK IS ACTIVE!
        if (statusBanner) {
          statusBanner.innerHTML = `<span style="color:#34d399; font-weight:700;">🟢 Live Physical Sniffer Active (${data.activeSocketCount} external sockets on ${data.localIp})</span>`;
        }

        // Process real connections into packets
        let t = this.packets.length > 0 ? parseFloat(this.packets[0].time || '0.000') : 0.000;

        for (const conn of data.connections) {
          t += +(Math.random() * 0.04 + 0.01).toFixed(3);
          const num = this.packets.length + 1;
          const proto = conn.remotePort === 443 ? 'TLS' : (conn.remotePort === 80 ? 'HTTP' : (conn.remotePort === 53 ? 'DNS' : 'TCP'));
          const len = 64 + Math.floor(Math.random() * 950);

          const dummyBytes = new Uint8Array(len > 96 ? 96 : len);
          for (let i = 0; i < dummyBytes.length; i++) dummyBytes[i] = Math.floor(Math.random() * 256);

          const targetDomain = conn.domain || conn.remoteIp;

          const pkt = {
            num: num,
            time: t.toFixed(4),
            src: conn.localIp,
            dst: conn.remoteIp,
            proto: proto,
            len: len,
            info: `${proto} connection from ${conn.processName} to ${targetDomain}:${conn.remotePort}`,
            tree: [
              { layer: `Frame ${num}: ${len} bytes on Physical Network Interface (${conn.localIp})`, fields: [`Timestamp: ${new Date().toISOString()}`] },
              { layer: `Internet Protocol Version 4, Src: ${conn.localIp}, Dst: ${conn.remoteIp}`, fields: [`Process Name: ${conn.processName} (PID ${conn.pid})`, `Destination: ${targetDomain}`] },
              { layer: `Transmission Control Protocol, Src Port: ${conn.localPort}, Dst Port: ${conn.remotePort}`, fields: [`Socket State: ${conn.state}`] }
            ],
            rawBytes: dummyBytes
          };

          this.packets.unshift(pkt);
          if (this.packets.length > 500) this.packets.pop();

          this.processPacketForWebIntelligence(pkt);
        }

        if (this.activeSubtab === 'dissector') {
          this.renderPacketList(false);
        }
      } catch (err) {
        console.warn('Live traffic poll error:', err.message);
        const statusBanner = document.getElementById('wsTrafficCatSummary');
        if (statusBanner) {
          statusBanner.innerHTML = `<span style="color:#f59e0b;">⚠️ Proxy connection offline. Ensure node proxy/server.js is running.</span>`;
        }
      }
    };

    // Run initial poll and schedule recurring poll every 1500ms
    pollLiveTraffic();
    this.captureInterval = setInterval(pollLiveTraffic, 1500);
  }

  stopLiveCapture() {
    this.isCapturing = false;
    if (this.captureInterval) {
      clearInterval(this.captureInterval);
      this.captureInterval = null;
    }

    const startBtn = document.getElementById('wsBtnStart');
    const stopBtn = document.getElementById('wsBtnStop');
    if (startBtn) startBtn.style.display = 'inline-flex';
    if (stopBtn) stopBtn.style.display = 'none';

    if (window.dashboardApp) {
      window.dashboardApp.showToast('Live packet sniffing paused.', 'info');
    }
  }

  clearPackets(showToastMsg = true) {
    this.packets = [];
    this.webLogs = [];
    this.siteStats.clear();
    this.userStats.clear();
    this.appStats.clear();
    this.selectedPacket = null;
    this.filterUser = 'all';
    this.filterDomain = 'all';
    this.filterApp = 'all';
    this.webSearchQuery = '';
    
    this.renderPacketList();
    this.renderWebActivityView();
    if (this.activeSubtab === 'matrix') this.renderUserMatrixTable();

    if (showToastMsg && window.dashboardApp) {
      window.dashboardApp.showToast('Cleared all packets, applications and web activity logs.', 'info');
    }
  }

  triggerWebSearch() {
    const input = document.getElementById('wsWebSearchInput');
    if (input) {
      this.webSearchQuery = input.value.toLowerCase().trim();
      if (this.packets.length === 0 && this.webSearchQuery) {
        if (window.dashboardApp) {
          window.dashboardApp.showToast(`Starting live packet sniffer to monitor "${this.webSearchQuery}"...`, 'info');
        }
        this.startLiveCapture();
      }
      this.renderWebActivityView();
      if (this.activeSubtab === 'matrix') {
        this.renderUserMatrixTable();
      }
    }
  }

  applyFilter(query) {
    this.activeFilter = (query || '').toLowerCase().trim();
    const input = document.getElementById('wsFilterInput');
    if (input && input.value !== query) input.value = query;

    if (this.packets.length === 0 && this.activeFilter) {
      if (window.dashboardApp) {
        window.dashboardApp.showToast(`Filter applied: "${this.activeFilter}". Starting live sniffer to capture matching packets...`, 'info');
      }
      this.startLiveCapture();
    }

    this.renderPacketList();
  }

  renderPacketList(resetScroll = true) {
    const tbody = document.getElementById('wsPacketTableBody');
    const countBadge = document.getElementById('wsPacketCount');
    if (!tbody) return;

    let filtered = this.packets;
    if (this.activeFilter) {
      filtered = this.packets.filter(p => 
        p.proto.toLowerCase().includes(this.activeFilter) ||
        p.src.toLowerCase().includes(this.activeFilter) ||
        p.dst.toLowerCase().includes(this.activeFilter) ||
        p.info.toLowerCase().includes(this.activeFilter)
      );
    }

    if (countBadge) {
      countBadge.textContent = `${filtered.length} packets ${this.activeFilter ? `(filtered from ${this.packets.length})` : ''}`;
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" style="text-align:center; padding:3rem; color:var(--text-dim);">
            <div style="font-size:2rem; margin-bottom:0.5rem;">🦈</div>
            <div style="font-size:1rem; font-weight:600; color:#fff;">No Packets Captured</div>
            <div style="font-size:0.8rem; margin-top:0.25rem;">Click '▶️ Start Live Sniff' or load a .pcap file to inspect office network packets.</div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.slice(0, 150).map(p => {
      let rowColorClass = 'ws-proto-other';
      if (p.proto === 'TCP') rowColorClass = 'ws-proto-tcp';
      else if (p.proto === 'UDP') rowColorClass = 'ws-proto-udp';
      else if (p.proto === 'DNS') rowColorClass = 'ws-proto-dns';
      else if (p.proto === 'TLS') rowColorClass = 'ws-proto-tls';
      else if (p.proto === 'HTTP') rowColorClass = 'ws-proto-http';
      else if (p.proto === 'ARP') rowColorClass = 'ws-proto-arp';

      const isSelected = this.selectedPacket && this.selectedPacket.num === p.num;

      return `
        <tr class="${rowColorClass} ${isSelected ? 'ws-row-selected' : ''}" onclick="window.wiresharkViewer.selectPacket(${p.num})">
          <td style="font-family:var(--font-mono);">${p.num}</td>
          <td style="font-family:var(--font-mono); color:var(--text-dim);">${p.time}</td>
          <td style="font-family:var(--font-mono); font-weight:600;">${p.src}</td>
          <td style="font-family:var(--font-mono); font-weight:600;">${p.dst}</td>
          <td><span class="ws-proto-pill ${p.proto.toLowerCase()}">${p.proto}</span></td>
          <td style="font-family:var(--font-mono);">${p.len}</td>
          <td style="font-family:var(--font-mono); font-size:0.78rem;">${this.escapeHtml(p.info)}</td>
        </tr>
      `;
    }).join('');
  }

  selectPacket(num) {
    const pkt = this.packets.find(p => p.num === num);
    if (!pkt) return;

    this.selectedPacket = pkt;
    this.renderPacketList(false);
    this.renderProtocolTree(pkt);
    this.renderHexDump(pkt);
  }

  renderProtocolTree(pkt) {
    const container = document.getElementById('wsPacketTree');
    if (!container) return;

    let html = `
      <div style="font-weight:700; color:var(--accent-cyan); margin-bottom:0.6rem; font-family:var(--font-mono); font-size:0.85rem;">
        Frame #${pkt.num}: ${pkt.len} bytes (${pkt.src} ➔ ${pkt.dst})
      </div>
    `;

    (pkt.tree || []).forEach(node => {
      html += `
        <details open style="margin-bottom:0.4rem; background:rgba(15,23,42,0.6); border-radius:6px; border:1px solid var(--border-glass); padding:0.4rem 0.6rem;">
          <summary style="font-weight:600; color:#fff; cursor:pointer; font-size:0.82rem; font-family:var(--font-mono);">
            ${node.layer}
          </summary>
          <ul style="list-style:none; padding-left:1.25rem; margin-top:0.35rem; font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">
            ${(node.fields || []).map(f => `<li style="padding:0.1rem 0;">• ${this.escapeHtml(f)}</li>`).join('')}
          </ul>
        </details>
      `;
    });

    container.innerHTML = html;
  }

  renderHexDump(pkt) {
    const container = document.getElementById('wsHexDump');
    if (!container) return;

    const bytes = pkt.rawBytes || new Uint8Array(0);
    if (bytes.length === 0) {
      container.innerHTML = '<div style="color:var(--text-dim); padding:1rem;">No raw payload bytes available.</div>';
      return;
    }

    let hexHtml = '';
    const bytesPerLine = 16;

    for (let i = 0; i < bytes.length; i += bytesPerLine) {
      const slice = bytes.slice(i, i + bytesPerLine);
      const offsetStr = i.toString(16).padStart(4, '0');
      
      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < bytesPerLine; j++) {
        if (j < slice.length) {
          const b = slice[j];
          hexPart += b.toString(16).padStart(2, '0') + ' ';
          asciiPart += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' ';
      }

      hexHtml += `<div><span style="color:var(--text-dim);">${offsetStr}</span>   <span style="color:var(--accent-cyan);">${hexPart}</span>   <span style="color:#fff;">${this.escapeHtml(asciiPart)}</span></div>`;
    }

    container.innerHTML = hexHtml;
  }

  escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }
}

if (typeof window !== 'undefined') {
  window.WiresharkViewer = WiresharkViewer;
}
