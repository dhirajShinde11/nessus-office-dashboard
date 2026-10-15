/**
 * Nessus Client-side File Parser
 * Parses native .nessus (XML v2) files and JSON scan exports directly in the browser
 */

class NessusFileParser {
  /**
   * Parse a File object (.nessus XML or .json)
   * @param {File} file
   * @returns {Promise<Object>} Formatted dataset
   */
  static async parseFile(file) {
    const text = await file.text();
    const fileName = file.name.toLowerCase();

    if (fileName.endsWith('.json')) {
      return this.parseJSON(text, file.name);
    } else if (fileName.endsWith('.nessus') || text.includes('<NessusClientData_v2>')) {
      return this.parseXML(text, file.name);
    } else {
      // Try JSON first, then XML
      try {
        return this.parseJSON(text, file.name);
      } catch (e) {
        return this.parseXML(text, file.name);
      }
    }
  }

  static parseJSON(jsonText, fileName) {
    const raw = JSON.parse(jsonText);
    if (raw.info && raw.hosts && raw.vulnerabilities) {
      return raw; // Already in dashboard format
    }
    // If it's a raw Nessus API export
    const client = new window.NessusApiClient();
    return client.transformScanData(raw);
  }

  /**
   * Parses official Tenable .nessus XML format
   */
  static parseXML(xmlText, fileName) {
    const parser = new DOMParser();
    const xmlDoc = parser.parseFromString(xmlText, 'text/xml');

    const parserError = xmlDoc.querySelector('parsererror');
    if (parserError) {
      throw new Error('Invalid .nessus XML file format: ' + parserError.textContent);
    }

    const reportElem = xmlDoc.querySelector('Report');
    const scanName = reportElem ? (reportElem.getAttribute('name') || fileName) : fileName;

    const reportHosts = Array.from(xmlDoc.querySelectorAll('ReportHost'));
    const hosts = [];
    const vulnsMap = {};
    const subnetsMap = {};

    reportHosts.forEach((hostElem, idx) => {
      const hostName = hostElem.getAttribute('name') || `Host-${idx + 1}`;
      
      // Parse HostProperties tags
      const properties = {};
      const tagNodes = hostElem.querySelectorAll('HostProperties tag');
      tagNodes.forEach(tag => {
        properties[tag.getAttribute('name')] = tag.textContent;
      });

      const ip = properties['host-ip'] || hostName;
      const fqdn = properties['host-fqdn'] || hostName;
      const mac = properties['mac-address'] || 'N/A';
      const os = properties['operating-system'] || properties['os'] || 'Identified by Nessus';
      const scanStart = properties['HOST_START'] || 'N/A';
      const scanEnd = properties['HOST_END'] || 'N/A';

      // Infer category & subnet
      const isServer = os.toLowerCase().includes('server') || os.toLowerCase().includes('linux');
      const isFirewall = os.toLowerCase().includes('forti') || os.toLowerCase().includes('cisco') || os.toLowerCase().includes('palo');
      const category = isFirewall ? 'firewall' : (isServer ? 'server' : 'workstation');
      
      const ipParts = ip.split('.');
      const subnet = ipParts.length === 4 ? `${ipParts[0]}.${ipParts[1]}.${ipParts[2]}.0/24` : '192.168.1.0/24';

      const hostVulnCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      const hostPorts = [];
      const portSeen = new Set();
      const hostVulnIds = [];

      // Parse ReportItems (Vulnerabilities & open ports)
      const reportItems = Array.from(hostElem.querySelectorAll('ReportItem'));
      reportItems.forEach(item => {
        const port = parseInt(item.getAttribute('port'), 10) || 0;
        const proto = item.getAttribute('protocol') || 'tcp';
        const svcName = item.getAttribute('svc_name') || 'unknown';
        const sevNum = parseInt(item.getAttribute('severity'), 10) || 0;
        const pluginId = parseInt(item.getAttribute('pluginID'), 10) || 0;
        const pluginName = item.getAttribute('pluginName') || 'Unknown Plugin';
        const pluginFamily = item.getAttribute('pluginFamily') || 'General';

        // Track port if not seen
        const portKey = `${port}/${proto}`;
        if (port > 0 && !portSeen.has(portKey)) {
          portSeen.add(portKey);
          hostPorts.push({
            port: port,
            proto: proto,
            service: svcName,
            banner: item.querySelector('plugin_output')?.textContent?.trim().slice(0, 120) || `${svcName} service active`
          });
        }

        // Tally severity
        const sevMap = ['info', 'low', 'medium', 'high', 'critical'];
        const sev = sevMap[sevNum] || 'info';
        hostVulnCounts[sev] += 1;
        hostVulnIds.push(pluginId);

        // Store or update global vulnerability entry
        if (!vulnsMap[pluginId]) {
          const cvss3 = parseFloat(item.querySelector('cvss3_base_score')?.textContent) || (sevNum * 2.5);
          const cve = item.querySelector('cve')?.textContent || 'N/A';
          const synopsis = item.querySelector('synopsis')?.textContent || pluginName;
          const description = item.querySelector('description')?.textContent || 'Detected by Nessus scanner.';
          const solution = item.querySelector('solution')?.textContent || 'Apply vendor patches.';
          const exploitAvailable = item.querySelector('exploit_available')?.textContent === 'true';
          const pluginOutput = item.querySelector('plugin_output')?.textContent || '';

          vulnsMap[pluginId] = {
            plugin_id: pluginId,
            name: pluginName,
            severity: sev,
            severity_num: sevNum,
            cvss3_score: cvss3,
            vpr_score: Math.min(10, cvss3 * 0.95),
            cve: cve,
            family: pluginFamily,
            exploit_available: exploitAvailable,
            exploit_frameworks: exploitAvailable ? ['Public / Metasploit'] : [],
            synopsis: synopsis,
            description: description,
            solution: solution,
            affected_hosts: [],
            packet_evidence: pluginOutput ? pluginOutput.slice(0, 400) : `Identified on port ${port}/${proto}`
          };
        }

        const hostLabel = `${ip} (${hostName})`;
        if (!vulnsMap[pluginId].affected_hosts.includes(hostLabel)) {
          vulnsMap[pluginId].affected_hosts.push(hostLabel);
        }
      });

      // Calculate host risk score
      const riskScore = Math.min(100, Math.round(
        hostVulnCounts.critical * 35 +
        hostVulnCounts.high * 15 +
        hostVulnCounts.medium * 5 +
        hostVulnCounts.low * 1
      ));

      hosts.push({
        id: `host-${idx + 1}`,
        ip: ip,
        hostname: hostName,
        fqdn: fqdn,
        mac: mac,
        vendor: 'Identified Asset',
        os: os,
        category: category,
        subnet: subnet,
        status: 'online',
        risk_score: riskScore,
        ports: hostPorts.sort((a, b) => a.port - b.port),
        vuln_counts: hostVulnCounts,
        vuln_ids: hostVulnIds
      });

      // Aggregate Subnet
      if (!subnetsMap[subnet]) {
        subnetsMap[subnet] = {
          cidr: subnet,
          name: `Subnet ${subnet}`,
          vlan_id: 10,
          description: `Discovered network segment containing ${subnet}`,
          total_hosts: 0,
          critical_vulns: 0
        };
      }
      subnetsMap[subnet].total_hosts += 1;
      subnetsMap[subnet].critical_vulns += hostVulnCounts.critical;
    });

    // Subnets array
    const subnets = Object.values(subnetsMap);

    // Total risk calculation
    const totalCrit = hosts.reduce((acc, h) => acc + h.vuln_counts.critical, 0);
    const overallRisk = Math.min(100, Math.round(totalCrit * 18 + hosts.length * 2 + 15));

    return {
      info: {
        id: `scan-imported-${Date.now()}`,
        name: scanName,
        status: 'completed',
        scanner_name: 'Nessus XML v2 Parser',
        scanner_ip: 'Imported File',
        targets: subnets.map(s => s.cidr).join(', ') || 'N/A',
        scan_start: 'Imported Scan Data',
        scan_end: new Date().toLocaleString(),
        duration: 'N/A',
        policy: 'Exported Nessus Scan Policy',
        total_packets_probed: hosts.length * 350,
        network_latency_avg: '1.5 ms',
        risk_score: overallRisk
      },
      subnets: subnets,
      hosts: hosts,
      vulnerabilities: Object.values(vulnsMap).sort((a, b) => b.severity_num - a.severity_num),
      packet_logs: []
    };
  }
}

if (typeof window !== 'undefined') {
  window.NessusFileParser = NessusFileParser;
}
