/**
 * Clean Empty Dataset for Tenable Nessus SOC Dashboard
 * Ready for live API synchronization or file import
 */

const OFFICE_NETWORK_MOCK = {
  info: {
    id: null,
    name: "No Scan Data Loaded",
    status: "Standby",
    scanner_name: "Tenable Nessus",
    scanner_ip: "—",
    targets: "No target subnet specified",
    scan_start: "—",
    scan_end: "—",
    duration: "—",
    policy: "—",
    total_packets_probed: 0,
    network_latency_avg: "—",
    risk_score: 0
  },
  subnets: [],
  hosts: [],
  vulnerabilities: [],
  packet_logs: []
};

if (typeof window !== 'undefined') {
  window.OFFICE_NETWORK_MOCK = OFFICE_NETWORK_MOCK;
}
