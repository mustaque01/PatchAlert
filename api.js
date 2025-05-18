const API_BASE = "http://localhost:5000/api";

async function fetchVulnerabilities() {
  const response = await fetch(`${API_BASE}/vulnerabilities`);
  return await response.json();
}
