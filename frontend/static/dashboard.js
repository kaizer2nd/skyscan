// Dashboard JavaScript

const API_BASE_URL = '';
let currentScanDetail = null;

// Check authentication on page load
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('access_token');
    if (!token) {
        window.location.href = '/login';
        return;
    }
    
    loadUserInfo();
    loadScanHistory();
    
    // Set up auto-refresh every 30 seconds
    setInterval(loadScanHistory, 30000);
});

// Logout handler
document.getElementById('logoutBtn').addEventListener('click', () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('user_email');
    window.location.href = '/login';
});

// Helper function to get auth headers
function getAuthHeaders() {
    const token = localStorage.getItem('access_token');
    return {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
    };
}

// Show alert
function showAlert(message, type = 'info') {
    const alertContainer = document.getElementById('alert-container');
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} alert-dismissible fade show`;
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    alertContainer.appendChild(alert);
    
    setTimeout(() => alert.remove(), 5000);
}

// Load user information
async function loadUserInfo() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/user/info`, {
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            const data = await response.json();
            document.getElementById('userEmail').textContent = data.email;
        } else if (response.status === 401) {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error loading user info:', error);
    }
}

// Load scan history
async function loadScanHistory() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/user/history`, {
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            const scans = await response.json();
            updateDashboardStats(scans);
            renderScanHistory(scans);
        } else if (response.status === 401) {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Error loading scan history:', error);
    }
}

// Update dashboard statistics
function updateDashboardStats(scans) {
    document.getElementById('totalScans').textContent = scans.length;
    
    let criticalTotal = 0;
    let highTotal = 0;
    let mediumLowTotal = 0;
    
    scans.forEach(scan => {
        const counts = scan.severity_counts || {};
        criticalTotal += counts.CRITICAL || 0;
        highTotal += counts.HIGH || 0;
        mediumLowTotal += (counts.MEDIUM || 0) + (counts.LOW || 0);
    });
    
    document.getElementById('criticalCount').textContent = criticalTotal;
    document.getElementById('highCount').textContent = highTotal;
    document.getElementById('mediumLowCount').textContent = mediumLowTotal;
}

// Render scan history table
function renderScanHistory(scans) {
    const tbody = document.getElementById('scanHistoryTable');
    
    if (scans.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="text-center">No scans found. Start your first scan above!</td></tr>';
        return;
    }
    
    tbody.innerHTML = scans.map(scan => {
        const counts = scan.severity_counts || {};
        const statusBadge = getStatusBadge(scan.status);
        const scanId = scan.scan_id.substring(0, 8);
        
        return `
            <tr>
                <td><code>${scanId}...</code></td>
                <td><span class="badge bg-secondary">${scan.scan_type}</span></td>
                <td>${formatDate(scan.timestamp)}</td>
                <td>${statusBadge}</td>
                <td><span class="severity-critical">${counts.CRITICAL || 0}</span></td>
                <td><span class="severity-high">${counts.HIGH || 0}</span></td>
                <td><span class="severity-medium">${counts.MEDIUM || 0}</span></td>
                <td><span class="severity-low">${counts.LOW || 0}</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="viewScanDetail('${scan.scan_id}')">
                        <i class="bi bi-eye"></i> View
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

// Get status badge HTML
function getStatusBadge(status) {
    const badges = {
        'completed': '<span class="badge bg-success">Completed</span>',
        'running': '<span class="badge bg-warning">Running</span>',
        'failed': '<span class="badge bg-danger">Failed</span>',
        'pending': '<span class="badge bg-secondary">Pending</span>'
    };
    return badges[status] || badges['pending'];
}

// Format date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString();
}

// Start Network Scan
async function startNetworkScan() {
    const target = prompt('Enter target IP address or hostname:\n(e.g., scanme.nmap.org, 127.0.0.1)', 'scanme.nmap.org');
    
    if (!target) return;
    
    showAlert(`Starting network scan on ${target}...`, 'info');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/network`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                target: target,
                scan_type: 'quick'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert(`Scan started successfully! ID: ${data.scan_id.substring(0, 8)}`, 'success');
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert('Failed to start scan: ' + data.detail, 'danger');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        showAlert('Error starting scan. Please try again.', 'danger');
    }
}

// Start Cloud Scan
async function startCloudScan() {
    if (!confirm('Start a cloud configuration scan?')) return;
    
    showAlert('Starting cloud scan...', 'info');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/cloud`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                config: null  // Uses demo config
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert(`Scan started successfully! ID: ${data.scan_id.substring(0, 8)}`, 'success');
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert('Failed to start scan: ' + data.detail, 'danger');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        showAlert('Error starting scan. Please try again.', 'danger');
    }
}

// Start Full Scan
async function startFullScan() {
    const target = prompt(
        'Enter target IP address or hostname for full scan:\n(e.g., scanme.nmap.org, 127.0.0.1)', 
        'scanme.nmap.org'
    );
    
    if (!target) return;
    
    showAlert(`Starting comprehensive scan on ${target}...`, 'info');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/full`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({
                target: target,
                scan_type: 'full'
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert(`Full scan started successfully on ${target}! ID: ${data.scan_id.substring(0, 8)}`, 'success');
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert('Failed to start scan: ' + data.detail, 'danger');
        }
    } catch (error) {
        console.error('Error starting scan:', error);
        showAlert('Error starting scan. Please try again.', 'danger');
    }
}

// View scan detail
async function viewScanDetail(scanId) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/user/scan/${scanId}`, {
            headers: getAuthHeaders()
        });
        
        if (response.ok) {
            const scan = await response.json();
            currentScanDetail = scan;
            renderScanDetail(scan);
            
            const modal = new bootstrap.Modal(document.getElementById('scanDetailModal'));
            modal.show();
        } else {
            showAlert('Failed to load scan details', 'danger');
        }
    } catch (error) {
        console.error('Error loading scan detail:', error);
        showAlert('Error loading scan details', 'danger');
    }
}

// Render scan detail modal
function renderScanDetail(scan) {
    const report = scan.full_report_json || {};
    const execSummary = report.executive_summary || {};
    const vulnerabilities = report.vulnerability_details || [];
    const remediationPlan = report.remediation_plan || [];
    
    const content = `
        <div class="scan-detail">
            <h4>Scan ID: ${scan.scan_id}</h4>
            <p><strong>Type:</strong> ${scan.scan_type} | <strong>Status:</strong> ${scan.status}</p>
            <p><strong>Timestamp:</strong> ${formatDate(scan.timestamp)}</p>
            
            <hr>
            
            <h5>Executive Summary</h5>
            <div class="alert alert-${getRiskAlertType(execSummary.risk_level)}">
                <strong>Risk Level:</strong> ${execSummary.risk_level || 'N/A'} 
                <strong>Risk Score:</strong> ${execSummary.risk_score || 0}/10
            </div>
            <p>${execSummary.summary || scan.summary}</p>
            
            <h5>Severity Breakdown</h5>
            <div class="row mb-3">
                <div class="col-md-3">
                    <div class="card bg-danger text-white">
                        <div class="card-body text-center">
                            <h3>${scan.severity_counts.CRITICAL || 0}</h3>
                            <p class="mb-0">Critical</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-warning text-white">
                        <div class="card-body text-center">
                            <h3>${scan.severity_counts.HIGH || 0}</h3>
                            <p class="mb-0">High</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-info text-white">
                        <div class="card-body text-center">
                            <h3>${scan.severity_counts.MEDIUM || 0}</h3>
                            <p class="mb-0">Medium</p>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card bg-secondary text-white">
                        <div class="card-body text-center">
                            <h3>${scan.severity_counts.LOW || 0}</h3>
                            <p class="mb-0">Low</p>
                        </div>
                    </div>
                </div>
            </div>
            
            ${vulnerabilities.length > 0 ? `
                <h5>Vulnerabilities (Top 10)</h5>
                <div class="table-responsive">
                    <table class="table table-sm">
                        <thead>
                            <tr>
                                <th>CVE ID</th>
                                <th>Description</th>
                                <th>Severity</th>
                                <th>CVSS</th>
                                <th>Asset</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${vulnerabilities.slice(0, 10).map(v => `
                                <tr>
                                    <td><code>${v.cve_id}</code></td>
                                    <td>${v.description.substring(0, 60)}...</td>
                                    <td><span class="severity-${v.severity.toLowerCase()}">${v.severity}</span></td>
                                    <td>${v.cvss_score}</td>
                                    <td>${v.asset_ip || 'N/A'}</td>
                                </tr>
                            `).join('')}
                        </tbody>
                    </table>
                </div>
            ` : '<p>No vulnerabilities found.</p>'}
            
            ${remediationPlan.length > 0 ? `
                <h5>Remediation Plan (Top 5)</h5>
                <div class="accordion" id="remediationAccordion">
                    ${remediationPlan.slice(0, 5).map((item, index) => `
                        <div class="accordion-item">
                            <h2 class="accordion-header" id="heading${index}">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse${index}">
                                    <strong>${item.priority}</strong>: ${item.cve_id} - ${item.affected_service || 'N/A'}
                                </button>
                            </h2>
                            <div id="collapse${index}" class="accordion-collapse collapse" data-bs-parent="#remediationAccordion">
                                <div class="accordion-body">
                                    <p><strong>Action:</strong> ${item.recommended_action}</p>
                                    <p><strong>Effort:</strong> ${item.estimated_effort}</p>
                                    <p><strong>Risk Reduction:</strong> ${item.risk_reduction}%</p>
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            ` : ''}
        </div>
    `;
    
    document.getElementById('scanDetailContent').innerHTML = content;
}

// Get risk alert type
function getRiskAlertType(riskLevel) {
    const types = {
        'CRITICAL': 'danger',
        'HIGH': 'warning',
        'MEDIUM': 'info',
        'LOW': 'success',
        'NONE': 'secondary'
    };
    return types[riskLevel] || 'info';
}

// Download report
function downloadReport() {
    if (!currentScanDetail) return;
    
    const dataStr = JSON.stringify(currentScanDetail.full_report_json, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `scan_report_${currentScanDetail.scan_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
}
