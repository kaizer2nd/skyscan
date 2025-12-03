// Dashboard JavaScript for SkyScan

const API_BASE_URL = '';
let currentScanDetail = null;
let selectedScanType = null;

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

// Select scan type
function selectScanType(type) {
    console.log('Selecting scan type:', type);
    selectedScanType = type;
    
    // Update card styling
    document.querySelectorAll('.scan-input-card').forEach(card => {
        card.classList.remove('active');
    });
    const selectedCard = document.getElementById(`scanCard-${type}`);
    if (selectedCard) {
        selectedCard.classList.add('active');
    }
    
    // Show input form
    const inputForm = document.getElementById('scanInputForm');
    if (inputForm) {
        inputForm.style.display = 'block';
    }
    
    // Hide all forms
    const forms = ['vulnerabilityForm', 'networkForm', 'cloudForm'];
    forms.forEach(formId => {
        const form = document.getElementById(formId);
        if (form) form.style.display = 'none';
    });
    
    // Show selected form
    const selectedForm = document.getElementById(`${type}Form`);
    if (selectedForm) {
        selectedForm.style.display = 'block';
        console.log('Form displayed:', `${type}Form`);
    } else {
        console.error('Form not found:', `${type}Form`);
    }
}

// Start vulnerability scan (comprehensive)
async function startVulnerabilityScan() {
    console.log('startVulnerabilityScan called');
    const targetInput = document.getElementById('vulnerabilityTarget');
    if (!targetInput) {
        console.error('Target input not found');
        showAlert('Error: Form not loaded properly', 'danger');
        return;
    }
    
    const target = targetInput.value.trim();
    console.log('Target:', target);
    
    if (!target) {
        showAlert('Please enter a target URL or IP address', 'warning');
        return;
    }
    
    try {
        console.log('Sending request to /api/scan/vulnerability');
        const response = await fetch(`${API_BASE_URL}/api/scan/vulnerability`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ target })
        });
        
        const data = await response.json();
        console.log('Response:', data);
        
        if (response.ok) {
            showAlert(`✓ Scan started successfully! ${data.message}`, 'success');
            targetInput.value = '';
            
            // Refresh history after a delay
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert(`Error: ${data.detail || 'Failed to start scan'}`, 'danger');
        }
    } catch (error) {
        console.error('Error starting vulnerability scan:', error);
        showAlert('Failed to start scan. Check console for details.', 'danger');
    }
}

// Start network scan
async function startNetworkScan() {
    console.log('startNetworkScan called');
    const target = document.getElementById('networkTarget').value.trim();
    const scanType = document.getElementById('networkScanType').value;
    console.log('Network target:', target, 'Type:', scanType);
    
    if (!target) {
        showAlert('Please enter a target IP or CIDR range', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/network`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ target, scan_type: scanType })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert(`Network scan started: ${data.message}`, 'success');
            document.getElementById('networkTarget').value = '';
            
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert(`Error: ${data.detail || 'Failed to start scan'}`, 'danger');
        }
    } catch (error) {
        console.error('Error starting network scan:', error);
        showAlert('Failed to start scan', 'danger');
    }
}

// Start cloud scan
async function startCloudScan() {
    console.log('startCloudScan called');
    try {
        const response = await fetch(`${API_BASE_URL}/api/scan/cloud`, {
            method: 'POST',
            headers: getAuthHeaders(),
            body: JSON.stringify({ config: null })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            showAlert(`Cloud scan started: ${data.message}`, 'success');
            
            setTimeout(loadScanHistory, 2000);
        } else {
            showAlert(`Error: ${data.detail || 'Failed to start scan'}`, 'danger');
        }
    } catch (error) {
        console.error('Error starting cloud scan:', error);
        showAlert('Failed to start scan', 'danger');
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
        tbody.innerHTML = `
            <tr>
                <td colspan="10" class="text-center text-muted py-4">
                    <i class="bi bi-inbox display-6"></i>
                    <p class="mt-2">No scans yet. Start your first scan above!</p>
                </td>
            </tr>
        `;
        return;
    }
    
    // Sort by timestamp (newest first)
    scans.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    tbody.innerHTML = scans.map(scan => {
        const counts = scan.severity_counts || {};
        const timestamp = new Date(scan.timestamp).toLocaleString();
        const status = scan.status || 'unknown';
        const riskLevel = scan.risk_level || 'Unknown';
        const target = scan.target || 'N/A';
        
        // Status badge
        let statusBadge = '';
        if (status === 'completed') {
            statusBadge = '<span class="badge bg-success">✓ Complete</span>';
        } else if (status === 'failed') {
            statusBadge = '<span class="badge bg-danger">✗ Failed</span>';
        } else if (status === 'running') {
            statusBadge = '<span class="badge bg-warning">⟳ Running</span>';
        } else {
            statusBadge = '<span class="badge bg-secondary">Pending</span>';
        }
        
        // Risk badge
        let riskBadge = `<span class="risk-badge risk-${riskLevel.toUpperCase()}">${riskLevel}</span>`;
        if (riskLevel === 'Unknown') {
            riskBadge = '<span class="badge bg-secondary">N/A</span>';
        }
        
        // Scan type badge
        let typeBadge = '';
        if (scan.scan_type === 'vulnerability') {
            typeBadge = '<span class="badge bg-primary"><i class="bi bi-shield-check"></i> Comprehensive</span>';
        } else if (scan.scan_type === 'network') {
            typeBadge = '<span class="badge bg-success"><i class="bi bi-radar"></i> Network</span>';
        } else if (scan.scan_type === 'cloud') {
            typeBadge = '<span class="badge bg-info"><i class="bi bi-cloud-check"></i> Cloud</span>';
        } else {
            typeBadge = `<span class="badge bg-secondary">${scan.scan_type}</span>`;
        }
        
        return `
            <tr>
                <td>${typeBadge}</td>
                <td class="text-truncate" style="max-width: 150px;" title="${target}">${target}</td>
                <td><small>${timestamp}</small></td>
                <td>${statusBadge}</td>
                <td>${riskBadge}</td>
                <td class="text-center"><span class="badge bg-danger">${counts.CRITICAL || 0}</span></td>
                <td class="text-center"><span class="badge bg-warning">${counts.HIGH || 0}</span></td>
                <td class="text-center"><span class="badge bg-info">${counts.MEDIUM || 0}</span></td>
                <td class="text-center"><span class="badge bg-secondary">${counts.LOW || 0}</span></td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="viewScanDetail('${scan.scan_id}')">
                        <i class="bi bi-eye"></i> View
                    </button>
                </td>
            </tr>
        `;
    }).join('');
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
            displayScanDetail(scan);
        } else {
            showAlert('Failed to load scan details', 'danger');
        }
    } catch (error) {
        console.error('Error loading scan detail:', error);
        showAlert('Failed to load scan details', 'danger');
    }
}

// Display scan detail in modal
function displayScanDetail(scan) {
    const modalContent = document.getElementById('scanDetailContent');
    
    // Build report content based on scan type
    let reportHTML = '';
    
    if (scan.scan_type === 'vulnerability') {
        // Show formatted text report for vulnerability scan
        reportHTML = `
            <div class="mb-3">
                <h6><strong>Target:</strong> ${scan.target || 'N/A'}</h6>
                <h6><strong>Scan ID:</strong> ${scan.scan_id}</h6>
                <h6><strong>Timestamp:</strong> ${new Date(scan.timestamp).toLocaleString()}</h6>
                <h6><strong>Risk Level:</strong> <span class="risk-badge risk-${(scan.risk_level || 'Unknown').toUpperCase()}">${scan.risk_level || 'Unknown'}</span></h6>
                <h6><strong>Severity Score:</strong> ${scan.severity_score || 0}/100</h6>
            </div>
            <hr>
            <pre class="report-text">${scan.formatted_report || 'No formatted report available'}</pre>
        `;
    } else {
        // Show JSON report for other scan types
        const report = scan.full_report_json || {};
        reportHTML = `
            <div class="mb-3">
                <h6><strong>Scan ID:</strong> ${scan.scan_id}</h6>
                <h6><strong>Type:</strong> ${scan.scan_type}</h6>
                <h6><strong>Timestamp:</strong> ${new Date(scan.timestamp).toLocaleString()}</h6>
                <h6><strong>Status:</strong> ${scan.status}</h6>
            </div>
            <hr>
            <h6 class="mb-3">Summary:</h6>
            <p>${scan.summary || 'No summary available'}</p>
            <hr>
            <h6 class="mb-3">Severity Breakdown:</h6>
            <div class="row">
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-danger">${(scan.severity_counts || {}).CRITICAL || 0}</h3>
                            <small>Critical</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-warning">${(scan.severity_counts || {}).HIGH || 0}</h3>
                            <small>High</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-info">${(scan.severity_counts || {}).MEDIUM || 0}</h3>
                            <small>Medium</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="card text-center">
                        <div class="card-body">
                            <h3 class="text-secondary">${(scan.severity_counts || {}).LOW || 0}</h3>
                            <small>Low</small>
                        </div>
                    </div>
                </div>
            </div>
            <hr>
            <h6 class="mb-3">Full Report Data:</h6>
            <pre class="report-text">${JSON.stringify(report, null, 2)}</pre>
        `;
    }
    
    modalContent.innerHTML = reportHTML;
    
    // Show modal
    const modal = new bootstrap.Modal(document.getElementById('scanDetailModal'));
    modal.show();
}

// Download report
function downloadReport() {
    if (!currentScanDetail) {
        showAlert('No scan detail loaded', 'warning');
        return;
    }
    
    const reportContent = currentScanDetail.formatted_report || 
                         JSON.stringify(currentScanDetail.full_report_json, null, 2);
    
    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `skyscan-report-${currentScanDetail.scan_id}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showAlert('Report downloaded successfully', 'success');
}
