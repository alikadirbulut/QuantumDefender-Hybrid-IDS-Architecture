// QuantumDefender Cloud v9.0 — Next-Gen Advanced SOC Dashboard

const socket = io();

// --- Global state ---
let table;
let totalEvents = 0;
let totalAlerts = 0;
let uniqueAgents = new Set();
let sourceCounts = {};
let protoCounts = {};
let agentCounts = {};
let threatCounts = {};
let alertsChart, protoChart, sourceChart, agentChart, threatChart, eventsChart;
let alertSeries = [], alertLabels = [];
let eventsSeries = [], eventsLabels = [];
let startTime = Date.now();
let alertOnlyFilter = false;
let currentDeviceId = null; // Global device ID for device management

// --- Initialize ---
$(document).ready(() => {
  // Theme initialization
  try {
    const savedTheme = localStorage.getItem('qd-theme');
    if (savedTheme === 'light') {
      $('body').addClass('light-theme');
      $('#themeToggleIcon').removeClass('bi-moon-stars').addClass('bi-sun');
    }
  } catch (e) {
    // ignore storage errors
  }

  initNavigation();
  initTable();
  initCharts();
  initEventHandlers();

  // Mobile sidebar toggle
  $('#sidebarToggle').on('click', () => {
    $('.sidebar').toggleClass('open');
  });

  fetchStats();
  updateUptime();
  setInterval(updateUptime, 1000);
  setInterval(fetchStats, 10000);
  setInterval(fetchAnalytics, 30000); // Refresh analytics every 30 seconds
  
  // Auto-refresh devices if on devices view
  setInterval(() => {
    if ($('#view-devices').is(':visible') && !$('#view-devices').hasClass('hidden')) {
      fetchDevices();
    }
  }, 15000); // Every 15 seconds
  setInterval(fetchThreats, 15000);
  setInterval(fetchAgents, 15000);

  socket.on('connect', () => {
    setCloudStatus('Cloud: Ready', true);
    console.log('Connected to QuantumDefender Cloud');
  });
  
  socket.on('disconnect', () => {
    setCloudStatus('Cloud: Disconnected', false);
  });
  
  socket.on('connect_error', () => {
    setCloudStatus('Cloud: Error', false);
  });
});

// ===== Navigation =====
function initNavigation() {
  $('.sidebar li').on('click', function () {
    $('.sidebar li').removeClass('active');
    $(this).addClass('active');
    const view = $(this).data('view');
    $('.view-section').addClass('hidden');
    $(`#view-${view}`).removeClass('hidden');
    
    // Load data when switching views
    if (view === 'threats') {
      fetchThreats();
      loadThreatTabs();
      fetch('/api/threats/stats')
        .then(r => r.json())
        .then(data => {
          $('#threatCritical').text(data.critical || 0);
          $('#threatActiveIPs').text(data.active_ips || 0);
          $('#threatSuspiciousURLs').text(data.suspicious_urls || 0);
        });
    }
    if (view === 'agents') {
      fetchAgents();
      fetchEnhancedAgents();
    }
    if (view === 'devices') {
      fetchDevices();
      fetchEnhancedDevices();
    }
    if (view === 'export') updateExportStats();
    if (view === 'map') fetchGeoMap();
    if (view === 'analytics') {
      populateAgentFilter();
      fetchEnhancedAnalytics();
      fetchAnalytics();
    }
    if (view === 'signatures') {
      loadSignatures();
      fetchEnhancedSignatures();
    }
  });
}

// ===== DataTable =====
function initTable() {
  table = $('#eventsTable').DataTable({
    order: [[0, 'desc']],
    pageLength: 25,
    lengthMenu: [[10, 25, 50, 100], [10, 25, 50, 100]],
    columns: [
      { data: 'timestamp', width: '12%' },
      { data: 'agent_id', width: '8%' },
      { data: 'host', width: '10%' },
      { data: 'conn', width: '15%' },
      { data: 'protocol', width: '8%' },
      { data: 'bytes', width: '10%' },
      { data: 'region', width: '8%' },
      { data: 'url', width: '15%' },
      { data: 'score', width: '8%' },
      { data: 'detection_source', width: '8%' },
      { data: 'status', width: '8%' }
    ],
    language: {
      search: "Search events:",
      lengthMenu: "Show _MENU_ events per page",
      info: "Showing _START_ to _END_ of _TOTAL_ events",
      infoEmpty: "No events available",
      zeroRecords: "No matching events found"
    }
  });

  // Click row -> details modal
  $('#eventsTable tbody').on('click', 'tr', function () {
    const data = table.row(this).data();
    if (!data) return;
    const raw = data._raw || data;
    const json = JSON.stringify(raw, null, 2);
    $('#eventDetails').html(`<pre>${json}</pre>`);
    new bootstrap.Modal(document.getElementById('eventModal')).show();
  });
}

// ===== Event Handlers =====
function initEventHandlers() {
  $('#btnFilterAlerts').on('click', function() {
    alertOnlyFilter = !alertOnlyFilter;
    $(this).html(alertOnlyFilter ? 
      '<i class="bi bi-funnel-fill"></i> Show All' : 
      '<i class="bi bi-funnel"></i> Filter Alerts');
    
    table.column(10).search(alertOnlyFilter ? 'ALERT' : '').draw();
  });

  $('#btnClearFeed').on('click', function() {
    if (confirm('Clear all events from the feed?')) {
      table.clear().draw();
      totalEvents = 0;
      totalAlerts = 0;
      uniqueAgents.clear();
      updateMetrics();
    }
  });

  $('#btnAddSig').on('click', () => {
    new bootstrap.Modal(document.getElementById('sigModal')).show();
  });

  $('#sigForm').on('submit', function(e) {
    e.preventDefault();
    const data = {
      name: $('#sigName').val(),
      rule: $('#sigRule').val(),
      severity: $('#sigSeverity').val(),
      type: $('#sigType').val() || 'url',
      enabled: $('#sigEnabled').is(':checked')
    };
    
    fetch('/api/add_signature', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
      .then(r => r.json())
      .then(res => {
        $('#sigModal').modal('hide');
        $('#sigForm')[0].reset();
        loadSignatures();
        fetchEnhancedSignatures();
        showNotification('Signature added successfully', 'success');
      })
      .catch(err => {
        showNotification('Failed to add signature', 'error');
        console.error(err);
      });
  });

  $('#btnRefreshThreats').on('click', fetchThreats);
  $('#btnRefreshAgents').on('click', fetchAgents);
  $('#btnRefreshDevices').on('click', fetchDevices);
  $('#btnRefreshGeo').on('click', fetchGeoMap);
  
  $('#btnExportJSON').on('click', () => exportData('json', false));
  $('#btnExportAlerts').on('click', () => exportData('json', true));
  $('#btnExportCSV').on('click', () => exportData('csv', false));

  // Theme toggle
  $('#themeToggle').on('click', () => {
    const body = $('body');
    const icon = $('#themeToggleIcon');
    const isLight = body.hasClass('light-theme');
    if (isLight) {
      body.removeClass('light-theme');
      icon.removeClass('bi-sun').addClass('bi-moon-stars');
      try { localStorage.setItem('qd-theme', 'dark'); } catch (e) {}
    } else {
      body.addClass('light-theme');
      icon.removeClass('bi-moon-stars').addClass('bi-sun');
      try { localStorage.setItem('qd-theme', 'light'); } catch (e) {}
    }
  });
  
  // Device management handlers
  // Note: currentDeviceId is declared globally above
  
  // Use event delegation for buttons that might be in modals
  $(document).on('click', '#btnSendNotification', function() {
    console.log('btnSendNotification clicked, currentDeviceId:', currentDeviceId);
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    console.log('Opening notification modal for device:', currentDeviceId);
    const modal = new bootstrap.Modal(document.getElementById('notificationModal'));
    modal.show();
  });
  
  $(document).on('click', '#btnDropConnection', function() {
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    console.log('Opening drop connection modal for device:', currentDeviceId);
    const modal = new bootstrap.Modal(document.getElementById('dropConnectionModal'));
    modal.show();
  });
  
  $(document).on('click', '#btnRestartCapture', function() {
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    if (confirm(`Restart capture on device ${currentDeviceId}?`)) {
      console.log('Sending restart command to device:', currentDeviceId);
      fetch(`/api/devices/${currentDeviceId}/restart_capture`, { 
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })
        .then(r => {
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          return r.json();
        })
        .then(res => {
          console.log('Restart command response:', res);
          showNotification('Restart command sent successfully', 'success');
          $('#deviceModal').modal('hide');
        })
        .catch(err => {
          console.error('Restart command error:', err);
          showNotification(`Failed to send command: ${err.message}`, 'error');
        });
    }
  });
  
  $(document).on('click', '#btnBlockIP', function() {
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    console.log('Opening block IP modal for device:', currentDeviceId);
    const modal = new bootstrap.Modal(document.getElementById('blockIPModal'));
    modal.show();
  });
  
  $(document).on('click', '#btnViewConnections', function() {
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    console.log('Loading connections for device:', currentDeviceId);
    fetch(`/api/devices/${currentDeviceId}/info`)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then(info => {
        console.log('Device info:', info);
        const connectionsHtml = info.recent_events && info.recent_events.length > 0
          ? info.recent_events.map(e => `
            <tr>
              <td>${formatTimestamp(e.ts || e.timestamp)}</td>
              <td>${e.src_ip || 'N/A'}</td>
              <td>${e.dst_ip || 'N/A'}</td>
              <td>${e.protocol || 'N/A'}</td>
              <td>${formatBytes(e.bytes_sent || 0)}</td>
              <td><span class="badge bg-${e.alert ? 'danger' : 'success'}">${e.alert ? 'ALERT' : 'OK'}</span></td>
            </tr>
          `).join('')
          : '<tr><td colspan="6" class="text-center text-muted">No recent connections</td></tr>';
        
        const modalHtml = `
          <div class="modal fade" id="connectionsModal" tabindex="-1">
            <div class="modal-dialog modal-xl modal-dialog-centered">
              <div class="modal-content">
                <div class="modal-header">
                  <h5 class="modal-title"><i class="bi bi-diagram-3"></i> Active Connections - ${currentDeviceId}</h5>
                  <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body">
                  <div class="table-responsive">
                    <table class="table table-dark table-striped">
                      <thead>
                        <tr>
                          <th>Time</th><th>Source IP</th><th>Dest IP</th><th>Protocol</th><th>Bytes</th><th>Status</th>
                        </tr>
                      </thead>
                      <tbody>${connectionsHtml}</tbody>
                    </table>
                  </div>
                </div>
              </div>
            </div>
          </div>`;
        $('body').append(modalHtml);
        const connectionsModal = new bootstrap.Modal(document.getElementById('connectionsModal'));
        connectionsModal.show();
        $('#connectionsModal').on('hidden.bs.modal', function() {
          $(this).remove();
        });
      })
      .catch(err => {
        console.error('Failed to load connections:', err);
        showNotification(`Failed to load connections: ${err.message}`, 'error');
      });
  });
  
  $(document).on('click', '#btnUpdateConfig', function() {
    if (!currentDeviceId) {
      alert('No device selected. Please select a device first.');
      return;
    }
    const config = prompt('Enter JSON configuration:\nExample: {"batch_size": 30, "send_interval": 5.0}');
    if (config) {
      try {
        const parsed = JSON.parse(config);
        console.log('Sending config update:', parsed);
        fetch(`/api/devices/${currentDeviceId}/update_config`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(parsed)
        })
          .then(r => {
            if (!r.ok) throw new Error(`HTTP ${r.status}`);
            return r.json();
          })
          .then(res => {
            console.log('Config update response:', res);
            showNotification('Configuration update sent successfully', 'success');
            $('#deviceModal').modal('hide');
          })
          .catch(err => {
            console.error('Config update error:', err);
            showNotification(`Failed to update config: ${err.message}`, 'error');
          });
      } catch (e) {
        showNotification(`Invalid JSON format: ${e.message}`, 'error');
      }
    }
  });
  
  
  // Form handlers with better error handling
  $(document).on('submit', '#notificationForm', function(e) {
    e.preventDefault();
    if (!currentDeviceId) {
      alert('No device selected');
      return false;
    }
    
    const title = $('#notifTitle').val().trim();
    const message = $('#notifMessage').val().trim();
    
    if (!title || !message) {
      alert('Please fill in both title and message');
      return false;
    }
    
    console.log('Sending notification to device:', currentDeviceId, { title, message });
    
    fetch(`/api/devices/${currentDeviceId}/send_notification`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, message })
    })
      .then(r => {
        if (!r.ok) {
          return r.json().then(err => { throw new Error(err.error || `HTTP ${r.status}`); });
        }
        return r.json();
      })
      .then(res => {
        console.log('Notification sent:', res);
        showNotification('Notification sent successfully!', 'success');
        $('#notificationModal').modal('hide');
        $('#notificationForm')[0].reset();
      })
      .catch(err => {
        console.error('Notification error:', err);
        showNotification(`Failed to send notification: ${err.message}`, 'error');
      });
    
    return false;
  });
  
  // Handle drop connection type change
  $(document).on('change', '#dropType', function() {
    const type = $(this).val();
    if (type === 'domain') {
      $('#dropIP').hide();
      $('#dropDomainWrapper').show();
      $('#dropLabel').text('Target Domain Name');
      $('#dropHint').text('Enter domain name (e.g., example.com)');
    } else if (type === 'cidr') {
      $('#dropIP').show();
      $('#dropDomainWrapper').hide();
      $('#dropLabel').text('Target CIDR/Subnet');
      $('#dropHint').text('Enter CIDR (e.g., 192.168.1.0/24)');
    } else {
      $('#dropIP').show();
      $('#dropDomainWrapper').hide();
      $('#dropLabel').text('Target IP Address');
      $('#dropHint').text('Enter IP address (e.g., 192.168.1.100)');
    }
  });
  
  $(document).on('submit', '#dropConnectionForm', function(e) {
    e.preventDefault();
    if (!currentDeviceId) {
      alert('No device selected');
      return false;
    }
    
    const dropType = $('#dropType').val();
    const ip = $('#dropIP').val().trim();
    const domain = $('#dropDomain').val().trim();
    const port = $('#dropPort').val().trim();
    
    if (dropType === 'ip') {
      if (!ip) {
        alert('Please enter an IP address');
        return false;
      }
      // Validate IP format
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
        alert('Invalid IP address format');
        return false;
      }
    } else if (dropType === 'domain') {
      if (!domain) {
        alert('Please enter a domain name');
        return false;
      }
      // Basic domain validation
      if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(domain)) {
        alert('Invalid domain format');
        return false;
      }
    } else if (dropType === 'cidr') {
      if (!ip) {
        alert('Please enter a CIDR');
        return false;
      }
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(ip)) {
        alert('Invalid CIDR format (expected: x.x.x.x/y)');
        return false;
      }
    }
    
    const dropData = { port: port || null };
    if (dropType === 'ip') {
      dropData.ip = ip;
    } else if (dropType === 'domain') {
      dropData.domain = domain;
    } else if (dropType === 'cidr') {
      dropData.cidr = ip;
    }
    
    console.log('Dropping connection:', dropData, 'device:', currentDeviceId);
    
    fetch(`/api/devices/${currentDeviceId}/drop_connection`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(dropData)
    })
      .then(r => {
        if (!r.ok) {
          return r.json().then(err => { throw new Error(err.error || `HTTP ${r.status}`); });
        }
        return r.json();
      })
      .then(res => {
        console.log('Connection drop sent:', res);
        const target = ip || domain;
        showNotification(`Connection drop command sent for ${target}${port ? ':' + port : ''}`, 'success');
        $('#dropConnectionModal').modal('hide');
        $('#dropConnectionForm')[0].reset();
        $('#dropIP').show();
        $('#dropDomainWrapper').hide();
      })
      .catch(err => {
        console.error('Drop connection error:', err);
        showNotification(`Failed to drop connection: ${err.message}`, 'error');
      });
    
    return false;
  });
  
  // Handle block type change
  $(document).on('change', '#blockType', function() {
    const type = $(this).val();
    const label = $('#blockLabel');
    const input = $('#blockIP');
    const hint = $('#blockHint');
    
    if (type === 'ip') {
      label.text('IP Address to Block');
      input.attr('placeholder', '192.168.1.100');
      hint.text('Enter IP address (e.g., 192.168.1.100)');
    } else if (type === 'domain') {
      label.text('Domain Name to Block');
      input.attr('placeholder', 'example.com');
      hint.text('Enter domain name (e.g., example.com)');
    } else if (type === 'cidr') {
      label.text('CIDR/Subnet to Block');
      input.attr('placeholder', '192.168.1.0/24');
      hint.text('Enter CIDR notation (e.g., 192.168.1.0/24 or 0.0.0.0/0)');
    }
  });
  
  $(document).on('submit', '#blockIPForm', function(e) {
    e.preventDefault();
    if (!currentDeviceId) {
      alert('No device selected');
      return false;
    }
    
    const blockType = $('#blockType').val();
    const value = $('#blockIP').val().trim();
    const reason = $('#blockReason').val().trim() || 'Blocked from cloud dashboard';
    
    if (!value) {
      alert(`Please enter a ${blockType === 'ip' ? 'IP address' : blockType === 'domain' ? 'domain name' : 'CIDR'}`);
      return false;
    }
    
    // Validate based on type
    if (blockType === 'ip') {
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
        alert('Invalid IP address format');
        return false;
      }
    } else if (blockType === 'domain') {
      if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/.test(value)) {
        alert('Invalid domain format');
        return false;
      }
    } else if (blockType === 'cidr') {
      if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$/.test(value)) {
        alert('Invalid CIDR format (expected: x.x.x.x/y)');
        return false;
      }
    }
    
    const blockData = { agent_id: currentDeviceId, reason };
    if (blockType === 'ip') {
      blockData.ip = value;
    } else if (blockType === 'domain') {
      blockData.domain = value;
    } else if (blockType === 'cidr') {
      blockData.cidr = value;
    }
    
    console.log('Blocking:', blockData);
    
    fetch(`/api/firewall/block`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(blockData)
    })
      .then(r => {
        if (!r.ok) {
          return r.json().then(err => { throw new Error(err.error || `HTTP ${r.status}`); });
        }
        return r.json();
      })
      .then(res => {
        console.log('Block result:', res);
        const target = value;
        showNotification(`${blockType.toUpperCase()} ${target} blocked successfully!`, 'success');
        $('#blockIPModal').modal('hide');
        $('#blockIPForm')[0].reset();
        $('#blockType').val('ip');
      })
      .catch(err => {
        console.error('Block error:', err);
        showNotification(`Failed to block: ${err.message}`, 'error');
      });
    
    return false;
  });
}

// ===== Socket Events =====
socket.on('new_event', e => {
  totalEvents++;
  if (e.alert) totalAlerts++;
  uniqueAgents.add(e.agent_id);

  updateMetrics();

  const conn = `${e.src_ip || 'N/A'} → ${e.dst_ip || 'N/A'}`;
  const score = typeof e.score === 'number' ? e.score.toFixed(3) : (e.score || '0.000');
  const source = e.detection_source || 'unknown';
  const statusBadge = e.alert
    ? '<span class="badge bg-danger">ALERT</span>'
    : '<span class="badge bg-success">OK</span>';

  // Fix bytes display - handle both numeric and string formats
  let bytesSent = e.bytes_sent || e.bytes_sent_formatted || 0;
  let bytesRecv = e.bytes_recv || e.bytes_recv_formatted || 0;
  
  // If already formatted as string, use it; otherwise format it
  const bytesDisplay = (e.bytes_sent_formatted && e.bytes_recv_formatted)
    ? `${e.bytes_sent_formatted}/${e.bytes_recv_formatted}`
    : `${formatBytes(parseFloat(bytesSent) || 0)}/${formatBytes(parseFloat(bytesRecv) || 0)}`;

  const row = {
    timestamp: formatTimestamp(e.timestamp),
    agent_id: `<code>${e.agent_id}</code>`,
    host: e.host || 'N/A',
    conn: `<small>${conn}</small>`,
    protocol: `<span class="badge bg-primary">${e.protocol || 'N/A'}</span>`,
    bytes: bytesDisplay,
    region: e.region || 'Unknown',
    url: e.url ? `<a href="${e.url}" target="_blank" rel="noopener" class="text-info">${truncate(e.url, 40)}</a>` : 'N/A',
    score: `<code>${score}</code>`,
    detection_source: `<span class="badge bg-primary">${source}</span>`,
    status: statusBadge,
    _raw: e
  };

  const node = table.row.add(row).draw(false).node();
  if (e.alert) {
    $(node).addClass('table-danger');
    // Animate alert row
    $(node).css('animation', 'pulse 0.5s ease');
  }

  // Update stats
  protoCounts[e.protocol] = (protoCounts[e.protocol] || 0) + 1;
  sourceCounts[e.detection_source] = (sourceCounts[e.detection_source] || 0) + 1;
  agentCounts[e.agent_id] = (agentCounts[e.agent_id] || 0) + 1;
  
  if (e.alert && e.reason) {
    threatCounts[e.reason] = (threatCounts[e.reason] || 0) + 1;
  }

  updateCharts();

  // Alert toast when malicious traffic is detected
  if (e.alert) {
    showAlertToast(e);
  }
});

socket.on('alert_notification', data => {
  console.log('Alert notification:', data);
});

socket.on('ingest_ack', payload => {
  $('#ingestPill').text(`Ingest: ${payload.count} events`);
  $('#ingestPill').addClass('ok');
  setTimeout(() => $('#ingestPill').removeClass('ok'), 2000);
});

socket.on('signature_added', sig => {
  loadSignatures();
  showNotification('New signature added', 'info');
});

// ===== Charts =====
function initCharts() {
  const chartOptions = {
    responsive: false,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: '#e8f0ff' }
      }
    },
    scales: {
      x: { 
        ticks: { color: '#9fb3c8' },
        grid: { color: 'rgba(255,255,255,0.05)' }
      },
      y: { 
        ticks: { color: '#9fb3c8' },
        grid: { color: 'rgba(255,255,255,0.05)' }
      }
    }
  };

  // Alerts Over Time
  const ctxAlerts = document.getElementById('alertsChart').getContext('2d');
  const gradientAlerts = ctxAlerts.createLinearGradient(0, 0, 0, 120);
  gradientAlerts.addColorStop(0, 'rgba(255,82,82,0.8)');
  gradientAlerts.addColorStop(1, 'rgba(255,82,82,0.1)');

  alertsChart = new Chart(ctxAlerts, {
    type: 'line',
    data: {
      labels: alertLabels,
      datasets: [{
          label: 'Alerts',
          data: alertSeries,
        borderColor: '#ff5252',
        backgroundColor: gradientAlerts,
          fill: true,
        tension: 0.4,
        pointRadius: 3,
        pointHoverRadius: 5
      }]
    },
    options: chartOptions
  });

  // Events Over Time
  const ctxEvents = document.getElementById('eventsChart').getContext('2d');
  const gradientEvents = ctxEvents.createLinearGradient(0, 0, 0, 120);
  gradientEvents.addColorStop(0, 'rgba(0,255,224,0.8)');
  gradientEvents.addColorStop(1, 'rgba(0,255,224,0.1)');

  eventsChart = new Chart(ctxEvents, {
    type: 'line',
    data: {
      labels: eventsLabels,
      datasets: [{
        label: 'Events',
        data: eventsSeries,
        borderColor: '#00ffe0',
        backgroundColor: gradientEvents,
        fill: true,
        tension: 0.4
      }]
    },
    options: chartOptions
  });

  // Protocols
  protoChart = new Chart(document.getElementById('protoChart'), {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
          data: [],
          backgroundColor: [
          '#00ffe0', '#7c6fff', '#ff5c8a', '#00e676', '#ffd54f', '#ff5252'
        ]
      }]
    },
    options: {
      ...chartOptions,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e8f0ff' } }
      }
    }
  });

  // Detection Sources
  sourceChart = new Chart(document.getElementById('sourceChart'), {
    type: 'pie',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: ['#00e676', '#ff6b6b', '#ffd166', '#7c6fff']
      }]
    },
    options: {
      ...chartOptions,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e8f0ff' } }
      }
    }
  });

  // Agent Activity
  agentChart = new Chart(document.getElementById('agentChart'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Events',
        data: [],
        backgroundColor: '#00ffe0'
      }]
    },
    options: {
      ...chartOptions,
      indexAxis: 'y',
      plugins: {
        legend: { display: false }
      }
    }
  });

  // Threat Distribution
  threatChart = new Chart(document.getElementById('threatChart'), {
    type: 'doughnut',
    data: {
      labels: [],
      datasets: [{
        data: [],
        backgroundColor: [
          '#ff5252', '#ff6b6b', '#ff8a80', '#ffd54f', '#ffeb3b'
        ]
      }]
    },
    options: {
      ...chartOptions,
      plugins: {
        legend: { position: 'bottom', labels: { color: '#e8f0ff' } }
      }
    }
  });
}

function updateCharts() {
  // Alerts timeline
  if (alertLabels.length > 20) {
    alertLabels.shift();
    alertSeries.shift();
  }
  alertLabels.push(new Date().toLocaleTimeString());
  alertSeries.push(totalAlerts);
  alertsChart.update('none');

  // Events timeline
  if (eventsLabels.length > 20) {
    eventsLabels.shift();
    eventsSeries.shift();
  }
  eventsLabels.push(new Date().toLocaleTimeString());
  eventsSeries.push(totalEvents);
  eventsChart.update('none');

  // Protocols
  protoChart.data.labels = Object.keys(protoCounts);
  protoChart.data.datasets[0].data = Object.values(protoCounts);
  protoChart.update('none');

  // Sources
  sourceChart.data.labels = Object.keys(sourceCounts);
  sourceChart.data.datasets[0].data = Object.values(sourceCounts);
  sourceChart.update('none');

  // Agents
  const sortedAgents = Object.entries(agentCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);
  agentChart.data.labels = sortedAgents.map(a => a[0]);
  agentChart.data.datasets[0].data = sortedAgents.map(a => a[1]);
  agentChart.update('none');

  // Threats
  const sortedThreats = Object.entries(threatCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);
  threatChart.data.labels = sortedThreats.map(t => truncate(t[0], 20));
  threatChart.data.datasets[0].data = sortedThreats.map(t => t[1]);
  threatChart.update('none');
}

// ===== Stats & Data Fetching =====
function fetchStats() {
  fetch('/stats')
    .then(r => r.json())
    .then(s => {
      $('#totalEvents').text(formatNumber(s.total_events || 0));
      $('#totalAlerts').text(formatNumber(s.total_alerts || 0));
      $('#uniqueAgents').text(formatNumber(s.unique_agents || 0));
      
      // Update threat counts from server
      if (s.top_threats) {
        Object.assign(threatCounts, s.top_threats);
        updateCharts();
      }
    })
    .catch(err => console.error('Stats fetch failed', err));

  // Fetch enhanced analytics
  fetchAnalytics();
}

function fetchAnalytics() {
  // Timeline data
  fetch('/api/analytics/timeline')
    .then(r => r.json())
    .then(data => {
      if (data.labels && data.events && data.alerts) {
        eventsChart.data.labels = data.labels;
        eventsChart.data.datasets[0].data = data.events;
        alertsChart.data.labels = data.labels;
        alertsChart.data.datasets[0].data = data.alerts;
        eventsChart.update('none');
        alertsChart.update('none');
      }
    })
    .catch(err => console.error('Timeline fetch failed', err));
  
  // Protocol distribution
  fetch('/api/analytics/protocols')
    .then(r => r.json())
    .then(data => {
      protoChart.data.labels = Object.keys(data);
      protoChart.data.datasets[0].data = Object.values(data);
      protoChart.update('none');
    })
    .catch(err => console.error('Protocols fetch failed', err));
  
  // Top threats
  fetch('/api/analytics/top_threats')
    .then(r => r.json())
    .then(data => {
      threatChart.data.labels = data.map(t => truncate(t.threat, 15));
      threatChart.data.datasets[0].data = data.map(t => t.count);
      threatChart.update('none');
    })
    .catch(err => console.error('Top threats fetch failed', err));
  
  // Agent activity
  fetch('/api/analytics/agent_activity')
    .then(r => r.json())
    .then(data => {
      agentChart.data.labels = data.map(a => a.agent_id);
      agentChart.data.datasets[0].data = data.map(a => a.total_events);
      agentChart.update('none');
    })
    .catch(err => console.error('Agent activity fetch failed', err));
}

function fetchThreats() {
  fetch('/api/threats')
    .then(r => r.json())
    .then(threats => {
      const list = $('#threatList');
      list.empty();
      
      if (!threats.length) {
        list.html('<div class="col-12"><p class="text-muted text-center">No threats detected</p></div>');
        return;
      }
      
      threats.forEach(threat => {
        const card = `
          <div class="col-md-6 col-lg-4">
            <div class="threat-card">
              <div class="threat-name">${escapeHtml(threat.threat)}</div>
              <div class="threat-count">${threat.count}</div>
              <small class="text-muted">Severity: <span class="badge bg-${threat.severity === 'high' ? 'danger' : threat.severity === 'medium' ? 'warning' : 'success'}">${threat.severity}</span></small>
            </div>
          </div>`;
        list.append(card);
      });
    })
    .catch(err => console.error('Threats fetch failed', err));
}

function fetchAgents() {
  fetch('/api/agents')
    .then(r => r.json())
    .then(agents => {
      const list = $('#agentList');
      list.empty();
      
      if (!agents.length) {
        list.html('<div class="col-12"><p class="text-muted text-center">No agents connected</p></div>');
        return;
      }
      
      agents.forEach(agent => {
        const statusClass = agent.status === 'active' ? 'active' : 'inactive';
        const lastSeen = agent.last_seen ? 
          new Date(agent.last_seen * 1000).toLocaleString() : 'Never';
        const card = `
          <div class="col-md-6 col-lg-4">
            <div class="agent-card ${statusClass}">
              <h6><i class="bi bi-cpu-fill"></i> Agent ${agent.agent_id}</h6>
              <p class="mb-1"><small class="text-muted">Last Seen:</small> ${lastSeen}</p>
              <p class="mb-1"><small class="text-muted">Events:</small> <strong>${agent.event_count}</strong></p>
              <p class="mb-0"><small class="text-muted">Alerts:</small> <strong class="text-danger">${agent.alert_count}</strong></p>
              <span class="badge bg-${agent.status === 'active' ? 'success' : 'secondary'} mt-2">${agent.status}</span>
            </div>
          </div>`;
        list.append(card);
      });
    })
    .catch(err => console.error('Agents fetch failed', err));
}

function fetchDevices() {
  fetch('/api/devices')
    .then(r => r.json())
    .then(devices => {
      const list = $('#deviceList');
      list.empty();
      
      if (!devices.length) {
        list.html('<div class="col-12"><p class="text-muted text-center">No devices connected</p></div>');
        return;
      }
      
      devices.forEach(device => {
        const statusClass = device.status === 'online' ? 'active' : 'inactive';
        const lastSeen = device.last_seen ? 
          new Date(device.last_seen * 1000).toLocaleString() : 'Never';
        const timeAgo = device.last_seen ? 
          Math.floor((Date.now() / 1000 - device.last_seen) / 60) + ' min ago' : 'Never';
        
        const card = `
          <div class="col-md-6 col-lg-4">
            <div class="agent-card ${statusClass}" style="cursor: pointer;" data-agent-id="${device.agent_id}">
              <h6><i class="bi bi-laptop"></i> ${device.hostname || device.agent_id}</h6>
              <p class="mb-1"><small class="text-muted">Agent ID:</small> <code>${device.agent_id}</code></p>
              <p class="mb-1"><small class="text-muted">IP:</small> ${device.ip}</p>
              <p class="mb-1"><small class="text-muted">OS:</small> ${device.os}</p>
              <p class="mb-1"><small class="text-muted">Region:</small> ${device.region}</p>
              <p class="mb-1"><small class="text-muted">Last Seen:</small> ${timeAgo}</p>
              <p class="mb-1"><small class="text-muted">Events:</small> <strong>${device.total_events || 0}</strong></p>
              <p class="mb-0"><small class="text-muted">Alerts:</small> <strong class="text-danger">${device.total_alerts || 0}</strong></p>
              <span class="badge bg-${device.status === 'online' ? 'success' : 'secondary'} mt-2">${device.status}</span>
            </div>
          </div>`;
        list.append(card);
      });
      
      // Use event delegation for dynamically created cards
      // Remove old handlers first to avoid duplicates
      $(document).off('click', '.agent-card[data-agent-id]');
      $(document).on('click', '.agent-card[data-agent-id]', function() {
        const agentId = $(this).data('agent-id');
        console.log('Device card clicked:', agentId);
        showDeviceActions(agentId);
      });
    })
    .catch(err => console.error('Devices fetch failed', err));
}

function showDeviceActions(agentId) {
  // Set global currentDeviceId so button handlers can access it
  currentDeviceId = agentId;
  console.log('Device selected:', agentId, 'currentDeviceId set to:', currentDeviceId);
  
  fetch(`/api/devices/${agentId}/info`)
    .then(r => {
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      return r.json();
    })
    .then(info => {
      console.log('Device info loaded:', info);
      const html = `
        <div class="card mb-3">
          <h6><i class="bi bi-info-circle"></i> Device Information</h6>
          <p class="mb-1"><strong>Hostname:</strong> ${info.hostname || 'N/A'}</p>
          <p class="mb-1"><strong>IP:</strong> ${info.ip || 'N/A'}</p>
          <p class="mb-1"><strong>OS:</strong> ${info.os || 'N/A'}</p>
          <p class="mb-1"><strong>Region:</strong> ${info.region || 'N/A'}</p>
          <p class="mb-1"><strong>Status:</strong> <span class="badge bg-${info.status === 'online' ? 'success' : 'secondary'}">${info.status || 'unknown'}</span></p>
          <p class="mb-0"><strong>Statistics:</strong></p>
          <ul class="mb-0">
            <li>Total Events: ${info.statistics?.total_events || 0}</li>
            <li>Total Alerts: ${info.statistics?.total_alerts || 0}</li>
            <li>Unique Destinations: ${info.statistics?.unique_destinations || 0}</li>
            <li>Total Bytes Sent: ${formatBytes(info.statistics?.total_bytes_sent || 0)}</li>
            <li>Total Bytes Recv: ${formatBytes(info.statistics?.total_bytes_recv || 0)}</li>
          </ul>
        </div>`;
      $('#deviceInfo').html(html);
      const modal = new bootstrap.Modal(document.getElementById('deviceModal'));
      modal.show();
      console.log('Device modal opened, currentDeviceId:', currentDeviceId);
    })
    .catch(err => {
      console.error('Failed to load device info:', err);
      showNotification(`Failed to load device info: ${err.message}`, 'error');
    });
}

function loadSignatures() {
  fetch('/api/signatures')
    .then(r => r.json())
    .then(sigs => {
      const list = $('#signatureList');
      list.empty();
      
      if (!sigs.length) {
        list.html('<p class="text-muted text-center">No signatures available.</p>');
        return;
      }
      
      sigs.forEach(sig => {
        const card = `
          <div class="signature-card" data-severity="${sig.severity || 'Low'}">
            <h6><i class="bi bi-bug"></i> ${escapeHtml(sig.name || 'Unnamed')}</h6>
            <div class="signature-meta">${escapeHtml(sig.rule || 'No rule')}</div>
            <small class="signature-meta">Severity: <span class="badge bg-${sig.severity === 'High' ? 'danger' : sig.severity === 'Medium' ? 'warning' : 'success'}">${sig.severity}</span></small>
          </div>`;
        list.append(card);
      });
    })
    .catch(err => console.error('Signature fetch failed', err));
}

function updateExportStats() {
  $('#exportTotalEvents').text(formatNumber(totalEvents));
  $('#exportTotalAlerts').text(formatNumber(totalAlerts));
  const now = new Date();
  const start = new Date(startTime);
  $('#exportDateRange').text(`${start.toLocaleDateString()} - ${now.toLocaleDateString()}`);
}

function exportData(format, alertsOnly) {
  const params = new URLSearchParams({
    format: format,
    alert_only: alertsOnly.toString()
  });
  
  fetch(`/api/export?${params}`)
    .then(r => r.json())
    .then(data => {
      if (format === 'json') {
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `quantumdefender-export-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showNotification('Export downloaded', 'success');
      } else {
        showNotification('CSV export coming soon', 'info');
      }
    })
    .catch(err => {
      showNotification('Export failed', 'error');
      console.error(err);
    });
}

// ===== Geographic Map Functions =====
function fetchGeoMap() {
  fetch('/api/analytics/geographic')
    .then(r => r.json())
    .then(data => {
      const container = $('#geoMapContent');
      const statsContainer = $('#geoStats');
      
      if (!data || Object.keys(data).length === 0) {
        container.html('<p class="text-muted">No geographic data available</p>');
        statsContainer.html('<p class="text-muted">No regional statistics</p>');
        return;
      }
      
      // Create visual map representation
      const regions = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 10);
      const maxCount = Math.max(...regions.map(r => r[1]), 1);
      
      let mapHtml = '<div class="row g-3">';
      regions.forEach(([region, count]) => {
        const percentage = (count / maxCount) * 100;
        const intensity = Math.min(percentage / 10, 1);
        mapHtml += `
          <div class="col-md-6 col-lg-4">
            <div class="card" style="background: rgba(0, 255, 224, ${intensity * 0.1}); border: 1px solid rgba(0, 255, 224, ${intensity * 0.3});">
              <div class="card-body">
                <h6><i class="bi bi-geo-alt"></i> ${escapeHtml(region || 'Unknown')}</h6>
                <div class="d-flex justify-content-between align-items-center">
                  <span class="badge bg-danger">${formatNumber(count)} threats</span>
                  <div class="progress" style="width: 60%; height: 8px;">
                    <div class="progress-bar bg-danger" role="progressbar" style="width: ${percentage}%"></div>
                  </div>
                </div>
              </div>
            </div>
          </div>`;
      });
      mapHtml += '</div>';
      
      container.html(mapHtml);
      
      // Create stats cards
      let statsHtml = '';
      regions.forEach(([region, count]) => {
        statsHtml += `
          <div class="col-md-6 col-lg-3 mb-2">
            <div class="card">
              <div class="card-body p-2">
                <small class="text-muted">${escapeHtml(region || 'Unknown')}</small>
                <div class="h5 mb-0 text-danger">${formatNumber(count)}</div>
              </div>
            </div>
          </div>`;
      });
      statsContainer.html(statsHtml || '<p class="text-muted">No regional statistics</p>');
    })
    .catch(err => {
      console.error('Geo map fetch failed:', err);
      $('#geoMapContent').html('<p class="text-danger">Failed to load geographic data</p>');
    });
}

// ===== UI Helpers =====
function updateMetrics() {
  $('#totalEvents').text(formatNumber(totalEvents));
  $('#totalAlerts').text(formatNumber(totalAlerts));
  $('#uniqueAgents').text(formatNumber(uniqueAgents.size));
}

function updateUptime() {
  const elapsed = Date.now() - startTime;
  const hours = Math.floor(elapsed / 3600000);
  const minutes = Math.floor((elapsed % 3600000) / 60000);
  $('#uptime').text(`${hours}h ${minutes}m`);
}

function setCloudStatus(text, ok) {
  const pill = $('#cloudStatus');
  pill.text(text);
  pill.removeClass('ok warn');
  pill.addClass(ok ? 'ok' : 'warn');
}

function showAlertToast(event) {
  const toastEl = document.getElementById('alertToast');
  if (toastEl) {
    document.getElementById('toastAgent').innerText = event.agent_id || 'agent';
    document.getElementById('toastBody').innerText = 
      `${event.host || ''} → ${event.dst_ip || ''}: ${event.reason || 'Malicious traffic detected'}`;
    const toast = bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 5000 });
    toast.show();
  }
}

function showNotification(message, type = 'info') {
  // Enhanced notification with visual feedback
  console.log(`[${type.toUpperCase()}] ${message}`);
  
  // Create toast notification
  const toastHtml = `
    <div class="toast align-items-center text-white bg-${type === 'success' ? 'success' : type === 'error' ? 'danger' : 'info'} border-0" role="alert" aria-live="assertive" aria-atomic="true" style="position: fixed; top: 20px; right: 20px; z-index: 9999;">
      <div class="d-flex">
        <div class="toast-body">
          <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i> ${message}
        </div>
        <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
      </div>
    </div>`;
  
  const $toast = $(toastHtml);
  $('body').append($toast);
  const toast = new bootstrap.Toast($toast[0], { delay: 4000 });
  toast.show();
  
  $toast.on('hidden.bs.toast', function() {
    $(this).remove();
  });
}

// ===== Utility Functions =====
function formatTimestamp(ts) {
  if (!ts) return 'N/A';
  try {
    return new Date(ts).toLocaleTimeString();
  } catch {
    return ts;
  }
}

function formatBytes(bytes) {
  // Handle string inputs that might already be formatted
  if (typeof bytes === 'string') {
    // If it's already formatted (contains space), return as-is
    if (bytes.includes(' ')) return bytes;
    // Try to parse as number
    bytes = parseFloat(bytes);
  }
  
  if (!bytes || isNaN(bytes) || bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function formatNumber(num) {
  return new Intl.NumberFormat().format(num);
}

function truncate(str, len) {
  if (!str) return 'N/A';
  return str.length > len ? str.substring(0, len) + '...' : str;
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Load signatures on page load
$(document).ready(() => {
  loadSignatures();
  setInterval(loadSignatures, 30000);
  
  // Initialize enhanced features
  initEnhancedFeatures();
  initThreatTimelineChart();
  initConnectionsTimelineChart();
  fetchThreatTimeline(24);
});

// ===== Enhanced Features Initialization =====
function initEnhancedFeatures() {
  // Analytics enhancements
  populateAgentFilter();
  $('#analyticsTimeRange, #analyticsAgentFilter').on('change', function() {
    fetchEnhancedAnalytics();
  });
  $('#btnRefreshAnalytics').on('click', fetchEnhancedAnalytics);
  $('#btnExportAnalytics').on('click', () => exportAnalytics());
  // ML feedback & integrations
  fetchMlFeedbackStats();
  fetchThirdPartyStatus();
  
  // Threat Intel enhancements
  $('#btnCheckThreat').on('click', () => $('#checkThreatModal').modal('show'));
  $('#checkThreatForm').on('submit', function(e) {
    e.preventDefault();
    const input = $('#threatLookupInput').val();
    checkThreat(input);
  });
  $('#threatSearchInput').on('input', debounce(function() {
    filterThreats($(this).val());
  }, 300));
  $('#btnExportThreats').on('click', () => exportThreats());
  
  // Threat tab switching
  $('a[data-bs-toggle="tab"]').on('shown.bs.tab', function(e) {
    const target = $(e.target).attr('href');
    if (target === '#threatIPs' || target === '#threatURLs' || target === '#threatPatterns' || target === '#threatHistory') {
      loadThreatTabs();
    }
  });
  
  // Agents enhancements
  $('#agentSearchInput').on('input', debounce(function() {
    filterAgents($(this).val());
  }, 300));
  $('#agentStatusFilter').on('change', function() {
    filterAgents($('#agentSearchInput').val(), $(this).val());
  });
  $('#btnBulkAgentAction').on('click', () => $('#bulkActionModal').modal('show'));
  $('#btnExportAgents').on('click', () => exportAgents());
  
  // Signatures enhancements
  $('#signatureSearchInput').on('input', debounce(function() {
    filterSignatures($(this).val());
  }, 300));
  $('#signatureSeverityFilter, #signatureStatusFilter').on('change', function() {
    filterSignatures($('#signatureSearchInput').val());
  });
  $('#btnTestSig').on('click', () => $('#testSigModal').modal('show'));
  $('#testSigForm').on('submit', function(e) {
    e.preventDefault();
    testSignatureRule($('#testSigRule').val(), $('#testSigData').val());
  });
  $('#btnImportSig').on('click', () => importSignatures());
  $('#btnExportSig').on('click', () => exportSignatures());
  fetchGeneratedSignatures();
  
  // Device Management enhancements
  $('#deviceSearchInput').on('input', debounce(function() {
    filterDevices($(this).val());
  }, 300));
  $('#deviceStatusFilter').on('change', function() {
    filterDevices($('#deviceSearchInput').val(), $(this).val());
  });
  $('#btnBulkDeviceAction').on('click', () => $('#bulkActionModal').modal('show'));
  $('#btnExportDevices').on('click', () => exportDevices());
  
  // Bulk actions
  $('#btnExecuteBulkAction').on('click', executeBulkAction);
  
  // Initialize peak activity chart
  initPeakActivityChart();

  // Firewall view
  fetchFirewallStats();
  fetchFirewallRules();

  $('#fwAddForm').on('submit', function(e) {
    e.preventDefault();
    addFirewallRule();
  });
}

// ===== Enhanced Analytics =====
let peakActivityChart = null;

function initPeakActivityChart() {
  const ctx = document.getElementById('peakActivityChart');
  if (!ctx) return;
  
  peakActivityChart = new Chart(ctx.getContext('2d'), {
    type: 'bar',
    data: {
      labels: [],
      datasets: [{
        label: 'Events',
        data: [],
        backgroundColor: '#00ffe0'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        labels: { color: '#e8f0ff' }
      },
      scales: {
        x: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

function populateAgentFilter() {
  fetch('/api/agents')
    .then(r => r.json())
    .then(agents => {
      const select = $('#analyticsAgentFilter');
      select.empty();
      select.append('<option value="all">All Agents</option>');
      agents.forEach(agent => {
        select.append(`<option value="${agent.agent_id}">${agent.agent_id}</option>`);
      });
    })
    .catch(err => console.error('Failed to load agents for filter', err));
}

function fetchEnhancedAnalytics() {
  const timeRange = $('#analyticsTimeRange').val();
  const agentFilter = $('#analyticsAgentFilter').val();
  
  fetch(`/api/analytics/enhanced?time_range=${timeRange}&agent=${agentFilter}`)
    .then(r => r.json())
    .then(data => {
      // Update summary cards
      $('#analyticsTotalEvents').text(formatNumber(data.total_events || 0));
      $('#analyticsTotalAlerts').text(formatNumber(data.total_alerts || 0));
      $('#analyticsAvgScore').text((data.avg_threat_score || 0).toFixed(2));
      $('#analyticsUniqueIPs').text(formatNumber(data.unique_ips || 0));
      
      // Update change indicators
      if (data.events_change) {
        $('#analyticsEventsChange').text(`${data.events_change > 0 ? '+' : ''}${data.events_change.toFixed(1)}%`)
          .removeClass('text-muted text-success text-danger')
          .addClass(data.events_change > 0 ? 'text-success' : 'text-danger');
      }
      if (data.alerts_change) {
        $('#analyticsAlertsChange').text(`${data.alerts_change > 0 ? '+' : ''}${data.alerts_change.toFixed(1)}%`)
          .removeClass('text-muted text-success text-danger')
          .addClass(data.alerts_change > 0 ? 'text-danger' : 'text-success');
      }
      
      // Update top destinations
      if (data.top_destinations) {
        const html = data.top_destinations.map(d => `
          <div class="d-flex justify-content-between align-items-center mb-2 p-2" style="background: rgba(255,255,255,0.05); border-radius: 4px;">
            <div>
              <strong>${escapeHtml(d.destination)}</strong><br>
              <small class="text-muted">${d.count} events</small>
            </div>
            <span class="badge bg-${d.alert_count > 0 ? 'danger' : 'info'}">${d.alert_count} alerts</span>
          </div>
        `).join('');
        $('#topDestinations').html(html || '<p class="text-muted text-center">No data</p>');
      }
      
      // Update peak activity chart
      if (data.peak_activity && peakActivityChart) {
        peakActivityChart.data.labels = data.peak_activity.map(p => p.hour);
        peakActivityChart.data.datasets[0].data = data.peak_activity.map(p => p.count);
        peakActivityChart.update('none');
      }
    })
    .catch(err => console.error('Enhanced analytics fetch failed', err));
}

function fetchMlFeedbackStats() {
  fetch('/api/ml/feedback/stats')
    .then(r => r.json())
    .then(data => {
      $('#mlDetections').text(data.ml_detections ?? 0);
      $('#mlGeneratedSigs').text(data.ml_generated_signatures ?? 0);
      $('#thirdPartySigs').text(data.third_party_signatures ?? 0);
      $('#mlPatternsInQueue').text(data.patterns_in_queue ?? 0);
      const enabled = data.signature_generation_enabled;
      const badge = $('#mlFeedbackStatus');
      badge.removeClass('bg-secondary bg-danger bg-success');
      if (enabled) {
        badge.addClass('bg-success').text('ML Feedback: Enabled');
      } else {
        badge.addClass('bg-danger').text('ML Feedback: Disabled');
      }
    })
    .catch(() => {
      $('#mlFeedbackStatus').removeClass('bg-success bg-secondary').addClass('bg-danger').text('ML Feedback: Error');
    });
}

function fetchThirdPartyStatus() {
  fetch('/api/third_party/status')
    .then(r => r.json())
    .then(status => {
      const updateBadge = (id, cfg) => {
        const el = $(id);
        el.removeClass('bg-secondary bg-danger bg-success bg-warning');
        if (!cfg.configured) {
          el.addClass('bg-secondary').text('Not configured');
        } else if (cfg.enabled) {
          el.addClass('bg-success').text('Enabled');
        } else {
          el.addClass('bg-warning').text('Disabled');
        }
      };
      updateBadge('#tpAbuseipdb', status.abuseipdb || { enabled: false, configured: false });
      updateBadge('#tpVirustotal', status.virustotal || { enabled: false, configured: false });
      updateBadge('#tpAlienvault', status.alienvault || { enabled: false, configured: false });
    })
    .catch(() => {
      ['#tpAbuseipdb', '#tpVirustotal', '#tpAlienvault'].forEach(id => {
        $(id).removeClass('bg-success bg-secondary bg-warning').addClass('bg-danger').text('Error');
      });
    });
}

function exportAnalytics() {
  const timeRange = $('#analyticsTimeRange').val();
  fetch(`/api/analytics/export?time_range=${timeRange}`)
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `analytics-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Analytics exported successfully', 'success');
    })
    .catch(err => {
      console.error('Export failed', err);
      showNotification('Export failed', 'error');
    });
}

// ===== Enhanced Threat Intel =====
function checkThreat(input) {
  fetch('/api/threats/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: input })
  })
    .then(r => r.json())
    .then(data => {
      const result = `
        <div class="card mt-3">
          <h6>Threat Analysis Results</h6>
          <p><strong>Input:</strong> ${escapeHtml(input)}</p>
          <p><strong>Threat Level:</strong> <span class="badge bg-${data.threat_level === 'high' ? 'danger' : data.threat_level === 'medium' ? 'warning' : 'success'}">${data.threat_level || 'none'}</span></p>
          <p><strong>Alert Count:</strong> ${data.alert_count || 0}</p>
          <p><strong>First Seen:</strong> ${data.first_seen || 'N/A'}</p>
          <p><strong>Last Seen:</strong> ${data.last_seen || 'N/A'}</p>
          ${data.related_threats ? `<p><strong>Related Threats:</strong> ${data.related_threats.join(', ')}</p>` : ''}
        </div>
      `;
      $('#threatLookupResult').html(result);
    })
    .catch(err => {
      $('#threatLookupResult').html(`<div class="alert alert-danger">Error: ${err.message}</div>`);
    });
}

function filterThreats(query) {
  $('.threat-card').each(function() {
    const text = $(this).text().toLowerCase();
    $(this).closest('.col-md-6, .col-lg-4').toggle(text.includes(query.toLowerCase()));
  });
}

function loadThreatTabs() {
  // Load malicious IPs
  fetch('/api/threats/malicious_ips')
    .then(r => r.json())
    .then(ips => {
      const html = ips.map(ip => `
        <tr>
          <td><code>${escapeHtml(ip.ip)}</code></td>
          <td>${ip.count}</td>
          <td><span class="badge bg-${ip.threat_level === 'high' ? 'danger' : ip.threat_level === 'medium' ? 'warning' : 'info'}">${ip.threat_level}</span></td>
          <td>${formatTimestamp(ip.first_seen)}</td>
          <td>${formatTimestamp(ip.last_seen)}</td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="blockThreatIP('${ip.ip}')">Block</button>
            <button class="btn btn-sm btn-info" onclick="viewThreatDetails('ip', '${ip.ip}')">Details</button>
          </td>
        </tr>
      `).join('');
      $('#threatIPTableBody').html(html || '<tr><td colspan="6" class="text-center text-muted">No data</td></tr>');
    });
  
  // Load suspicious URLs
  fetch('/api/threats/suspicious_urls')
    .then(r => r.json())
    .then(urls => {
      const html = urls.map(url => `
        <tr>
          <td><code>${escapeHtml(url.url)}</code></td>
          <td>${url.count}</td>
          <td><span class="badge bg-${url.threat_level === 'high' ? 'danger' : url.threat_level === 'medium' ? 'warning' : 'info'}">${url.threat_level}</span></td>
          <td>${formatTimestamp(url.first_seen)}</td>
          <td>${formatTimestamp(url.last_seen)}</td>
          <td>
            <button class="btn btn-sm btn-danger" onclick="blockThreatURL('${url.url}')">Block</button>
            <button class="btn btn-sm btn-info" onclick="viewThreatDetails('url', '${url.url}')">Details</button>
          </td>
        </tr>
      `).join('');
      $('#threatURLTableBody').html(html || '<tr><td colspan="6" class="text-center text-muted">No data</td></tr>');
    });
  
  // Load threat patterns
  fetch('/api/threats/patterns')
    .then(r => r.json())
    .then(patterns => {
      const html = patterns.map(p => `
        <div class="col-md-6 col-lg-4">
          <div class="card">
            <h6>${escapeHtml(p.pattern)}</h6>
            <p class="mb-1"><strong>Count:</strong> ${p.count}</p>
            <p class="mb-1"><strong>Severity:</strong> <span class="badge bg-${p.severity === 'High' ? 'danger' : p.severity === 'Medium' ? 'warning' : 'success'}">${p.severity}</span></p>
            <p class="mb-0"><strong>Last Seen:</strong> ${formatTimestamp(p.last_seen)}</p>
          </div>
        </div>
      `).join('');
      $('#threatPatternList').html(html || '<div class="col-12"><p class="text-muted text-center">No patterns</p></div>');
    });
  
  // Load threat history
  fetch('/api/threats/history?limit=50')
    .then(r => r.json())
    .then(history => {
      const html = history.map(h => `
        <tr>
          <td>${formatTimestamp(h.timestamp)}</td>
          <td>${escapeHtml(h.threat)}</td>
          <td><code>${escapeHtml(h.ip)}</code></td>
          <td>${escapeHtml(h.agent_id)}</td>
          <td>${(h.score || 0).toFixed(2)}</td>
          <td><button class="btn btn-sm btn-info" onclick="viewThreatEventDetails(${h.event_id})">View</button></td>
        </tr>
      `).join('');
      $('#threatHistoryTableBody').html(html || '<tr><td colspan="6" class="text-center text-muted">No history</td></tr>');
    });
}

function blockThreatIP(ip) {
  fetch('/api/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, agent_id: 'all' })
  })
    .then(r => r.json())
    .then(data => {
      showNotification(`IP ${ip} blocked successfully`, 'success');
      loadThreatTabs();
    })
    .catch(err => showNotification(`Failed to block IP: ${err.message}`, 'error'));
}

function blockThreatURL(url) {
  fetch('/api/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domain: url, agent_id: 'all' })
  })
    .then(r => r.json())
    .then(data => {
      showNotification(`URL ${url} blocked successfully`, 'success');
      loadThreatTabs();
    })
    .catch(err => showNotification(`Failed to block URL: ${err.message}`, 'error'));
}

function viewThreatDetails(type, value) {
  // Implementation for viewing threat details
  showNotification(`Viewing details for ${type}: ${value}`, 'info');
}

function viewThreatEventDetails(eventId) {
  // Implementation for viewing event details
  showNotification(`Viewing event ${eventId}`, 'info');
}

function exportThreats() {
  fetch('/api/threats/export')
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `threats-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Threats exported successfully', 'success');
    })
    .catch(err => showNotification('Export failed', 'error'));
}

// ===== Enhanced Agents =====
function filterAgents(query, status) {
  query = (query || '').toLowerCase();
  status = status || 'all';
  
  $('.agent-card').each(function() {
    const $card = $(this);
    const text = $card.text().toLowerCase();
    const cardStatus = $card.hasClass('active') ? 'online' : 'offline';
    
    const matchesQuery = !query || text.includes(query);
    const matchesStatus = status === 'all' || cardStatus === status;
    
    $card.closest('.col-md-6, .col-lg-4').toggle(matchesQuery && matchesStatus);
  });
}

function fetchEnhancedAgents() {
  fetch('/api/agents/enhanced')
    .then(r => r.json())
    .then(data => {
      $('#agentsTotal').text(data.total || 0);
      $('#agentsOnline').text(data.online || 0);
      $('#agentsOffline').text(data.offline || 0);
      $('#agentsAvgHealth').text((data.avg_health || 0) + '%');
    })
    .catch(err => console.error('Enhanced agents fetch failed', err));
}

function exportAgents() {
  fetch('/api/agents/export')
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `agents-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Agents exported successfully', 'success');
    })
    .catch(err => showNotification('Export failed', 'error'));
}

// ===== Enhanced Signatures =====
function filterSignatures(query) {
  query = (query || '').toLowerCase();
  const severity = $('#signatureSeverityFilter').val();
  const status = $('#signatureStatusFilter').val();
  
  $('.signature-card').each(function() {
    const $card = $(this);
    const text = $card.text().toLowerCase();
    const cardSeverity = $card.data('severity') || '';
    const isActive = !$card.hasClass('disabled');
    
    const matchesQuery = !query || text.includes(query);
    const matchesSeverity = severity === 'all' || cardSeverity === severity;
    const matchesStatus = status === 'all' || (status === 'active' && isActive) || (status === 'disabled' && !isActive);
    
    $card.toggle(matchesQuery && matchesSeverity && matchesStatus);
  });
}

function testSignatureRule(rule, testData) {
  fetch('/api/signatures/test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rule: rule, test_data: testData })
  })
    .then(r => r.json())
    .then(data => {
      const result = `
        <div class="alert alert-${data.matched ? 'danger' : 'success'}">
          <strong>Result:</strong> ${data.matched ? 'MATCHED' : 'NO MATCH'}
          ${data.matched ? '<br><strong>Matched Groups:</strong> ' + (data.groups || []).join(', ') : ''}
          ${data.error ? '<br><strong>Error:</strong> ' + escapeHtml(data.error) : ''}
        </div>
      `;
      $('#testSigResult').html(result);
    })
    .catch(err => {
      $('#testSigResult').html(`<div class="alert alert-danger">Error: ${err.message}</div>`);
    });
}

function importSignatures() {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = '.json';
  input.onchange = function(e) {
    const file = e.target.files[0];
    if (!file) return;
    
    const reader = new FileReader();
    reader.onload = function(e) {
      try {
        const data = JSON.parse(e.target.result);
        fetch('/api/signatures/import', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        })
          .then(r => r.json())
          .then(result => {
            showNotification(`Imported ${result.imported || 0} signatures`, 'success');
            loadSignatures();
          })
          .catch(err => showNotification('Import failed', 'error'));
      } catch (err) {
        showNotification('Invalid file format', 'error');
      }
    };
    reader.readAsText(file);
  };
  input.click();
}

function exportSignatures() {
  fetch('/api/signatures/export')
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `signatures-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Signatures exported successfully', 'success');
    })
    .catch(err => showNotification('Export failed', 'error'));
}

function fetchEnhancedSignatures() {
  fetch('/api/signatures/stats')
    .then(r => r.json())
    .then(data => {
      $('#signaturesTotal').text(data.total || 0);
      $('#signaturesActive').text(data.active || 0);
      $('#signaturesMatches').text(data.matches_today || 0);
      $('#signaturesHigh').text(data.high_severity || 0);
    })
    .catch(err => console.error('Signature stats fetch failed', err));
  
  // Fetch matcher status
  fetch('/api/signatures/matcher/stats')
    .then(r => r.json())
    .then(data => {
      const badge = $('#matcherStatusBadge');
      const type = $('#matcherType');
      
      if (data.optimized_matcher_enabled) {
        badge.removeClass('bg-secondary bg-danger').addClass('bg-success');
        badge.text('✅ Optimized');
        type.text(`${data.matcher_type} • ${data.total_signatures || 0} signatures loaded`);
      } else {
        badge.removeClass('bg-secondary bg-success').addClass('bg-warning');
        badge.text('⚠️ Fallback');
        type.text(`${data.matcher_type} • ${data.total_signatures || 0} signatures`);
      }
    })
    .catch(err => {
      console.error('Matcher stats fetch failed', err);
      $('#matcherStatusBadge').removeClass('bg-success bg-warning').addClass('bg-danger');
      $('#matcherStatusBadge').text('❌ Error');
      $('#matcherType').text('Failed to load status');
    });
}

function fetchGeneratedSignatures() {
  fetch('/api/signatures/generated')
    .then(r => r.json())
    .then(data => {
      const list = $('#generatedSignaturesList');
      const all = [
        ...(data.ml_generated || []).map(s => ({ ...s, _source: 'ML Feedback' })),
        ...(data.third_party_generated || []).map(s => ({ ...s, _source: 'Third‑Party' }))
      ];
      if (!all.length) {
        list.html('<p class="text-muted text-center mb-0">No auto‑generated signatures yet.</p>');
        return;
      }
      const html = all.slice(0, 20).map(s => `
        <div class="signature-card mb-2" data-severity="${(s.severity || 'Low')}">
          <h6><i class="bi bi-magic"></i> ${escapeHtml(s.pattern || '')}</h6>
          <div class="signature-meta">
            <strong>Type:</strong> ${escapeHtml(s.type || '')} &nbsp;·&nbsp;
            <strong>Source:</strong> ${escapeHtml(s.source || s._source || '')}
          </div>
        </div>
      `).join('');
      list.html(html);
    })
    .catch(() => {
      $('#generatedSignaturesList').html('<p class="text-muted text-center mb-0">Failed to load generated signatures.</p>');
    });

// ===== Enhanced Device Management =====
function filterDevices(query, status) {
  query = (query || '').toLowerCase();
  status = status || 'all';
  
  $('.agent-card[data-agent-id]').each(function() {
    const $card = $(this);
    const text = $card.text().toLowerCase();
    const cardStatus = $card.hasClass('active') ? 'online' : 'offline';
    
    const matchesQuery = !query || text.includes(query);
    const matchesStatus = status === 'all' || cardStatus === status;
    
    $card.closest('.col-md-6, .col-lg-4').toggle(matchesQuery && matchesStatus);
  });
}

function fetchEnhancedDevices() {
  fetch('/api/devices/stats')
    .then(r => r.json())
    .then(data => {
      $('#devicesTotal').text(data.total || 0);
      $('#devicesConnections').text(data.active_connections || 0);
      $('#devicesBlocked').text(data.blocked_ips || 0);
      $('#devicesEvents').text(formatNumber(data.total_events || 0));
    })
    .catch(err => console.error('Device stats fetch failed', err));
}

function exportDevices() {
  fetch('/api/devices/export')
    .then(r => r.json())
    .then(data => {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `devices-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showNotification('Devices exported successfully', 'success');
    })
    .catch(err => showNotification('Export failed', 'error'));
}

// ===== Bulk Actions =====
function executeBulkAction() {
  const action = $('#bulkActionType').val();
  const items = $('#bulkActionItems').val().split('\n').filter(i => i.trim());
  
  if (items.length === 0) {
    showNotification('Please enter at least one item', 'error');
    return;
  }
  
  fetch('/api/bulk/execute', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: action, items: items })
  })
    .then(r => r.json())
    .then(data => {
      showNotification(`Bulk action executed: ${data.processed || 0} items processed`, 'success');
      $('#bulkActionModal').modal('hide');
      $('#bulkActionItems').val('');
    })
    .catch(err => showNotification(`Bulk action failed: ${err.message}`, 'error'));
}

// ===== Utility: Debounce =====
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

// Enhanced navigation with data loading
function initNavigationEnhanced() {
  $('.sidebar li').on('click', function() {
    $('.sidebar li').removeClass('active');
    $(this).addClass('active');
    const view = $(this).data('view');
    $('.view-section').addClass('hidden');
    $(`#view-${view}`).removeClass('hidden');
    
    // Load data when switching views
    if (view === 'feed') {
      // Already loaded
    } else if (view === 'analytics') {
      fetchEnhancedAnalytics();
      fetchAnalytics();
      fetchMlFeedbackStats();
      fetchThirdPartyStatus();
    } else if (view === 'threats') {
      fetchThreats();
      loadThreatTabs();
      fetch('/api/threats/stats')
        .then(r => r.json())
        .then(data => {
          $('#threatCritical').text(data.critical || 0);
          $('#threatActiveIPs').text(data.active_ips || 0);
          $('#threatSuspiciousURLs').text(data.suspicious_urls || 0);
        });
    } else if (view === 'agents') {
      fetchAgents();
      fetchEnhancedAgents();
    } else if (view === 'firewall') {
      fetchFirewallStats();
      fetchFirewallRules();
    } else if (view === 'signatures') {
      loadSignatures();
      fetchEnhancedSignatures();
      fetchGeneratedSignatures();
    } else if (view === 'devices') {
      fetchDevices();
      fetchEnhancedDevices();
      fetchAllDevicesPerformance();
    } else if (view === 'connections') {
      fetchActiveConnections();
      fetchConnectionHealth();
      fetchThreatCorrelation();
      fetchConnectionsTimeline(24);
      updateConnectionFlowDiagram();
    } else if (view === 'automation') {
      loadAutomationRules();
    } else if (view === 'map') {
      fetchGeoMap();
    } else if (view === 'export') {
      updateExportStats();
    }
  });
}

// ===== Firewall Management =====
function fetchFirewallStats() {
  fetch('/api/firewall/summary')
    .then(r => r.json())
    .then(data => {
      $('#fwTotalRules').text(data.total_rules || 0);
      $('#fwTotalIps').text(data.ips || 0);
      $('#fwTotalDomains').text(data.domains || 0);
      $('#fwTotalCidrs').text(data.cidrs || 0);
    })
    .catch(err => console.error('Failed to fetch firewall summary:', err));
}

function fetchFirewallRules() {
  fetch('/api/firewall/rules/flat')
    .then(r => r.json())
    .then(rules => {
      const tbody = $('#fwRulesTableBody');
      if (!rules.length) {
        tbody.html('<tr><td colspan="5" class="text-center text-muted">No firewall rules configured.</td></tr>');
        return;
      }
      const html = rules.map(rule => `
        <tr>
          <td>${rule.scope === 'all' ? '<span class="badge bg-info">All Agents</span>' : `<code>${escapeHtml(rule.scope)}</code>`}</td>
          <td><span class="badge bg-${rule.mode === 'page' ? 'warning' : rule.mode === 'allow' ? 'success' : 'danger'} text-uppercase">${escapeHtml(rule.mode || 'drop')}</span></td>
          <td><span class="badge bg-primary text-uppercase">${escapeHtml(rule.type)}</span></td>
          <td><code>${escapeHtml(rule.value)}</code></td>
          <td class="text-end">
            <button class="btn btn-sm btn-outline-danger" onclick="unblockFirewallRule('${rule.scope}', '${rule.type}', '${rule.value}')">
              <i class="bi bi-x-circle"></i> Remove
            </button>
          </td>
        </tr>
      `).join('');
      tbody.html(html);
    })
    .catch(err => {
      console.error('Failed to fetch firewall rules:', err);
      $('#fwRulesTableBody').html('<tr><td colspan="4" class="text-center text-danger">Failed to load firewall rules.</td></tr>');
    });
}

function unblockFirewallRule(scope, type, value) {
  const payload = {};
  if (scope && scope !== 'all') {
    payload.agent_id = scope;
  }
  if (type === 'ip') {
    payload.ip = value;
  } else if (type === 'domain') {
    payload.domain = value;
  } else if (type === 'cidr') {
    payload.cidr = value;
  }
  fetch('/api/firewall/unblock', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(r => r.json())
    .then(() => {
      showNotification('Firewall rule removed', 'success');
      fetchFirewallStats();
      fetchFirewallRules();
    })
    .catch(err => {
      showNotification(`Failed to remove rule: ${err.message}`, 'error');
    });
}

function addFirewallRule() {
  const type = $('#fwRuleType').val();
  const value = $('#fwRuleValue').val().trim();
  const portRaw = $('#fwRulePort').val().trim();
  const scope = $('#fwRuleScope').val().trim();
  const actionMode = $('#fwRuleAction').val() || 'drop';
  if (!value) {
    showNotification('Please enter a value for the rule', 'error');
    return;
  }
  const payload = {};
  if (type === 'ip') {
    payload.ip = value;
  } else if (type === 'domain') {
    payload.domain = value;
  } else if (type === 'cidr') {
    payload.cidr = value;
  }
  if (portRaw) {
    const portNum = parseInt(portRaw, 10);
    if (!isNaN(portNum) && portNum > 0 && portNum <= 65535) {
      payload.port = portNum;
    }
  }
  // Attach desired action/mode for the rule
  payload.mode = actionMode;
  if (scope && scope.toLowerCase() !== 'all') {
    payload.agent_id = scope;
  } else {
    payload.agent_id = 'all';
  }
  fetch('/api/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  })
    .then(r => r.json())
    .then(res => {
      if (res.error) {
        throw new Error(res.error);
      }
      showNotification('Firewall rule added', 'success');
      $('#fwRuleValue').val('');
      fetchFirewallStats();
      fetchFirewallRules();
    })
    .catch(err => {
      showNotification(`Failed to add rule: ${err.message}`, 'error');
    });
}

// Replace original initNavigation
initNavigation = initNavigationEnhanced;

// ===============================================================
// NEW CUTTING-EDGE FEATURES v9.0
// ===============================================================

// ===== Real-Time Connection Monitoring =====
function fetchActiveConnections() {
  fetch('/api/connections/active')
    .then(r => r.json())
    .then(connections => {
      if ($('#activeConnectionsList').length) {
        const html = connections.length > 0
          ? connections.map(conn => `
            <tr>
              <td><code>${escapeHtml(conn.agent_id)}</code></td>
              <td>${escapeHtml(conn.src_ip)}</td>
              <td>${escapeHtml(conn.dst_ip)}</td>
              <td><span class="badge bg-primary">${escapeHtml(conn.protocol)}</span></td>
              <td>${conn.port || 'N/A'}</td>
              <td>${formatBytes(conn.bytes_sent + conn.bytes_recv)}</td>
              <td>${conn.packet_count}</td>
              <td>${formatTimestamp(conn.last_seen)}</td>
            </tr>
          `).join('')
          : '<tr><td colspan="8" class="text-center text-muted">No active connections</td></tr>';
        $('#activeConnectionsList').html(html);
      }
    })
    .catch(err => console.error('Failed to fetch active connections:', err));
}

function fetchConnectionHealth() {
  fetch('/api/connections/health')
    .then(r => r.json())
    .then(health => {
      if ($('#connectionHealthScore').length) {
        $('#connectionHealthScore').text(Math.round(health.health_score) + '%');
        $('#totalUniqueConnections').text(health.total_unique_connections);
        $('#suspiciousConnections').text(health.suspicious_connections);
        
        const healthEl = $('#connectionHealthIndicator');
        healthEl.removeClass('bg-success bg-warning bg-danger');
        if (health.health_score >= 80) {
          healthEl.addClass('bg-success').text('Healthy');
        } else if (health.health_score >= 50) {
          healthEl.addClass('bg-warning').text('Warning');
        } else {
          healthEl.addClass('bg-danger').text('Critical');
        }
      }
    })
    .catch(err => console.error('Failed to fetch connection health:', err));
}

// ===== Threat Correlation =====
function fetchThreatCorrelation() {
  fetch('/api/threats/correlation')
    .then(r => r.json())
    .then(data => {
      if ($('#correlatedThreatsList').length) {
        const html = data.correlated_threats.length > 0
          ? data.correlated_threats.map(threat => `
            <div class="card mb-2">
              <div class="card-body">
                <h6><code>${escapeHtml(threat.ip)}</code></h6>
                <p class="mb-1"><strong>Affected Agents:</strong> ${threat.affected_agents}</p>
                <p class="mb-1"><strong>Event Count:</strong> ${threat.event_count}</p>
                <p class="mb-0"><strong>Reasons:</strong> ${threat.reasons.join(', ')}</p>
              </div>
            </div>
          `).join('')
          : '<p class="text-muted text-center">No correlated threats found</p>';
        $('#correlatedThreatsList').html(html);
      }
    })
    .catch(err => console.error('Failed to fetch threat correlation:', err));
}

// ===== Device Performance Monitoring =====
function fetchDevicePerformance(agentId) {
  if (!agentId) return;
  fetch(`/api/devices/${agentId}/performance`)
    .then(r => r.json())
    .then(perf => {
      if ($(`#perf-${agentId}`).length) {
        $(`#perf-${agentId}`).html(`
          <div class="row">
            <div class="col-md-6">
              <p><strong>Health Score:</strong> <span class="badge bg-${perf.health_score >= 80 ? 'success' : perf.health_score >= 50 ? 'warning' : 'danger'}">${Math.round(perf.health_score)}%</span></p>
              <p><strong>Total Events:</strong> ${perf.event_metrics.total_events}</p>
              <p><strong>Alerts:</strong> ${perf.event_metrics.alerts}</p>
            </div>
            <div class="col-md-6">
              <p><strong>Unique Destinations:</strong> ${perf.event_metrics.unique_destinations}</p>
              <p><strong>Avg Bytes/Event:</strong> ${formatBytes(perf.event_metrics.avg_bytes_per_event)}</p>
              <p><strong>Unique Protocols:</strong> ${perf.event_metrics.unique_protocols}</p>
            </div>
          </div>
        `);
      }
    })
    .catch(err => console.error('Failed to fetch device performance:', err));
}

function fetchAllDevicesPerformance() {
  fetch('/api/devices/performance/summary')
    .then(r => r.json())
    .then(devices => {
      if ($('#devicesPerformanceList').length) {
        const html = devices.map(dev => `
          <tr>
            <td><code>${escapeHtml(dev.agent_id)}</code></td>
            <td>${dev.total_events}</td>
            <td><span class="badge bg-danger">${dev.alerts}</span></td>
            <td>${formatBytes(dev.avg_bytes_per_event)}</td>
            <td>${dev.unique_destinations}</td>
            <td><span class="badge bg-${dev.health_score >= 80 ? 'success' : dev.health_score >= 50 ? 'warning' : 'danger'}">${Math.round(dev.health_score)}%</span></td>
          </tr>
        `).join('');
        $('#devicesPerformanceList').html(html || '<tr><td colspan="6" class="text-center text-muted">No performance data</td></tr>');
      }
    })
    .catch(err => console.error('Failed to fetch devices performance:', err));
}

// ===== Threat Timeline Visualization =====
let threatTimelineChart = null;

function initThreatTimelineChart() {
  const ctx = document.getElementById('threatTimelineChart');
  if (!ctx) return;
  
  threatTimelineChart = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Total Events',
        data: [],
        borderColor: '#00ffe0',
        backgroundColor: 'rgba(0, 255, 224, 0.1)',
        fill: true
      }, {
        label: 'Alerts',
        data: [],
        borderColor: '#ff5252',
        backgroundColor: 'rgba(255, 82, 82, 0.1)',
        fill: true
      }]
    },
    options: {
      responsive: false,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#e8f0ff' } }
      },
      scales: {
        x: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

let connectionsTimelineChart = null;

function initConnectionsTimelineChart() {
  const ctx = document.getElementById('connectionsTimelineChart');
  if (!ctx) return;
  
  connectionsTimelineChart = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: [],
      datasets: [{
        label: 'Total Events',
        data: [],
        borderColor: '#00ffe0',
        backgroundColor: 'rgba(0, 255, 224, 0.1)',
        fill: true
      }, {
        label: 'Alerts',
        data: [],
        borderColor: '#ff5252',
        backgroundColor: 'rgba(255, 82, 82, 0.1)',
        fill: true
      }]
    },
    options: {
      responsive: false,
      maintainAspectRatio: false,
      plugins: {
        legend: { labels: { color: '#e8f0ff' } }
      },
      scales: {
        x: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } },
        y: { ticks: { color: '#9fb3c8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
      }
    }
  });
}

function fetchThreatTimeline(hours = 24) {
  fetch(`/api/threats/timeline?hours=${hours}`)
    .then(r => r.json())
    .then(data => {
      if (threatTimelineChart) {
        threatTimelineChart.data.labels = data.map(d => d.time);
        threatTimelineChart.data.datasets[0].data = data.map(d => d.total_events);
        threatTimelineChart.data.datasets[1].data = data.map(d => d.alerts);
        threatTimelineChart.update('none');
      }
    })
    .catch(err => console.error('Failed to fetch threat timeline:', err));
}

function fetchConnectionsTimeline(hours = 24) {
  fetch(`/api/threats/timeline?hours=${hours}`)
    .then(r => r.json())
    .then(data => {
      if (connectionsTimelineChart) {
        connectionsTimelineChart.data.labels = data.map(d => d.time);
        connectionsTimelineChart.data.datasets[0].data = data.map(d => d.total_events);
        connectionsTimelineChart.data.datasets[1].data = data.map(d => d.alerts);
        connectionsTimelineChart.update('none');
      }
    })
    .catch(err => console.error('Failed to fetch connections timeline:', err));
}

// ===== Threat Predictions =====
function fetchThreatPredictions() {
  fetch('/api/analytics/predictions')
    .then(r => r.json())
    .then(pred => {
      if ($('#predictedAlerts').length) {
        $('#predictedAlerts').text(pred.predicted_alerts_next_hour);
        $('#predictionConfidence').text(pred.confidence + '%');
      }
    })
    .catch(err => console.error('Failed to fetch threat predictions:', err));
}

// Auto-refresh new features
setInterval(() => {
  if ($('#view-devices').is(':visible')) {
    fetchAllDevicesPerformance();
  }
  fetchConnectionHealth();
  fetchActiveConnections();
  fetchThreatCorrelation();
  fetchThreatPredictions();
}, 30000); // Every 30 seconds

// Initialize threat timeline chart
$(document).ready(() => {
  initThreatTimelineChart();
  fetchThreatTimeline(24);
  initConnectionFlowDiagram();
  loadAutomationRules();
});

// ===== Connection Flow Diagram =====
function initConnectionFlowDiagram() {
  const svg = document.getElementById('flowSvg');
  if (!svg) return;
  
  // Clear existing content
  svg.innerHTML = '';
  
  // This will be populated with real connection data
  updateConnectionFlowDiagram();
}

function updateConnectionFlowDiagram() {
  const svg = document.getElementById('flowSvg');
  if (!svg) return;
  
  fetch('/api/connections/active')
    .then(r => r.json())
    .then(connections => {
      if (connections.length === 0) {
        svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#9fb3c8" font-size="16">No active connections</text>';
        return;
      }
      
      // Group connections by agent
      const agentGroups = {};
      connections.forEach(conn => {
        if (!agentGroups[conn.agent_id]) {
          agentGroups[conn.agent_id] = [];
        }
        agentGroups[conn.agent_id].push(conn);
      });
      
      const agents = Object.keys(agentGroups);
      const width = svg.clientWidth || 800;
      const height = svg.clientHeight || 400;
      const agentY = height / (agents.length + 1);
      
      // Draw agents
      agents.forEach((agentId, idx) => {
        const y = agentY * (idx + 1);
        const x = 100;
        
        // Agent node
        svg.innerHTML += `
          <circle cx="${x}" cy="${y}" r="30" fill="#00ffe0" opacity="0.8"/>
          <text x="${x}" y="${y + 5}" text-anchor="middle" fill="#0a0e1a" font-size="12" font-weight="bold">${agentId.substring(0, 6)}</text>
        `;
        
        // Connections from this agent
        const conns = agentGroups[agentId];
        const uniqueDests = [...new Set(conns.map(c => c.dst_ip))];
        uniqueDests.forEach((dest, destIdx) => {
          const destX = width - 100;
          const destY = (height / (uniqueDests.length + 1)) * (destIdx + 1);
          
          // Destination node
          svg.innerHTML += `
            <circle cx="${destX}" cy="${destY}" r="25" fill="#ff5252" opacity="0.8"/>
            <text x="${destX}" y="${destY + 4}" text-anchor="middle" fill="#fff" font-size="10">${dest.split('.').pop()}</text>
          `;
          
          // Connection line
          svg.innerHTML += `
            <line x1="${x + 30}" y1="${y}" x2="${destX - 25}" y2="${destY}" 
                  stroke="#7c6fff" stroke-width="2" opacity="0.6" marker-end="url(#arrowhead)"/>
          `;
        });
      });
      
      // Arrow marker definition
      if (!document.getElementById('arrowhead')) {
        const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
        const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
        marker.setAttribute('id', 'arrowhead');
        marker.setAttribute('markerWidth', '10');
        marker.setAttribute('markerHeight', '10');
        marker.setAttribute('refX', '9');
        marker.setAttribute('refY', '3');
        marker.setAttribute('orient', 'auto');
        const polygon = document.createElementNS('http://www.w3.org/2000/svg', 'polygon');
        polygon.setAttribute('points', '0 0, 10 3, 0 6');
        polygon.setAttribute('fill', '#7c6fff');
        marker.appendChild(polygon);
        defs.appendChild(marker);
        svg.appendChild(defs);
      }
    })
    .catch(err => {
      console.error('Failed to update connection flow:', err);
      const svg = document.getElementById('flowSvg');
      if (svg) {
        svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#ff5252" font-size="14">Error loading connection flow</text>';
      }
    });
}

// Auto-update connection flow diagram
setInterval(() => {
  if ($('#view-connections').is(':visible') && !$('#view-connections').hasClass('hidden')) {
    updateConnectionFlowDiagram();
  }
}, 10000); // Every 10 seconds

// ===== Automation Rules Management =====
function loadAutomationRules() {
  fetch('/api/automation/rules')
    .then(r => r.json())
    .then(rules => {
      const tbody = $('#automationRulesList');
      if (rules.length === 0) {
        tbody.html('<tr><td colspan="7" class="text-center text-muted">No automation rules configured</td></tr>');
        return;
      }
      
      const html = rules.map(rule => `
        <tr>
          <td>${rule.id}</td>
          <td><strong>${escapeHtml(rule.name || 'Unnamed Rule')}</strong></td>
          <td><code>${escapeHtml(rule.condition_type || 'N/A')}</code>: ${escapeHtml(rule.condition_value || 'N/A')}</td>
          <td><span class="badge bg-info">${escapeHtml(rule.action || 'N/A')}</span></td>
          <td>
            <span class="badge bg-${rule.enabled ? 'success' : 'secondary'}">
              ${rule.enabled ? 'Active' : 'Disabled'}
            </span>
          </td>
          <td>${formatTimestamp(rule.created_at)}</td>
          <td>
            <button class="btn btn-sm btn-outline-warning" onclick="toggleAutomationRule(${rule.id})">
              <i class="bi bi-toggle-${rule.enabled ? 'on' : 'off'}"></i>
            </button>
            <button class="btn btn-sm btn-outline-danger" onclick="deleteAutomationRule(${rule.id})">
              <i class="bi bi-trash"></i>
            </button>
          </td>
        </tr>
      `).join('');
      tbody.html(html);
      
      // Update stats
      $('#totalRules').text(rules.length);
      $('#activeRules').text(rules.filter(r => r.enabled).length);
    })
    .catch(err => {
      console.error('Failed to load automation rules:', err);
      $('#automationRulesList').html('<tr><td colspan="7" class="text-center text-danger">Error loading rules</td></tr>');
    });
}

function toggleAutomationRule(ruleId) {
  fetch(`/api/automation/rules/${ruleId}/toggle`, { method: 'POST' })
    .then(r => r.json())
    .then(data => {
      showNotification('Rule toggled successfully', 'success');
      loadAutomationRules();
    })
    .catch(err => {
      showNotification(`Failed to toggle rule: ${err.message}`, 'error');
    });
}

function deleteAutomationRule(ruleId) {
  if (!confirm('Are you sure you want to delete this automation rule?')) return;
  
  fetch(`/api/automation/rules/${ruleId}`, { method: 'DELETE' })
    .then(r => r.json())
    .then(data => {
      showNotification('Rule deleted successfully', 'success');
      loadAutomationRules();
    })
    .catch(err => {
      showNotification(`Failed to delete rule: ${err.message}`, 'error');
    });
}

// Handle automation rule form submission
$(document).on('submit', '#automationRuleForm', function(e) {
  e.preventDefault();
  
  const ruleData = {
    name: $('#ruleName').val(),
    condition_type: $('#ruleConditionType').val(),
    condition_value: $('#ruleConditionValue').val(),
    action: $('#ruleAction').val(),
    action_params: $('#ruleActionParams').val() ? JSON.parse($('#ruleActionParams').val()) : {},
    enabled: $('#ruleEnabled').is(':checked')
  };
  
  fetch('/api/automation/rules', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(ruleData)
  })
    .then(r => r.json())
    .then(data => {
      showNotification('Automation rule created successfully', 'success');
      $('#automationRuleModal').modal('hide');
      $('#automationRuleForm')[0].reset();
      loadAutomationRules();
    })
    .catch(err => {
      showNotification(`Failed to create rule: ${err.message}`, 'error');
    });
});

// Button handlers
$(document).on('click', '#btnAddAutomationRule', function() {
  $('#automationRuleModal').modal('show');
});

$(document).on('click', '#btnRefreshAutomation', function() {
  loadAutomationRules();
});

$(document).on('click', '#btnRefreshConnections', function() {
  fetchActiveConnections();
  fetchConnectionHealth();
  fetchThreatCorrelation();
  updateConnectionFlowDiagram();
});

// ===== Real-Time Correlated Threat Alerts =====
let lastCorrelatedThreats = [];
let correlatedThreatAlertShown = {};

function checkForNewCorrelatedThreats() {
  fetch('/api/threats/correlation')
    .then(r => r.json())
    .then(data => {
      const currentThreats = data.correlated_threats || [];
      
      // Find new threats that haven't been alerted
      currentThreats.forEach(threat => {
        const threatKey = `${threat.ip}_${threat.affected_agents}`;
        if (!correlatedThreatAlertShown[threatKey] && threat.affected_agents > 1) {
          showCorrelatedThreatAlert(threat);
          correlatedThreatAlertShown[threatKey] = true;
        }
      });
      
      lastCorrelatedThreats = currentThreats;
    })
    .catch(err => console.error('Failed to check correlated threats:', err));
}

function showCorrelatedThreatAlert(threat) {
  $('#correlatedThreatIP').text(threat.ip);
  $('#correlatedThreatAgents').text(threat.affected_agents);
  $('#correlatedThreatCount').text(threat.event_count);
  
  // Store threat IP for blocking
  $('#btnBlockCorrelatedThreat').data('threat-ip', threat.ip);
  
  const toast = new bootstrap.Toast(document.getElementById('correlatedThreatToast'), {
    delay: 10000, // 10 seconds
    autohide: false
  });
  toast.show();
  
  // Also show in main notification
  showNotification(`🚨 Correlated threat detected: ${threat.ip} affecting ${threat.affected_agents} agents`, 'error');
}

// Handle block correlated threat button
$(document).on('click', '#btnBlockCorrelatedThreat', function() {
  const ip = $(this).data('threat-ip');
  if (!ip) return;
  
  fetch('/api/firewall/block', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, agent_id: 'all', reason: 'Correlated threat detected' })
  })
    .then(r => r.json())
    .then(data => {
      showNotification(`IP ${ip} blocked successfully`, 'success');
      bootstrap.Toast.getInstance(document.getElementById('correlatedThreatToast')).hide();
    })
    .catch(err => {
      showNotification(`Failed to block IP: ${err.message}`, 'error');
    });
});

// Check for correlated threats every 30 seconds
setInterval(checkForNewCorrelatedThreats, 30000);
}