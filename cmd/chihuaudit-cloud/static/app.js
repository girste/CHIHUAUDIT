(function() {
  'use strict';

  var currentHostId = null;

  // --- API helpers ---
  async function api(path, opts) {
    var res = await fetch(path, opts);
    if (res.status === 401) {
      window.location.href = '/login.html';
      throw new Error('unauthorized');
    }
    if (!res.ok) {
      var data = await res.json().catch(function() { return {}; });
      throw new Error(data.error || 'Request failed');
    }
    return res.json();
  }

  // --- Auth ---
  window.logout = async function() {
    await fetch('/api/logout', {method: 'POST'});
    window.location.href = '/login.html';
  };

  // --- Dashboard ---
  async function loadDashboard() {
    try {
      var results = await Promise.all([
        api('/api/dashboard'),
        api('/api/hosts')
      ]);
      var stats = results[0];
      var hosts = results[1];

      document.getElementById('stat-hosts').textContent = stats.total_hosts;
      document.getElementById('stat-online').textContent = stats.online_hosts;
      document.getElementById('stat-audits').textContent = stats.total_audits;

      renderHostsTable(hosts);
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('Dashboard load error:', e);
    }
  }

  function renderHostsTable(hosts) {
    var tbody = document.getElementById('hosts-table');
    if (!hosts.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:#8b949e">No hosts yet</td></tr>';
      return;
    }
    tbody.innerHTML = hosts.map(function(h) {
      var lastSeen = h.last_seen ? timeAgo(new Date(h.last_seen)) : 'Never';
      var online = h.last_seen && (Date.now() - new Date(h.last_seen).getTime()) < 86400000;
      var statusBadge = online
        ? '<span class="badge badge-green">Online</span>'
        : '<span class="badge badge-gray">Offline</span>';
      return '<tr>' +
        '<td><a href="#" onclick="showHost(' + h.id + '); return false">' + esc(h.name) + '</a></td>' +
        '<td>' + lastSeen + '</td>' +
        '<td>' + h.audit_count + '</td>' +
        '<td>' + statusBadge + '</td>' +
        '<td><a href="#" onclick="showHost(' + h.id + '); return false" class="btn btn-sm">View</a></td>' +
      '</tr>';
    }).join('');
  }

  // --- Host Detail ---
  window.showHost = async function(id) {
    currentHostId = id;
    document.getElementById('view-dashboard').style.display = 'none';
    document.getElementById('view-host').style.display = 'block';

    try {
      var results = await Promise.all([
        api('/api/hosts/' + id),
        api('/api/hosts/' + id + '/audits'),
        api('/api/hosts/' + id + '/config')
      ]);
      var host = results[0];
      var audits = results[1];
      var cfg = results[2];

      document.getElementById('host-name').textContent = host.name;
      document.getElementById('delete-host-btn').onclick = function() { deleteHost(id); };

      // Hide rotated key from previous rotation
      document.getElementById('rotated-key-result').style.display = 'none';

      // Load config
      document.getElementById('cfg-webhook').value = cfg.webhook_url || '';
      document.getElementById('cfg-cpu').value = cfg.cpu_threshold || 60;
      document.getElementById('cfg-mem').value = cfg.memory_threshold || 60;
      document.getElementById('cfg-disk').value = cfg.disk_threshold || 80;
      document.getElementById('cfg-ignore').value = (cfg.ignore_changes || []).join(', ');
      document.getElementById('cfg-retention').value = cfg.retention_days || 90;
      document.getElementById('config-status').style.display = 'none';
      document.getElementById('webhook-status').style.display = 'none';

      // Latest audit - structured rendering
      var latestDiv = document.getElementById('latest-audit');
      if (audits.length > 0) {
        var prevResults = audits.length > 1 ? audits[1].results : null;
        latestDiv.innerHTML = renderAuditResults(audits[0].results, prevResults);
      } else {
        latestDiv.innerHTML = '<div class="audit-results"><pre>No audits yet</pre></div>';
      }

      // Audit history table
      var tbody = document.getElementById('audits-table');
      if (!audits.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#8b949e">No audits</td></tr>';
        return;
      }
      tbody.innerHTML = audits.map(function(a) {
        var date = new Date(a.created_at).toLocaleString();
        var checks = countChecks(a.results);
        return '<tr>' +
          '<td>' + date + '</td>' +
          '<td>' + checks + '</td>' +
          '<td><a href="#" onclick="showAuditDetail(' + a.id + ', ' + esc(JSON.stringify(JSON.stringify(a.results))) + '); return false" class="btn btn-sm">View</a></td>' +
        '</tr>';
      }).join('');
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('Host load error:', e);
    }
  };

  window.showDashboard = function() {
    currentHostId = null;
    document.getElementById('view-dashboard').style.display = 'block';
    document.getElementById('view-host').style.display = 'none';
    loadDashboard();
  };

  async function deleteHost(id) {
    if (!confirm('Delete this host and all its audits?')) return;
    try {
      await api('/api/hosts/' + id, {method: 'DELETE'});
      showDashboard();
    } catch (e) {
      alert('Error: ' + e.message);
    }
  }

  // --- Host Config ---
  window.saveHostConfig = async function() {
    if (!currentHostId) return;
    var ignoreStr = document.getElementById('cfg-ignore').value;
    var ignoreArr = ignoreStr.split(',').map(function(s) { return s.trim(); }).filter(Boolean);

    try {
      await api('/api/hosts/' + currentHostId + '/config', {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          webhook_url: document.getElementById('cfg-webhook').value.trim(),
          cpu_threshold: parseFloat(document.getElementById('cfg-cpu').value) || 60,
          memory_threshold: parseFloat(document.getElementById('cfg-mem').value) || 60,
          disk_threshold: parseFloat(document.getElementById('cfg-disk').value) || 80,
          ignore_changes: ignoreArr,
          retention_days: parseInt(document.getElementById('cfg-retention').value) || 90
        })
      });
      var statusEl = document.getElementById('config-status');
      statusEl.style.display = 'inline';
      setTimeout(function() { statusEl.style.display = 'none'; }, 3000);
    } catch (e) {
      alert('Error saving config: ' + e.message);
    }
  };

  window.toggleSection = function(id) {
    var el = document.getElementById(id);
    if (el) el.classList.toggle('collapsed');
  };

  // --- Add Host Modal ---
  window.showAddHostModal = function() {
    document.getElementById('host-name-input').value = '';
    document.getElementById('api-key-result').style.display = 'none';
    document.getElementById('create-host-btn').style.display = '';
    document.getElementById('add-host-modal').classList.add('active');
  };

  window.closeAddHostModal = function() {
    document.getElementById('add-host-modal').classList.remove('active');
    loadDashboard();
  };

  window.createHost = async function() {
    var name = document.getElementById('host-name-input').value.trim();
    if (!name) return alert('Name is required');
    try {
      var host = await api('/api/hosts', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({name: name})
      });
      document.getElementById('api-key-value').textContent = host.api_key;
      document.getElementById('api-key-result').style.display = 'block';
      document.getElementById('create-host-btn').style.display = 'none';
    } catch (e) {
      alert('Error: ' + e.message);
    }
  };

  // --- Audit Detail Modal ---
  window.showAuditDetail = function(id, resultsStr) {
    var results = JSON.parse(resultsStr);
    document.getElementById('audit-detail-content').innerHTML = renderAuditResults(results, null);
    document.getElementById('audit-detail-modal').classList.add('active');
  };

  window.closeAuditDetail = function() {
    document.getElementById('audit-detail-modal').classList.remove('active');
  };

  // --- Structured Audit Rendering ---
  var SECTION_ORDER = [
    {key: 'security',  label: 'Security',  icon: '&#128274;'},
    {key: 'services',  label: 'Services',  icon: '&#9881;'},
    {key: 'resources', label: 'Resources', icon: '&#128200;'},
    {key: 'storage',   label: 'Storage',   icon: '&#128190;'},
    {key: 'database',  label: 'Database',  icon: '&#128451;'},
    {key: 'docker',    label: 'Docker',    icon: '&#128051;'},
    {key: 'network',   label: 'Network',   icon: '&#127760;'},
    {key: 'logs',      label: 'Logs',      icon: '&#128196;'},
    {key: 'backups',   label: 'Backups',   icon: '&#128229;'},
    {key: 'tuning',    label: 'Tuning',    icon: '&#128295;'},
    {key: 'system',    label: 'System',    icon: '&#128187;'}
  ];

  var STATUS_KEYS = ['firewall', 'web_status', 'db_status', 'disk_health', 'status', 'available'];

  function renderAuditResults(results, prevResults) {
    if (!results || typeof results !== 'object' || Array.isArray(results)) {
      return '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
    }

    var html = '';
    var prev = prevResults && typeof prevResults === 'object' ? prevResults : {};

    // Top-level info (hostname, os, kernel, etc.)
    var topKeys = ['hostname', 'os', 'kernel', 'uptime', 'timestamp', 'total_checks'];
    var topHtml = '';
    for (var i = 0; i < topKeys.length; i++) {
      if (results[topKeys[i]] !== undefined) {
        topHtml += renderItem(topKeys[i], results[topKeys[i]], null);
      }
    }
    if (topHtml) {
      html += '<div class="audit-card open"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">&#128187; System Info <span class="toggle-icon">&#9660;</span></div><div class="audit-card-body">' + topHtml + '</div></div>';
    }

    // Known sections
    for (var s = 0; s < SECTION_ORDER.length; s++) {
      var sec = SECTION_ORDER[s];
      if (!results[sec.key] || typeof results[sec.key] !== 'object') continue;
      var sectionData = results[sec.key];
      var prevSection = prev[sec.key] && typeof prev[sec.key] === 'object' ? prev[sec.key] : null;
      var badge = getSectionBadge(sectionData);
      var bodyHtml = renderObject(sectionData, prevSection);

      html += '<div class="audit-card">' +
        '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' +
          sec.icon + ' ' + sec.label +
          (badge ? ' <span class="section-badge">' + badge + '</span>' : '') +
          ' <span class="toggle-icon">&#9660;</span>' +
        '</div>' +
        '<div class="audit-card-body">' + bodyHtml + '</div></div>';
    }

    // Remaining unknown sections
    var renderedKeys = {};
    for (var t = 0; t < topKeys.length; t++) renderedKeys[topKeys[t]] = true;
    for (var u = 0; u < SECTION_ORDER.length; u++) renderedKeys[SECTION_ORDER[u].key] = true;
    renderedKeys['skipped'] = true;
    renderedKeys['notes'] = true;

    var allKeys = Object.keys(results);
    for (var e = 0; e < allKeys.length; e++) {
      var ek = allKeys[e];
      if (renderedKeys[ek]) continue;
      var val = results[ek];
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        var prevExtra = prev[ek] && typeof prev[ek] === 'object' ? prev[ek] : null;
        html += '<div class="audit-card">' +
          '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' + esc(formatKey(ek)) + ' <span class="toggle-icon">&#9660;</span></div>' +
          '<div class="audit-card-body">' + renderObject(val, prevExtra) + '</div></div>';
      }
    }

    // Notes
    if (results.notes && results.notes.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">&#128221; Notes <span class="toggle-icon">&#9660;</span></div><div class="audit-card-body">';
      for (var n = 0; n < results.notes.length; n++) {
        html += '<div class="audit-item"><span class="audit-item-value">' + esc(String(results.notes[n])) + '</span></div>';
      }
      html += '</div></div>';
    }
    // Skipped
    if (results.skipped && results.skipped.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">&#9888; Skipped <span class="toggle-icon">&#9660;</span></div><div class="audit-card-body">';
      for (var sk = 0; sk < results.skipped.length; sk++) {
        html += '<div class="audit-item"><span class="audit-item-value">' + esc(String(results.skipped[sk])) + '</span></div>';
      }
      html += '</div></div>';
    }

    return html || '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
  }

  function renderObject(obj, prevObj) {
    var html = '';
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = obj[k];
      var pv = prevObj ? prevObj[k] : undefined;

      if (v && typeof v === 'object' && !Array.isArray(v)) {
        html += '<div style="margin:.4rem 0 .2rem;font-size:.8rem;color:#58a6ff;font-weight:600">' + esc(formatKey(k)) + '</div>';
        html += renderObject(v, pv && typeof pv === 'object' ? pv : null);
      } else if (Array.isArray(v)) {
        html += renderArrayItems(k, v, pv);
      } else {
        html += renderItem(k, v, pv);
      }
    }
    return html;
  }

  function renderItem(key, value, prevValue) {
    var changed = prevValue !== undefined && prevValue !== null && JSON.stringify(prevValue) !== JSON.stringify(value);
    var valStr = formatValue(key, value);
    var statusClass = getStatusClass(key, value);
    var changeClass = changed ? ' changed' : '';

    return '<div class="audit-item">' +
      '<span class="audit-item-key">' + esc(formatKey(key)) + '</span>' +
      '<span class="audit-item-value' + changeClass + ' ' + statusClass + '">' + valStr +
        (changed ? ' <span style="font-size:.7rem;color:#8b949e">(was: ' + esc(formatValueRaw(prevValue)) + ')</span>' : '') +
      '</span></div>';
  }

  function renderArrayItems(key, arr, prevArr) {
    if (!arr.length) return renderItem(key, 'none', prevArr);

    if (arr[0] && typeof arr[0] === 'object') {
      var html = '<div style="margin:.4rem 0 .2rem;font-size:.8rem;color:#58a6ff;font-weight:600">' + esc(formatKey(key)) + ' (' + arr.length + ')</div>';
      for (var i = 0; i < arr.length; i++) {
        var item = arr[i];
        var prevItem = null;
        if (Array.isArray(prevArr)) {
          for (var j = 0; j < prevArr.length; j++) {
            if (prevArr[j] && (prevArr[j].path === item.path || prevArr[j].name === item.name)) {
              prevItem = prevArr[j]; break;
            }
          }
        }
        html += renderObject(item, prevItem);
        if (i < arr.length - 1) html += '<div style="border-bottom:1px solid #21262d;margin:.3rem 0"></div>';
      }
      return html;
    }

    var prevStr = Array.isArray(prevArr) ? prevArr.join(', ') : null;
    return renderItem(key, arr.join(', '), prevStr);
  }

  function getSectionBadge(data) {
    for (var i = 0; i < STATUS_KEYS.length; i++) {
      var k = STATUS_KEYS[i];
      if (data[k] !== undefined) {
        var v = data[k];
        if (typeof v === 'boolean') {
          return v ? '<span class="badge badge-green">OK</span>' : '<span class="badge badge-red">Issue</span>';
        }
        var sv = String(v).toLowerCase();
        if (sv === 'active' || sv === 'enabled' || sv === 'running' || sv === 'all passed' || sv === 'ok' || sv === 'pass' || sv === 'healthy') {
          return '<span class="badge badge-green">' + esc(String(v)) + '</span>';
        }
        if (sv === 'inactive' || sv === 'disabled' || sv === 'stopped' || sv === 'not found' || sv === 'n/a') {
          return '<span class="badge badge-gray">' + esc(String(v)) + '</span>';
        }
        if (sv.indexOf('fail') !== -1 || sv.indexOf('error') !== -1 || sv.indexOf('critical') !== -1 || sv.indexOf('degrad') !== -1) {
          return '<span class="badge badge-red">' + esc(String(v)) + '</span>';
        }
        if (sv.indexOf('warn') !== -1) {
          return '<span class="badge badge-yellow">' + esc(String(v)) + '</span>';
        }
      }
    }
    if (typeof data.failed === 'number' && data.failed > 0) {
      return '<span class="badge badge-red">' + data.failed + ' failed</span>';
    }
    return '';
  }

  function getStatusClass(key, value) {
    var s = String(value).toLowerCase();
    if (s === 'active' || s === 'enabled' || s === 'running' || s === 'ok' || s === 'pass' || s === 'healthy' || s === 'all passed' || value === true) return 'status-pass';
    if (s.indexOf('fail') !== -1 || s.indexOf('error') !== -1 || s.indexOf('degrad') !== -1 || s === 'inactive' || s === 'disabled' || s === 'stopped' || value === false) return 'status-fail';
    if (s.indexOf('warn') !== -1) return 'status-warn';
    return '';
  }

  function formatKey(key) {
    return key.replace(/_/g, ' ').replace(/\b\w/g, function(c) { return c.toUpperCase(); });
  }

  function formatValue(key, value) {
    if (value === null || value === undefined) return '<span class="status-unknown">N/A</span>';
    if (typeof value === 'boolean') return value ? '<span class="status-pass">Yes</span>' : '<span class="status-fail">No</span>';
    if (typeof value === 'number') {
      if (key.indexOf('percent') !== -1 || key.indexOf('pct') !== -1) return esc(value.toFixed(1) + '%');
      if (key.indexOf('bytes') !== -1 || key.indexOf('_total') !== -1 || key.indexOf('_used') !== -1 || key.indexOf('_free') !== -1 || key.indexOf('_available') !== -1) return esc(formatBytes(value));
      return esc(String(value));
    }
    return esc(String(value));
  }

  function formatValueRaw(value) {
    if (value === null || value === undefined) return 'N/A';
    if (typeof value === 'number' && value % 1 !== 0) return value.toFixed(1);
    return String(value);
  }

  function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    var units = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = Math.floor(Math.log(bytes) / Math.log(1024));
    if (i >= units.length) i = units.length - 1;
    return (bytes / Math.pow(1024, i)).toFixed(1) + ' ' + units[i];
  }

  // --- Helpers ---
  function esc(str) {
    var d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
  }

  function timeAgo(date) {
    var s = Math.floor((Date.now() - date.getTime()) / 1000);
    if (s < 60) return s + 's ago';
    if (s < 3600) return Math.floor(s/60) + 'm ago';
    if (s < 86400) return Math.floor(s/3600) + 'h ago';
    return Math.floor(s/86400) + 'd ago';
  }

  function countChecks(results) {
    if (Array.isArray(results)) return results.length + ' checks';
    if (typeof results === 'object' && results !== null) return Object.keys(results).length + ' sections';
    return '-';
  }

  // --- Test Webhook ---
  window.testWebhook = async function() {
    if (!currentHostId) return;
    var statusEl = document.getElementById('webhook-status');
    statusEl.textContent = 'Sending...';
    statusEl.style.color = '#8b949e';
    statusEl.style.display = 'inline';
    try {
      await api('/api/hosts/' + currentHostId + '/test-webhook', {method: 'POST'});
      statusEl.textContent = 'Sent!';
      statusEl.style.color = '#3fb950';
    } catch (e) {
      statusEl.textContent = 'Failed: ' + e.message;
      statusEl.style.color = '#f85149';
    }
    setTimeout(function() { statusEl.style.display = 'none'; }, 5000);
  };

  // --- Rotate API Key ---
  window.rotateAPIKey = async function() {
    if (!currentHostId) return;
    if (!confirm('Rotate API key? The old key will stop working immediately.')) return;
    try {
      var result = await api('/api/hosts/' + currentHostId + '/rotate-key', {method: 'POST'});
      document.getElementById('rotated-key-value').textContent = result.api_key;
      document.getElementById('rotated-key-result').style.display = 'block';
    } catch (e) {
      alert('Error: ' + e.message);
    }
  };

  // --- Auto-refresh ---
  setInterval(function() {
    if (currentHostId) {
      showHost(currentHostId);
    } else {
      loadDashboard();
    }
  }, 30000);

  // --- Init ---
  loadDashboard();
})();
