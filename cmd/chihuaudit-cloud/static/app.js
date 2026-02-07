(function() {
  'use strict';

  var currentHostId = null;
  var _ignoredKeys = {};    // current host's ignored keys set
  var _currentConfig = null; // current host's config for saving
  var _allAudits = [];       // store all audits for filtering

  // --- API helpers ---
  async function api(path, opts) {
    var res = await fetch(path, opts);
    if (res.status === 401) {
      window.location.href = '/login.html';
      throw new Error('unauthorized');
    }
    if (!res.ok) {
      var data = await res.json().catch(function() { return {}; });
      throw new Error(data.error || 'Request failed (HTTP ' + res.status + ')');
    }
    return res.json();
  }

  // --- Auth ---
  window.logout = async function() {
    await fetch('/api/logout', {method: 'POST'});
    window.location.href = '/login.html';
  };

  // Load username into header
  async function loadUsername() {
    try {
      var me = await api('/api/me');
      document.getElementById('username-display').textContent = me.username;
    } catch (e) { /* ignore */ }
  }

  // --- State preservation helpers ---
  function saveAccordionState(containerId) {
    var cards = document.querySelectorAll('#' + containerId + ' .audit-card');
    var state = [];
    for (var i = 0; i < cards.length; i++) {
      state.push(cards[i].classList.contains('open'));
    }
    return state;
  }

  function restoreAccordionState(containerId, state) {
    if (!state || !state.length) return;
    var cards = document.querySelectorAll('#' + containerId + ' .audit-card');
    for (var i = 0; i < cards.length && i < state.length; i++) {
      if (state[i]) cards[i].classList.add('open');
      else cards[i].classList.remove('open');
    }
  }

  function saveUIState() {
    return {
      scrollY: window.scrollY,
      accordions: currentHostId ? saveAccordionState('latest-audit') : null,
      configOpen: currentHostId ? document.getElementById('host-config-wrapper').style.display !== 'none' : false,
      rotatedKeyVisible: currentHostId ? document.getElementById('rotated-key-result').style.display !== 'none' : false
    };
  }

  function restoreUIState(state) {
    if (!state) return;
    if (state.accordions) restoreAccordionState('latest-audit', state.accordions);
    if (currentHostId) {
      if (state.configOpen) {
        document.getElementById('host-config-wrapper').style.display = 'block';
        /* config restored */
      }
      if (state.rotatedKeyVisible) {
        document.getElementById('rotated-key-result').style.display = 'block';
      }
    }
    window.scrollTo(0, state.scrollY);
  }

  // --- Dashboard ---
  async function loadDashboard() {
    try {
      var results = await Promise.all([
        api('/api/hosts'),
        api('/api/alerts/recent').catch(function() { return []; })
      ]);
      var hosts = results[0];
      var alerts = results[1];

      document.getElementById('host-count').textContent = '(' + hosts.length + ')';
      renderHostsTable(hosts);
      renderAlertsSection(alerts);
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('Dashboard load error:', e);
    }
  }

  function renderHostsTable(hosts) {
    var tbody = document.getElementById('hosts-table');
    if (!hosts.length) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#8b949e">No hosts yet</td></tr>';
      return;
    }
    tbody.innerHTML = hosts.map(function(h) {
      var lastSeen = h.last_seen ? timeAgo(new Date(h.last_seen)) : 'Never';
      var online = h.last_seen && (Date.now() - new Date(h.last_seen).getTime()) < 86400000;
      var dot = online
        ? '<span class="status-dot online"></span>'
        : '<span class="status-dot offline"></span>';
      return '<tr>' +
        '<td>' + dot + '<a href="#" onclick="showHost(' + h.id + '); return false">' + esc(h.name) + '</a></td>' +
        '<td>' + lastSeen + '</td>' +
        '<td>' + h.audit_count + '</td>' +
        '<td><a href="#" onclick="showHost(' + h.id + '); return false" class="btn btn-sm">View</a></td>' +
      '</tr>';
    }).join('');
  }

  // --- Host Detail ---
  window.showHost = async function(id, preserveState) {
    var uiState = preserveState ? saveUIState() : null;
    currentHostId = id;
    document.getElementById('view-dashboard').style.display = 'none';
    document.getElementById('view-host').style.display = 'block';
    document.getElementById('view-guide').style.display = 'none';

    // Only show loading on first load, not refresh
    if (!preserveState) {
      document.getElementById('latest-audit').innerHTML = '<div style="text-align:center;padding:2rem;color:#8b949e">Loading...</div>';
    }

    try {
      var results = await Promise.all([
        api('/api/hosts/' + id),
        api('/api/hosts/' + id + '/audits'),
        api('/api/hosts/' + id + '/config'),
        api('/api/hosts/' + id + '/metrics').catch(function() { return []; }),
        api('/api/hosts/' + id + '/alerts').catch(function() { return []; })
      ]);
      var host = results[0];
      var audits = results[1];
      var cfg = results[2];
      var metrics = results[3];
      var hostAlerts = results[4];

      _currentConfig = cfg;
      _ignoredKeys = {};
      var ignArr = cfg.ignore_changes || [];
      for (var ig = 0; ig < ignArr.length; ig++) _ignoredKeys[ignArr[ig]] = true;

      document.getElementById('host-name').textContent = host.name;
      document.getElementById('delete-host-btn').onclick = function() { deleteHost(id); };

      // Only reset these on first load
      if (!preserveState) {
        document.getElementById('rotated-key-result').style.display = 'none';
      }

      // Render active alerts
      renderHostAlerts(hostAlerts);

      // Load config values (don't reset visibility on refresh)
      document.getElementById('cfg-webhook').value = cfg.webhook_url || '';
      document.getElementById('cfg-cpu').value = cfg.cpu_threshold || 60;
      document.getElementById('cfg-mem').value = cfg.memory_threshold || 60;
      document.getElementById('cfg-disk').value = cfg.disk_threshold || 80;
      document.getElementById('cfg-retention').value = cfg.retention_count || 1000;

      if (!preserveState) {
        document.getElementById('config-status').style.display = 'none';
        document.getElementById('webhook-status').style.display = 'none';
        document.getElementById('host-config-wrapper').style.display = 'none';
        /* config hidden */
      }

      // Latest audit - structured rendering
      var latestDiv = document.getElementById('latest-audit');
      if (audits.length > 0) {
        var prevResults = audits.length > 1 ? audits[1].results : null;
        var checksLabel = countChecks(audits[0].results);
        document.getElementById('latest-audit-label').textContent = 'Latest Audit (' + checksLabel + ')';
        latestDiv.innerHTML = renderAuditResults(audits[0].results, prevResults, true);
      } else {
        latestDiv.innerHTML = '<div class="audit-results"><pre>No audits yet</pre></div>';
      }

      // Audit history table
      _allAudits = audits; // Save for filtering
      var tbody = document.getElementById('audits-table');
      if (!audits.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#8b949e">No audits</td></tr>';
      } else {
        window._auditCache = {};
        renderAuditsTable(audits);
      }

      // Restore UI state after DOM rebuild
      if (preserveState && uiState) {
        restoreUIState(uiState);
      }
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('Host load error:', e);
    }
  };

  window.showDashboard = function() {
    currentHostId = null;
    document.getElementById('view-dashboard').style.display = 'block';
    document.getElementById('view-host').style.display = 'none';
    document.getElementById('view-guide').style.display = 'none';
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
    var ignoreArr = Object.keys(_ignoredKeys).filter(function(k) { return _ignoredKeys[k]; });

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
          retention_count: parseInt(document.getElementById('cfg-retention').value) || 1000
        })
      });
      var statusEl = document.getElementById('config-status');
      statusEl.style.display = 'inline';
      setTimeout(function() { statusEl.style.display = 'none'; }, 3000);
    } catch (e) {
      alert('Error saving config: ' + e.message);
    }
  };

  // --- Toggle Ignore for an individual item key ---
  window.toggleIgnore = function(key, checkboxEl) {
    if (!currentHostId) return;

    var isChecked = checkboxEl.checked;
    if (isChecked) { _ignoredKeys[key] = true; } else { delete _ignoredKeys[key]; }

    // Update row styling
    var row = checkboxEl.closest('.audit-item');
    if (row) row.classList.toggle('item-ignored', isChecked);

    // Save to server
    saveIgnoreKeys();
  };

  // --- Toggle Host Config ---
  window.toggleHostConfig = function() {
    var wrapper = document.getElementById('host-config-wrapper');
    wrapper.style.display = wrapper.style.display === 'none' ? 'block' : 'none';
  };

  // --- Add Host Modal ---
  window.showAddHostModal = function() {
    document.getElementById('host-name-input').value = '';
    document.getElementById('add-host-step1').style.display = '';
    document.getElementById('add-host-step2').style.display = 'none';
    document.getElementById('add-host-modal').classList.add('active');
    document.getElementById('host-name-input').focus();
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
      var key = host.api_key;
      var cloudUrl = window.location.origin;
      document.getElementById('api-key-value').textContent = key;
      var configJSON = JSON.stringify({cloud_url: cloudUrl, api_key: key}, null, 2);
      document.getElementById('step2-config').textContent = configJSON;
      document.getElementById('add-host-step1').style.display = 'none';
      document.getElementById('add-host-step2').style.display = '';
    } catch (e) {
      alert('Error: ' + e.message);
    }
  };

  // --- Audit Detail Modal ---
  window.showAuditDetail = function(id) {
    var results = window._auditCache ? window._auditCache[id] : null;
    if (!results) return;
    document.getElementById('audit-detail-content').innerHTML = renderAuditResults(results, null, false);
    document.getElementById('audit-detail-modal').classList.add('active');
  };

  window.closeAuditDetail = function() {
    document.getElementById('audit-detail-modal').classList.remove('active');
  };

  // --- Guide ---
  window.showGuide = function() {
    document.getElementById('view-dashboard').style.display = 'none';
    document.getElementById('view-host').style.display = 'none';
    document.getElementById('view-guide').style.display = 'block';
  };

  window.hideGuide = function() {
    if (currentHostId) {
      document.getElementById('view-host').style.display = 'block';
    } else {
      document.getElementById('view-dashboard').style.display = 'block';
    }
    document.getElementById('view-guide').style.display = 'none';
  };

  // --- Structured Audit Rendering ---
  var SECTION_ORDER = [
    {key: 'security',  label: 'Security'},
    {key: 'services',  label: 'Services'},
    {key: 'resources', label: 'Resources'},
    {key: 'storage',   label: 'Storage'},
    {key: 'database',  label: 'Database'},
    {key: 'docker',    label: 'Docker'},
    {key: 'network',   label: 'Network'},
    {key: 'logs',      label: 'Logs'},
    {key: 'backups',   label: 'Backups'},
    {key: 'tuning',    label: 'Tuning'},
    {key: 'system',    label: 'System'}
  ];

  var STATUS_KEYS = ['firewall', 'web_status', 'db_status', 'disk_health', 'status', 'available'];

  function renderAuditResults(results, prevResults, showTicks) {
    if (!results || typeof results !== 'object' || Array.isArray(results)) {
      return '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
    }

    var html = '';
    var prev = prevResults && typeof prevResults === 'object' ? prevResults : {};

    // Top-level info as compact bar
    var topKeys = ['hostname', 'os', 'kernel', 'uptime', 'timestamp', 'total_checks'];
    var topItems = [];
    for (var i = 0; i < topKeys.length; i++) {
      if (results[topKeys[i]] !== undefined) {
        topItems.push('<span>' + esc(formatKey(topKeys[i])) + '<strong>' + esc(String(results[topKeys[i]])) + '</strong></span>');
      }
    }
    if (topItems.length) {
      html += '<div class="system-info-bar">' + topItems.join('') + '</div>';
    }

    // Known sections
    for (var s = 0; s < SECTION_ORDER.length; s++) {
      var sec = SECTION_ORDER[s];
      if (!results[sec.key] || typeof results[sec.key] !== 'object') continue;
      var sectionData = results[sec.key];
      var prevSection = prev[sec.key] && typeof prev[sec.key] === 'object' ? prev[sec.key] : null;
      var badge = getSectionBadge(sectionData);
      var counter = {n: 0};
      var bodyHtml = renderObject(sectionData, prevSection, sec.key, counter, showTicks);
      var selectAll = showTicks ? '<input type="checkbox" class="ignore-tick" onclick="event.stopPropagation();selectAllSection(\'' + esc(sec.key) + '\',this)">' : '';

      html += '<div class="audit-card">' +
        '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' +
          selectAll + sec.label +
          (badge ? '<span class="section-badge">' + badge + '</span>' : '') +
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
        var ekCounter = {n: 0};
        var ekSelectAll = showTicks ? '<input type="checkbox" class="ignore-tick" onclick="event.stopPropagation();selectAllSection(\'' + esc(ek) + '\',this)">' : '';
        html += '<div class="audit-card">' +
          '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' + ekSelectAll + esc(formatKey(ek)) + '</div>' +
          '<div class="audit-card-body">' + renderObject(val, prevExtra, ek, ekCounter, showTicks) + '</div></div>';
      }
    }

    // Notes
    if (results.notes && results.notes.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">Notes</div><div class="audit-card-body">';
      for (var n = 0; n < results.notes.length; n++) {
        html += '<div class="audit-item' + (n % 2 ? ' row-alt' : '') + '"><span class="audit-item-value">' + esc(String(results.notes[n])) + '</span></div>';
      }
      html += '</div></div>';
    }
    // Skipped
    if (results.skipped && results.skipped.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">Skipped</div><div class="audit-card-body">';
      for (var sk = 0; sk < results.skipped.length; sk++) {
        html += '<div class="audit-item' + (sk % 2 ? ' row-alt' : '') + '"><span class="audit-item-value">' + esc(String(results.skipped[sk])) + '</span></div>';
      }
      html += '</div></div>';
    }

    return html || '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
  }

  // Select/deselect all ticks in a section
  window.selectAllSection = function(sectionKey, labelEl) {
    var checked = labelEl.checked;
    var card = labelEl.closest('.audit-card');
    if (!card) return;
    var ticks = card.querySelectorAll('.ignore-tick');
    for (var i = 0; i < ticks.length; i++) {
      if (ticks[i].checked !== checked) {
        ticks[i].checked = checked;
        var ignKey = ticks[i].getAttribute('data-ignore-key');
        if (checked) { _ignoredKeys[ignKey] = true; } else { delete _ignoredKeys[ignKey]; }
        var row = ticks[i].closest('.audit-item');
        if (row) row.classList.toggle('item-ignored', checked);
      }
    }
    // Save to server
    saveIgnoreKeys();
  };

  function saveIgnoreKeys() {
    if (!currentHostId) return;
    var ignoreArr = Object.keys(_ignoredKeys).filter(function(k) { return _ignoredKeys[k]; });
    api('/api/hosts/' + currentHostId + '/config', {
      method: 'PUT',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        webhook_url: _currentConfig ? _currentConfig.webhook_url : '',
        cpu_threshold: _currentConfig ? _currentConfig.cpu_threshold : 60,
        memory_threshold: _currentConfig ? _currentConfig.memory_threshold : 60,
        disk_threshold: _currentConfig ? _currentConfig.disk_threshold : 80,
        ignore_changes: ignoreArr,
        retention_count: _currentConfig ? _currentConfig.retention_count : 1000
      })
    }).catch(function(e) { console.error('Failed to save ignore config:', e); });
  }

  function renderObject(obj, prevObj, sectionKey, counter, showTicks) {
    var html = '';
    var keys = Object.keys(obj);
    for (var i = 0; i < keys.length; i++) {
      var k = keys[i];
      var v = obj[k];
      var pv = prevObj ? prevObj[k] : undefined;

      if (v && typeof v === 'object' && !Array.isArray(v)) {
        html += '<div style="margin:.4rem 0 .2rem;font-size:.8rem;color:#58a6ff;font-weight:600">' + esc(formatKey(k)) + '</div>';
        html += renderObject(v, pv && typeof pv === 'object' ? pv : null, sectionKey, counter, showTicks);
      } else if (Array.isArray(v)) {
        html += renderArrayItems(k, v, pv, sectionKey, counter, showTicks);
      } else {
        html += renderItem(k, v, pv, sectionKey, counter, showTicks);
      }
    }
    return html;
  }

  function renderItem(key, value, prevValue, sectionKey, counter, showTick) {
    var changed = prevValue !== undefined && prevValue !== null && JSON.stringify(prevValue) !== JSON.stringify(value);
    var valStr = formatValue(key, value);
    var statusClass = getStatusClass(key, value);
    var changeClass = changed ? ' changed' : '';
    var altClass = counter.n % 2 ? ' row-alt' : '';
    counter.n++;

    var ignoreKey = sectionKey ? sectionKey + '.' + key : key;
    var isIgnored = _ignoredKeys[ignoreKey];
    var ignoredClass = isIgnored ? ' item-ignored' : '';
    var tickHtml = '';
    if (showTick) {
      tickHtml = '<input type="checkbox" class="ignore-tick" data-ignore-key="' + esc(ignoreKey) + '" ' +
        (isIgnored ? 'checked ' : '') +
        'onclick="toggleIgnore(\'' + esc(ignoreKey) + '\', this)" title="Ignore this item in alerts">';
    }

    return '<div class="audit-item' + altClass + ignoredClass + '">' +
      '<div class="audit-item-left">' + tickHtml +
        '<span class="audit-item-key">' + esc(formatKey(key)) + '</span></div>' +
      '<span class="audit-item-value' + changeClass + ' ' + statusClass + '">' + valStr +
        (changed ? ' <span style="font-size:.7rem;color:#8b949e">(was: ' + esc(formatValueRaw(prevValue)) + ')</span>' : '') +
      '</span></div>';
  }

  function renderArrayItems(key, arr, prevArr, sectionKey, counter, showTicks) {
    if (!arr.length) return renderItem(key, 'none', prevArr, sectionKey, counter, showTicks);

    if (arr[0] && typeof arr[0] === 'object') {
      var html = '<div style="margin:.4rem 0 .2rem;font-size:.8rem;color:#58a6ff;font-weight:600">' + esc(formatKey(key)) + ' (' + arr.length + ')</div>';
      for (var i = 0; i < arr.length; i++) {
        var item = arr[i];
        var prevItem = null;
        if (Array.isArray(prevArr)) {
          for (var j = 0; j < prevArr.length; j++) {
            if (prevArr[j]) {
              // Match by multiple possible keys (path, name, bind+port, device, user, etc.)
              var match = false;
              if (item.path && prevArr[j].path === item.path) match = true;
              else if (item.name && prevArr[j].name === item.name) match = true;
              else if (item.bind && item.port && prevArr[j].bind === item.bind && prevArr[j].port === item.port) match = true;
              else if (item.device && prevArr[j].device === item.device) match = true;
              else if (item.user && prevArr[j].user === item.user) match = true;
              
              if (match) {
                prevItem = prevArr[j];
                break;
              }
            }
          }
        }
        html += renderObject(item, prevItem, sectionKey, counter, showTicks);
        if (i < arr.length - 1) html += '<div style="border-bottom:1px solid #21262d;margin:.3rem 0"></div>';
      }
      return html;
    }

    var prevStr = Array.isArray(prevArr) ? prevArr.join(', ') : null;
    return renderItem(key, arr.join(', '), prevStr, sectionKey, counter, showTicks);
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

  // --- Host Alerts Banner ---
  // --- Render Host Alerts (expanded list) ---
  function renderHostAlerts(alerts) {
    var countEl = document.getElementById('alert-count');
    var listEl = document.getElementById('host-alerts-list');
    
    if (!alerts || !alerts.length) {
      countEl.textContent = '0';
      listEl.innerHTML = '<div style="color:#8b949e;font-size:.875rem;padding:1rem">No active alerts</div>';
      return;
    }
    
    countEl.textContent = alerts.length;
    
    var html = '<div style="display:flex;flex-direction:column;gap:.75rem">';
    for (var i = 0; i < alerts.length; i++) {
      var a = alerts[i];
      
      var severityColor = '#f0883e'; // warning
      var severityIcon = '⚠️';
      
      if (a.type === 'security') {
        if (a.severity === 'critical') {
          severityColor = '#f85149';
          severityIcon = '🔴';
        } else if (a.severity === 'info') {
          severityColor = '#58a6ff';
          severityIcon = 'ℹ️';
        }
        
        html += '<div style="padding:1rem;background:#161b22;border:1px solid ' + severityColor + ';border-radius:6px">' +
          '<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem">' +
            '<span>' + severityIcon + '</span>' +
            '<strong style="color:' + severityColor + '">' + esc(a.key) + '</strong>' +
            '<span style="margin-left:auto;font-size:.75rem;color:#8b949e">' + timeAgo(new Date(a.first_exceeded_at)) + '</span>' +
          '</div>' +
          '<div style="color:#c9d1d9;font-size:.875rem">' + esc(a.description) + '</div>' +
        '</div>';
      } else {
        // Threshold breach
        severityColor = a.current_value >= a.threshold_value * 1.2 ? '#f85149' : '#f0883e';
        severityIcon = a.current_value >= a.threshold_value * 1.2 ? '🔴' : '⚠️';
        
        html += '<div style="padding:1rem;background:#161b22;border:1px solid ' + severityColor + ';border-radius:6px">' +
          '<div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.5rem">' +
            '<span>' + severityIcon + '</span>' +
            '<strong style="color:' + severityColor + '">' + esc(formatKey(a.metric)) + '</strong>' +
            '<span style="margin-left:auto;font-size:.75rem;color:#8b949e">' + timeAgo(new Date(a.first_exceeded_at)) + '</span>' +
          '</div>' +
          '<div style="color:#c9d1d9;font-size:.875rem">' + 
            'Current: ' + a.current_value.toFixed(1) + '% (threshold: ' + a.threshold_value.toFixed(0) + '%)' +
          '</div>' +
        '</div>';
      }
    }
    html += '</div>';
    
    listEl.innerHTML = html;
  }

  // --- Dashboard Alerts Section ---
  function renderAlertsSection(alerts) {
    var el = document.getElementById('alerts-section');
    if (!alerts || !alerts.length) {
      el.innerHTML = '';
      return;
    }
    var html = '<div class="alerts-section"><h3 style="font-size:.9rem;color:#8b949e;margin-bottom:.5rem">Active Alerts</h3>';
    for (var i = 0; i < alerts.length; i++) {
      var a = alerts[i];
      var severity = a.current_value >= a.threshold_value * 1.2 ? 'danger' : 'warning';
      var duration = timeAgo(new Date(a.first_exceeded_at));
      html += '<div class="alert-card ' + severity + '">' +
        '<div><span class="alert-metric">' + esc(formatKey(a.metric)) + '</span> ' +
        '<span class="alert-host">on ' + esc(a.host_name) + '</span></div>' +
        '<div style="text-align:right"><span class="alert-value">' + a.current_value.toFixed(1) + '%</span> ' +
        '<span style="color:#8b949e;font-size:.75rem">(threshold: ' + a.threshold_value.toFixed(0) + '%)</span>' +
        '<div class="alert-duration">since ' + duration + '</div></div></div>';
    }
    html += '</div>';
    el.innerHTML = html;
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
    if (!confirm('Rotate API key?\n\nThe old key will stop working immediately. The agent on this host will fail to push audits until you update its config.json with the new key.')) return;
    try {
      var result = await api('/api/hosts/' + currentHostId + '/rotate-key', {method: 'POST'});
      document.getElementById('rotated-key-value').textContent = result.api_key;
      document.getElementById('rotated-key-result').style.display = 'block';
    } catch (e) {
      alert('Error: ' + e.message);
    }
  };

  // --- ESC key closes modals ---
  document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') {
      if (document.getElementById('audit-detail-modal').classList.contains('active')) {
        closeAuditDetail();
      } else if (document.getElementById('add-host-modal').classList.contains('active')) {
        closeAddHostModal();
      }
    }
  });

  // --- Audit filtering and rendering ---
  function renderAuditsTable(audits) {
    var tbody = document.getElementById('audits-table');
    window._auditCache = {};
    tbody.innerHTML = audits.map(function(a) {
      window._auditCache[a.id] = a.results;
      var date = new Date(a.created_at).toLocaleString();
      var checks = countChecks(a.results);
      return '<tr>' +
        '<td>' + date + '</td>' +
        '<td>' + checks + '</td>' +
        '<td><a href="#" onclick="showAuditDetail(' + a.id + '); return false" class="btn btn-sm">View</a></td>' +
      '</tr>';
    }).join('');
  }

  window.filterAudits = function(query) {
    if (!query || query.trim() === '') {
      renderAuditsTable(_allAudits);
      return;
    }

    query = query.toLowerCase();
    var filtered = _allAudits.filter(function(audit) {
      // Search in audit results (deep search in JSON)
      var jsonStr = JSON.stringify(audit.results).toLowerCase();
      return jsonStr.indexOf(query) !== -1;
    });

    if (filtered.length === 0) {
      document.getElementById('audits-table').innerHTML = 
        '<tr><td colspan="3" style="text-align:center;color:#8b949e">No audits match "' + query + '"</td></tr>';
    } else {
      renderAuditsTable(filtered);
    }
  };

  // --- Auto-refresh (preserves state) ---
  setInterval(function() {
    // Don't refresh if a modal is open or guide is visible
    if (document.getElementById('audit-detail-modal').classList.contains('active')) return;
    if (document.getElementById('add-host-modal').classList.contains('active')) return;
    if (document.getElementById('view-guide').style.display !== 'none') return;

    if (currentHostId) {
      showHost(currentHostId, true);
    } else if (document.getElementById('view-dashboard').style.display !== 'none') {
      loadDashboard();
    }
  }, 30000);

  // --- Init ---
  loadUsername();
  loadDashboard();
})();
