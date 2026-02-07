(function() {
  'use strict';

  var currentHostId = null;
  var _ignoredKeys = {};    // current host's ignored keys set
  var _currentConfig = null; // current host's config for saving

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
        document.getElementById('config-toggle-icon').innerHTML = '&#9660;';
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

      // Host alerts banner
      renderHostAlertsBanner(hostAlerts);

      // Performance charts
      renderHostCharts(metrics, cfg);

      // Load config values (don't reset visibility on refresh)
      document.getElementById('cfg-webhook').value = cfg.webhook_url || '';
      document.getElementById('cfg-cpu').value = cfg.cpu_threshold || 60;
      document.getElementById('cfg-mem').value = cfg.memory_threshold || 60;
      document.getElementById('cfg-disk').value = cfg.disk_threshold || 80;
      document.getElementById('cfg-retention').value = cfg.retention_days || 90;

      if (!preserveState) {
        document.getElementById('config-status').style.display = 'none';
        document.getElementById('webhook-status').style.display = 'none';
        document.getElementById('host-config-wrapper').style.display = 'none';
        document.getElementById('config-toggle-icon').innerHTML = '&#9654;';
      }

      // Latest audit - structured rendering
      var latestDiv = document.getElementById('latest-audit');
      if (audits.length > 0) {
        var prevResults = audits.length > 1 ? audits[1].results : null;
        latestDiv.innerHTML = renderAuditResults(audits[0].results, prevResults, true);
      } else {
        latestDiv.innerHTML = '<div class="audit-results"><pre>No audits yet</pre></div>';
      }

      // Audit history table
      var tbody = document.getElementById('audits-table');
      if (!audits.length) {
        tbody.innerHTML = '<tr><td colspan="3" style="text-align:center;color:#8b949e">No audits</td></tr>';
      } else {
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
    var icon = document.getElementById('config-toggle-icon');
    if (wrapper.style.display === 'none') {
      wrapper.style.display = 'block';
      icon.innerHTML = '&#9660;';
    } else {
      wrapper.style.display = 'none';
      icon.innerHTML = '&#9654;';
    }
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

  function renderAuditResults(results, prevResults, showTicks) {
    if (!results || typeof results !== 'object' || Array.isArray(results)) {
      return '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
    }

    var html = '';
    var prev = prevResults && typeof prevResults === 'object' ? prevResults : {};

    // Top-level info (hostname, os, kernel, etc.)
    var topKeys = ['hostname', 'os', 'kernel', 'uptime', 'timestamp', 'total_checks'];
    var topCounter = {n: 0};
    var topHtml = '';
    for (var i = 0; i < topKeys.length; i++) {
      if (results[topKeys[i]] !== undefined) {
        topHtml += renderItem(topKeys[i], results[topKeys[i]], null, '', topCounter, false);
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
      var counter = {n: 0};
      var bodyHtml = renderObject(sectionData, prevSection, sec.key, counter, showTicks);
      var selectAll = showTicks ? ' <label style="font-size:.7rem;font-weight:400;color:#8b949e;margin-left:auto;margin-right:.5rem;cursor:pointer" onclick="event.stopPropagation();selectAllSection(\'' + esc(sec.key) + '\',this)"><input type="checkbox" style="accent-color:#238636;vertical-align:middle;cursor:pointer;margin-right:.2rem">all</label>' : '';

      html += '<div class="audit-card">' +
        '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' +
          sec.icon + ' ' + sec.label + selectAll +
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
        var ekCounter = {n: 0};
        var ekSelectAll = showTicks ? ' <label style="font-size:.7rem;font-weight:400;color:#8b949e;margin-left:auto;margin-right:.5rem;cursor:pointer" onclick="event.stopPropagation();selectAllSection(\'' + esc(ek) + '\',this)"><input type="checkbox" style="accent-color:#238636;vertical-align:middle;cursor:pointer;margin-right:.2rem">all</label>' : '';
        html += '<div class="audit-card">' +
          '<div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">' + esc(formatKey(ek)) + ekSelectAll + ' <span class="toggle-icon">&#9660;</span></div>' +
          '<div class="audit-card-body">' + renderObject(val, prevExtra, ek, ekCounter, showTicks) + '</div></div>';
      }
    }

    // Notes
    if (results.notes && results.notes.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">&#128221; Notes <span class="toggle-icon">&#9660;</span></div><div class="audit-card-body">';
      for (var n = 0; n < results.notes.length; n++) {
        html += '<div class="audit-item' + (n % 2 ? ' row-alt' : '') + '"><span class="audit-item-value">' + esc(String(results.notes[n])) + '</span></div>';
      }
      html += '</div></div>';
    }
    // Skipped
    if (results.skipped && results.skipped.length) {
      html += '<div class="audit-card"><div class="audit-card-header" onclick="this.parentElement.classList.toggle(\'open\')">&#9888; Skipped <span class="toggle-icon">&#9660;</span></div><div class="audit-card-body">';
      for (var sk = 0; sk < results.skipped.length; sk++) {
        html += '<div class="audit-item' + (sk % 2 ? ' row-alt' : '') + '"><span class="audit-item-value">' + esc(String(results.skipped[sk])) + '</span></div>';
      }
      html += '</div></div>';
    }

    return html || '<div class="audit-results"><pre>' + esc(JSON.stringify(results, null, 2)) + '</pre></div>';
  }

  // Select/deselect all ticks in a section
  window.selectAllSection = function(sectionKey, labelEl) {
    var cb = labelEl.querySelector('input[type="checkbox"]');
    var checked = cb.checked;
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
        retention_days: _currentConfig ? _currentConfig.retention_days : 90
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
            if (prevArr[j] && (prevArr[j].path === item.path || prevArr[j].name === item.name)) {
              prevItem = prevArr[j]; break;
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
  function renderHostAlertsBanner(alerts) {
    var el = document.getElementById('host-alerts-banner');
    if (!alerts || !alerts.length) {
      el.innerHTML = '';
      return;
    }
    var html = '';
    for (var i = 0; i < alerts.length; i++) {
      var a = alerts[i];
      var severity = a.current_value >= a.threshold_value * 1.2 ? '' : ' warn';
      html += '<div class="host-alert-banner' + severity + '">' +
        '&#9888; <strong>' + esc(formatKey(a.metric)) + '</strong>: ' +
        a.current_value.toFixed(1) + '% (threshold: ' + a.threshold_value.toFixed(0) + '%) &mdash; since ' +
        timeAgo(new Date(a.first_exceeded_at)) + '</div>';
    }
    el.innerHTML = html;
  }

  // --- Performance Charts (SVG) ---
  function renderHostCharts(metrics, cfg) {
    var el = document.getElementById('host-charts');
    if (!metrics || metrics.length < 2) {
      el.innerHTML = '';
      return;
    }
    var cpuThreshold = cfg.cpu_threshold || 60;
    var memThreshold = cfg.memory_threshold || 60;
    var diskThreshold = cfg.disk_threshold || 80;

    el.innerHTML = '<div class="charts-grid">' +
      renderMiniChart('CPU', metrics.map(function(m) { return m.cpu_percent; }), cpuThreshold, '#58a6ff') +
      renderMiniChart('Memory', metrics.map(function(m) { return m.mem_percent; }), memThreshold, '#a371f7') +
      renderMiniChart('Disk', metrics.map(function(m) { return m.disk_percent; }), diskThreshold, '#f0883e') +
    '</div>';
  }

  function renderMiniChart(label, values, threshold, color) {
    var latest = values.length > 0 ? values[values.length - 1] : 0;
    var w = 200, h = 60;
    var maxVal = Math.max(100, Math.max.apply(null, values));
    var n = values.length;
    if (n < 2) return '<div class="chart-card"><h4>' + esc(label) + '</h4><div class="chart-value">' + latest.toFixed(1) + '%</div><div style="color:#8b949e;font-size:.75rem">Not enough data</div></div>';

    var points = [];
    for (var i = 0; i < n; i++) {
      var x = (i / (n - 1)) * w;
      var y = h - (values[i] / maxVal) * h;
      points.push(x.toFixed(1) + ',' + y.toFixed(1));
    }
    var polyline = points.join(' ');
    var areaPoints = '0,' + h + ' ' + polyline + ' ' + w + ',' + h;
    var thresholdY = (h - (threshold / maxVal) * h).toFixed(1);

    var latestColor = latest >= threshold ? '#f85149' : color;

    return '<div class="chart-card">' +
      '<h4>' + esc(label) + '</h4>' +
      '<div class="chart-value" style="color:' + latestColor + '">' + latest.toFixed(1) + '%</div>' +
      '<svg viewBox="0 0 ' + w + ' ' + h + '" preserveAspectRatio="none">' +
        '<polygon points="' + areaPoints + '" fill="' + color + '" opacity="0.15"/>' +
        '<polyline points="' + polyline + '" fill="none" stroke="' + color + '" stroke-width="1.5"/>' +
        '<line x1="0" y1="' + thresholdY + '" x2="' + w + '" y2="' + thresholdY + '" stroke="#f85149" stroke-width="1" stroke-dasharray="4,3" opacity="0.6"/>' +
      '</svg>' +
    '</div>';
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
