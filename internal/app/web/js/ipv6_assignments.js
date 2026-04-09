(function () {
  const app = window.ForwardApp;
  if (!app) return;

  function hostInterfaces() {
    return Array.isArray(app.hostNetworkInterfaces) ? app.hostNetworkInterfaces : [];
  }

  function hostInterfaceToPickerItem(iface) {
    const addresses = Array.isArray(iface && iface.addresses) ? iface.addresses : [];
    return {
      name: String(iface && iface.name || '').trim(),
      kind: String(iface && iface.kind || '').trim(),
      parent: String(iface && iface.parent || '').trim(),
      addrs: addresses
        .map((address) => String(address && address.ip || '').trim())
        .filter(Boolean)
    };
  }

  function findHostInterface(name) {
    const target = String(name || '').trim();
    if (!target) return null;
    return hostInterfaces().find((iface) => iface && iface.name === target) || null;
  }

  function hostPickerItems(filterFn) {
    return hostInterfaces()
      .filter((iface) => iface && iface.name && (!filterFn || filterFn(iface)))
      .map((iface) => hostInterfaceToPickerItem(iface))
      .sort((a, b) => app.compareValues(a.name, b.name));
  }

  function hasIPv6Prefix(iface) {
    return (Array.isArray(iface && iface.addresses) ? iface.addresses : []).some((address) =>
      address && address.family === 'ipv6' && String(address.cidr || '').trim()
    );
  }

  function getParentInterfaceItems() {
    return hostPickerItems((iface) => hasIPv6Prefix(iface));
  }

  function getTargetInterfaceItems(parentName) {
    const selectedParent = String(parentName || '').trim();
    const items = hostPickerItems((iface) => iface && iface.name !== selectedParent);
    if (items.length > 0) return items;
    return (Array.isArray(app.interfaces) ? app.interfaces : [])
      .filter((iface) => iface && iface.name && iface.name !== selectedParent)
      .slice()
      .sort((a, b) => app.compareValues(a.name, b.name));
  }

  app.getParentInterfaceItems = getParentInterfaceItems;
  app.getTargetInterfaceItems = getTargetInterfaceItems;
  app.validateIPv6PrefixField = validateIPv6PrefixField;

  function buildParentPrefixOptions(parentName) {
    const iface = findHostInterface(parentName);
    if (!iface) return [];

    const grouped = Object.create(null);
    (Array.isArray(iface.addresses) ? iface.addresses : []).forEach((address) => {
      if (!address || address.family !== 'ipv6') return;
      const cidr = String(address.cidr || '').trim();
      const ip = String(address.ip || '').trim();
      if (!cidr) return;
      if (!grouped[cidr]) grouped[cidr] = { value: cidr, ips: [] };
      if (ip && grouped[cidr].ips.indexOf(ip) < 0) grouped[cidr].ips.push(ip);
    });

    return Object.keys(grouped)
      .map((key) => grouped[key])
      .sort((a, b) => app.compareValues(a.value, b.value));
  }

  app.getIPv6ParentPrefixOptions = buildParentPrefixOptions;

  function formatParentPrefixOption(option) {
    if (!option) return '';
    const ips = Array.isArray(option.ips) ? option.ips.filter(Boolean) : [];
    if (!ips.length) return option.value;
    const preview = ips.slice(0, 2).join(', ');
    const suffix = ips.length > 2 ? ', +' + (ips.length - 2) : '';
    return option.value + ' (' + preview + suffix + ')';
  }

  app.formatIPv6ParentPrefixOption = formatParentPrefixOption;

  function ensureParentPrefixOption(selectEl, value) {
    if (!selectEl || !value) return;
    const exists = Array.from(selectEl.options || []).some((option) => option.value === value);
    if (exists) return;
    app.addOption(selectEl, value, value);
  }

  function populateParentPrefixSelect(selected) {
    const el = app.el;
    const selectEl = el.ipv6ParentPrefix;
    if (!selectEl) return;

    const parentName = String(el.ipv6ParentInterface && el.ipv6ParentInterface.value || '').trim();
    const current = selected == null ? String(selectEl.value || '').trim() : String(selected || '').trim();
    app.clearNode(selectEl);

    if (!parentName) {
      app.addSelectPlaceholderOption(selectEl, app.t('ipv6.form.parentPrefix.placeholder'), { value: '' });
      selectEl.value = '';
      return;
    }

    const options = buildParentPrefixOptions(parentName);
    if (!options.length) {
      app.addSelectPlaceholderOption(selectEl, app.t('ipv6.form.parentPrefix.empty'), { value: '' });
      selectEl.value = '';
      return;
    }

    app.addSelectPlaceholderOption(selectEl, app.t('common.unspecified'), { value: '', hidden: true });
    options.forEach((option) => {
      app.addOption(selectEl, option.value, formatParentPrefixOption(option));
    });
    if (current) ensureParentPrefixOption(selectEl, current);
    selectEl.value = current && Array.from(selectEl.options || []).some((option) => option.value === current)
      ? current
      : '';
  }

  function clearAssignedPrefixAutofillState() {
    const input = app.el && app.el.ipv6AssignedPrefix;
    if (!input || !input.dataset) return;
    input.dataset.autoValue = '';
  }

  const IPV6_ALL_BITS = (1n << 128n) - 1n;

  function parseIPv6Hextet(text) {
    const value = String(text || '').trim();
    if (!/^[0-9a-f]{1,4}$/i.test(value)) return null;
    return parseInt(value, 16);
  }

  function parseIPv6ToBigInt(value) {
    let text = String(value || '').trim().toLowerCase();
    if (!text || text.indexOf(':') < 0 || text.indexOf('%') >= 0) return null;

    if (text.indexOf('.') >= 0) {
      const lastColon = text.lastIndexOf(':');
      if (lastColon < 0) return null;
      const ipv4 = app.parseIPv4(text.slice(lastColon + 1));
      if (!ipv4) return null;
      const high = ((ipv4[0] << 8) | ipv4[1]).toString(16);
      const low = ((ipv4[2] << 8) | ipv4[3]).toString(16);
      text = text.slice(0, lastColon) + ':' + high + ':' + low;
    }

    const halves = text.split('::');
    if (halves.length > 2) return null;

    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const groups = [];

    if (halves.length === 1) {
      if (left.length !== 8) return null;
      for (let i = 0; i < left.length; i++) {
        const parsed = parseIPv6Hextet(left[i]);
        if (parsed == null) return null;
        groups.push(parsed);
      }
    } else {
      if (left.length + right.length > 7) return null;
      for (let i = 0; i < left.length; i++) {
        const parsed = parseIPv6Hextet(left[i]);
        if (parsed == null) return null;
        groups.push(parsed);
      }
      for (let i = 0; i < 8 - left.length - right.length; i++) groups.push(0);
      for (let i = 0; i < right.length; i++) {
        const parsed = parseIPv6Hextet(right[i]);
        if (parsed == null) return null;
        groups.push(parsed);
      }
    }

    if (groups.length !== 8) return null;

    let result = 0n;
    for (let i = 0; i < groups.length; i++) {
      result = (result << 16n) | BigInt(groups[i]);
    }
    return result;
  }

  function formatIPv6FromBigInt(value) {
    const groups = [];
    for (let i = 0; i < 8; i++) {
      const shift = BigInt((7 - i) * 16);
      groups.push(Number((value >> shift) & 0xffffn));
    }

    let bestStart = -1;
    let bestLen = 0;
    for (let i = 0; i < groups.length; ) {
      if (groups[i] !== 0) {
        i++;
        continue;
      }
      let j = i;
      while (j < groups.length && groups[j] === 0) j++;
      const runLen = j - i;
      if (runLen > bestLen && runLen > 1) {
        bestStart = i;
        bestLen = runLen;
      }
      i = j;
    }

    const rendered = groups.map((group) => group.toString(16));
    if (bestStart < 0) return rendered.join(':');

    const left = rendered.slice(0, bestStart).join(':');
    const right = rendered.slice(bestStart + bestLen).join(':');
    if (!left && !right) return '::';
    if (!left) return '::' + right;
    if (!right) return left + '::';
    return left + '::' + right;
  }

  function ipv6PrefixMask(prefixLen) {
    const len = parseInt(prefixLen, 10);
    if (Number.isNaN(len) || len <= 0) return 0n;
    if (len >= 128) return IPV6_ALL_BITS;
    return (IPV6_ALL_BITS << BigInt(128 - len)) & IPV6_ALL_BITS;
  }

  function maskIPv6Value(value, prefixLen) {
    return value & ipv6PrefixMask(prefixLen);
  }

  function parseIPv6Prefix(value) {
    const text = String(value || '').trim();
    if (!app.isValidIPv6Prefix(text)) return null;
    const slash = text.lastIndexOf('/');
    const prefixLen = parseInt(text.slice(slash + 1).trim(), 10);
    const addressValue = parseIPv6ToBigInt(text.slice(0, slash).trim());
    if (addressValue == null || Number.isNaN(prefixLen) || prefixLen < 1 || prefixLen > 128) return null;
    return {
      value: text,
      prefixLen: prefixLen,
      network: maskIPv6Value(addressValue, prefixLen)
    };
  }

  function ipv6PrefixSize(prefixLen) {
    const len = parseInt(prefixLen, 10);
    if (Number.isNaN(len) || len < 0 || len > 128) return 0n;
    return 1n << BigInt(128 - len);
  }

  function formatIPv6Prefix(network, prefixLen) {
    return formatIPv6FromBigInt(network) + '/' + prefixLen;
  }

  function ipv6PrefixesOverlap(a, b) {
    if (!a || !b) return false;
    const prefixLen = a.prefixLen < b.prefixLen ? a.prefixLen : b.prefixLen;
    return maskIPv6Value(a.network, prefixLen) === maskIPv6Value(b.network, prefixLen);
  }

  function clampIPv6IntervalToParent(parent, start, end) {
    const parentEnd = parent.network + ipv6PrefixSize(parent.prefixLen) - 1n;
    const nextStart = start > parent.network ? start : parent.network;
    const nextEnd = end < parentEnd ? end : parentEnd;
    if (nextStart > nextEnd) return null;
    return { start: nextStart, end: nextEnd };
  }

  function mergeIPv6Intervals(intervals) {
    const sorted = (intervals || []).slice().sort((a, b) => (a.start < b.start ? -1 : (a.start > b.start ? 1 : 0)));
    const merged = [];
    sorted.forEach((interval) => {
      if (!interval) return;
      const last = merged.length ? merged[merged.length - 1] : null;
      if (!last || interval.start > last.end + 1n) {
        merged.push({ start: interval.start, end: interval.end });
        return;
      }
      if (interval.end > last.end) last.end = interval.end;
    });
    return merged;
  }

  function buildAssignedPrefixUsageIntervals(parent, options) {
    const opts = options || {};
    const parentName = String(opts.parentInterface || '').trim();
    const intervals = [];
    const assignments = Array.isArray(app.state && app.state.ipv6Assignments && app.state.ipv6Assignments.data)
      ? app.state.ipv6Assignments.data
      : [];

    assignments.forEach((item) => {
      if (!item) return;
      if (parentName && String(item.parent_interface || '').trim() && String(item.parent_interface || '').trim() !== parentName) return;
      const prefix = parseIPv6Prefix(assignmentDraftPrefix(item));
      if (!prefix || !ipv6PrefixesOverlap(parent, prefix)) return;
      const interval = clampIPv6IntervalToParent(parent, prefix.network, prefix.network + ipv6PrefixSize(prefix.prefixLen) - 1n);
      if (interval) intervals.push(interval);
    });

    if (opts.includeParentAddresses) {
      const iface = findHostInterface(parentName);
      (Array.isArray(iface && iface.addresses) ? iface.addresses : []).forEach((address) => {
        if (!address || address.family !== 'ipv6') return;
        const ipValue = parseIPv6ToBigInt(String(address.ip || '').trim());
        if (ipValue == null) return;
        const interval = clampIPv6IntervalToParent(parent, ipValue, ipValue);
        if (interval) intervals.push(interval);
      });
    }

    return mergeIPv6Intervals(intervals);
  }

  function alignIPv6ValueUp(value, prefixLen) {
    const size = ipv6PrefixSize(prefixLen);
    if (size <= 1n) return value;
    return maskIPv6Value(value + size - 1n, prefixLen);
  }

  function findFirstAvailableIPv6ChildPrefix(parent, desiredPrefixLen, options) {
    const opts = options || {};
    const candidateSize = ipv6PrefixSize(desiredPrefixLen);
    const parentEnd = parent.network + ipv6PrefixSize(parent.prefixLen) - 1n;
    let candidate = alignIPv6ValueUp(
      opts.startValue == null ? parent.network : opts.startValue,
      desiredPrefixLen
    );
    if (candidate < parent.network) candidate = parent.network;

    const intervals = buildAssignedPrefixUsageIntervals(parent, {
      parentInterface: opts.parentInterface,
      includeParentAddresses: !!opts.includeParentAddresses
    });

    for (let i = 0; i < intervals.length; i++) {
      const interval = intervals[i];
      if (candidate + candidateSize - 1n < interval.start) break;
      if (candidate > interval.end) continue;
      candidate = alignIPv6ValueUp(interval.end + 1n, desiredPrefixLen);
      if (candidate + candidateSize - 1n > parentEnd) return '';
    }

    if (candidate + candidateSize - 1n > parentEnd) return '';
    return formatIPv6Prefix(candidate, desiredPrefixLen);
  }

  function defaultAssignedPrefixLength(parentPrefixLen) {
    if (parentPrefixLen >= 128) return 128;
    if (parentPrefixLen < 64) return 64;
    return 128;
  }

  function deriveIPv6AssignedPrefixFromParentPrefix(value) {
    const parent = parseIPv6Prefix(value);
    if (!parent) return '';
    if (parent.prefixLen === 128) return formatIPv6Prefix(parent.network, 128);

    const parentInterface = String(app.el && app.el.ipv6ParentInterface && app.el.ipv6ParentInterface.value || '').trim();
    const desiredPrefixLen = Math.max(parent.prefixLen, defaultAssignedPrefixLength(parent.prefixLen));

    if (desiredPrefixLen === 128) {
      return findFirstAvailableIPv6ChildPrefix(parent, 128, {
        parentInterface: parentInterface,
        includeParentAddresses: true,
        startValue: parent.network + 1n
      }) || findFirstAvailableIPv6ChildPrefix(parent, 128, {
        parentInterface: parentInterface,
        includeParentAddresses: true,
        startValue: parent.network
      }) || formatIPv6Prefix(parent.network, 128);
    }

    return findFirstAvailableIPv6ChildPrefix(parent, desiredPrefixLen, {
      parentInterface: parentInterface,
      startValue: parent.network
    }) || formatIPv6Prefix(parent.network, desiredPrefixLen);
  }

  app.deriveIPv6AssignedPrefixFromParentPrefix = deriveIPv6AssignedPrefixFromParentPrefix;

  function ipv6PrefixLength(value) {
    const text = String(value || '').trim();
    const slash = text.lastIndexOf('/');
    if (slash <= 0 || slash === text.length - 1) return 0;
    const prefixLen = parseInt(text.slice(slash + 1).trim(), 10);
    if (Number.isNaN(prefixLen) || prefixLen < 1 || prefixLen > 128) return 0;
    return prefixLen;
  }

  function describeIPv6AssignmentMode(value) {
    const prefixLen = ipv6PrefixLength(value);
    if (prefixLen === 128) return app.t('ipv6.form.modeHint.singleAddress');
    if (prefixLen === 64) return app.t('ipv6.form.modeHint.slaacPrefix');
    if (prefixLen > 0) return app.t('ipv6.form.modeHint.delegatedPrefix', { prefix_len: prefixLen });
    return app.t('ipv6.form.modeHint.generic');
  }

  app.describeIPv6AssignmentMode = describeIPv6AssignmentMode;

  app.updateIPv6AssignmentModeHint = function updateIPv6AssignmentModeHint() {
    const hintEl = app.el && app.el.ipv6AssignmentModeHint;
    if (!hintEl) return;
    hintEl.textContent = describeIPv6AssignmentMode(app.el && app.el.ipv6AssignedPrefix ? app.el.ipv6AssignedPrefix.value : '');
  };

  function syncIPv6AssignedPrefixFromParentPrefix(options) {
    const el = app.el;
    const assignedEl = el.ipv6AssignedPrefix;
    const parentPrefixEl = el.ipv6ParentPrefix;
    if (!assignedEl || !parentPrefixEl) return;

    const opts = options || {};
    const nextValue = String(parentPrefixEl.value || '').trim();
    const nextAssignedValue = deriveIPv6AssignedPrefixFromParentPrefix(nextValue) || nextValue;
    const currentValue = String(assignedEl.value || '').trim();
    const autoValue = String(assignedEl.dataset && assignedEl.dataset.autoValue || '').trim();

    if (!nextValue) {
      if (autoValue && currentValue === autoValue) assignedEl.value = '';
      clearAssignedPrefixAutofillState();
      app.updateIPv6AssignmentModeHint();
      return;
    }

    if (opts.force || !currentValue || (autoValue && currentValue === autoValue)) {
      assignedEl.value = nextAssignedValue;
      if (assignedEl.dataset) assignedEl.dataset.autoValue = nextAssignedValue;
      app.clearFieldError(assignedEl);
      app.updateIPv6AssignmentModeHint();
      return;
    }

    if (currentValue === nextAssignedValue) {
      if (assignedEl.dataset) assignedEl.dataset.autoValue = nextAssignedValue;
      app.updateIPv6AssignmentModeHint();
      return;
    }

    clearAssignedPrefixAutofillState();
    app.updateIPv6AssignmentModeHint();
  }

  app.syncIPv6AssignedPrefixFromParentPrefix = syncIPv6AssignedPrefixFromParentPrefix;

  function validateIPv6PrefixField(input) {
    if (!input) return true;
    const value = String(input.value || '').trim();
    if (app.isValidIPv6Prefix(value)) {
      app.clearFieldError(input);
      return true;
    }
    app.setFieldError(input, app.t('validation.ipv6Prefix'));
    return false;
  }

  function assignmentDraftPrefix(item) {
    const assigned = String(item && item.assigned_prefix || '').trim();
    if (assigned) return assigned;
    const address = String(item && item.address || '').trim();
    const prefixLen = parseInt(item && item.prefix_len, 10);
    if (!address) return '';
    if (!Number.isNaN(prefixLen) && prefixLen > 0) return address + '/' + prefixLen;
    return address;
  }

  function formatIPv6AssignmentHandoutCount(item) {
    const prefixLen = ipv6PrefixLength(assignmentDraftPrefix(item));
    const raCount = Math.max(0, parseInt(item && item.ra_advertisement_count, 10) || 0);
    const dhcpCount = Math.max(0, parseInt(item && item.dhcpv6_reply_count, 10) || 0);
    const parts = [];

    if (prefixLen === 64 || prefixLen === 128) {
      parts.push(app.t('ipv6.list.assignmentCount.ra', { count: raCount }));
    }
    if (prefixLen === 128) {
      parts.push(app.t('ipv6.list.assignmentCount.dhcpv6', { count: dhcpCount }));
    }

    return parts.length ? parts.join(' / ') : app.t('common.dash');
  }

  app.formatIPv6AssignmentHandoutCount = formatIPv6AssignmentHandoutCount;

  function assignmentRuntimeInfo(item) {
    return app.statusInfo(String(item && item.runtime_status || '').trim().toLowerCase(), item && item.enabled !== false);
  }

  function assignmentRuntimeTitle(item) {
    const lines = [];
    const runtime = assignmentRuntimeInfo(item);
    lines.push(runtime.text);
    if (item && item.runtime_detail) lines.push(String(item.runtime_detail).trim());
    const handoutText = formatIPv6AssignmentHandoutCount(item);
    if (handoutText && handoutText !== app.t('common.dash')) lines.push(handoutText);
    return lines.join('\n');
  }

  function assignmentEnabledBadge(item) {
    const runtime = assignmentRuntimeInfo(item);
    return app.createBadgeNode('badge-' + runtime.badge, runtime.text, assignmentRuntimeTitle(item));
  }

  app.refreshIPv6AssignmentInterfaceSelectors = function refreshIPv6AssignmentInterfaceSelectors(options) {
    const opts = options || {};
    const el = app.el;
    if (!el.ipv6ParentInterface || !el.ipv6TargetInterface) return;

    app.populateInterfacePicker(el.ipv6ParentInterface, el.ipv6ParentPicker, el.ipv6ParentOptions, {
      items: getParentInterfaceItems(),
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });

    app.populateInterfacePicker(el.ipv6TargetInterface, el.ipv6TargetPicker, el.ipv6TargetOptions, {
      items: getTargetInterfaceItems(el.ipv6ParentInterface.value),
      preserveSelected: false,
      placeholder: app.t('interface.picker.placeholder')
    });

    populateParentPrefixSelect(opts.preservePrefix ? el.ipv6ParentPrefix.value : '');
    syncIPv6AssignedPrefixFromParentPrefix();
    app.updateIPv6AssignmentModeHint();
  };

  app.syncIPv6AssignmentFormState = function syncIPv6AssignmentFormState() {
    const el = app.el;
    const formState = app.state.forms.ipv6Assignment;
    const pending = !!app.state.pendingForms.ipv6Assignment;

    if (formState.mode === 'edit' && el.editIPv6AssignmentId.value) {
      el.ipv6AssignmentFormTitle.textContent = app.t('ipv6.form.title.edit', { id: el.editIPv6AssignmentId.value });
      el.ipv6AssignmentSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('ipv6.form.submit.edit');
      el.ipv6AssignmentCancelBtn.style.display = '';
    } else {
      el.ipv6AssignmentFormTitle.textContent = app.t('ipv6.form.title.add');
      el.ipv6AssignmentSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('ipv6.form.submit.add');
      el.ipv6AssignmentCancelBtn.style.display = 'none';
    }

    el.ipv6AssignmentCancelBtn.textContent = app.t('common.cancelEdit');
    el.ipv6AssignmentSubmitBtn.disabled = pending;
    el.ipv6AssignmentSubmitBtn.classList.toggle('is-busy', pending);
    el.ipv6AssignmentCancelBtn.disabled = pending;
  };

  app.setIPv6AssignmentFormAdd = function setIPv6AssignmentFormAdd() {
    app.state.forms.ipv6Assignment = { mode: 'add', sourceId: 0 };
    app.el.editIPv6AssignmentId.value = '';
    app.syncIPv6AssignmentFormState();
  };

  app.enterIPv6AssignmentEditMode = function enterIPv6AssignmentEditMode(item) {
    const el = app.el;
    app.state.forms.ipv6Assignment = { mode: 'edit', sourceId: item.id };
    clearAssignedPrefixAutofillState();
    el.editIPv6AssignmentId.value = item.id;
    el.ipv6ParentInterface.value = item.parent_interface || '';
    el.ipv6TargetInterface.value = item.target_interface || '';
    el.ipv6AssignedPrefix.value = assignmentDraftPrefix(item);
    el.ipv6AssignmentRemark.value = item.remark || '';
    app.refreshIPv6AssignmentInterfaceSelectors({ preservePrefix: false });
    el.ipv6ParentPrefix.value = item.parent_prefix || '';
    populateParentPrefixSelect(item.parent_prefix || '');
    app.updateIPv6AssignmentModeHint();
    app.syncIPv6AssignmentFormState();
    el.ipv6AssignmentFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitIPv6AssignmentEditMode = function exitIPv6AssignmentEditMode() {
    app.setIPv6AssignmentFormAdd();
    if (app.el.ipv6AssignmentForm) app.el.ipv6AssignmentForm.reset();
    if (app.el.ipv6ParentInterface) app.el.ipv6ParentInterface.value = '';
    if (app.el.ipv6TargetInterface) app.el.ipv6TargetInterface.value = '';
    clearAssignedPrefixAutofillState();
    app.refreshIPv6AssignmentInterfaceSelectors({ preservePrefix: false });
    app.updateIPv6AssignmentModeHint();
  };

  app.buildIPv6AssignmentFromForm = function buildIPv6AssignmentFromForm() {
    const el = app.el;
    return {
      parent_interface: app.getInterfaceSubmissionValue(el.ipv6ParentInterface, el.ipv6ParentPicker, {
        items: getParentInterfaceItems(),
        preserveSelected: true
      }),
      target_interface: app.getInterfaceSubmissionValue(el.ipv6TargetInterface, el.ipv6TargetPicker, {
        items: getTargetInterfaceItems(el.ipv6ParentInterface.value),
        preserveSelected: true
      }),
      parent_prefix: String(el.ipv6ParentPrefix && el.ipv6ParentPrefix.value || '').trim(),
      assigned_prefix: String(el.ipv6AssignedPrefix && el.ipv6AssignedPrefix.value || '').trim(),
      remark: String(el.ipv6AssignmentRemark && el.ipv6AssignmentRemark.value || '').trim()
    };
  };

  app.getIPv6AssignmentFieldInputs = function getIPv6AssignmentFieldInputs(issue) {
    const msg = String((issue && issue.message) || '').trim();
    const field = String((issue && issue.field) || '').trim();
    const map = {
      id: app.el.editIPv6AssignmentId,
      parent_interface: app.el.ipv6ParentPicker || app.el.ipv6ParentInterface,
      target_interface: app.el.ipv6TargetPicker || app.el.ipv6TargetInterface,
      parent_prefix: app.el.ipv6ParentPrefix,
      assigned_prefix: app.el.ipv6AssignedPrefix,
      address: app.el.ipv6AssignedPrefix,
      prefix_len: app.el.ipv6AssignedPrefix,
      remark: app.el.ipv6AssignmentRemark
    };
    if (map[field]) return [map[field]];
    if (msg.indexOf('parent_interface ') === 0) return [app.el.ipv6ParentPicker || app.el.ipv6ParentInterface];
    if (msg.indexOf('target_interface ') === 0) return [app.el.ipv6TargetPicker || app.el.ipv6TargetInterface];
    if (msg.indexOf('parent_prefix ') === 0) return [app.el.ipv6ParentPrefix];
    if (msg.indexOf('assigned_prefix ') === 0 || msg.indexOf('address ') === 0 || msg.indexOf('prefix_len ') === 0) {
      return [app.el.ipv6AssignedPrefix];
    }
    return [];
  };

  app.applyIPv6AssignmentValidationIssues = function applyIPv6AssignmentValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getIPv6AssignmentFieldInputs(issue);
      if (!inputs.length) return;
      const translated = app.translateValidationMessage(issue.message);
      inputs.forEach((input) => {
        if (!input) return;
        if (!firstInvalid) firstInvalid = input;
        if (!input.hasAttribute('aria-invalid')) app.setFieldError(input, translated);
      });
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.getValidationIssueSummary({ issues: relevant }, null, 3) || app.translateValidationMessage(relevant[0].message));
  };

  app.getIPv6AssignmentSortValue = function getIPv6AssignmentSortValue(item, key) {
    if (key === 'enabled') return item.enabled === false ? 0 : 1;
    return item[key];
  };

  app.renderIPv6AssignmentsTable = function renderIPv6AssignmentsTable() {
    const el = app.el;
    const st = app.state.ipv6Assignments;
    if (!st) return;
    app.closeDropdowns();

    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, [
        item.id,
        item.remark,
        item.parent_interface,
        item.parent_prefix,
        item.target_interface,
        item.assigned_prefix,
        item.address,
        item.prefix_len,
        formatIPv6AssignmentHandoutCount(item),
        item.runtime_status,
        item.runtime_detail,
        assignmentRuntimeInfo(item).text,
        app.t(item.enabled === false ? 'status.disabled' : 'status.enabled')
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getIPv6AssignmentSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.ipv6AssignmentsBody);
    app.updateSortIndicators('ipv6AssignmentsTable', st);
    app.renderFilterMeta('ipv6Assignments', filteredList.length, st.data.length);
    app.renderPagination('ipv6Assignments', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noIPv6Assignments, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('ipv6.list.empty'),
        actionButton: app.el.emptyAddIPv6AssignmentBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('ipv6AssignmentsTable', false);
      return;
    }

    app.hideEmptyState(el.noIPv6Assignments);
    app.toggleTableVisibility('ipv6AssignmentsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('ipv6-assignment', item.id);
      const toggleText = pending ? app.t('common.processing') : app.t(item.enabled === false ? 'common.enable' : 'common.disable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.appendChild(app.createCell(String(item.id)));
      tr.appendChild(app.createCell(item.remark || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.parent_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.parent_prefix || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.target_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.assigned_prefix || assignmentDraftPrefix(item) || app.emptyCellNode()));
      tr.appendChild(app.createCell(formatIPv6AssignmentHandoutCount(item)));
      tr.appendChild(app.createCell(assignmentEnabledBadge(item)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: item.enabled === false ? 'btn-enable-ipv6-assignment' : 'btn-disable-ipv6-assignment',
          text: toggleText,
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-edit-ipv6-assignment',
          text: app.t('common.edit'),
          dataset: { ipv6Assignment: app.encData(item) },
          disabled: pending
        },
        {
          className: 'btn-delete-ipv6-assignment',
          text: app.t('common.delete'),
          dataset: { id: item.id },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.ipv6AssignmentsBody.appendChild(fragment);
  };

  app.loadIPv6Assignments = async function loadIPv6Assignments() {
    try {
      app.state.ipv6Assignments.data = await app.apiCall('GET', '/api/ipv6-assignments');
      app.markDataFresh();
      app.renderIPv6AssignmentsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load ipv6 assignments:', e);
    }
  };

  app.toggleIPv6Assignment = async function toggleIPv6Assignment(id) {
    if (app.isRowPending('ipv6-assignment', id)) return;
    const current = (app.state.ipv6Assignments.data || []).find((item) => item.id === id);
    if (!current) return;

    app.setRowPending('ipv6-assignment', id, true);
    app.renderIPv6AssignmentsTable();
    try {
      await app.apiCall('PUT', '/api/ipv6-assignments', {
        id: current.id,
        parent_interface: current.parent_interface || '',
        target_interface: current.target_interface || '',
        parent_prefix: current.parent_prefix || '',
        assigned_prefix: assignmentDraftPrefix(current),
        remark: current.remark || '',
        enabled: current.enabled === false
      });
      app.notify('success', app.t(current.enabled === false ? 'toast.enabled' : 'toast.disabled', { item: app.t('noun.ipv6Assignment') }));
      await app.loadIPv6Assignments();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['update']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.operationFailed', { message: message }));
      }
    } finally {
      app.setRowPending('ipv6-assignment', id, false);
      app.renderIPv6AssignmentsTable();
    }
  };

  app.deleteIPv6Assignment = async function deleteIPv6Assignment(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('ipv6.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('ipv6-assignment', id, true);
    app.renderIPv6AssignmentsTable();
    try {
      await app.apiCall('DELETE', '/api/ipv6-assignments?id=' + id);
      if (parseInt(app.el.editIPv6AssignmentId.value || '0', 10) === id) app.exitIPv6AssignmentEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.ipv6Assignment') }));
      await app.loadIPv6Assignments();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('ipv6-assignment', id, false);
      app.renderIPv6AssignmentsTable();
    }
  };

  app.refreshLocalizedUI = (function wrapRefreshLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original();
      if (typeof app.syncIPv6AssignmentFormState === 'function') app.syncIPv6AssignmentFormState();
      if (typeof app.refreshIPv6AssignmentInterfaceSelectors === 'function') {
        app.refreshIPv6AssignmentInterfaceSelectors({ preservePrefix: true });
      }
      if (typeof app.updateIPv6AssignmentModeHint === 'function') app.updateIPv6AssignmentModeHint();
    };
  })(app.refreshLocalizedUI);
})();
