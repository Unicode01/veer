(function () {
  const app = window.ForwardApp;
  if (!app) return;

  function sortInterfacesByName(items) {
    return (items || []).slice().sort((a, b) => app.compareValues(a.name, b.name));
  }

  function interfaceLabel(iface) {
    if (!iface) return '';
    if (typeof app.interfaceOptionLabel === 'function') {
      return app.interfaceOptionLabel(iface);
    }
    const addrs = Array.isArray(iface.addrs) ? iface.addrs.filter(Boolean) : [];
    if (!addrs.length) return iface.name || '';
    return (iface.name || '') + ' (' + addrs.join(', ') + ')';
  }

  function findInterface(name) {
    const target = String(name || '').trim();
    if (!target) return null;
    return (app.interfaces || []).find((iface) => iface && iface.name === target) || null;
  }

  function hasOptionValue(sel, value) {
    return !!(sel && value && Array.from(sel.options || []).some((option) => option.value === value));
  }

  function normalizedInterfaceQuery(query) {
    return String(query || '').trim().toLowerCase();
  }

  function interfaceSearchText(iface) {
    if (!iface) return '';
    return [
      iface.name,
      iface.kind,
      iface.parent,
      interfaceLabel(iface),
      ...(Array.isArray(iface.addrs) ? iface.addrs : [])
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
  }

  function filterInterfacesByQuery(items, query) {
    const tokens = normalizedInterfaceQuery(query).split(/\s+/).filter(Boolean);
    const list = Array.isArray(items) ? items : [];
    if (!tokens.length) return sortInterfacesByName(list);
    return sortInterfacesByName(list.filter((iface) => {
      const haystack = interfaceSearchText(iface);
      return tokens.every((token) => haystack.indexOf(token) >= 0);
    }));
  }

  function isLikelyGlobalIPv6(addr) {
    const text = String(addr || '').trim().toLowerCase();
    if (!app.isValidIPv6(text)) return false;
    if (text === '::1') return false;
    if (text.startsWith('fe80:')) return false;
    if (text.startsWith('fc') || text.startsWith('fd')) return false;
    return true;
  }

  function egressNATOutInterfaceScore(iface) {
    if (!iface || !iface.name) return -1000;

    const name = String(iface.name || '').trim().toLowerCase();
    if (!name || name === 'lo') return -1000;

    let score = 0;
    const kind = String(iface.kind || '').trim().toLowerCase();
    const addrs = Array.isArray(iface.addrs) ? iface.addrs.filter(Boolean) : [];

    if (kind === 'bridge') score += 4;
    else if (kind === 'device') score += 3;
    else score += 1;

    if (!String(iface.parent || '').trim()) score += 2;
    else score -= 4;

    if (/^(wan|wwan|ppp|pppoe)/i.test(name)) score += 6;
    else if (/^(vmbr|br|bond)/i.test(name)) score += 3;
    else if (/^(eno|ens|enp|eth)/i.test(name)) score += 2;

    let hasPublicIPv4 = false;
    let hasPrivateIPv4 = false;
    let hasGlobalIPv6 = false;
    addrs.forEach((addr) => {
      if (app.isPublicIPv4(addr)) {
        hasPublicIPv4 = true;
        score += 20;
        return;
      }
      if (app.parseIPv4(addr)) {
        hasPrivateIPv4 = true;
        score += 2;
        return;
      }
      if (isLikelyGlobalIPv6(addr)) {
        hasGlobalIPv6 = true;
        score += 10;
        return;
      }
      if (app.isValidIPv6(addr)) score += 1;
    });

    if (!addrs.length) score -= 5;
    if (hasPublicIPv4 && hasGlobalIPv6) score += 3;
    if (hasPublicIPv4) score += 2;
    else if (hasPrivateIPv4) score += 1;

    return score;
  }

  function choosePreferredEgressNATOutInterface(candidates) {
    const list = Array.isArray(candidates) ? candidates.slice() : [];
    if (!list.length) return null;
    list.sort((a, b) => {
      const scoreDiff = egressNATOutInterfaceScore(b) - egressNATOutInterfaceScore(a);
      if (scoreDiff !== 0) return scoreDiff;
      return app.compareValues(a && a.name, b && b.name);
    });
    return list[0] || null;
  }

  app.updateEgressNATOutInterfaceHint = function updateEgressNATOutInterfaceHint(name, autoSelected) {
    const hintEl = app.el.egressNATOutInterfaceHint || app.$('egressNATOutInterfaceHint');
    if (!hintEl) return;

    const ifaceName = String(name || '').trim();
    const enabled = !!autoSelected && !!ifaceName;
    hintEl.dataset.mode = enabled ? 'auto' : '';
    hintEl.dataset.interfaceName = enabled ? ifaceName : '';
    hintEl.textContent = enabled
      ? app.t('egressNAT.form.outInterfaceHintAuto', { name: ifaceName })
      : '';
    hintEl.hidden = !enabled;
  };

  function isSingleTargetInterface(iface) {
    if (!iface) return false;
    const name = String(iface.name || '').trim();
    const parent = String(iface.parent || '').trim();
    if (!name) return false;
    switch (String(iface.kind || '').trim().toLowerCase()) {
      case 'bridge':
        return false;
      case 'device':
        if (name.toLowerCase() === 'lo') return false;
        return !parent;
      default:
        return true;
    }
  }

  function normalizeEgressNATScopeSelection(parentName, childName) {
    const parent = String(parentName || '').trim();
    const child = String(childName || '').trim();
    const parentInfo = findInterface(parent);
    if (!child && isSingleTargetInterface(parentInfo)) {
      const normalizedParent = String(parentInfo.parent || '').trim();
      if (!normalizedParent) {
        return {
          parent_interface: String(parentInfo.name || '').trim(),
          child_interface: ''
        };
      }
      return {
        parent_interface: normalizedParent,
        child_interface: String(parentInfo.name || '').trim()
      };
    }
    return {
      parent_interface: parent,
      child_interface: child
    };
  }

  const egressNATProtocolOrder = ['tcp', 'udp', 'icmp'];

  function protocolCheckboxes() {
    return [
      app.el.egressNATProtocolTCP,
      app.el.egressNATProtocolUDP,
      app.el.egressNATProtocolICMP
    ].filter(Boolean);
  }

  function splitProtocolValue(value) {
    return String(value || '')
      .toLowerCase()
      .split(/[\s,+/|]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  }

  app.normalizeEgressNATProtocolValue = function normalizeEgressNATProtocolValue(value) {
    const selected = Object.create(null);
    splitProtocolValue(value).forEach((item) => {
      if (egressNATProtocolOrder.includes(item)) selected[item] = true;
    });
    return egressNATProtocolOrder.filter((item) => selected[item]).join('+');
  };

  app.formatEgressNATProtocol = function formatEgressNATProtocol(protocol) {
    const normalized = app.normalizeEgressNATProtocolValue(protocol);
    if (!normalized) return app.t('egressNAT.form.protocolPlaceholder');
    return normalized.split('+').map((item) => item.toUpperCase()).join(' + ');
  };

  app.normalizeEgressNATTypeValue = function normalizeEgressNATTypeValue(value) {
    return String(value || '').trim().toLowerCase() === 'full_cone' ? 'full_cone' : 'symmetric';
  };

  app.formatEgressNATNatType = function formatEgressNATNatType(value) {
    return app.t(
      app.normalizeEgressNATTypeValue(value) === 'full_cone'
        ? 'egressNAT.natType.fullCone'
        : 'egressNAT.natType.symmetric'
    );
  };

  app.refreshEgressNATProtocolUI = function refreshEgressNATProtocolUI(protocol) {
    const normalized = app.normalizeEgressNATProtocolValue(
      protocol == null && app.el.egressNATProtocol ? app.el.egressNATProtocol.value : protocol
    );
    if (app.el.egressNATProtocol) app.el.egressNATProtocol.value = normalized;

    const selected = Object.create(null);
    splitProtocolValue(normalized).forEach((item) => {
      selected[item] = true;
    });
    protocolCheckboxes().forEach((input) => {
      input.checked = !!selected[String(input.value || '').toLowerCase()];
    });

    if (app.el.egressNATProtocolTrigger) {
      const label = app.formatEgressNATProtocol(normalized);
      app.el.egressNATProtocolTrigger.value = label;
      app.el.egressNATProtocolTrigger.title = label;
      app.el.egressNATProtocolTrigger.setAttribute('aria-label', label);
    }
  };

  app.getEgressNATProtocolValue = function getEgressNATProtocolValue() {
    return app.normalizeEgressNATProtocolValue(app.el.egressNATProtocol ? app.el.egressNATProtocol.value : '');
  };

  app.setEgressNATProtocolValue = function setEgressNATProtocolValue(protocol) {
    app.refreshEgressNATProtocolUI(protocol);
  };

  app.syncEgressNATProtocolSelectionFromInputs = function syncEgressNATProtocolSelectionFromInputs() {
    const selected = protocolCheckboxes()
      .filter((input) => input.checked)
      .map((input) => input.value);
    app.refreshEgressNATProtocolUI(selected.join('+'));
    if (app.el.egressNATProtocolTrigger) app.clearFieldError(app.el.egressNATProtocolTrigger);
  };

  app.closeEgressNATProtocolMenu = function closeEgressNATProtocolMenu() {
    if (app.el.egressNATProtocolMenu) app.el.egressNATProtocolMenu.hidden = true;
    if (app.el.egressNATProtocolDropdown) app.el.egressNATProtocolDropdown.classList.remove('open');
    if (app.el.egressNATProtocolTrigger) app.el.egressNATProtocolTrigger.setAttribute('aria-expanded', 'false');
  };

  app.openEgressNATProtocolMenu = function openEgressNATProtocolMenu() {
    if (!app.el.egressNATProtocolMenu || !app.el.egressNATProtocolTrigger || app.el.egressNATProtocolTrigger.disabled) return;
    app.el.egressNATProtocolMenu.hidden = false;
    if (app.el.egressNATProtocolDropdown) app.el.egressNATProtocolDropdown.classList.add('open');
    app.el.egressNATProtocolTrigger.setAttribute('aria-expanded', 'true');
  };

  app.toggleEgressNATProtocolMenu = function toggleEgressNATProtocolMenu(forceOpen) {
    const isOpen = !!(app.el.egressNATProtocolMenu && !app.el.egressNATProtocolMenu.hidden);
    if (forceOpen === true) {
      app.openEgressNATProtocolMenu();
      return;
    }
    if (forceOpen === false || isOpen) {
      app.closeEgressNATProtocolMenu();
      return;
    }
    app.openEgressNATProtocolMenu();
  };

  app.isEgressNATSingleTargetInterfaceName = function isEgressNATSingleTargetInterfaceName(name) {
    return isSingleTargetInterface(findInterface(name));
  };

  app.getEgressNATParentInterfaces = function getEgressNATParentInterfaces() {
    const seen = Object.create(null);
    const parents = [];
    (app.interfaces || []).forEach((iface) => {
      if (!iface || !iface.name || seen[iface.name]) return;
      const hasChildren = (app.interfaces || []).some((child) => child && child.parent === iface.name);
      const isBridge = String(iface.kind || '').trim().toLowerCase() === 'bridge';
      if (!hasChildren && !isBridge && !isSingleTargetInterface(iface)) return;
      seen[iface.name] = true;
      parents.push(iface);
    });
    return sortInterfacesByName(parents);
  };

  app.getEgressNATChildInterfaces = function getEgressNATChildInterfaces(parentName) {
    if (app.isEgressNATSingleTargetInterfaceName(parentName)) return [];
    return sortInterfacesByName((app.interfaces || []).filter((iface) => iface.parent === parentName));
  };

  app.formatEgressNATChildScope = function formatEgressNATChildScope(value, parentName) {
    if (value) return value;
    if (app.isEgressNATSingleTargetInterfaceName(parentName)) return app.t('egressNAT.scope.self');
    return app.t('egressNAT.scope.allChildren');
  };

  app.formatEgressNATTableChildScope = function formatEgressNATTableChildScope(value, parentName) {
    if (value) return value;
    if (app.isEgressNATSingleTargetInterfaceName(parentName)) return app.t('egressNAT.scope.self');
    return 'ALL';
  };

  app.formatEgressNATStatsChildScope = function formatEgressNATStatsChildScope(value, parentName) {
    return app.formatEgressNATTableChildScope(value, parentName);
  };

  app.populateEgressNATSourceIPSelect = function populateEgressNATSourceIPSelect(selected) {
    const inputEl = app.el.egressNATOutSourceIP;
    if (!inputEl) return;

    const current = selected == null ? inputEl.value : selected;
    const listId = inputEl.getAttribute('list');
    const listEl = listId ? app.$(listId) : null;
    if (!listEl) {
      inputEl.value = current || '';
      return;
    }

    const ifaceName = app.el.egressNATOutInterface ? app.el.egressNATOutInterface.value : '';
    const seen = Object.create(null);
    app.clearNode(listEl);

    function appendOption(value, label) {
      if (!value || seen[value] || !app.parseIPv4(value)) return;
      seen[value] = true;
      const opt = document.createElement('option');
      opt.value = value;
      opt.label = label;
      listEl.appendChild(opt);
    }

    if (!ifaceName) {
      (app.interfaces || []).forEach((iface) => {
        (iface.addrs || []).forEach((addr) => appendOption(addr, addr + ' (' + iface.name + ')'));
      });
    } else {
      const iface = (app.interfaces || []).find((item) => item.name === ifaceName);
      if (iface) (iface.addrs || []).forEach((addr) => appendOption(addr, addr));
    }

    inputEl.value = current || '';
  };

  function egressNATOutInterfaceCandidates(parentName, childName) {
    const parent = String(parentName || '').trim();
    const child = String(childName || '').trim();
    const excluded = Object.create(null);
    const parentInfo = findInterface(parent);

    if (isSingleTargetInterface(parentInfo) && parentInfo && parentInfo.name) {
      excluded[parentInfo.name] = true;
    } else if (child) {
      excluded[child] = true;
    }

    return sortInterfacesByName((app.interfaces || []).filter((iface) => iface && iface.name && !excluded[iface.name]));
  }

  app.getEgressNATOutInterfaceCandidates = function getEgressNATOutInterfaceCandidates(parentName, childName) {
    return egressNATOutInterfaceCandidates(parentName, childName);
  };

  app.populateEgressNATInterfaceSelectors = function populateEgressNATInterfaceSelectors(options) {
    const el = app.el;
    if (!el.egressNATParentInterface || !el.egressNATChildInterface || !el.egressNATOutInterface) return;
    const opts = options || {};
    const preserveOutSelection = !!opts.preserveOutSelection;
    const autoSelectOut = opts.autoSelectOut !== false;
    const parentItems = app.getEgressNATParentInterfaces();
    app.populateInterfacePicker(el.egressNATParentInterface, el.egressNATParentPicker, el.egressNATParentOptions, {
      items: parentItems,
      preserveSelected: true,
      placeholder: app.t('interface.picker.placeholder')
    });

    const selectedParent = String(el.egressNATParentInterface.value || '').trim();
    const isSingleTargetParent = app.isEgressNATSingleTargetInterfaceName(selectedParent);
    const childPlaceholder = !selectedParent
      ? app.t('common.selectInterfaceFirst')
      : app.t(isSingleTargetParent ? 'egressNAT.scope.self' : 'egressNAT.form.childInterfaceAll');

    if (isSingleTargetParent) {
      el.egressNATChildInterface.value = '';
      app.populateInterfacePicker(el.egressNATChildInterface, el.egressNATChildPicker, el.egressNATChildOptions, {
        items: [],
        disabled: true,
        placeholder: childPlaceholder
      });
      if (typeof app.clearFieldError === 'function') app.clearFieldError(el.egressNATChildPicker || el.egressNATChildInterface);
    } else {
      app.populateInterfacePicker(el.egressNATChildInterface, el.egressNATChildPicker, el.egressNATChildOptions, {
        items: app.getEgressNATChildInterfaces(selectedParent),
        preserveSelected: true,
        disabled: !selectedParent,
        placeholder: childPlaceholder
      });
    }

    const selectedChild = String(el.egressNATChildInterface.value || '').trim();
    const outCandidates = egressNATOutInterfaceCandidates(selectedParent, selectedChild);
    app.populateInterfacePicker(el.egressNATOutInterface, el.egressNATOutPicker, el.egressNATOutOptions, {
      items: outCandidates,
      preserveSelected: preserveOutSelection,
      placeholder: app.t('interface.picker.placeholder')
    });

    if (!preserveOutSelection && autoSelectOut && selectedParent && !el.egressNATOutInterface.value) {
      const preferredOut = choosePreferredEgressNATOutInterface(outCandidates);
      if (preferredOut) {
        app.setInterfacePickerValue(el.egressNATOutInterface, el.egressNATOutPicker, preferredOut.name, {
          items: outCandidates,
          preserveSelected: true
        });
        app.updateEgressNATOutInterfaceHint(preferredOut.name, true);
      } else {
        app.updateEgressNATOutInterfaceHint('', false);
      }
    } else {
      app.updateEgressNATOutInterfaceHint('', false);
    }
    app.populateEgressNATSourceIPSelect(el.egressNATOutSourceIP.value);
  };

  app.syncEgressNATFormState = function syncEgressNATFormState() {
    const el = app.el;
    const formState = app.state.forms.egressNAT;
    const pending = !!app.state.pendingForms.egressNAT;

    if (formState.mode === 'edit' && el.editEgressNATId.value) {
      el.egressNATFormTitle.textContent = app.t('egressNAT.form.title.edit', { id: el.editEgressNATId.value });
      el.egressNATSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('egressNAT.form.submit.edit');
      el.egressNATCancelBtn.style.display = '';
    } else {
      el.egressNATFormTitle.textContent = app.t('egressNAT.form.title.add');
      el.egressNATSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('egressNAT.form.submit.add');
      el.egressNATCancelBtn.style.display = 'none';
    }

    el.egressNATCancelBtn.textContent = app.t('common.cancelEdit');
    el.egressNATSubmitBtn.disabled = pending;
    el.egressNATSubmitBtn.classList.toggle('is-busy', pending);
    el.egressNATCancelBtn.disabled = pending;
  };

  app.setEgressNATFormAdd = function setEgressNATFormAdd() {
    app.state.forms.egressNAT = { mode: 'add', sourceId: 0 };
    app.el.editEgressNATId.value = '';
    app.setEgressNATProtocolValue('tcp+udp');
    if (app.el.egressNATNatType) app.el.egressNATNatType.value = 'symmetric';
    app.syncEgressNATFormState();
  };

  app.enterEgressNATEditMode = function enterEgressNATEditMode(item) {
    const el = app.el;
    app.state.forms.egressNAT = { mode: 'edit', sourceId: item.id };
    el.editEgressNATId.value = item.id;
    el.egressNATParentInterface.value = item.parent_interface || '';
    el.egressNATChildInterface.value = item.child_interface || '';
    el.egressNATOutInterface.value = item.out_interface || '';
    app.populateEgressNATInterfaceSelectors({ preserveOutSelection: true });
    app.populateEgressNATSourceIPSelect(item.out_source_ip || '');
    app.setEgressNATProtocolValue(item.protocol || 'tcp+udp');
    if (el.egressNATNatType) el.egressNATNatType.value = app.normalizeEgressNATTypeValue(item.nat_type);
    app.syncEgressNATFormState();
    el.egressNATFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitEgressNATEditMode = function exitEgressNATEditMode() {
    app.setEgressNATFormAdd();
    app.el.egressNATForm.reset();
    app.populateEgressNATInterfaceSelectors();
    app.setEgressNATProtocolValue('tcp+udp');
    if (app.el.egressNATNatType) app.el.egressNATNatType.value = 'symmetric';
    app.closeEgressNATProtocolMenu();
  };

  app.buildEgressNATFromForm = function buildEgressNATFromForm() {
    const el = app.el;
    const parentInterface = app.getInterfaceSubmissionValue(el.egressNATParentInterface, el.egressNATParentPicker, {
      items: app.getEgressNATParentInterfaces(),
      preserveSelected: true
    });
    const childInterface = app.getInterfaceSubmissionValue(el.egressNATChildInterface, el.egressNATChildPicker, {
      items: app.getEgressNATChildInterfaces(parentInterface),
      preserveSelected: true
    });
    const outInterface = app.getInterfaceSubmissionValue(el.egressNATOutInterface, el.egressNATOutPicker, {
      items: egressNATOutInterfaceCandidates(parentInterface, childInterface),
      preserveSelected: true
    });
    const scope = normalizeEgressNATScopeSelection(
      parentInterface,
      app.isEgressNATSingleTargetInterfaceName(parentInterface) ? '' : childInterface
    );
    return {
      parent_interface: scope.parent_interface,
      child_interface: scope.child_interface,
      out_interface: String(outInterface || '').trim(),
      out_source_ip: el.egressNATOutSourceIP.value.trim(),
      protocol: app.getEgressNATProtocolValue() || '',
      nat_type: app.normalizeEgressNATTypeValue(el.egressNATNatType ? el.egressNATNatType.value : '')
    };
  };

  app.getEgressNATFieldInputs = function getEgressNATFieldInputs(issue) {
    const msg = String((issue && issue.message) || '').trim();
    const field = String((issue && issue.field) || '').trim();
    const map = {
      id: app.el.editEgressNATId,
      parent_interface: app.el.egressNATParentPicker || app.el.egressNATParentInterface,
      child_interface: app.el.egressNATChildPicker || app.el.egressNATChildInterface,
      out_interface: app.el.egressNATOutPicker || app.el.egressNATOutInterface,
      out_source_ip: app.el.egressNATOutSourceIP,
      protocol: app.el.egressNATProtocolTrigger || app.el.egressNATProtocol,
      nat_type: app.el.egressNATNatType,
      egress_nat: app.el.egressNATParentPicker || app.el.egressNATParentInterface
    };
    if (map[field]) return [map[field]];
    if (msg === 'parent_interface, child_interface, out_interface are required') {
      return [app.el.egressNATParentPicker || app.el.egressNATParentInterface, app.el.egressNATOutPicker || app.el.egressNATOutInterface];
    }
    if (msg === 'parent_interface and out_interface are required') {
      return [app.el.egressNATParentPicker || app.el.egressNATParentInterface, app.el.egressNATOutPicker || app.el.egressNATOutInterface];
    }
    if (msg === 'parent_interface must be different from out_interface when selecting a single target interface') {
      return [app.el.egressNATParentPicker || app.el.egressNATParentInterface, app.el.egressNATOutPicker || app.el.egressNATOutInterface];
    }
    if (msg === 'child_interface must be different from out_interface') {
      return [app.el.egressNATChildPicker || app.el.egressNATChildInterface, app.el.egressNATOutPicker || app.el.egressNATOutInterface];
    }
    if (msg === 'child_interface is not attached to the selected parent_interface') {
      return [app.el.egressNATChildPicker || app.el.egressNATChildInterface];
    }
    if (msg === 'parent_interface has no eligible child interfaces for egress nat takeover') {
      return [app.el.egressNATParentPicker || app.el.egressNATParentInterface];
    }
    if (msg.indexOf('parent_interface ') === 0) return [app.el.egressNATParentPicker || app.el.egressNATParentInterface];
    if (msg.indexOf('child_interface ') === 0) return [app.el.egressNATChildPicker || app.el.egressNATChildInterface];
    if (msg.indexOf('out_interface ') === 0) return [app.el.egressNATOutPicker || app.el.egressNATOutInterface];
    if (msg.indexOf('out_source_ip ') === 0) return [app.el.egressNATOutSourceIP];
    if (msg.indexOf('protocol ') === 0) return [app.el.egressNATProtocolTrigger || app.el.egressNATProtocol];
    if (msg.indexOf('nat_type ') === 0) return [app.el.egressNATNatType];
    return [];
  };

  app.applyEgressNATValidationIssues = function applyEgressNATValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const inputs = app.getEgressNATFieldInputs(issue);
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

  app.getEgressNATSortValue = function getEgressNATSortValue(item, key) {
    if (key === 'status') {
      if (!item.enabled) return 3;
      if (item.status === 'running') return 0;
      if (item.status === 'error') return 1;
      return 2;
    }
    return item[key];
  };

  app.renderEgressNATsTable = function renderEgressNATsTable() {
    const el = app.el;
    const st = app.state.egressNATs;
    if (!st) return;
    app.closeDropdowns();

    let filteredList = st.data.slice();
    if (st.searchQuery) {
      filteredList = filteredList.filter((item) => app.matchesSearch(st.searchQuery, [
        item.id,
        item.parent_interface,
        item.child_interface,
        app.formatEgressNATTableChildScope(item.child_interface, item.parent_interface),
        item.out_interface,
        item.out_source_ip,
        item.protocol,
        item.nat_type,
        app.formatEgressNATNatType(item.nat_type),
        app.statusInfo(item.status, item.enabled).text,
        item.kernel_reason,
        item.fallback_reason
      ]));
    }
    filteredList = app.sortByState(filteredList, st, app.getEgressNATSortValue);
    const list = app.paginateList(st, filteredList).items;

    app.clearNode(el.egressNATsBody);
    app.updateSortIndicators('egressNATsTable', st);
    app.renderFilterMeta('egressNATs', filteredList.length, st.data.length);
    app.renderPagination('egressNATs', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noEgressNATs, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('egressNAT.list.empty'),
        actionButton: app.el.emptyAddEgressNATBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('egressNATsTable', false);
      return;
    }

    app.hideEmptyState(el.noEgressNATs);
    app.toggleTableVisibility('egressNATsTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((item) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('egress-nat', item.id);
      const info = app.statusInfo(item.status, item.enabled);
      const engine = typeof app.getRuleEngineInfo === 'function'
        ? app.getRuleEngineInfo(item)
        : {
            badgeClass: 'badge-kernel',
            badgeText: String(item.effective_kernel_engine || item.effective_engine || 'kernel').toUpperCase(),
            title: item.fallback_reason || item.kernel_reason || ''
          };
      const statusTitle = [
        app.t('common.status') + ': ' + info.text,
        engine.title || ''
      ].filter(Boolean).join('\n');
      const toggleText = pending ? app.t('common.processing') : app.t(item.enabled ? 'common.disable' : 'common.enable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      tr.appendChild(app.createCell(String(item.id)));
      tr.appendChild(app.createCell(item.parent_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(app.formatEgressNATTableChildScope(item.child_interface, item.parent_interface)));
      tr.appendChild(app.createCell(item.out_interface || app.emptyCellNode()));
      tr.appendChild(app.createCell(item.out_source_ip || app.emptyCellNode()));
      tr.appendChild(app.createCell(app.formatEgressNATProtocol(item.protocol || 'tcp+udp')));
      tr.appendChild(app.createCell(app.formatEgressNATNatType(item.nat_type)));
      tr.appendChild(app.createCell(app.createBadgeNode('badge-' + info.badge, info.text, statusTitle)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: item.enabled ? 'btn-egress-disable' : 'btn-egress-enable',
          text: toggleText,
          dataset: { id: item.id },
          disabled: pending
        },
        {
          className: 'btn-edit-egress-nat',
          text: app.t('common.edit'),
          dataset: { egressNat: app.encData(item) },
          disabled: pending
        },
        {
          className: 'btn-delete-egress-nat',
          text: app.t('common.delete'),
          dataset: { id: item.id },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.egressNATsBody.appendChild(fragment);
  };

  app.loadEgressNATs = async function loadEgressNATs() {
    try {
      app.state.egressNATs.data = await app.apiCall('GET', '/api/egress-nats');
      app.markDataFresh();
      app.renderEgressNATsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load egress nats:', e);
    }
  };

  app.toggleEgressNAT = async function toggleEgressNAT(id) {
    if (app.isRowPending('egress-nat', id)) return;
    const source = (app.state.egressNATs.data || []).find((item) => item.id === id);
    const willEnable = source ? source.enabled === false : false;

    app.setRowPending('egress-nat', id, true);
    app.renderEgressNATsTable();
    try {
      await app.apiCall('POST', '/api/egress-nats/toggle?id=' + id);
      app.notify('success', app.t(willEnable ? 'toast.enabled' : 'toast.disabled', { item: app.t('noun.egressNAT') }));
      await app.loadEgressNATs();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['toggle']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.operationFailed', { message: message }));
      }
    } finally {
      app.setRowPending('egress-nat', id, false);
      app.renderEgressNATsTable();
    }
  };

  app.deleteEgressNAT = async function deleteEgressNAT(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('egressNAT.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('egress-nat', id, true);
    app.renderEgressNATsTable();
    try {
      await app.apiCall('DELETE', '/api/egress-nats?id=' + id);
      if (parseInt(app.el.editEgressNATId.value || '0', 10) === id) app.exitEgressNATEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.egressNAT') }));
      await app.loadEgressNATs();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('egress-nat', id, false);
      app.renderEgressNATsTable();
    }
  };

  app.refreshLocalizedUI = (function wrapRefreshLocalizedUI(original) {
    return function refreshLocalizedUI() {
      if (typeof original === 'function') original();
      const hintEl = app.el.egressNATOutInterfaceHint || app.$('egressNATOutInterfaceHint');
      if (!hintEl) return;
      if (String(hintEl.dataset.mode || '') !== 'auto') return;
      app.updateEgressNATOutInterfaceHint(hintEl.dataset.interfaceName || '', true);
    };
  })(app.refreshLocalizedUI);

  app.refreshEgressNATProtocolUI('tcp+udp');
})();
