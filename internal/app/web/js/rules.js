(function () {
  const app = window.ForwardApp;
  if (!app) return;

  app.refreshRuleInterfaceSelectors = function refreshRuleInterfaceSelectors() {
    const el = app.el;
    app.populateInterfacePicker(el.inInterface, el.inInterfacePicker, el.inInterfaceOptions, {
      preserveSelected: true
    });
    app.populateInterfacePicker(el.outInterface, el.outInterfacePicker, el.outInterfaceOptions, {
      preserveSelected: true
    });
    app.populateIPSelect(el.inInterface, el.inIP, el.inIP.value);
    app.refreshRuleSourceIPOptions(el.ruleOutSourceIP.value);
  };

  app.refreshRuleSourceIPOptions = function refreshRuleSourceIPOptions(selected) {
    const el = app.el;
    const family = typeof app.ipFamily === 'function' ? app.ipFamily(app.$('outIP').value) : '';
    app.populateSourceIPSelect(el.outInterface, el.ruleOutSourceIP, selected == null ? el.ruleOutSourceIP.value : selected, true, {
      family: family
    });
  };

  app.syncRuleFormState = function syncRuleFormState() {
    const el = app.el;
    const formState = app.state.forms.rule;
    const pending = !!app.state.pendingForms.rule;

    if (formState.mode === 'edit' && el.editRuleId.value) {
      el.ruleFormTitle.textContent = app.t('rule.form.title.edit', { id: el.editRuleId.value });
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.edit');
      el.ruleCancelBtn.style.display = '';
    } else if (formState.mode === 'clone' && formState.sourceId) {
      el.ruleFormTitle.textContent = app.t('rule.form.title.clone', { id: formState.sourceId });
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.clone');
      el.ruleCancelBtn.style.display = '';
    } else {
      el.ruleFormTitle.textContent = app.t('rule.form.title.add');
      el.ruleSubmitBtn.textContent = pending ? app.t('common.saving') : app.t('rule.form.submit.add');
      el.ruleCancelBtn.style.display = 'none';
    }

    el.ruleCancelBtn.textContent = app.t('common.cancelEdit');
    el.ruleSubmitBtn.disabled = pending;
    el.ruleSubmitBtn.classList.toggle('is-busy', pending);
    el.ruleCancelBtn.disabled = pending;
  };

  app.setRuleFormAdd = function setRuleFormAdd() {
    app.state.forms.rule = { mode: 'add', sourceId: 0 };
    app.el.editRuleId.value = '';
    app.syncRuleFormState();
  };

  app.enterRuleEditMode = function enterRuleEditMode(rule) {
    const el = app.el;
    app.state.forms.rule = { mode: 'edit', sourceId: rule.id };
    el.editRuleId.value = rule.id;
    app.syncRuleFormState();

    app.$('ruleRemark').value = rule.remark || '';
    app.populateTagSelect(app.$('ruleTag'), rule.tag);
    el.inInterface.value = rule.in_interface || '';
    el.inIP.value = rule.in_ip || '';
    app.$('inPort').value = rule.in_port;
    el.outInterface.value = rule.out_interface || '';
    el.ruleOutSourceIP.value = rule.out_source_ip || '';
    app.$('outIP').value = rule.out_ip;
    app.refreshRuleInterfaceSelectors();
    app.$('outPort').value = rule.out_port;
    app.$('protocol').value = rule.protocol;
    app.$('ruleTransparent').checked = !!rule.transparent;
    app.updateRuleTransparentWarning();
    el.ruleFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.enterRuleCloneMode = function enterRuleCloneMode(rule) {
    const el = app.el;
    app.state.forms.rule = { mode: 'clone', sourceId: rule.id };
    el.editRuleId.value = '';
    app.syncRuleFormState();

    app.$('ruleRemark').value = rule.remark || '';
    app.populateTagSelect(app.$('ruleTag'), rule.tag);
    el.inInterface.value = rule.in_interface || '';
    el.inIP.value = rule.in_ip || '';
    app.$('inPort').value = rule.in_port;
    el.outInterface.value = rule.out_interface || '';
    el.ruleOutSourceIP.value = rule.out_source_ip || '';
    app.$('outIP').value = rule.out_ip;
    app.refreshRuleInterfaceSelectors();
    app.$('outPort').value = rule.out_port;
    app.$('protocol').value = rule.protocol;
    app.$('ruleTransparent').checked = !!rule.transparent;
    app.updateRuleTransparentWarning();
    el.ruleFormTitle.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  app.exitRuleEditMode = function exitRuleEditMode() {
    app.setRuleFormAdd();
    app.el.ruleForm.reset();
    app.refreshRuleInterfaceSelectors();
    app.updateRuleTransparentWarning();
  };

  app.getRuleSelection = function getRuleSelection() {
    if (!(app.state.rules.selectedIds instanceof Set)) {
      app.state.rules.selectedIds = new Set(app.state.rules.selectedIds || []);
    }
    return app.state.rules.selectedIds;
  };

  app.clearRuleSelection = function clearRuleSelection() {
    app.getRuleSelection().clear();
  };

  app.setRuleSelected = function setRuleSelected(id, selected) {
    const selection = app.getRuleSelection();
    if (selected) selection.add(id);
    else selection.delete(id);
  };

  app.pruneRuleSelection = function pruneRuleSelection() {
    const knownIds = new Set((app.state.rules.data || []).map((rule) => rule.id));
    app.getRuleSelection().forEach((id) => {
      if (!knownIds.has(id)) app.state.rules.selectedIds.delete(id);
    });
  };

  app.getRuleSortValue = function getRuleSortValue(rule, key) {
    if (key === 'status') {
      if (!rule.enabled) return 3;
      if (rule.status === 'running') return 0;
      if (rule.status === 'error') return 1;
      return 2;
    }
    if (key === 'transparent') return rule.transparent ? 1 : 0;
    if (key === 'effective_engine') return rule.effective_engine || 'userspace';
    return rule[key];
  };

  app.translateRuntimeReason = function translateRuntimeReason(reason) {
    const text = String(reason || '').trim();
    if (!text) return '';
    const xdpGenericExperimentalReason = 'xdp dataplane generic/mixed attachment requires experimental feature "xdp_generic"';
    const xdpVethNATRedirectPrefix = 'xdp dataplane nat redirect over veth is disabled on ';

    const translated = {
      'kernel dataplane does not support mixed IPv4/IPv6 forwarding': app.t('runtimeReason.kernelMixedFamily'),
      'kernel dataplane currently does not support transparent IPv6 rules': app.t('runtimeReason.kernelTransparentIPv6'),
      'xdp dataplane generic/mixed attachment requires experimental feature "xdp_generic"': app.t('runtimeReason.xdpGenericExperimental')
    };

    if (text.indexOf(xdpGenericExperimentalReason) >= 0) {
      return text.replace(xdpGenericExperimentalReason, app.t('runtimeReason.xdpGenericExperimental'));
    }
    if (text.indexOf(xdpVethNATRedirectPrefix) === 0) {
      return app.t('runtimeReason.xdpVethNatRedirectLegacyKernel');
    }
    return Object.prototype.hasOwnProperty.call(translated, text) ? translated[text] : text;
  };

  app.getRuleEngineInfo = function getRuleEngineInfo(rule) {
    const effective = (rule.effective_engine || 'userspace').toLowerCase();
    const kernelEngine = String(rule.effective_kernel_engine || '').toLowerCase();
    const runtimeReason = typeof app.translateRuntimeReason === 'function'
      ? app.translateRuntimeReason(rule.fallback_reason || rule.kernel_reason || '')
      : String(rule.fallback_reason || rule.kernel_reason || '').trim();
    let badgeClass = 'badge-userspace';
    let badgeText = app.t('rule.engine.effective.' + effective);
    if (effective === 'kernel') {
      if (kernelEngine === 'xdp') {
        badgeClass = 'badge-xdp';
        badgeText = 'XDP';
      } else if (kernelEngine === 'tc') {
        badgeClass = 'badge-tc';
        badgeText = 'TC';
      } else if (kernelEngine === 'mixed') {
        badgeClass = 'badge-kernel';
        badgeText = 'MIXED';
      } else {
        badgeClass = 'badge-kernel';
      }
    }
    let hintKey = '';
    if (rule.fallback_reason) hintKey = 'rule.engine.hint.fallback';
    else if (effective === 'kernel') hintKey = 'rule.engine.hint.kernelActive';
    else if (!rule.kernel_eligible) hintKey = 'rule.engine.hint.userspaceOnly';

    const titleParts = [
      app.t('rule.engine.effectiveLabel') + ': ' + app.t('rule.engine.effective.' + effective)
    ];
    if (effective === 'kernel' && kernelEngine) titleParts.push('Kernel Engine: ' + kernelEngine.toUpperCase());
    if (runtimeReason) titleParts.push(runtimeReason);

    return {
      badgeClass: badgeClass,
      badgeText: badgeText,
      hintText: hintKey ? app.t(hintKey) : '',
      title: titleParts.join('\n')
    };
  };

  app.getAddressFamilyInfo = function getAddressFamilyInfo(primaryIP, secondaryIP) {
    const families = [primaryIP, secondaryIP]
      .map((value) => {
        const text = String(value || '').trim();
        return text && typeof app.ipFamily === 'function' ? app.ipFamily(text) : '';
      })
      .filter(Boolean);
    if (!families.length) return null;

    let family = families[0];
    if (families.some((value) => value !== family)) family = 'mixed';

    return {
      family: family,
      badgeClass: family === 'mixed' ? 'badge-family-mixed' : 'badge-family-' + family,
      badgeText: app.t('common.family.' + family),
      title: app.t('common.familyLabel') + ': ' + app.t('common.family.' + family),
      searchText: [family, app.t('common.family.' + family)]
        .filter(Boolean)
        .join(' ')
    };
  };

  app.createAddressFamilyBadgeNode = function createAddressFamilyBadgeNode(primaryIP, secondaryIP) {
    const info = typeof app.getAddressFamilyInfo === 'function'
      ? app.getAddressFamilyInfo(primaryIP, secondaryIP)
      : null;
    if (!info) return null;
    return app.createBadgeNode(info.badgeClass, info.badgeText, info.title);
  };

  app.getFilteredRules = function getFilteredRules() {
    const st = app.state.rules;
    let filteredList = st.data.slice();
    if (st.filterTag) filteredList = filteredList.filter((rule) => rule.tag === st.filterTag);
    if (st.searchQuery) {
      filteredList = filteredList.filter((rule) => app.matchesSearch(st.searchQuery, [
        rule.id,
        rule.remark,
        rule.tag,
        rule.in_interface,
        rule.in_ip,
        rule.in_port,
        rule.out_interface,
        rule.out_ip,
        rule.out_source_ip,
        rule.out_port,
        rule.protocol,
        rule.effective_engine,
        rule.effective_kernel_engine,
        rule.kernel_reason,
        rule.fallback_reason,
        (typeof app.getAddressFamilyInfo === 'function'
          ? (app.getAddressFamilyInfo(rule.in_ip, rule.out_ip) || {}).searchText
          : ''),
        app.statusInfo(rule.status, rule.enabled).text
      ]));
    }
    return app.sortByState(filteredList, st, app.getRuleSortValue);
  };

  app.syncRulesSelectionState = function syncRulesSelectionState(pageItems) {
    const selectAll = app.el.rulesSelectAll;
    if (!selectAll) return;

    const st = app.state.rules;
    const selection = app.getRuleSelection();
    const selectableIds = (pageItems || [])
      .filter((rule) => !app.isRowPending('rule', rule.id))
      .map((rule) => rule.id);
    const selectedOnPage = selectableIds.filter((id) => selection.has(id)).length;

    selectAll.disabled = selectableIds.length === 0 || st.batchDeleting;
    selectAll.checked = selectableIds.length > 0 && selectedOnPage === selectableIds.length;
    selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < selectableIds.length;
  };

  app.renderRulesToolbar = function renderRulesToolbar(filteredList, pageItems) {
    const st = app.state.rules;
    const selection = app.getRuleSelection();
    const selectedCount = selection.size;

    if (app.el.rulesSelectAll) {
      app.el.rulesSelectAll.setAttribute('aria-label', app.t('rule.selection.selectAll'));
    }

    if (app.el.rulesSelectionMeta) {
      app.el.rulesSelectionMeta.hidden = selectedCount === 0;
      app.el.rulesSelectionMeta.textContent = selectedCount > 0
        ? app.t('rule.selection.summary', { count: selectedCount })
        : '';
    }

    if (app.el.batchDeleteRulesBtn) {
      app.el.batchDeleteRulesBtn.disabled = selectedCount === 0 || st.batchDeleting;
      app.el.batchDeleteRulesBtn.classList.toggle('is-busy', st.batchDeleting);
      app.el.batchDeleteRulesBtn.textContent = st.batchDeleting
        ? app.t('common.processing')
        : app.t('rule.batch.delete');
    }

    app.syncRulesSelectionState(pageItems);
  };

  app.getRuleFieldInput = function getRuleFieldInput(field) {
    const map = {
      id: app.el.editRuleId,
      in_interface: app.el.inInterfacePicker || app.el.inInterface,
      in_ip: app.el.inIP,
      in_port: app.$('inPort'),
      out_interface: app.el.outInterfacePicker || app.el.outInterface,
      out_ip: app.$('outIP'),
      out_source_ip: app.el.ruleOutSourceIP,
      out_port: app.$('outPort'),
      protocol: app.$('protocol')
    };
    return map[field] || null;
  };

  app.normalizeValidationMessage = function normalizeValidationMessage(message) {
    const text = String(message || '').trim();
    const prefixes = [
      'listen_interface ',
      'listen_ip ',
      'backend_ip ',
      'backend_source_ip ',
      'in_interface ',
      'in_ip ',
      'target_interface ',
      'parent_prefix ',
      'parent_interface ',
      'child_interface ',
      'assigned_prefix ',
      'address ',
      'prefix_len ',
      'out_interface ',
      'out_ip ',
      'out_source_ip ',
      'protocol ',
      'nat_type '
    ];
    for (const prefix of prefixes) {
      if (text.indexOf(prefix) === 0) return text.slice(prefix.length);
    }
    return text;
  };

  app.translateValidationMessage = function translateValidationMessage(message) {
    const rawText = String(message || '').trim();
    if (rawText.indexOf('overlaps with ipv6 assignment #') === 0) {
      return app.t('validation.ipv6AssignmentOverlap', {
        id: rawText.slice('overlaps with ipv6 assignment #'.length)
      });
    }
    if (rawText.indexOf('child_interface conflicts with egress nat #') === 0) {
      return app.t('validation.egressNATChildConflict', {
        id: rawText.slice('child_interface conflicts with egress nat #'.length)
      });
    }
    if (rawText.indexOf('egress nat scope conflicts with egress nat #') === 0) {
      return app.t('validation.egressNATChildConflict', {
        id: rawText.slice('egress nat scope conflicts with egress nat #'.length)
      });
    }
    if (rawText.indexOf('mac_address conflicts with reservation #') === 0) {
      return app.t('validation.managedNetworkReservationMACConflict', {
        id: rawText.slice('mac_address conflicts with reservation #'.length)
      });
    }
    if (rawText.indexOf('ipv4_address conflicts with reservation #') === 0) {
      return app.t('validation.managedNetworkReservationIPConflict', {
        id: rawText.slice('ipv4_address conflicts with reservation #'.length)
      });
    }

    const text = app.normalizeValidationMessage(rawText);
    if (!text) return app.t('validation.reviewErrors');

    const known = {
      'invalid id': app.t('validation.invalidID'),
      'id is required': app.t('validation.invalidID'),
      'is required': app.t('validation.required'),
      'must be greater than 0': app.t('validation.positiveId'),
      'must be omitted when creating a rule': app.t('validation.ruleCreateIDOmit'),
      'must be omitted when creating a managed network': app.t('validation.managedNetworkCreateIDOmit'),
      'must be omitted when creating a managed network reservation': app.t('validation.managedNetworkReservationCreateIDOmit'),
      'must be omitted when creating an egress nat': app.t('validation.egressNATCreateIDOmit'),
      'must be omitted when creating an ipv6 assignment': app.t('validation.ipv6AssignmentCreateIDOmit'),
      'must be a valid Ethernet MAC address': app.t('validation.macAddress'),
      'must be a valid IP address': app.t('validation.ip'),
      'must be a valid IPv4 address': app.t('validation.ipv4'),
      'must be a valid IPv4 CIDR': app.t('validation.ipv4CIDR'),
      'must be a valid IPv6 address': app.t('validation.ipv6'),
      'must be a valid IPv6 CIDR prefix': app.t('validation.ipv6Prefix'),
      'must be between 1 and 128': app.t('validation.prefixLength'),
      'must be a specific non-loopback IP address': app.t('validation.sourceIPSpecific'),
      'must be a specific non-loopback IPv6 address': app.t('validation.ipv6'),
      'must be a specific non-loopback IPv4 address': app.t('validation.sourceIPSpecific'),
      'must be omitted when transparent mode is enabled': app.t('validation.sourceIPTransparent'),
      'must be between 1 and 65535': app.t('validation.portRange'),
      'must be tcp, udp, or tcp+udp': app.t('validation.protocol'),
      'must include one or more of tcp, udp, icmp': app.t('validation.egressNATProtocol'),
      'must be symmetric or full_cone': app.t('validation.egressNATNatType'),
      'must be auto, userspace, or kernel': app.t('validation.enginePreference'),
      'interface does not exist on this host': app.t('validation.interfaceMissing'),
      'must be assigned to the selected outbound interface': app.t('validation.sourceIPOutboundInterface'),
      'must be assigned to a local interface': app.t('validation.sourceIPLocal'),
      'must match outbound IP address family': app.t('validation.sourceIPOutboundFamily'),
      'must match backend_ip address family': app.t('validation.sourceIPBackendFamily'),
      'must match out_ip address family': app.t('validation.sourceIPTargetFamily'),
      'transparent mode currently supports only IPv4 rules': app.t('validation.transparentIPv4Only'),
      'fixed source IP currently supports only IPv4 userspace forwarding': app.t('validation.sourceIPIPv4Only'),
      'duplicate rule id in update list': app.t('validation.ruleDuplicateUpdate'),
      'cannot update a rule scheduled for deletion': app.t('validation.ruleDeletePendingUpdate'),
      'duplicate rule id in set_enabled list': app.t('validation.ruleDuplicateToggle'),
      'cannot change enabled state for a rule scheduled for deletion': app.t('validation.ruleDeletePendingToggle'),
      'at least one batch operation is required': app.t('validation.ruleBatchRequired'),
      'rule not found': app.t('validation.ruleNotFound'),
      'site not found': app.t('validation.siteNotFound'),
      'range not found': app.t('validation.rangeNotFound'),
      'managed network not found': app.t('validation.managedNetworkNotFound'),
      'managed network reservation not found': app.t('validation.managedNetworkReservationNotFound'),
      'managed network ipv4 is disabled': app.t('validation.managedNetworkReservationIPv4Disabled'),
      'managed network ipv4 configuration is invalid': app.t('validation.managedNetworkReservationIPv4Invalid'),
      'ipv6 assignment not found': app.t('validation.ipv6AssignmentNotFound'),
      'egress nat not found': app.t('validation.egressNATNotFound'),
      'must be one of create, existing': app.t('validation.managedNetworkBridgeMode'),
      'bridge interface does not exist on this host': app.t('validation.managedNetworkBridgeMissing'),
      'bridge name is already used by a non-bridge interface': app.t('validation.managedNetworkBridgeNameConflict'),
      'bridge_mtu must be between 0 and 65535': app.t('validation.managedNetworkBridgeMTU'),
      'must stay inside managed network ipv4_cidr': app.t('validation.managedNetworkReservationIPv4InsideCIDR'),
      'must not use the managed network gateway address': app.t('validation.managedNetworkReservationGatewayConflict'),
      'must use a usable host address': app.t('validation.managedNetworkReservationHostRequired'),
      'domain and backend_ip are required': app.t('validation.siteRequired'),
      'at least one of backend_http_port or backend_https_port is required': app.t('validation.sitePortsRequired'),
      'in_ip, start_port, end_port, out_ip are required': app.t('validation.rangeRequired'),
      'start_port must be <= end_port': app.t('validation.rangeOrder'),
      'parent_interface, child_interface, out_interface are required': app.t('validation.egressNATRequired'),
      'parent_interface and out_interface are required': app.t('validation.egressNATRequired'),
      'and out_interface are required': app.t('validation.egressNATRequired'),
      'parent_interface must be different from out_interface when selecting a single target interface': app.t('validation.egressNATSingleTargetOutConflict'),
      'must be different from out_interface when selecting a single target interface': app.t('validation.egressNATSingleTargetOutConflict'),
      'must be different from parent_interface': app.t('validation.targetInterfaceDifferent'),
      'must exist on the selected parent_interface': app.t('validation.parentPrefixMissing'),
      'must be contained within parent_prefix': app.t('validation.assignedPrefixInsideParent'),
      'is already assigned on the host': app.t('validation.ipv6AssignedOnHost'),
      'child_interface must be different from out_interface': app.t('validation.childInterfaceDifferent'),
      'child_interface is not attached to the selected parent_interface': app.t('validation.childParentMismatch'),
      'parent_interface has no eligible child interfaces for egress nat takeover': app.t('validation.egressNATNoChildren')
    };
    if (known[text]) return known[text];
    if (text.indexOf('listener conflicts with ') === 0) {
      return app.t('validation.listenerConflict', { detail: text.slice('listener conflicts with '.length) });
    }
    if (text.indexOf('HTTP route conflicts with ') === 0 || text.indexOf('HTTPS route conflicts with ') === 0) {
      return app.t('validation.routeConflict', { detail: text });
    }
    return text;
  };

  app.translateRuleValidationMessage = app.translateValidationMessage;

  app.getValidationIssueMessage = function getValidationIssueMessage(payload, scopes) {
    const messages = app.getValidationIssueMessages(payload, scopes, 1);
    return messages.length ? messages[0] : '';
  };

  app.getValidationIssueMessages = function getValidationIssueMessages(payload, scopes, maxItems) {
    const issues = payload && Array.isArray(payload.issues) ? payload.issues : [];
    if (!issues.length) return [];
    const allowedScopes = Array.isArray(scopes) && scopes.length ? scopes : null;
    let relevant = allowedScopes
      ? issues.filter((issue) => issue && allowedScopes.indexOf(issue.scope) >= 0)
      : issues;
    if (!relevant.length && allowedScopes) relevant = issues;
    if (!relevant.length) return [];

    const limit = maxItems > 0 ? maxItems : 0;
    const messages = [];
    const seen = Object.create(null);
    relevant.forEach((issue) => {
      if (limit > 0 && messages.length >= limit) return;
      const translated = app.translateValidationMessage(issue && issue.message);
      if (!translated || seen[translated]) return;
      seen[translated] = true;
      messages.push(translated);
    });
    return messages;
  };

  app.getValidationIssueSummary = function getValidationIssueSummary(payload, scopes, maxItems) {
    const issues = payload && Array.isArray(payload.issues) ? payload.issues : [];
    if (!issues.length) return '';

    const limit = maxItems > 0 ? maxItems : 3;
    const messages = app.getValidationIssueMessages(payload, scopes, limit);
    if (!messages.length) return '';

    const joiner = app.t('validation.issueJoiner');
    const totalMessages = app.getValidationIssueMessages(payload, scopes, 0);
    const hiddenCount = Math.max(0, totalMessages.length - messages.length);
    const summary = messages.join(joiner);
    if (hiddenCount <= 0) return summary;
    return app.t('validation.issueSummaryMore', {
      messages: summary,
      count: hiddenCount
    });
  };

  app.applyRuleValidationIssues = function applyRuleValidationIssues(issues) {
    const relevant = (issues || []).filter((issue) => issue && (issue.scope === 'create' || issue.scope === 'update'));
    if (!relevant.length) {
      app.notify('error', app.t('validation.reviewErrors'));
      return;
    }

    let firstInvalid = null;
    relevant.forEach((issue) => {
      const input = app.getRuleFieldInput(issue.field);
      if (!input) return;
      if (!firstInvalid) firstInvalid = input;
      if (!input.hasAttribute('aria-invalid')) {
        app.setFieldError(input, app.translateValidationMessage(issue.message));
      }
    });

    if (firstInvalid && typeof firstInvalid.focus === 'function') firstInvalid.focus();
    app.notify('error', app.getValidationIssueSummary({ issues: relevant }, null, 3) || app.translateValidationMessage(relevant[0].message));
  };

  app.validateRuleDraft = async function validateRuleDraft(rule, editing) {
    const payload = {
      create: editing ? [] : [rule],
      update: editing ? [rule] : [],
      delete_ids: [],
      set_enabled: []
    };
    const resp = await app.apiCall('POST', '/api/rules/validate', payload);
    if (!resp || !resp.valid) {
      app.applyRuleValidationIssues(resp && resp.issues);
      return null;
    }
    return editing
      ? ((resp.update && resp.update[0]) || rule)
      : ((resp.create && resp.create[0]) || rule);
  };

  app.renderRulesTable = function renderRulesTable() {
    const el = app.el;
    const st = app.state.rules;
    app.closeDropdowns();
    if (st.sortKey === 'effective_engine') {
      st.sortKey = '';
      st.sortAsc = true;
    }
    const filteredList = app.getFilteredRules();
    const pageInfo = app.paginateList(st, filteredList);
    const list = pageInfo.items;
    const selection = app.getRuleSelection();

    app.clearNode(el.rulesBody);
    app.updateSortIndicators('rulesTable', st);
    app.renderFilterMeta('rules', filteredList.length, st.data.length);
    app.renderRulesToolbar(filteredList, list);
    app.renderPagination('rules', filteredList.length);

    if (filteredList.length === 0) {
      app.updateEmptyState(el.noRules, {
        message: st.data.length > 0 && app.hasActiveFilters(st) ? app.t('common.noMatches') : app.t('rule.list.empty'),
        actionButton: app.el.emptyAddRuleBtn,
        showAction: st.data.length === 0 && !app.hasActiveFilters(st),
        filtered: app.hasActiveFilters(st)
      });
      app.toggleTableVisibility('rulesTable', false);
      app.renderOverview();
      return;
    }

    app.hideEmptyState(el.noRules);
    app.toggleTableVisibility('rulesTable', true);

    const fragment = document.createDocumentFragment();
    list.forEach((rule) => {
      const tr = document.createElement('tr');
      const pending = app.isRowPending('rule', rule.id);
      const info = app.statusInfo(rule.status, rule.enabled);
      const engine = typeof app.getRuleEngineInfo === 'function'
        ? app.getRuleEngineInfo(rule)
        : {
            badgeClass: (rule.effective_engine || 'userspace') === 'kernel' ? 'badge-kernel' : 'badge-userspace',
            badgeText: (rule.effective_engine || 'userspace'),
            title: rule.fallback_reason || rule.kernel_reason || ''
          };
      const statusTitle = [
        app.t('common.status') + ': ' + info.text,
        engine.title || ''
      ].filter(Boolean).join('\n');
      const toggleClass = rule.enabled ? 'btn-disable' : 'btn-enable';
      const toggleText = pending ? app.t('common.processing') : app.t(rule.enabled ? 'common.disable' : 'common.enable');
      tr.className = pending ? 'row-pending' : '';
      tr.setAttribute('aria-busy', pending ? 'true' : 'false');

      const checkbox = app.createNode('input', {
        className: 'rule-select-checkbox',
        attrs: {
          type: 'checkbox',
          'aria-label': app.t('rule.selection.toggle', { id: rule.id })
        },
        dataset: {
          id: rule.id
        }
      });
      checkbox.checked = selection.has(rule.id);
      if (pending || st.batchDeleting) {
        checkbox.disabled = true;
        checkbox.setAttribute('aria-disabled', 'true');
      }

      tr.appendChild(app.createCell(checkbox, 'cell-select'));
      tr.appendChild(app.createCell(String(rule.id)));
      tr.appendChild(app.createCell(rule.remark
        ? app.createNode('span', { text: rule.remark, title: rule.remark })
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createTagBadgeNode('rules', rule.tag, st.filterTag === rule.tag)));
      tr.appendChild(app.createCell(rule.in_interface ? rule.in_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(rule.in_ip));
      tr.appendChild(app.createCell(String(rule.in_port)));
      tr.appendChild(app.createCell(rule.out_interface ? rule.out_interface : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createEndpointNode(rule.out_ip, rule.out_source_ip)));
      tr.appendChild(app.createCell(String(rule.out_port)));
      tr.appendChild(app.createCell(String(rule.protocol || '').toUpperCase()));
      tr.appendChild(app.createCell(rule.transparent
        ? app.createBadgeNode('badge-running', app.t('common.yes'))
        : app.emptyCellNode()));
      tr.appendChild(app.createCell(app.createBadgeNode('badge-' + info.badge, info.text, statusTitle)));
      tr.appendChild(app.createCell(app.createActionDropdown([
        {
          className: toggleClass,
          text: toggleText,
          dataset: { id: rule.id, type: 'rule' },
          disabled: pending
        },
        {
          className: 'btn-edit',
          text: app.t('common.edit'),
          dataset: { rule: app.encData(rule) },
          disabled: pending
        },
        {
          className: 'btn-clone',
          text: app.t('common.clone'),
          dataset: { rule: app.encData(rule) },
          disabled: pending
        },
        {
          className: 'btn-delete',
          text: app.t('common.delete'),
          dataset: { id: rule.id, type: 'rule' },
          disabled: pending
        }
      ], pending), 'cell-actions'));

      fragment.appendChild(tr);
    });

    el.rulesBody.appendChild(fragment);

    app.renderOverview();
  };

  app.loadRules = async function loadRules() {
    try {
      app.state.rules.data = await app.apiCall('GET', '/api/rules');
      app.pruneRuleSelection();
      app.markDataFresh();
      app.renderRulesTable();
      if (typeof app.renderRuleStatsTable === 'function') app.renderRuleStatsTable();
    } catch (e) {
      if (e.message !== 'unauthorized') console.error('load rules:', e);
    }
  };

  app.deleteRule = async function deleteRule(id) {
    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('rule.delete.confirm', { id: id }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    app.setRowPending('rule', id, true);
    app.renderRulesTable();
    try {
      await app.apiCall('DELETE', '/api/rules?id=' + id);
      app.getRuleSelection().delete(id);
      if (app.el.editRuleId.value === String(id)) app.exitRuleEditMode();
      app.notify('success', app.t('toast.deleted', { item: app.t('noun.rule') }));
      await app.loadRules();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueMessage(e.payload, ['delete']) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      app.setRowPending('rule', id, false);
      app.renderRulesTable();
    }
  };

  app.deleteSelectedRules = async function deleteSelectedRules(ids) {
    const st = app.state.rules;
    if (st.batchDeleting) return;

    const targetIds = Array.from(new Set((ids || Array.from(app.getRuleSelection()))
      .map((value) => parseInt(value, 10))
      .filter((value) => !Number.isNaN(value) && value > 0)));
    if (!targetIds.length) return;

    const confirmed = await app.confirmAction({
      title: app.t('confirm.deleteTitle'),
      message: app.t('rule.batch.delete.confirm', { count: targetIds.length }),
      confirmText: app.t('common.delete'),
      cancelText: app.t('common.cancel'),
      danger: true
    });
    if (!confirmed) return;

    st.batchDeleting = true;
    targetIds.forEach((id) => app.setRowPending('rule', id, true));
    app.renderRulesTable();

    try {
      await app.apiCall('POST', '/api/rules/batch', {
        create: [],
        update: [],
        delete_ids: targetIds,
        set_enabled: []
      });
      targetIds.forEach((id) => app.getRuleSelection().delete(id));
      if (targetIds.indexOf(parseInt(app.el.editRuleId.value || '0', 10)) >= 0) app.exitRuleEditMode();
      app.notify('success', app.t('rule.batch.delete.success', { count: targetIds.length }));
      await app.loadRules();
    } catch (e) {
      if (e.message !== 'unauthorized') {
        const message = app.getValidationIssueSummary(e.payload, ['delete', 'delete_ids'], 3) || app.translateValidationMessage(e.message);
        app.notify('error', app.t('errors.deleteFailed', { message: message }));
      }
    } finally {
      st.batchDeleting = false;
      targetIds.forEach((id) => app.setRowPending('rule', id, false));
      app.renderRulesTable();
    }
  };

  app.buildRuleFromForm = function buildRuleFromForm() {
    const el = app.el;
    return {
      in_interface: app.getInterfaceSubmissionValue(el.inInterface, el.inInterfacePicker),
      in_ip: el.inIP.value,
      in_port: parseInt(app.$('inPort').value, 10),
      out_interface: app.getInterfaceSubmissionValue(el.outInterface, el.outInterfacePicker),
      out_ip: app.$('outIP').value.trim(),
      out_source_ip: app.$('ruleTransparent').checked ? '' : el.ruleOutSourceIP.value,
      out_port: parseInt(app.$('outPort').value, 10),
      protocol: app.$('protocol').value,
      remark: app.$('ruleRemark').value.trim(),
      tag: app.$('ruleTag').value,
      transparent: app.$('ruleTransparent').checked
    };
  };
})();
