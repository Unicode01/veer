<link rel="stylesheet" href="{$asset_url|escape:'html'}/assets/client.css">

<div class="forward-client">
    <div class="forward-shell">
        <div class="forward-hero">
            <div class="forward-hero__main">
                <span class="forward-kicker">Forward</span>
                <h2 class="forward-hero__title">转发与共享建站</h2>
                <p class="forward-hero__text">管理端口转发规则和 80/443 共享站点。</p>
            </div>
            <div class="forward-hero__stats">
                <div class="forward-stat">
                    <span class="forward-stat__label">端口规则</span>
                    <strong class="forward-stat__value">{$current_rule_count}</strong>
                    <span class="forward-stat__hint">{if $max_rules > 0}上限 {$max_rules}{else}不限{/if}</span>
                </div>
                <div class="forward-stat">
                    <span class="forward-stat__label">共享站点</span>
                    <strong class="forward-stat__value">{$current_site_count}</strong>
                    <span class="forward-stat__hint">{if $max_sites > 0}上限 {$max_sites}{else}不限{/if}</span>
                </div>
            </div>
        </div>

        <div id="forwardNotice" class="forward-notice" style="display:none;"></div>

        {if !$is_logged_in}
            <div class="forward-empty">
                <h3>请先登录</h3>
                <p>登录后才能管理资源。</p>
            </div>
        {elseif !$has_access}
            <div class="forward-empty">
                <h3>未开放</h3>
                <p>您的产品暂未开放 Forward 功能。</p>
            </div>
        {else}
            <div class="forward-grid">
                <div class="forward-card">
                    <div class="forward-card__head">
                        <div>
                            <span class="forward-card__eyebrow">目标服务</span>
                            <h3 class="forward-card__title">选择服务 IP</h3>
                        </div>
                        <span class="forward-chip">入口 {$server_ip_summary|escape:'html'}</span>
                    </div>

                    <div class="form-group">
                        <label for="forwardServiceSelect">服务 IP</label>
                        <select class="form-control forward-control" id="forwardServiceSelect">
                            <option value="">-- 请选择服务 IP --</option>
                            {foreach $services as $productName => $serviceGroup}
                                <optgroup label="{$productName|escape:'html'}">
                                    {foreach $serviceGroup as $service}
                                        {foreach $service.ips as $ip}
                                            <option value="{$ip|escape:'html'}" data-product="{$service.product_name|escape:'html'}" data-service-id="{$service.service_id|escape:'html'}" data-server-id="{$service.server_id|escape:'html'}" data-server-label="{$service.server_label|escape:'html'}" data-listen-ips="{$service.listen_ips_csv|escape:'html'}">
                                                {$service.product_name|escape:'html'} - {$ip|escape:'html'} ({$service.server_label|escape:'html'})
                                            </option>
                                        {/foreach}
                                    {/foreach}
                                </optgroup>
                            {/foreach}
                        </select>
                        <p class="help-block forward-help" id="forwardServiceHelp">请选择目标服务 IP，入口 IP 会按宿主机自动限制。</p>
                    </div>

                    <div class="forward-selection">
                        <div>
                            <span class="forward-selection__label">当前选择</span>
                            <strong class="forward-selection__value" id="forwardSelectedTarget">未选择</strong>
                        </div>
                        <div>
                            <span class="forward-selection__label">可用入口 IP</span>
                            <strong class="forward-selection__value" id="forwardSelectedListenIps">{$server_ip_summary|escape:'html'}</strong>
                        </div>
                        <div>
                            <span class="forward-selection__label">规则预览</span>
                            <code class="forward-selection__route" id="forwardRulePreview">{$server_ip|escape:'html'}:入口端口 -> 目标IP:目标端口</code>
                        </div>
                        <div>
                            <span class="forward-selection__label">站点预览</span>
                            <code class="forward-selection__route" id="forwardSitePreview">{$server_ip|escape:'html'}:80/443 -> 目标IP</code>
                        </div>
                        <div class="forward-actionbar" style="margin-top:0;">
                            <button type="button" class="btn btn-default btn-xs forward-copy-btn" data-copy-target="#forwardRulePreview">复制规则预览</button>
                            <button type="button" class="btn btn-default btn-xs forward-copy-btn" data-copy-target="#forwardSitePreview">复制站点预览</button>
                        </div>
                    </div>

                    <div class="forward-actionbar">
                        <button type="button" class="btn btn-success forward-btn" id="forwardQuickSshBtn" {if !$can_add_more}disabled{/if}>快速添加 SSH</button>
                        <button type="button" class="btn btn-primary forward-btn" id="forwardOpenAddRuleBtn" {if !$can_add_more}disabled{/if}>添加端口规则</button>
                        <button type="button" class="btn btn-primary forward-btn" id="forwardOpenAddSiteBtn" {if !$can_add_more_sites}disabled{/if}>添加共享站点</button>
                    </div>
                    <p class="forward-inline-tip">说明：入口 IP 会按宿主机自动限制，共享站点域名必须唯一。</p>
                </div>

                <div class="forward-card">
                    <div class="forward-card__head">
                        <div>
                            <span class="forward-card__eyebrow">资源概览</span>
                            <h3 class="forward-card__title">当前配额与状态</h3>
                        </div>
                        <span class="forward-chip forward-chip--soft">服务 IP {$service_ip_count|escape:'html'}</span>
                    </div>

                    <div class="forward-overview">
                        <div class="forward-overview__row">
                            <span>端口规则状态</span>
                            <span>{$active_rule_count|escape:'html'} 启用 / {$inactive_rule_count|escape:'html'} 停用</span>
                        </div>
                        <div class="forward-overview__row">
                            <span>共享站点状态</span>
                            <span>{$active_site_count|escape:'html'} 启用 / {$inactive_site_count|escape:'html'} 停用</span>
                        </div>
                        <div class="forward-overview__row">
                            <span>规则剩余额度</span>
                            <span>{if $max_rules > 0}{$max_rules-$current_rule_count}{else}不限{/if}</span>
                        </div>
                        <div class="forward-overview__row">
                            <span>站点剩余额度</span>
                            <span>{if $max_sites > 0}{$max_sites-$current_site_count}{else}不限{/if}</span>
                        </div>
                    </div>

                    <div class="forward-side-note">
                        <strong>安全提示</strong>
                        <p>编辑现有规则和站点时，目标 IP 固定为原绑定服务，避免跨服务越权修改。</p>
                    </div>
                </div>
            </div>

            <div class="forward-card forward-card--table">
                <div class="forward-card__head">
                    <h3 class="forward-card__title">端口规则</h3>
                </div>
                <div class="table-responsive forward-table-wrap">
                    <table class="table forward-table">
                        <thead>
                            <tr>
                                <th>规则</th>
                                <th>目标</th>
                                <th>入口</th>
                                <th>状态</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {if $rules|@count > 0}
                                {foreach $rules as $rule}
                                    <tr>
                                        <td>
                                            <div class="forward-rule-name">{$rule.rule_name|escape:'html'}</div>
                                            {if $rule.product_name}
                                                <div class="forward-rule-meta">产品：{$rule.product_name|escape:'html'}</div>
                                            {/if}
                                            {if $rule.server_label}
                                                <div class="forward-rule-meta">宿主机：{$rule.server_label|escape:'html'}</div>
                                            {/if}
                                            {if $rule.description}
                                                <div class="forward-rule-desc">{$rule.description|escape:'html'}</div>
                                            {/if}
                                        </td>
                                        <td>
                                            <div class="forward-code">{$rule.out_ip|escape:'html'}:{$rule.out_port|escape:'html'}</div>
                                            <div class="forward-badges" style="margin-top:8px;">
                                                <span class="forward-badge forward-badge--protocol">{$rule.protocol|upper|escape:'html'}</span>
                                            </div>
                                        </td>
                                        <td>
                                            <div class="forward-entry">
                                                <span class="forward-code">{$rule.in_ip|escape:'html'}:{$rule.in_port|escape:'html'}</span>
                                                <button type="button" class="btn btn-xs btn-default forward-copy-btn" data-copy="{$rule.in_ip|escape:'html'}:{$rule.in_port|escape:'html'}">复制</button>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="forward-badge forward-badge--{$rule.status_class|escape:'html'}">{$rule.status_text|escape:'html'}</span>
                                        </td>
                                        <td>
                                            <div class="forward-actions-cell">
                                                <button type="button" class="btn btn-xs {if $rule.enabled}btn-default{else}btn-success{/if} forward-toggle-rule-btn" data-id="{$rule.id|escape:'html'}">{if $rule.enabled}禁用{else}启用{/if}</button>
                                                <button
                                                    type="button"
                                                    class="btn btn-xs btn-warning forward-edit-rule-btn"
                                                    data-id="{$rule.id|escape:'html'}"
                                                    data-rule-name="{$rule.rule_name|escape:'html'}"
                                                    data-product="{$rule.product_name|escape:'html'}"
                                                    data-service-id="{$rule.service_id|escape:'html'}"
                                                    data-server-id="{$rule.server_id|escape:'html'}"
                                                    data-in-ip="{$rule.in_ip|escape:'html'}"
                                                    data-out-ip="{$rule.out_ip|escape:'html'}"
                                                    data-out-port="{$rule.out_port|escape:'html'}"
                                                    data-in-port="{$rule.in_port|escape:'html'}"
                                                    data-protocol="{$rule.protocol|escape:'html'}"
                                                    data-description="{$rule.description|escape:'html'}"
                                                >编辑</button>
                                                <button type="button" class="btn btn-xs btn-danger forward-delete-rule-btn" data-id="{$rule.id|escape:'html'}">删除</button>
                                            </div>
                                        </td>
                                    </tr>
                                {/foreach}
                            {else}
                                <tr>
                                    <td colspan="5" class="text-center text-muted">暂无规则</td>
                                </tr>
                            {/if}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="forward-card forward-card--table">
                <div class="forward-card__head">
                    <h3 class="forward-card__title">共享站点（80/443）</h3>
                </div>
                <div class="table-responsive forward-table-wrap">
                    <table class="table forward-table">
                        <thead>
                            <tr>
                                <th>域名</th>
                                <th>后端</th>
                                <th>入口</th>
                                <th>状态</th>
                                <th>操作</th>
                            </tr>
                        </thead>
                        <tbody>
                            {if $sites|@count > 0}
                                {foreach $sites as $site}
                                    <tr>
                                        <td>
                                            <div class="forward-rule-name">{$site.domain|escape:'html'}</div>
                                            {if $site.server_label}
                                                <div class="forward-rule-meta">宿主机：{$site.server_label|escape:'html'}</div>
                                            {/if}
                                            {if $site.description}
                                                <div class="forward-rule-desc">{$site.description|escape:'html'}</div>
                                            {/if}
                                        </td>
                                        <td>
                                            <div class="forward-code">{$site.backend_ip|escape:'html'}</div>
                                            <div class="forward-rule-meta">
                                                HTTP:{if $site.backend_http_port > 0}{$site.backend_http_port|escape:'html'}{else}关{/if}
                                                /
                                                HTTPS:{if $site.backend_https_port > 0}{$site.backend_https_port|escape:'html'}{else}关{/if}
                                            </div>
                                        </td>
                                        <td>
                                            <div class="forward-entry">
                                                <span class="forward-code">{$site.listen_ip|escape:'html'}:80/443</span>
                                                <button type="button" class="btn btn-xs btn-default forward-copy-btn" data-copy="{$site.listen_ip|escape:'html'}:80/443">复制</button>
                                            </div>
                                        </td>
                                        <td>
                                            <span class="forward-badge forward-badge--{$site.status_class|escape:'html'}">{$site.status_text|escape:'html'}</span>
                                        </td>
                                        <td>
                                            <div class="forward-actions-cell">
                                                <button type="button" class="btn btn-xs {if $site.enabled}btn-default{else}btn-success{/if} forward-toggle-site-btn" data-id="{$site.id|escape:'html'}">{if $site.enabled}禁用{else}启用{/if}</button>
                                                <button
                                                    type="button"
                                                    class="btn btn-xs btn-warning forward-edit-site-btn"
                                                    data-id="{$site.id|escape:'html'}"
                                                    data-domain="{$site.domain|escape:'html'}"
                                                    data-product="{$site.product_name|escape:'html'}"
                                                    data-service-id="{$site.service_id|escape:'html'}"
                                                    data-server-id="{$site.server_id|escape:'html'}"
                                                    data-listen-ip="{$site.listen_ip|escape:'html'}"
                                                    data-backend-ip="{$site.backend_ip|escape:'html'}"
                                                    data-http-port="{$site.backend_http_port|escape:'html'}"
                                                    data-https-port="{$site.backend_https_port|escape:'html'}"
                                                    data-description="{$site.description|escape:'html'}"
                                                >编辑</button>
                                                <button type="button" class="btn btn-xs btn-danger forward-delete-site-btn" data-id="{$site.id|escape:'html'}">删除</button>
                                            </div>
                                        </td>
                                    </tr>
                                {/foreach}
                            {else}
                                <tr>
                                    <td colspan="5" class="text-center text-muted">暂无共享站点</td>
                                </tr>
                            {/if}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="modal fade" id="forwardRuleAddModal" tabindex="-1" role="dialog">
                <div class="modal-dialog">
                    <div class="modal-content forward-modal">
                        <form id="forwardRuleAddForm">
                            <input type="hidden" name="csrf_token" value="{$csrf_token|escape:'html'}">
                            <input type="hidden" name="product_name" id="forward_rule_add_product_name">
                            <input type="hidden" name="service_id" id="forward_rule_add_service_id">
                            <input type="hidden" name="server_id" id="forward_rule_add_server_id">
                            <div class="modal-header forward-modal__header">
                                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                                <h4 class="modal-title">添加规则</h4>
                            </div>
                            <div class="modal-body forward-modal__body">
                                <div class="form-group">
                                    <label for="forward_rule_add_name">规则名称</label>
                                    <input class="form-control forward-control" id="forward_rule_add_name" name="rule_name" required maxlength="100">
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_add_ip">目标 IP</label>
                                    <input class="form-control forward-control" id="forward_rule_add_ip" name="internal_ip" readonly required>
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_add_listen_ip">入口 IP</label>
                                    <select class="form-control forward-control" id="forward_rule_add_listen_ip" name="listen_ip" required></select>
                                </div>
                                <div class="row">
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_rule_add_out_port">目标端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_rule_add_out_port" name="internal_port" min="1" max="65535" required>
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_rule_add_in_port">入口端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_rule_add_in_port" name="external_port" min="{$client_port_min|escape:'html'}" max="{$client_port_max|escape:'html'}" required>
                                            <p class="help-block forward-help">允许范围：{$client_port_range_text|escape:'html'}</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_add_protocol">协议</label>
                                    <select class="form-control forward-control" id="forward_rule_add_protocol" name="protocol">
                                        {foreach $allowed_protocols as $protocol}
                                            <option value="{$protocol|escape:'html'}">{$protocol|upper|escape:'html'}</option>
                                        {/foreach}
                                    </select>
                                </div>
                                <div class="form-group" style="margin-bottom:0;">
                                    <label for="forward_rule_add_desc">描述</label>
                                    <textarea class="form-control forward-control" id="forward_rule_add_desc" name="description" rows="3" maxlength="2000"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer forward-modal__footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">取消</button>
                                <button type="submit" class="btn btn-primary">保存</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div class="modal fade" id="forwardRuleEditModal" tabindex="-1" role="dialog">
                <div class="modal-dialog">
                    <div class="modal-content forward-modal">
                        <form id="forwardRuleEditForm">
                            <input type="hidden" name="csrf_token" value="{$csrf_token|escape:'html'}">
                            <input type="hidden" name="rule_id" id="forward_rule_edit_id">
                            <input type="hidden" name="service_id" id="forward_rule_edit_service_id">
                            <input type="hidden" name="server_id" id="forward_rule_edit_server_id">
                            <div class="modal-header forward-modal__header">
                                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                                <h4 class="modal-title">编辑规则</h4>
                            </div>
                            <div class="modal-body forward-modal__body">
                                <div class="form-group">
                                    <label for="forward_rule_edit_name">规则名称</label>
                                    <input class="form-control forward-control" id="forward_rule_edit_name" name="rule_name" required maxlength="100">
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_edit_ip">目标 IP</label>
                                    <input class="form-control forward-control" id="forward_rule_edit_ip" name="internal_ip" readonly required>
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_edit_listen_ip">入口 IP</label>
                                    <select class="form-control forward-control" id="forward_rule_edit_listen_ip" name="listen_ip" required></select>
                                </div>
                                <div class="row">
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_rule_edit_out_port">目标端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_rule_edit_out_port" name="internal_port" min="1" max="65535" required>
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_rule_edit_in_port">入口端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_rule_edit_in_port" name="external_port" min="{$client_port_min|escape:'html'}" max="{$client_port_max|escape:'html'}" required>
                                            <p class="help-block forward-help">允许范围：{$client_port_range_text|escape:'html'}</p>
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label for="forward_rule_edit_protocol">协议</label>
                                    <select class="form-control forward-control" id="forward_rule_edit_protocol" name="protocol">
                                        {foreach $allowed_protocols as $protocol}
                                            <option value="{$protocol|escape:'html'}">{$protocol|upper|escape:'html'}</option>
                                        {/foreach}
                                    </select>
                                </div>
                                <div class="form-group" style="margin-bottom:0;">
                                    <label for="forward_rule_edit_desc">描述</label>
                                    <textarea class="form-control forward-control" id="forward_rule_edit_desc" name="description" rows="3" maxlength="2000"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer forward-modal__footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">取消</button>
                                <button type="submit" class="btn btn-primary">保存</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div class="modal fade" id="forwardSiteAddModal" tabindex="-1" role="dialog">
                <div class="modal-dialog">
                    <div class="modal-content forward-modal">
                        <form id="forwardSiteAddForm">
                            <input type="hidden" name="csrf_token" value="{$csrf_token|escape:'html'}">
                            <input type="hidden" name="product_name" id="forward_site_add_product_name">
                            <input type="hidden" name="service_id" id="forward_site_add_service_id">
                            <input type="hidden" name="server_id" id="forward_site_add_server_id">
                            <div class="modal-header forward-modal__header">
                                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                                <h4 class="modal-title">添加共享站点</h4>
                            </div>
                            <div class="modal-body forward-modal__body">
                                <div class="form-group">
                                    <label for="forward_site_add_domain">域名</label>
                                    <input class="form-control forward-control" id="forward_site_add_domain" name="domain" placeholder="app.example.com" required maxlength="253">
                                </div>
                                <div class="form-group">
                                    <label for="forward_site_add_ip">目标 IP</label>
                                    <input class="form-control forward-control" id="forward_site_add_ip" name="backend_ip" readonly required>
                                </div>
                                <div class="form-group">
                                    <label for="forward_site_add_listen_ip">入口 IP</label>
                                    <select class="form-control forward-control" id="forward_site_add_listen_ip" name="listen_ip" required></select>
                                </div>
                                <div class="row">
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_site_add_http">HTTP 端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_site_add_http" name="backend_http_port" min="0" max="65535" value="80">
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_site_add_https">HTTPS 端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_site_add_https" name="backend_https_port" min="0" max="65535" value="443">
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group" style="margin-bottom:0;">
                                    <label for="forward_site_add_desc">描述</label>
                                    <textarea class="form-control forward-control" id="forward_site_add_desc" name="description" rows="3" maxlength="2000"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer forward-modal__footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">取消</button>
                                <button type="submit" class="btn btn-primary">保存</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <div class="modal fade" id="forwardSiteEditModal" tabindex="-1" role="dialog">
                <div class="modal-dialog">
                    <div class="modal-content forward-modal">
                        <form id="forwardSiteEditForm">
                            <input type="hidden" name="csrf_token" value="{$csrf_token|escape:'html'}">
                            <input type="hidden" name="site_id" id="forward_site_edit_id">
                            <input type="hidden" name="service_id" id="forward_site_edit_service_id">
                            <input type="hidden" name="server_id" id="forward_site_edit_server_id">
                            <div class="modal-header forward-modal__header">
                                <button type="button" class="close" data-dismiss="modal"><span>&times;</span></button>
                                <h4 class="modal-title">编辑共享站点</h4>
                            </div>
                            <div class="modal-body forward-modal__body">
                                <div class="form-group">
                                    <label for="forward_site_edit_domain">域名</label>
                                    <input class="form-control forward-control" id="forward_site_edit_domain" name="domain" required maxlength="253">
                                </div>
                                <div class="form-group">
                                    <label for="forward_site_edit_ip">目标 IP</label>
                                    <input class="form-control forward-control" id="forward_site_edit_ip" name="backend_ip" readonly required>
                                </div>
                                <div class="form-group">
                                    <label for="forward_site_edit_listen_ip">入口 IP</label>
                                    <select class="form-control forward-control" id="forward_site_edit_listen_ip" name="listen_ip" required></select>
                                </div>
                                <div class="row">
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_site_edit_http">HTTP 端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_site_edit_http" name="backend_http_port" min="0" max="65535">
                                        </div>
                                    </div>
                                    <div class="col-sm-6">
                                        <div class="form-group">
                                            <label for="forward_site_edit_https">HTTPS 端口</label>
                                            <input type="number" class="form-control forward-control" id="forward_site_edit_https" name="backend_https_port" min="0" max="65535">
                                        </div>
                                    </div>
                                </div>
                                <div class="form-group" style="margin-bottom:0;">
                                    <label for="forward_site_edit_desc">描述</label>
                                    <textarea class="form-control forward-control" id="forward_site_edit_desc" name="description" rows="3" maxlength="2000"></textarea>
                                </div>
                            </div>
                            <div class="modal-footer forward-modal__footer">
                                <button type="button" class="btn btn-default" data-dismiss="modal">取消</button>
                                <button type="submit" class="btn btn-primary">保存</button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>
        {/if}
    </div>
</div>

{if $is_logged_in && $has_access}
<script>
(function ($) {
    var csrfToken = '{$csrf_token|escape:'javascript'}';
    var serverIpText = '{$server_ip|escape:'javascript'}';
    var serverIpSummaryText = '{$server_ip_summary|escape:'javascript'}';
    var clientPortMin = {$client_port_min|intval};
    var clientPortMax = {$client_port_max|intval};
    var clientPortRangeText = '{$client_port_range_text|escape:'javascript'}';
    var domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/i;
    var noticeTimer = null;

    function selectedService() {
        return $('#forwardServiceSelect option:selected');
    }

    function parseListenIps(value) {
        if (!value) {
            return [];
        }
        return String(value)
            .split(',')
            .map(function (item) { return $.trim(item); })
            .filter(function (item, index, list) {
                return item && list.indexOf(item) === index;
            });
    }

    function formatListenIps(ips) {
        return ips.length ? ips.join(', ') : '未配置';
    }

    function normalizeServerId(value) {
        var parsed = parseInt(value, 10);
        return isNaN(parsed) ? 0 : parsed;
    }

    function normalizeServiceId(value) {
        var parsed = parseInt(value, 10);
        return isNaN(parsed) ? 0 : parsed;
    }

    function findServiceOption(ip, product, serverId, serviceId) {
        var normalizedProduct = $.trim(String(product || ''));
        var normalizedServerId = normalizeServerId(serverId);
        var normalizedServiceId = normalizeServiceId(serviceId);
        var $options = $('#forwardServiceSelect option').filter(function () {
            return $(this).val() === ip;
        });
        var $matched;

        if (!$options.length) {
            return $();
        }

        if (normalizedServiceId > 0) {
            $matched = $options.filter(function () {
                return normalizeServiceId($(this).data('service-id')) === normalizedServiceId;
            }).first();
            return $matched.length ? $matched : $();
        }

        if (normalizedServerId > 0) {
            $matched = $options.filter(function () {
                return normalizeServerId($(this).data('server-id')) === normalizedServerId;
            }).first();
            return $matched.length ? $matched : $();
        }

        if (normalizedProduct) {
            $matched = $options.filter(function () {
                return $.trim(String($(this).data('product') || '')) === normalizedProduct;
            });
            if ($matched.length === 1) {
                return $matched.first();
            }
            if ($matched.length > 1) {
                return $();
            }
        }

        return $options.length === 1 ? $options.first() : $();
    }

    function listenIpsForServiceIp(ip, product, serverId, serviceId) {
        var option = findServiceOption(ip, product, serverId, serviceId);
        if (!option.length) {
            return [];
        }
        return parseListenIps(option.data('listen-ips') || '');
    }

    function ensureSelectOption($select, value) {
        if (!value) {
            return;
        }
        if ($select.find('option[value="' + value.replace(/"/g, '\\"') + '"]').length) {
            return;
        }
        $('<option></option>').val(value).text(value + ' (当前值)').appendTo($select);
    }

    function populateListenIpSelect($select, ips, selectedValue) {
        var selected = selectedValue || '';
        $select.empty();
        if (!ips.length && selected) {
            ips = [selected];
        }
        if (!ips.length) {
            $('<option></option>').val('').text('当前服务未配置入口 IP').appendTo($select);
            $select.prop('disabled', true);
            return;
        }
        $.each(ips, function (_, ip) {
            $('<option></option>').val(ip).text(ip).appendTo($select);
        });
        ensureSelectOption($select, selected);
        $select.prop('disabled', false);
        $select.val(selected && $select.find('option[value="' + selected.replace(/"/g, '\\"') + '"]').length ? selected : ips[0]);
    }

    function syncTopPreview() {
        var targetIp = $('#forward_rule_add_ip').val() || $('#forward_site_add_ip').val() || selectedService().val() || '目标IP';
        var ruleListenIp = $('#forward_rule_add_listen_ip').val() || serverIpText;
        var siteListenIp = $('#forward_site_add_listen_ip').val() || ruleListenIp;
        $('#forwardRulePreview').text(ruleListenIp + ':入口端口 -> ' + targetIp + ':目标端口');
        $('#forwardSitePreview').text(siteListenIp + ':80/443 -> ' + targetIp);
    }

    function showNotice(type, message) {
        var $notice = $('#forwardNotice');
        $notice.removeClass('forward-notice--success forward-notice--warning forward-notice--danger');
        $notice.addClass('forward-notice--' + type).text(message).stop(true, true).fadeIn(120);
        if (noticeTimer) {
            clearTimeout(noticeTimer);
        }
        if (type === 'success') {
            noticeTimer = setTimeout(function () {
                $notice.fadeOut(180);
            }, 2200);
        }
    }

    function setSubmitting($form, submitting) {
        var $submit = $form.find('button[type="submit"]');
        if (!$submit.data('default-text')) {
            $submit.data('default-text', $.trim($submit.text()));
        }
        $form.find('input, select, textarea, button').prop('disabled', submitting);
        $submit.text(submitting ? '保存中...' : $submit.data('default-text'));
    }

    function syncSelectedService() {
        var selected = selectedService();
        var ip = selected.val() || '';
        var product = selected.data('product') || '';
        var serviceId = normalizeServiceId(selected.data('service-id'));
        var serverId = normalizeServerId(selected.data('server-id'));
        var serverLabel = $.trim(String(selected.data('server-label') || ''));
        var listenIps = parseListenIps(selected.data('listen-ips') || '');
        var selectedText = ip ? $.grep([product, ip, serverLabel], function (item) { return item; }).join(' / ') : '未选择';
        $('#forwardSelectedTarget').text(selectedText);
        $('#forwardSelectedListenIps').text(ip ? formatListenIps(listenIps) : serverIpSummaryText);
        $('#forwardServiceHelp').text(ip ? ('已选择目标 IP: ' + ip + (serverLabel ? '（' + serverLabel + '）' : '') + '，可用入口 IP: ' + formatListenIps(listenIps)) : '请选择目标服务 IP，入口 IP 会按宿主机自动限制。');
        $('#forward_rule_add_ip').val(ip);
        $('#forward_rule_add_product_name').val(product);
        $('#forward_rule_add_service_id').val(serviceId);
        $('#forward_rule_add_server_id').val(serverId);
        $('#forward_site_add_ip').val(ip);
        $('#forward_site_add_product_name').val(product);
        $('#forward_site_add_service_id').val(serviceId);
        $('#forward_site_add_server_id').val(serverId);
        populateListenIpSelect($('#forward_rule_add_listen_ip'), listenIps);
        populateListenIpSelect($('#forward_site_add_listen_ip'), listenIps);
        syncTopPreview();
    }

    function requireServiceSelected() {
        syncSelectedService();
        if (!$('#forward_rule_add_ip').val()) {
            showNotice('warning', '请先选择目标服务 IP。');
            return false;
        }
        if (!$('#forward_rule_add_listen_ip').val()) {
            showNotice('warning', '当前服务所属宿主机未配置入口 IP。');
            return false;
        }
        return true;
    }

    function normalizeDomain(domain) {
        return $.trim(String(domain || '')).replace(/\.+$/, '').toLowerCase();
    }

    function validateSiteForm($form) {
        var $domain = $form.find('input[name="domain"]');
        var domain = normalizeDomain($domain.val());
        var httpPort = parseInt($form.find('input[name="backend_http_port"]').val(), 10);
        var httpsPort = parseInt($form.find('input[name="backend_https_port"]').val(), 10);

        if (!domainPattern.test(domain)) {
            showNotice('warning', '域名格式无效，请填写标准域名或 punycode。');
            $domain.focus();
            return false;
        }
        $domain.val(domain);

        if (isNaN(httpPort)) {
            httpPort = 0;
        }
        if (isNaN(httpsPort)) {
            httpsPort = 0;
        }
        if (httpPort === 0 && httpsPort === 0) {
            showNotice('warning', 'HTTP 和 HTTPS 端口至少启用一个。');
            return false;
        }
        return true;
    }

    function validateRuleForm($form) {
        var $listenPort = $form.find('input[name="external_port"]');
        var listenPort = parseInt($listenPort.val(), 10);
        if (isNaN(listenPort) || listenPort < clientPortMin || listenPort > clientPortMax) {
            showNotice('warning', '入口端口必须在 ' + clientPortRangeText + ' 之间。');
            $listenPort.focus();
            return false;
        }
        return true;
    }

    function randomPortInRange(min, max) {
        if (max <= min) {
            return min;
        }
        return min + Math.floor(Math.random() * (max - min + 1));
    }

    function postAction(payload, loadingText, successText, errorText) {
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: payload,
            dataType: 'json',
            beforeSend: function () {
                showNotice('warning', loadingText);
            }
        })
            .done(function (res) {
                if (res && res.success) {
                    showNotice('success', res.message || successText);
                    setTimeout(function () {
                        window.location.reload();
                    }, 300);
                } else {
                    showNotice('danger', res && res.message ? res.message : errorText);
                }
            })
            .fail(function () {
                showNotice('danger', errorText);
            });
    }

    $('#forwardServiceSelect').on('change', syncSelectedService);
    $('#forward_rule_add_listen_ip, #forward_site_add_listen_ip').on('change', syncTopPreview);

    $('#forwardOpenAddRuleBtn').on('click', function () {
        if (!requireServiceSelected()) {
            return;
        }
        $('#forwardRuleAddForm')[0].reset();
        syncSelectedService();
        $('#forwardRuleAddModal').modal('show');
    });

    $('#forwardQuickSshBtn').on('click', function () {
        if (!requireServiceSelected()) {
            return;
        }
        $('#forwardRuleAddForm')[0].reset();
        syncSelectedService();
        $('#forward_rule_add_name').val('SSH-' + Math.random().toString(36).slice(2, 6));
        $('#forward_rule_add_out_port').val('22');
        $('#forward_rule_add_in_port').val(String(randomPortInRange(clientPortMin, clientPortMax)));
        $('#forward_rule_add_protocol').val('tcp');
        $('#forward_rule_add_desc').val('快速创建的 SSH 转发规则');
        $('#forwardRuleAddModal').modal('show');
    });

    $('#forwardOpenAddSiteBtn').on('click', function () {
        if (!requireServiceSelected()) {
            return;
        }
        $('#forwardSiteAddForm')[0].reset();
        syncSelectedService();
        $('#forward_site_add_http').val('80');
        $('#forward_site_add_https').val('443');
        $('#forwardSiteAddModal').modal('show');
    });

    $('#forwardRuleAddForm').on('submit', function (e) {
        var $form = $(this);
        var formData = $form.serializeArray();
        e.preventDefault();
        if (!validateRuleForm($form)) {
            return;
        }
        formData.push({name: 'action', value: 'add_rule'});
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: $.param(formData),
            dataType: 'json',
            beforeSend: function () {
                setSubmitting($form, true);
            }
        })
            .done(function (res) {
                if (res && res.success) {
                    showNotice('success', res.message || '规则创建成功');
                    setTimeout(function () {
                        window.location.reload();
                    }, 300);
                } else {
                    showNotice('danger', res && res.message ? res.message : '保存失败');
                }
            })
            .fail(function () {
                showNotice('danger', '保存失败，请稍后重试');
            })
            .always(function () {
                setSubmitting($form, false);
            });
    });

    $('#forwardRuleEditForm').on('submit', function (e) {
        var $form = $(this);
        var formData = $form.serializeArray();
        e.preventDefault();
        if (!validateRuleForm($form)) {
            return;
        }
        formData.push({name: 'action', value: 'edit_rule'});
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: $.param(formData),
            dataType: 'json',
            beforeSend: function () {
                setSubmitting($form, true);
            }
        })
            .done(function (res) {
                if (res && res.success) {
                    showNotice('success', res.message || '规则更新成功');
                    setTimeout(function () {
                        window.location.reload();
                    }, 300);
                } else {
                    showNotice('danger', res && res.message ? res.message : '保存失败');
                }
            })
            .fail(function () {
                showNotice('danger', '保存失败，请稍后重试');
            })
            .always(function () {
                setSubmitting($form, false);
            });
    });

    $('#forwardSiteAddForm').on('submit', function (e) {
        var $form = $(this);
        var formData = $form.serializeArray();
        e.preventDefault();
        if (!validateSiteForm($form)) {
            return;
        }
        formData = $form.serializeArray();
        formData.push({name: 'action', value: 'add_site'});
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: $.param(formData),
            dataType: 'json',
            beforeSend: function () {
                setSubmitting($form, true);
            }
        })
            .done(function (res) {
                if (res && res.success) {
                    showNotice('success', res.message || '共享站点创建成功');
                    setTimeout(function () {
                        window.location.reload();
                    }, 300);
                } else {
                    showNotice('danger', res && res.message ? res.message : '保存失败');
                }
            })
            .fail(function () {
                showNotice('danger', '保存失败，请稍后重试');
            })
            .always(function () {
                setSubmitting($form, false);
            });
    });

    $('#forwardSiteEditForm').on('submit', function (e) {
        var $form = $(this);
        var formData = $form.serializeArray();
        e.preventDefault();
        if (!validateSiteForm($form)) {
            return;
        }
        formData = $form.serializeArray();
        formData.push({name: 'action', value: 'edit_site'});
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: $.param(formData),
            dataType: 'json',
            beforeSend: function () {
                setSubmitting($form, true);
            }
        })
            .done(function (res) {
                if (res && res.success) {
                    showNotice('success', res.message || '共享站点更新成功');
                    setTimeout(function () {
                        window.location.reload();
                    }, 300);
                } else {
                    showNotice('danger', res && res.message ? res.message : '保存失败');
                }
            })
            .fail(function () {
                showNotice('danger', '保存失败，请稍后重试');
            })
            .always(function () {
                setSubmitting($form, false);
            });
    });

    $('.forward-edit-rule-btn').on('click', function () {
        var outIp = $(this).data('out-ip');
        var product = $(this).data('product');
        var serviceId = normalizeServiceId($(this).data('service-id'));
        var serverId = normalizeServerId($(this).data('server-id'));
        populateListenIpSelect($('#forward_rule_edit_listen_ip'), listenIpsForServiceIp(outIp, product, serverId, serviceId), $(this).data('in-ip'));
        $('#forward_rule_edit_id').val($(this).data('id'));
        $('#forward_rule_edit_service_id').val(serviceId);
        $('#forward_rule_edit_server_id').val(serverId);
        $('#forward_rule_edit_name').val($(this).data('rule-name'));
        $('#forward_rule_edit_ip').val(outIp);
        $('#forward_rule_edit_out_port').val($(this).data('out-port'));
        $('#forward_rule_edit_in_port').val($(this).data('in-port'));
        $('#forward_rule_edit_protocol').val($(this).data('protocol'));
        $('#forward_rule_edit_desc').val($(this).data('description'));
        $('#forwardRuleEditModal').modal('show');
    });

    $('.forward-edit-site-btn').on('click', function () {
        var backendIp = $(this).data('backend-ip');
        var product = $(this).data('product');
        var serviceId = normalizeServiceId($(this).data('service-id'));
        var serverId = normalizeServerId($(this).data('server-id'));
        populateListenIpSelect($('#forward_site_edit_listen_ip'), listenIpsForServiceIp(backendIp, product, serverId, serviceId), $(this).data('listen-ip'));
        $('#forward_site_edit_id').val($(this).data('id'));
        $('#forward_site_edit_service_id').val(serviceId);
        $('#forward_site_edit_server_id').val(serverId);
        $('#forward_site_edit_domain').val($(this).data('domain'));
        $('#forward_site_edit_ip').val(backendIp);
        $('#forward_site_edit_http').val($(this).data('http-port'));
        $('#forward_site_edit_https').val($(this).data('https-port'));
        $('#forward_site_edit_desc').val($(this).data('description'));
        $('#forwardSiteEditModal').modal('show');
    });

    $('.forward-toggle-rule-btn').on('click', function () {
        postAction(
            {action: 'toggle_rule', rule_id: $(this).data('id'), csrf_token: csrfToken},
            '正在切换规则状态...',
            '规则状态已更新',
            '切换状态失败'
        );
    });

    $('.forward-delete-rule-btn').on('click', function () {
        if (!confirm('确定删除这条规则吗？')) {
            return;
        }
        postAction(
            {action: 'delete_rule', rule_id: $(this).data('id'), csrf_token: csrfToken},
            '正在删除规则...',
            '规则已删除',
            '删除失败'
        );
    });

    $('.forward-toggle-site-btn').on('click', function () {
        postAction(
            {action: 'toggle_site', site_id: $(this).data('id'), csrf_token: csrfToken},
            '正在切换站点状态...',
            '站点状态已更新',
            '切换状态失败'
        );
    });

    $('.forward-delete-site-btn').on('click', function () {
        if (!confirm('确定删除这个共享站点吗？')) {
            return;
        }
        postAction(
            {action: 'delete_site', site_id: $(this).data('id'), csrf_token: csrfToken},
            '正在删除站点...',
            '站点已删除',
            '删除失败'
        );
    });

    $('.forward-copy-btn').on('click', function () {
        var target = $(this).data('copy-target');
        var text = '';
        if (target) {
            text = $.trim($(target).text());
        }
        if (!text) {
            text = $(this).data('copy') || '';
        }
        if (!text) {
            showNotice('warning', '没有可复制的内容。');
            return;
        }
        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(
                function () {
                    showNotice('success', '已复制: ' + text);
                },
                function () {
                    showNotice('warning', '复制失败，请手动复制: ' + text);
                }
            );
        } else {
            showNotice('warning', '当前浏览器不支持自动复制，请手动复制: ' + text);
        }
    });

    syncSelectedService();
})(jQuery);
</script>
{/if}
