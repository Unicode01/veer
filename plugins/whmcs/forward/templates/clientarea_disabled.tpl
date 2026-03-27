<link rel="stylesheet" href="{$asset_url|escape:'html'}/assets/client.css">

<div class="forward-client">
    <div class="forward-shell">
        <div class="forward-hero">
            <div class="forward-hero__main">
                <span class="forward-kicker">Forward</span>
                <h2 class="forward-hero__title">转发规则管理</h2>
                <p class="forward-hero__text">当前页面不可用，但模块本身已加载。请检查账号权限或模块配置。</p>
            </div>
            <div class="forward-hero__stats">
                <div class="forward-stat">
                    <span class="forward-stat__label">当前状态</span>
                    <strong class="forward-stat__value">暂停</strong>
                    <span class="forward-stat__hint">未开放管理能力</span>
                </div>
                <div class="forward-stat">
                    <span class="forward-stat__label">提示</span>
                    <strong class="forward-stat__value">-</strong>
                    <span class="forward-stat__hint">请联系管理员处理</span>
                </div>
            </div>
        </div>

        <div class="forward-empty">
            <h3>服务暂不可用</h3>
            <p>{$message|escape:'html'}</p>
        </div>
    </div>
</div>
