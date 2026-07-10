let rbacState = {
    users: [],
    roles: [],
    permissions: {},
    assignments: [],
    selectedUserId: '',
    mainView: 'users',
    activeTab: 'roles',
    userSearch: '',
    roleSearch: '',
    permissionSearch: '',
    rolePermissionSelection: new Set(),
    resourceOptions: [],
    selectedResourceIds: new Set(),
    selectedResourceMeta: new Map(),
    resourceSearchTimer: null,
    resourceRequestSeq: 0,
    resourcePage: 0,
    resourcePageSize: 12,
    resourceHasMore: false,
    assignmentSearch: '',
    assignmentType: 'all',
    assignmentPage: 0,
    assignmentPageSize: 8,
    assignmentResourceType: 'conversation',
    showEffectivePermissions: false,
    auditLogs: [],
    auditLoading: false,
    pendingRoleUserId: '',
    pendingUserRoles: new Set(),
    editingRoleIsSystem: false,
    savingRoleId: '',
};

const rbacScopeMeta = {
    all: { tone: 'is-warn' },
    assigned: { tone: 'is-info' },
    own: { tone: '' },
};

const rbacResourceLabels = {
    project: '项目', conversation: '对话', vulnerability: '漏洞', webshell: 'WebShell 连接',
    batch_task: '批量任务', c2_listener: 'C2 监听器',
};

function rbacText(value, fallback = '') {
    return value == null || value === '' ? fallback : String(value);
}

function rbacEscape(value) {
    if (typeof escapeHtml === 'function') return escapeHtml(rbacText(value));
    const div = document.createElement('div');
    div.textContent = rbacText(value);
    return div.innerHTML;
}

function rbacT(key, fallback) {
    const options = arguments.length > 2 ? arguments[2] : undefined;
    const translator = typeof window !== 'undefined' && typeof window.t === 'function' ? window.t : null;
    if (translator) {
        const translated = translator(key, options);
        if (translated && translated !== key) return translated;
    }
    return fallback;
}

function rbacPermissionLabel(key) {
    const parts = String(key || '').split(':');
    return rbacT(`rbac.permissionDescriptions.${parts[0] || 'other'}.${parts[1] || 'unknown'}`, rbacState.permissions[key] || key);
}

function rbacPermissionModuleLabel(module) {
    return rbacT(`rbac.permissionModules.${module}`, module);
}

function rbacResourceLabel(type) {
    return rbacT(`rbac.resourceTypes.${type}`, rbacResourceLabels[type] || type);
}

function rbacRoleName(role) {
    if (!role) return '';
    return rbacRoleIsSystem(role) ? rbacT(`rbac.systemRoles.${role.id}.name`, role.name) : role.name;
}

function rbacRoleDescription(role) {
    if (!role) return '';
    return rbacRoleIsSystem(role) ? rbacT(`rbac.systemRoles.${role.id}.description`, role.description || '') : (role.description || '');
}

function rbacShortId(value) {
    const id = rbacText(value);
    if (id.length <= 16) return id;
    return `${id.slice(0, 8)}…${id.slice(-4)}`;
}

function rbacFormatResourceDetail(type, detail) {
    const text = rbacText(detail);
    if (!text) return '';
    if (type === 'conversation' && text) {
        return rbacT('rbac.resourceDetailProject', '所属项目 {{id}}', { id: rbacShortId(text) });
    }
    return text;
}

async function rbacCopyResourceId(id) {
    const value = rbacText(id);
    if (!value) return;
    try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(value);
        } else {
            const input = document.createElement('textarea');
            input.value = value;
            document.body.appendChild(input);
            input.select();
            document.execCommand('copy');
            document.body.removeChild(input);
        }
        rbacNotify(rbacT('rbac.copiedId', '已复制'), 'success');
    } catch (error) {
        rbacNotify(`${rbacT('rbac.copyId', '复制 ID')}: ${error.message || error}`, 'error');
    }
}

function rbacPendingSelectionCount() {
    const manualIds = document.getElementById('rbac-assignment-id')?.value.split(/[\s,，;；]+/).filter(Boolean) || [];
    return new Set([...rbacState.selectedResourceIds, ...manualIds]).size;
}

function rbacRememberSelectedResource(resource) {
    if (!resource || !resource.id) return;
    rbacState.selectedResourceMeta.set(resource.id, {
        label: resource.label || resource.id,
        detail: resource.detail || '',
        type: document.getElementById('rbac-assignment-type')?.value || '',
    });
}

function rbacSelectedResourceMeta(resourceId) {
    if (rbacState.selectedResourceMeta.has(resourceId)) {
        return rbacState.selectedResourceMeta.get(resourceId);
    }
    const cached = rbacState.resourceOptions.find(item => item.id === resourceId);
    if (cached) {
        return {
            label: cached.label || cached.id,
            detail: cached.detail || '',
            type: document.getElementById('rbac-assignment-type')?.value || '',
        };
    }
    return { label: resourceId, detail: '', type: document.getElementById('rbac-assignment-type')?.value || '' };
}

function clearRbacResourceSelection() {
    rbacState.selectedResourceIds.clear();
    rbacState.selectedResourceMeta.clear();
    const manual = document.getElementById('rbac-assignment-id');
    if (manual) manual.value = '';
    renderRbacResourcePicker();
    syncRbacAssignmentSubmit();
}

function renderRbacNoRoleNotice(user) {
    const box = document.getElementById('rbac-no-role-notice');
    if (!box) return;
    const hasRoles = user && rbacUserRoles(user).length > 0;
    if (!user || hasRoles) {
        box.hidden = true;
        box.innerHTML = '';
        return;
    }
    box.hidden = false;
    box.innerHTML = `
        <div class="rbac-no-role-notice-copy">
            <strong>${rbacEscape(rbacT('rbac.noRoleNoticeTitle', '尚未分配角色'))}</strong>
            <span>${rbacEscape(rbacT('rbac.noRoleNoticeHint', '请先分配角色，再配置资源授权。无角色时仅可访问本人创建的数据，且大部分功能不可用。'))}</span>
        </div>
        <button type="button" class="btn-secondary btn-small" onclick="focusRbacRoleAssignment()">${rbacEscape(rbacT('rbac.assignRolesNow', '去分配角色'))}</button>`;
}

function renderRbacPendingSelection() {
    const bar = document.getElementById('rbac-pending-bar');
    const list = document.getElementById('rbac-pending-list');
    const count = document.getElementById('rbac-pending-count');
    const manualIds = document.getElementById('rbac-assignment-id')?.value.split(/[\s,，;；]+/).map(id => id.trim()).filter(Boolean) || [];
    const selectedIds = Array.from(rbacState.selectedResourceIds);
    const total = new Set([...selectedIds, ...manualIds]).size;
    if (count) count.textContent = String(total);
    if (!bar || !list) return;
    if (total === 0) {
        bar.hidden = true;
        list.innerHTML = '';
        return;
    }
    bar.hidden = false;
    const resourceType = document.getElementById('rbac-assignment-type')?.value || '';
    const items = [
        ...selectedIds.map(id => ({ id, meta: rbacSelectedResourceMeta(id), manual: false })),
        ...manualIds.filter(id => !rbacState.selectedResourceIds.has(id)).map(id => ({ id, meta: { label: id, detail: rbacT('rbac.advancedAssignment', '高级：直接输入资源 ID'), type: resourceType }, manual: true })),
    ];
    list.innerHTML = items.map(item => `
        <div class="rbac-pending-item">
            <div class="rbac-pending-item-main">
                <strong>${rbacEscape(item.meta.label || item.id)}</strong>
                <small title="${rbacEscape(item.id)}">${rbacEscape(rbacShortId(item.id))}</small>
            </div>
            ${item.manual ? '' : `<button type="button" class="btn-link btn-small" onclick="toggleRbacResourceSelection('${rbacEscape(item.id)}', false)">${rbacEscape(rbacT('rbac.removePending', '移除'))}</button>`}
        </div>`).join('');
}

function rbacNotify(message, type = 'info') {
    if (typeof notifyApiError === 'function') {
        notifyApiError(message, type);
        return;
    }
    if (typeof showNotification === 'function') showNotification(message, type);
    else if (type === 'error') alert(message);
}

function rbacUserDisplayName(user) {
    return (user && (user.displayName || user.display_name || user.username)) || '';
}

function rbacUserIsBuiltin(user) {
    return !!(user && (user.isBuiltin || user.is_builtin || user.id === 'admin'));
}

function rbacUserRoles(user) {
    return Array.isArray(user && user.roles) ? user.roles : [];
}

function resolveUserEffectiveAccess(user) {
    const userRoles = user ? rbacUserRoles(user) : [];
    const effectivePermissions = new Set();
    const permissionsByModule = {};
    let effectiveScope = 'own';
    userRoles.forEach(roleId => {
        const role = rbacState.roles.find(r => r.id === roleId);
        (role && role.permissions || []).forEach(permission => {
            effectivePermissions.add(permission);
            const module = permission.split(':')[0] || 'other';
            if (!permissionsByModule[module]) permissionsByModule[module] = [];
            permissionsByModule[module].push(permission);
        });
        if (role && role.scope === 'all') effectiveScope = 'all';
        else if (role && role.scope === 'assigned' && effectiveScope !== 'all') effectiveScope = 'assigned';
    });
    const assignmentCount = user
        ? rbacState.assignments.filter(a => (a.userId || a.user_id) === user.id).length
        : 0;
    return { userRoles, effectivePermissions, permissionsByModule, effectiveScope, assignmentCount };
}

function toggleRbacEffectivePermissions() {
    rbacState.showEffectivePermissions = !rbacState.showEffectivePermissions;
    renderRbacEffectivePermissions(selectedRbacUser());
}

function renderRbacEffectivePermissions(user) {
    const box = document.getElementById('rbac-effective-permissions');
    if (!box) return;
    if (!user || !rbacState.showEffectivePermissions) {
        box.hidden = true;
        box.innerHTML = '';
        return;
    }
    const access = resolveUserEffectiveAccess(user);
    const modules = Object.keys(access.permissionsByModule).sort();
    if (!modules.length) {
        box.hidden = false;
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.noEffectivePermissions', '暂无有效权限')}</strong><span>${rbacEscape(rbacT('rbac.empty.assignRoleFirst', '分配角色后即可查看权限明细'))}</span></div>`;
        return;
    }
    box.hidden = false;
    box.innerHTML = `
        <div class="rbac-effective-permissions-head">
            <strong>${rbacEscape(rbacT('rbac.effectivePermissionsDetail', '有效权限明细'))}</strong>
            <button type="button" class="btn-link btn-small" onclick="toggleRbacEffectivePermissions()">${rbacEscape(rbacT('common.close', '关闭'))}</button>
        </div>
        <div class="rbac-effective-permissions-body">
            ${modules.map(module => `
                <section class="rbac-effective-module">
                    <h4>${rbacEscape(rbacPermissionModuleLabel(module))}<span>${access.permissionsByModule[module].length}</span></h4>
                    <div class="rbac-effective-permission-tags">
                        ${access.permissionsByModule[module].sort().map(key => `<span title="${rbacEscape(rbacPermissionLabel(key))}">${rbacEscape(rbacPermissionLabel(key))}</span>`).join('')}
                    </div>
                </section>`).join('')}
        </div>`;
}

function rbacRoleIsSystem(role) {
    return !!(role && (role.isSystem || role.is_system));
}

async function rbacRun(action, fallbackMessage) {
    try {
        await action();
        return true;
    } catch (error) {
        rbacNotify(`${fallbackMessage}: ${error.message || error}`, 'error');
        return false;
    }
}

async function initPlatformRbacPage() {
    if (typeof window !== 'undefined' && window.i18nReady) await window.i18nReady;
    const typeInput = document.getElementById('rbac-assignment-type');
    if (typeInput) rbacState.assignmentResourceType = typeInput.value || 'conversation';
    await rbacRun(loadPlatformRbac, rbacT('rbac.errors.loadFailed', '加载失败'));
    initRbacSelects();
}

function initRbacSelects() {
    if (typeof window.initSettingsCustomSelects !== 'function') return;
    ['page-platform-rbac', 'rbac-user-modal', 'rbac-role-modal'].forEach(id => {
        const root = document.getElementById(id);
        if (root) window.initSettingsCustomSelects(root);
    });
    if (typeof window.refreshSettingsCustomSelects === 'function') {
        window.refreshSettingsCustomSelects();
    }
}

async function refreshRbacAssignments() {
    const res = await apiFetch('/api/rbac/resource-assignments');
    const result = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(result.error || rbacT('rbac.errors.loadDataFailed', '无法加载权限数据'));
    rbacState.assignments = result.assignments || [];
    renderRbacOverview();
    renderRbacUsers();
    renderRbacAssignments();
}

async function refreshRbacUserRoles(userId, roles) {
    const user = rbacState.users.find(item => item.id === userId);
    if (user) user.roles = roles;
    rbacState.pendingRoleUserId = '';
    ensurePendingUserRoles(selectedRbacUser());
    renderRbacOverview();
    renderRbacUsers();
    renderRbacRoles();
}

async function loadPlatformRbac() {
    const responses = await Promise.all([
        apiFetch('/api/rbac/metadata'),
        apiFetch('/api/rbac/users'),
        apiFetch('/api/rbac/roles'),
        apiFetch('/api/rbac/resource-assignments'),
    ]);
    const payloads = await Promise.all(responses.map(response => response.json().catch(() => ({}))));
    const failedIndex = responses.findIndex(response => !response.ok);
    if (failedIndex >= 0) {
        throw new Error(payloads[failedIndex].error || rbacT('rbac.errors.loadDataFailed', '无法加载权限数据'));
    }
    const [meta, users, roles, assignments] = payloads;
    rbacState.permissions = meta.permissions || {};
    rbacState.users = users.users || [];
    rbacState.roles = roles.roles || [];
    rbacState.assignments = assignments.assignments || [];
    if (!rbacState.selectedUserId && rbacState.users.length) {
        rbacState.selectedUserId = rbacState.users[0].id;
    }
    if (rbacState.selectedUserId && !rbacState.users.some(u => u.id === rbacState.selectedUserId)) {
        rbacState.selectedUserId = rbacState.users[0] ? rbacState.users[0].id : '';
    }
    renderRbac();
}

function selectedRbacUser() {
    return rbacState.users.find(u => u.id === rbacState.selectedUserId) || null;
}

function renderRbac() {
    renderRbacOverview();
    renderRbacUsers();
    renderRbacRoles();
    renderRbacAssignments();
    renderRbacRoleCatalog();
    switchRbacView(rbacState.mainView);
}

function switchRbacView(view) {
    rbacState.mainView = view === 'roles' ? 'roles' : 'users';
    document.querySelectorAll('.rbac-workspace-tab').forEach(button => {
        const active = button.dataset.rbacView === rbacState.mainView;
        button.classList.toggle('is-active', active);
        button.setAttribute('aria-selected', String(active));
    });
    const usersView = document.getElementById('rbac-view-users');
    const rolesView = document.getElementById('rbac-view-roles');
    if (usersView) usersView.hidden = rbacState.mainView !== 'users';
    if (rolesView) rolesView.hidden = rbacState.mainView !== 'roles';
}

function renderRbacOverview() {
    const enabled = rbacState.users.filter(user => user.enabled).length;
    const setText = (id, value) => {
        const el = document.getElementById(id);
        if (el) el.textContent = String(value);
    };
    setText('rbac-metric-users', rbacState.users.length);
    setText('rbac-metric-enabled', enabled);
    setText('rbac-metric-roles', rbacState.roles.length);
    setText('rbac-metric-assignments', rbacState.assignments.length);
    const enabledMetric = document.querySelector('.rbac-metric-enabled');
    if (enabledMetric) {
        const allEnabled = rbacState.users.length > 0 && enabled === rbacState.users.length;
        enabledMetric.hidden = allEnabled;
    }
    const user = selectedRbacUser();
    const context = document.getElementById('rbac-metric-context');
    if (context) {
        if (!user) {
            context.hidden = true;
            context.textContent = '';
        } else {
            const access = resolveUserEffectiveAccess(user);
            context.hidden = false;
            context.textContent = rbacT('rbac.metricUserContext', '当前成员：{{name}} · {{roles}} 个角色 · {{grants}} 项授权', {
                name: rbacUserDisplayName(user),
                roles: access.userRoles.length,
                grants: access.assignmentCount,
            });
        }
    }
}

function renderRbacUsers() {
    const list = document.getElementById('rbac-users-list');
    const count = document.getElementById('rbac-users-count');
    if (count) count.textContent = String(rbacState.users.length);
    if (!list) return;
    const keyword = rbacState.userSearch.trim().toLowerCase();
    const users = keyword
        ? rbacState.users.filter(user => `${user.username || ''} ${rbacUserDisplayName(user)}`.toLowerCase().includes(keyword))
        : rbacState.users;
    if (!users.length) {
        list.innerHTML = `<div class="rbac-empty"><strong>${keyword ? rbacT('rbac.empty.noMatchingUsers', '没有匹配的成员') : rbacT('rbac.empty.noUsers', '还没有平台成员')}</strong><span>${keyword ? rbacT('rbac.empty.tryAnotherKeyword', '试试其他关键词') : rbacT('rbac.empty.addFirstUser', '点击右上角“添加成员”开始配置')}</span></div>`;
        return;
    }
    list.innerHTML = users.map(user => {
        const active = user.id === rbacState.selectedUserId ? ' is-active' : '';
        const roleNames = rbacUserRoles(user).map(roleId => {
            const role = rbacState.roles.find(r => r.id === roleId);
            return role ? rbacRoleName(role) : roleId;
        }).join(' / ');
        const assignmentCount = rbacState.assignments.filter(a => (a.userId || a.user_id) === user.id).length;
        const summary = `${roleNames || rbacT('rbac.noRoleAssigned', '未分配角色')} · ${assignmentCount ? rbacT('rbac.resourceCount', '{{count}} 项资源', { count: assignmentCount }) : rbacT('rbac.noExplicitGrant', '无单独授权')}`;
        const handle = `@${user.username}${rbacUserIsBuiltin(user) ? ` · ${rbacT('rbac.builtinAccount', '内置账号')}` : ''}`;
        return `
            <button type="button" class="rbac-user-row${active}" onclick="selectRbacUser('${rbacEscape(user.id)}')" title="${rbacEscape(`${rbacUserDisplayName(user)} (${handle}) — ${summary}`)}">
                <strong class="rbac-user-name">${rbacEscape(rbacUserDisplayName(user))}</strong>
                <span class="rbac-pill ${user.enabled ? 'is-ok' : 'is-muted'}">${user.enabled ? rbacT('rbac.statusEnabled', '启用') : rbacT('rbac.statusDisabled', '停用')}</span>
                <small class="rbac-user-handle">${rbacEscape(handle)}</small>
                <span class="rbac-user-summary">${rbacEscape(summary)}</span>
            </button>`;
    }).join('');
}

function setRbacUserSearch(value) {
    rbacState.userSearch = value || '';
    renderRbacUsers();
}

function selectRbacUser(userId) {
    if (userId !== rbacState.selectedUserId && selectedUserRolesAreDirty() &&
        !confirm(rbacT('rbac.confirmDiscardSwitchUser', '当前角色变更尚未保存，确定放弃并切换成员吗？'))) return;
    rbacState.selectedUserId = userId;
    rbacState.pendingRoleUserId = '';
    rbacState.pendingUserRoles.clear();
    rbacState.selectedResourceIds.clear();
    rbacState.selectedResourceMeta.clear();
    rbacState.resourcePage = 0;
    rbacState.assignmentPage = 0;
    rbacState.showEffectivePermissions = false;
    renderRbac();
    if (rbacState.activeTab === 'assignments') loadRbacResourceOptions();
}

function setRbacRoleSearch(value) {
    rbacState.roleSearch = value || '';
    renderRbacRoleCatalog();
}

function rbacScopeInfo(scope) {
    const meta = rbacScopeMeta[scope] || { tone: '' };
    return {
        tone: meta.tone,
        label: rbacT(`rbac.scopes.${scope}.label`, scope || rbacT('rbac.notConfigured', '未设置')),
        hint: rbacT(`rbac.scopes.${scope}.hint`, ''),
    };
}

function renderRbacRoleCatalog() {
    const box = document.getElementById('rbac-role-catalog');
    if (!box) return;
    const query = rbacState.roleSearch.trim().toLowerCase();
    const roles = rbacState.roles.filter(role => {
        const permissionText = (role.permissions || []).join(' ');
        return !query || `${rbacRoleName(role)} ${rbacRoleDescription(role)} ${permissionText}`.toLowerCase().includes(query);
    });
    if (!roles.length) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.noMatchingRoles', '没有匹配的角色')}</strong><span>${rbacT('rbac.empty.adjustRoleSearch', '调整搜索条件或新建自定义角色')}</span></div>`;
        return;
    }
    box.innerHTML = roles.map(role => {
        const permissions = role.permissions || [];
        const modules = Array.from(new Set(permissions.map(key => key.split(':')[0]))).filter(Boolean);
        const members = rbacState.users.filter(user => rbacUserRoles(user).includes(role.id)).length;
        const scope = rbacScopeInfo(role.scope);
        return `<article class="rbac-catalog-card">
            <div class="rbac-catalog-card-head">
                <div><h4>${rbacEscape(rbacRoleName(role))}</h4><p>${rbacEscape(rbacRoleDescription(role) || rbacT('rbac.noRoleDescription', '暂无角色说明'))}</p></div>
                ${rbacRoleIsSystem(role) ? `<span class="rbac-pill">${rbacT('rbac.systemBuiltin', '系统内置')}</span>` : `<span class="rbac-pill is-custom">${rbacT('rbac.customRole', '自定义')}</span>`}
            </div>
            <div class="rbac-catalog-stats">
                <div><strong>${permissions.length}</strong><span>${rbacT('rbac.operationPermissions', '操作权限')}</span></div>
                <div><strong>${members}</strong><span>${rbacT('rbac.assignedMembers', '已分配成员')}</span></div>
                <div><strong>${rbacEscape(scope.label)}</strong><span>${rbacT('rbac.scope', '资源范围')}</span></div>
            </div>
            <div class="rbac-module-tags">${modules.slice(0, 6).map(module => `<span title="${rbacEscape(module)}">${rbacEscape(rbacPermissionModuleLabel(module))}</span>`).join('')}${modules.length > 6 ? `<span>+${modules.length - 6}</span>` : ''}</div>
            <div class="rbac-catalog-card-foot">
                <span>${rbacEscape(scope.hint)}</span>
                <div>
                    <button type="button" class="btn-secondary btn-small" onclick="openRbacRoleModal('${rbacEscape(role.id)}')">${rbacRoleIsSystem(role) ? rbacT('rbac.viewPermissions', '查看权限') : rbacT('common.edit', '编辑')}</button>
                    ${rbacRoleIsSystem(role) ? '' : `<button type="button" class="btn-secondary btn-small btn-delete" onclick="deleteRbacRole('${rbacEscape(role.id)}')">${rbacT('common.delete', '删除')}</button>`}
                </div>
            </div>
        </article>`;
    }).join('');
}

function renderRbacRoles() {
    const title = document.getElementById('rbac-selected-title');
    const subtitle = document.getElementById('rbac-selected-subtitle');
    const summary = document.getElementById('rbac-selected-summary');
    const editBtn = document.getElementById('rbac-edit-user-btn');
    const deleteBtn = document.getElementById('rbac-delete-user-btn');
    const user = selectedRbacUser();
    ensurePendingUserRoles(user);
    if (title) {
        if (user) {
            const status = user.enabled ? rbacT('rbac.statusEnabled', '启用') : rbacT('rbac.statusDisabled', '停用');
            const displayName = rbacUserDisplayName(user);
            const handle = user.username === displayName ? '' : `@${user.username} · `;
            title.innerHTML = `<span class="rbac-detail-name">${rbacEscape(displayName)}</span><span class="rbac-detail-meta">${rbacEscape(handle)}${rbacEscape(status)}</span>`;
        } else {
            title.textContent = rbacT('rbac.selectUser', '选择用户');
        }
    }
    if (subtitle) {
        subtitle.textContent = user ? '' : rbacT('rbac.selectUserHint', '选择一个平台用户后编辑角色、状态与资源授权。');
        subtitle.hidden = !!user;
    }
    if (editBtn) editBtn.disabled = !user;
    if (deleteBtn) deleteBtn.disabled = !user || rbacUserIsBuiltin(user);
    renderRbacNoRoleNotice(user);
    if (summary) {
        if (!user) {
            summary.innerHTML = '';
        } else {
            const access = resolveUserEffectiveAccess(user);
            const scope = rbacScopeInfo(access.effectiveScope);
            const permissionsToggle = access.effectivePermissions.size
                ? ` <button type="button" class="btn-link btn-small rbac-summary-toggle" onclick="toggleRbacEffectivePermissions()">${rbacEscape(rbacT(rbacState.showEffectivePermissions ? 'rbac.hidePermissions' : 'rbac.viewPermissionsDetail', rbacState.showEffectivePermissions ? '收起明细' : '查看明细'))}</button>`
                : '';
            summary.innerHTML = `
                <div><span>${rbacT('rbac.roles', '角色')}</span><strong>${access.userRoles.length}</strong></div>
                <div class="rbac-summary-permissions"><span>${rbacT('rbac.effectivePermissions', '有效权限')}</span><strong>${access.effectivePermissions.size}</strong>${permissionsToggle}</div>
                <div><span>${rbacT('rbac.effectiveScope', '有效资源范围')}</span><strong title="${rbacEscape(scope.hint)}">${rbacEscape(scope.label)}</strong></div>
                <div><span>${rbacT('rbac.metricAssignments', '资源授权')}</span><strong>${access.assignmentCount}</strong></div>
                `;
        }
    }
    renderRbacEffectivePermissions(user);

    const box = document.getElementById('rbac-roles-list');
    if (!box) return;
    if (!rbacState.roles.length) {
        box.innerHTML = `<div class="empty-state">${rbacT('rbac.empty.noRoles', '暂无角色')}</div>`;
        return;
    }
    const userRoles = user ? rbacState.pendingUserRoles : new Set();
    box.innerHTML = rbacState.roles.map(role => {
        const checked = userRoles.has(role.id);
        const permissionCount = (role.permissions || []).length;
        const assignedUsers = rbacState.users.filter(u => rbacUserRoles(u).includes(role.id)).length;
        const scope = rbacScopeInfo(role.scope);
        return `
            <article class="rbac-role-card${checked ? ' is-selected' : ''}">
                <div class="rbac-role-card-head">
                    <label class="checkbox-label">
                        <input type="checkbox" class="modern-checkbox" ${checked ? 'checked' : ''} ${!user ? 'disabled' : ''} onchange="toggleSelectedUserRole('${rbacEscape(role.id)}', this.checked)">
                        <span class="checkbox-custom"></span>
                        <span class="checkbox-text"><strong>${rbacEscape(rbacRoleName(role))}</strong></span>
                    </label>
                    <span class="rbac-pill ${scope.tone}">${rbacEscape(scope.label)}</span>
                </div>
                <p>${rbacEscape(rbacRoleDescription(role) || rbacT('rbac.noDescription', '无描述'))}</p>
                <div class="rbac-role-card-foot">
                    <span>${rbacT('rbac.permissionCount', '{{count}} 项权限', { count: permissionCount })}</span>
                    <span>${rbacT('rbac.userCount', '{{count}} 个用户', { count: assignedUsers })}</span>
                    <span>${rbacEscape(scope.hint)}</span>
                </div>
            </article>`;
    }).join('');
    syncRbacRoleSaveActions();
}

function ensurePendingUserRoles(user) {
    if (!user) {
        rbacState.pendingRoleUserId = '';
        rbacState.pendingUserRoles.clear();
        return;
    }
    if (rbacState.pendingRoleUserId !== user.id) {
        rbacState.pendingRoleUserId = user.id;
        rbacState.pendingUserRoles = new Set(rbacUserRoles(user));
    }
}

function toggleSelectedUserRole(roleId, enabled) {
    if (!selectedRbacUser()) return;
    if (enabled) rbacState.pendingUserRoles.add(roleId);
    else rbacState.pendingUserRoles.delete(roleId);
    renderRbacRoles();
}

function selectedUserRolesAreDirty() {
    const user = selectedRbacUser();
    if (!user) return false;
    const current = new Set(rbacUserRoles(user));
    return current.size !== rbacState.pendingUserRoles.size ||
        Array.from(current).some(roleId => !rbacState.pendingUserRoles.has(roleId));
}

function syncRbacRoleSaveActions() {
    const dirty = selectedUserRolesAreDirty();
    const indicator = document.getElementById('rbac-role-unsaved');
    const reset = document.getElementById('rbac-role-reset-btn');
    const apply = document.getElementById('rbac-role-apply-btn');
    if (indicator) indicator.hidden = !dirty;
    if (reset) reset.disabled = !dirty;
    if (apply) apply.disabled = !dirty;
}

function resetSelectedUserRoles() {
    const user = selectedRbacUser();
    rbacState.pendingUserRoles = new Set(rbacUserRoles(user));
    renderRbacRoles();
}

async function saveSelectedUserRoles() {
    const user = selectedRbacUser();
    if (!user || !selectedUserRolesAreDirty()) return;
    const roles = Array.from(rbacState.pendingUserRoles);
    const saved = await rbacRun(async () => {
        const res = await apiFetch(`/api/rbac/users/${encodeURIComponent(user.id)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                display_name: user.displayName || user.display_name || '',
                enabled: user.enabled,
                roles,
            }),
        });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.saveFailed', '保存失败'));
        await refreshRbacUserRoles(user.id, roles);
        rbacNotify(rbacT('rbac.messages.roleChangesSaved', '角色变更已保存，权限立即生效'), 'success');
        if (rbacState.activeTab === 'audit') loadRbacUserAuditLogs();
    }, rbacT('rbac.errors.saveFailed', '保存失败'));
    if (!saved) {
        renderRbacRoles();
    }
}

function switchRbacTab(tab) {
    if (tab !== rbacState.activeTab && selectedUserRolesAreDirty() &&
        !confirm(rbacT('rbac.confirmDiscardSwitchTab', '当前角色变更尚未保存，确定放弃并切换标签吗？'))) return;
    if (tab !== rbacState.activeTab && selectedUserRolesAreDirty()) resetSelectedUserRoles();
    rbacState.activeTab = tab;
    document.querySelectorAll('.rbac-tab').forEach(btn => btn.classList.toggle('is-active', btn.dataset.rbacTab === tab));
    const roles = document.getElementById('rbac-tab-roles');
    const assignments = document.getElementById('rbac-tab-assignments');
    const audit = document.getElementById('rbac-tab-audit');
    if (roles) roles.hidden = tab !== 'roles';
    if (assignments) assignments.hidden = tab !== 'assignments';
    if (audit) audit.hidden = tab !== 'audit';
    if (tab === 'assignments') loadRbacResourceOptions();
    if (tab === 'audit') loadRbacUserAuditLogs();
    initRbacSelects();
}

function focusRbacRoleAssignment() {
    switchRbacTab('roles');
    requestAnimationFrame(() => {
        const panel = document.getElementById('rbac-tab-roles');
        const list = document.getElementById('rbac-roles-list');
        const section = panel?.querySelector('.rbac-section-toolbar') || list;
        if (panel) panel.scrollTop = 0;
        if (section) section.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        const highlight = list || panel;
        if (highlight) {
            highlight.classList.remove('rbac-focus-pulse');
            void highlight.offsetWidth;
            highlight.classList.add('rbac-focus-pulse');
            highlight.addEventListener('animationend', () => highlight.classList.remove('rbac-focus-pulse'), { once: true });
        }
        const firstCheckbox = list?.querySelector('input[type="checkbox"]:not(:disabled)');
        if (firstCheckbox) firstCheckbox.focus({ preventScroll: true });
    });
}

function renderRbacAssignments() {
    const box = document.getElementById('rbac-assignments-list');
    if (!box) return;
    const user = selectedRbacUser();
    const rows = user ? rbacState.assignments.filter(a => a.userId === user.id || a.user_id === user.id) : [];
    const count = document.getElementById('rbac-current-assignment-count');
    if (count) count.textContent = String(rows.length);
    if (!user) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.selectUserFirst', '请先选择用户')}</strong></div>`;
        renderRbacAssignmentPagination(0, 1);
        renderRbacPendingSelection();
        return;
    }
    if (!rows.length) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.noAssignments', '暂无资源授权')}</strong><span>${rbacT('rbac.empty.addAssignmentHint', '在左侧勾选资源，或使用上方「确认授权」按钮')}</span></div>`;
        renderRbacAssignmentPagination(0, 1);
        renderRbacPendingSelection();
        return;
    }
    const query = rbacState.assignmentSearch.trim().toLowerCase();
    const filteredRows = rows.filter(row => {
        const type = row.resourceType || row.resource_type || '';
        const id = row.resourceId || row.resource_id || '';
        const label = row.resourceLabel || row.resource_label || '';
        const detail = row.resourceDetail || row.resource_detail || '';
        return (rbacState.assignmentType === 'all' || type === rbacState.assignmentType) &&
            (!query || `${rbacResourceLabel(type)} ${type} ${label} ${detail} ${id}`.toLowerCase().includes(query));
    });
    const totalPages = Math.max(1, Math.ceil(filteredRows.length / rbacState.assignmentPageSize));
    rbacState.assignmentPage = Math.min(rbacState.assignmentPage, totalPages - 1);
    const start = rbacState.assignmentPage * rbacState.assignmentPageSize;
    const visibleRows = filteredRows.slice(start, start + rbacState.assignmentPageSize);
    if (!filteredRows.length) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.noMatchingAssignments', '没有匹配的授权')}</strong><span>${rbacT('rbac.empty.adjustAssignmentFilter', '调整资源类型或搜索条件')}</span></div>`;
        renderRbacAssignmentPagination(0, 1);
        renderRbacPendingSelection();
        return;
    }
    box.innerHTML = visibleRows.map(row => {
        const type = row.resourceType || row.resource_type;
        const id = row.resourceId || row.resource_id;
        const label = row.resourceLabel || row.resource_label || id;
        const detail = rbacFormatResourceDetail(type, row.resourceDetail || row.resource_detail || '');
        return `
            <div class="rbac-assignment-row">
                <span class="rbac-assignment-resource">
                    <span class="rbac-pill is-info">${rbacEscape(rbacResourceLabel(type))}</span>
                    <span class="rbac-assignment-resource-main">
                        <strong>${rbacEscape(label)}</strong>
                        <span class="rbac-assignment-resource-meta">
                            <code title="${rbacEscape(id)}">${rbacEscape(rbacShortId(id))}</code>
                            ${detail ? `<span>${rbacEscape(detail)}</span>` : ''}
                            <button type="button" class="btn-link btn-small" onclick="rbacCopyResourceId('${rbacEscape(id)}')">${rbacEscape(rbacT('rbac.copyId', '复制 ID'))}</button>
                        </span>
                    </span>
                </span>
                <button type="button" class="btn-secondary btn-small" onclick="deleteRbacAssignment('${rbacEscape(row.id)}')">${rbacT('rbac.revoke', '撤销')}</button>
            </div>`;
    }).join('');
    renderRbacAssignmentPagination(filteredRows.length, totalPages);
    renderRbacPendingSelection();
}

function renderRbacAssignmentPagination(total, totalPages) {
    const pagination = document.getElementById('rbac-assignment-pagination');
    if (!pagination) return;
    const pages = Math.max(1, totalPages || 1);
    rbacState.assignmentPage = Math.min(rbacState.assignmentPage, pages - 1);
    const info = pagination.querySelector('[data-rbac-page-info]');
    const previous = pagination.querySelector('[data-rbac-page-previous]');
    const next = pagination.querySelector('[data-rbac-page-next]');
    if (info) {
        info.textContent = total
            ? rbacT('rbac.pagination.pageSummary', '第 {{page}} / {{pages}} 页 · 共 {{total}} 项', {
                page: rbacState.assignmentPage + 1,
                pages,
                total,
            })
            : rbacT('rbac.pagination.emptySummary', '共 0 项');
    }
    if (previous) previous.disabled = total === 0 || rbacState.assignmentPage === 0;
    if (next) next.disabled = total === 0 || rbacState.assignmentPage >= pages - 1;
}

function filterRbacAssignments(value) {
    rbacState.assignmentSearch = value || '';
    rbacState.assignmentPage = 0;
    renderRbacAssignments();
}

function changeRbacAssignmentFilter(value) {
    rbacState.assignmentType = value || 'all';
    rbacState.assignmentPage = 0;
    renderRbacAssignments();
}

function changeRbacAssignmentPage(delta) {
    rbacState.assignmentPage = Math.max(0, rbacState.assignmentPage + delta);
    renderRbacAssignments();
}

function changeRbacResourceType() {
    const typeInput = document.getElementById('rbac-assignment-type');
    if (!typeInput) return;
    const nextType = typeInput.value;
    const previousType = rbacState.assignmentResourceType || 'conversation';
    if (nextType === previousType) return;
    if (rbacState.selectedResourceIds.size > 0 &&
        !confirm(rbacT('rbac.confirmDiscardResourceType', '切换资源类型将清空当前选择，确定继续吗？'))) {
        typeInput.value = previousType;
        initRbacSelects();
        return;
    }
    rbacState.assignmentResourceType = nextType;
    rbacState.selectedResourceIds.clear();
    rbacState.selectedResourceMeta.clear();
    rbacState.resourcePage = 0;
    const search = document.getElementById('rbac-resource-search');
    if (search) search.value = '';
    syncRbacAssignmentSubmit();
    loadRbacResourceOptions();
}

function queueRbacResourceSearch() {
    clearTimeout(rbacState.resourceSearchTimer);
    rbacState.resourcePage = 0;
    rbacState.resourceSearchTimer = setTimeout(loadRbacResourceOptions, 250);
}

async function loadRbacResourceOptions() {
    const picker = document.getElementById('rbac-resource-picker');
    const typeInput = document.getElementById('rbac-assignment-type');
    if (!picker || !typeInput || !selectedRbacUser()) return;
    const requestSeq = ++rbacState.resourceRequestSeq;
    const query = document.getElementById('rbac-resource-search')?.value.trim() || '';
    picker.innerHTML = `<div class="rbac-picker-status">${rbacT('rbac.loadingResources', '正在加载真实资源…')}</div>`;
    syncRbacResourcePagination(true);
    try {
        const offset = rbacState.resourcePage * rbacState.resourcePageSize;
        const res = await apiFetch(`/api/rbac/resources?type=${encodeURIComponent(typeInput.value)}&q=${encodeURIComponent(query)}&limit=${rbacState.resourcePageSize}&offset=${offset}`);
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.error || rbacT('rbac.errors.loadResourcesFailed', '加载资源失败'));
        if (requestSeq !== rbacState.resourceRequestSeq) return;
        rbacState.resourceOptions = result.resources || [];
        rbacState.resourceHasMore = !!result.has_more;
        renderRbacResourcePicker();
    } catch (error) {
        if (requestSeq !== rbacState.resourceRequestSeq) return;
        rbacState.resourceHasMore = false;
        picker.innerHTML = `<div class="rbac-picker-status is-error">${rbacEscape(error.message || rbacT('rbac.errors.loadResourcesFailed', '加载资源失败'))} <button type="button" class="btn-link" onclick="loadRbacResourceOptions()">${rbacT('rbac.retry', '重试')}</button></div>`;
        syncRbacResourcePagination(false);
    }
}

function renderRbacResourcePicker() {
    const picker = document.getElementById('rbac-resource-picker');
    if (!picker) return;
    const user = selectedRbacUser();
    const resourceType = document.getElementById('rbac-assignment-type')?.value || '';
    const assigned = new Set(rbacState.assignments
        .filter(row => (row.userId === user?.id || row.user_id === user?.id) && (row.resourceType || row.resource_type) === resourceType)
        .map(row => row.resourceId || row.resource_id));
    if (!rbacState.resourceOptions.length) {
        picker.innerHTML = `<div class="rbac-picker-status">${rbacT('rbac.empty.noMatchingResources', '没有匹配的真实资源')}</div>`;
        syncRbacResourcePagination(false);
        return;
    }
    picker.innerHTML = rbacState.resourceOptions.map(resource => {
        const alreadyAssigned = assigned.has(resource.id);
        const checked = rbacState.selectedResourceIds.has(resource.id);
        const detail = rbacFormatResourceDetail(resourceType, resource.detail || '');
        return `<label class="rbac-resource-option${alreadyAssigned ? ' is-assigned' : ''}">
            <input type="checkbox" class="modern-checkbox" value="${rbacEscape(resource.id)}" ${checked ? 'checked' : ''} ${alreadyAssigned ? 'disabled' : ''} onchange="toggleRbacResourceSelection(this.value, this.checked)">
            <span class="checkbox-custom"></span>
            <span class="rbac-resource-option-main">
                <strong title="${rbacEscape(resource.label || resource.id)}">${rbacEscape(resource.label || resource.id)}</strong>
                <small>
                    <code title="${rbacEscape(resource.id)}">${rbacEscape(rbacShortId(resource.id))}</code>
                    <button type="button" class="btn-link btn-small" onclick="event.preventDefault(); rbacCopyResourceId('${rbacEscape(resource.id)}')">${rbacEscape(rbacT('rbac.copyId', '复制 ID'))}</button>
                </small>
            </span>
            <span class="rbac-resource-option-detail">${alreadyAssigned ? rbacT('rbac.alreadyAssigned', '已授权') : rbacEscape(detail)}</span>
        </label>`;
    }).join('');
    syncRbacResourcePagination(false);
}

function syncRbacResourcePagination(loading) {
    const pagination = document.getElementById('rbac-resource-pagination');
    if (!pagination) return;
    const previous = pagination.querySelector('[data-rbac-page-previous]');
    const next = pagination.querySelector('[data-rbac-page-next]');
    const info = pagination.querySelector('[data-rbac-page-info]');
    if (previous) previous.disabled = loading || rbacState.resourcePage === 0;
    if (next) next.disabled = loading || !rbacState.resourceHasMore;
    if (info) info.textContent = rbacT('rbac.pagination.resourcePage', '第 {{page}} 页', { page: rbacState.resourcePage + 1 });
}

function changeRbacResourcePage(delta) {
    const nextPage = rbacState.resourcePage + delta;
    if (nextPage < 0 || (delta > 0 && !rbacState.resourceHasMore)) return;
    rbacState.resourcePage = nextPage;
    loadRbacResourceOptions();
}

function toggleRbacResourceSelection(resourceId, checked) {
    if (checked) {
        rbacState.selectedResourceIds.add(resourceId);
        const resource = rbacState.resourceOptions.find(item => item.id === resourceId);
        rbacRememberSelectedResource(resource || { id: resourceId, label: resourceId, detail: '' });
    } else {
        rbacState.selectedResourceIds.delete(resourceId);
        rbacState.selectedResourceMeta.delete(resourceId);
        if (rbacState.resourceOptions.length) renderRbacResourcePicker();
    }
    syncRbacAssignmentSubmit();
}

function syncRbacAssignmentSubmit() {
    renderRbacPendingSelection();
}

function rbacAuditActionLabel(log) {
    const action = log && log.action ? String(log.action) : '';
    const key = `rbac.auditActions.${action}`;
    const translated = rbacT(key, '');
    return translated || (log && log.message) || action;
}

async function loadRbacUserAuditLogs() {
    const box = document.getElementById('rbac-audit-list');
    const user = selectedRbacUser();
    if (!box) return;
    if (!user) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.selectUserFirst', '请先选择用户')}</strong></div>`;
        return;
    }
    rbacState.auditLoading = true;
    box.innerHTML = `<div class="rbac-picker-status">${rbacT('common.loading', '加载中…')}</div>`;
    try {
        const params = new URLSearchParams({
            category: 'rbac',
            q: user.id,
            page: '1',
            page_size: '20',
        });
        const res = await apiFetch(`/api/audit/logs?${params.toString()}`);
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.error || rbacT('rbac.errors.loadAuditFailed', '加载审计记录失败'));
        rbacState.auditLogs = (result.logs || []).filter(log => {
            const resourceId = log.resourceId || log.resource_id || '';
            const detail = log.detail || {};
            const detailUserId = detail.user_id || detail.userId || '';
            return resourceId === user.id || detailUserId === user.id || String(log.message || '').includes(user.username || '');
        });
        renderRbacAuditLogs();
    } catch (error) {
        box.innerHTML = `<div class="rbac-picker-status is-error">${rbacEscape(error.message || rbacT('rbac.errors.loadAuditFailed', '加载审计记录失败'))} <button type="button" class="btn-link" onclick="loadRbacUserAuditLogs()">${rbacT('rbac.retry', '重试')}</button></div>`;
    } finally {
        rbacState.auditLoading = false;
    }
}

function renderRbacAuditLogs() {
    const box = document.getElementById('rbac-audit-list');
    if (!box) return;
    if (!rbacState.auditLogs.length) {
        box.innerHTML = `<div class="rbac-empty"><strong>${rbacT('rbac.empty.noAuditLogs', '暂无变更记录')}</strong><span>${rbacT('rbac.empty.noAuditLogsHint', '该成员的角色与授权变更会显示在这里')}</span></div>`;
        return;
    }
    const formatTime = typeof formatAuditTime === 'function'
        ? formatAuditTime
        : (iso) => rbacText(iso);
    box.innerHTML = rbacState.auditLogs.map(log => `
        <article class="rbac-audit-row">
            <strong class="rbac-audit-action">${rbacEscape(rbacAuditActionLabel(log))}</strong>
            <span class="rbac-pill rbac-audit-actor">${rbacEscape(log.actor || rbacT('rbac.unknownActor', '未知操作者'))}</span>
            ${log.resourceType || log.resource_type ? `<span class="rbac-audit-detail">${rbacEscape(rbacResourceLabel(log.resourceType || log.resource_type))}</span>` : ''}
            ${log.resourceId || log.resource_id ? `<code class="rbac-audit-detail" title="${rbacEscape(log.resourceId || log.resource_id)}">${rbacEscape(rbacShortId(log.resourceId || log.resource_id))}</code>` : ''}
            <span class="rbac-audit-time">${rbacEscape(formatTime(log.createdAt || log.created_at))}</span>
        </article>`).join('');
}

function openRbacUserModal(userId = '') {
    const user = userId ? rbacState.users.find(u => u.id === userId) : null;
    document.getElementById('rbac-user-id').value = user ? user.id : '';
    document.getElementById('rbac-username').value = user ? user.username : '';
    document.getElementById('rbac-username').disabled = !!user;
    document.getElementById('rbac-display-name').value = user ? (user.displayName || user.display_name || '') : '';
    document.getElementById('rbac-password').value = '';
    document.getElementById('rbac-user-enabled').checked = user ? !!user.enabled : true;
    const createRoles = document.getElementById('rbac-user-roles-create-section');
    const editRoles = document.getElementById('rbac-user-roles-edit-section');
    if (createRoles) createRoles.hidden = !!user;
    if (editRoles) editRoles.hidden = !user;
    if (user) renderRbacUserRolesReadonly(user);
    else renderRbacUserRoleCheckboxes(new Set());
    initRbacSelects();
    openAppModal('rbac-user-modal');
}

function renderRbacUserRolesReadonly(user) {
    const box = document.getElementById('rbac-user-roles-readonly');
    if (!box) return;
    const roles = rbacUserRoles(user).map(roleId => rbacState.roles.find(role => role.id === roleId)).filter(Boolean);
    if (!roles.length) {
        box.innerHTML = `<div class="rbac-empty is-compact"><strong>${rbacT('rbac.noRoleAssigned', '未分配角色')}</strong></div>`;
        return;
    }
    box.innerHTML = roles.map(role => {
        const scope = rbacScopeInfo(role.scope);
        return `<div class="rbac-readonly-role"><strong>${rbacEscape(rbacRoleName(role))}</strong><span>${rbacEscape(scope.label)}</span></div>`;
    }).join('');
}

function openRbacRolesFromUserModal() {
    closeRbacUserModal();
    focusRbacRoleAssignment();
}

function openRbacUserModalForSelected() {
    const user = selectedRbacUser();
    if (!user) return;
    if (selectedUserRolesAreDirty() && !confirm(rbacT('rbac.confirmDiscardEditUser', '当前角色变更尚未保存，确定放弃并编辑成员资料吗？'))) return;
    if (selectedUserRolesAreDirty()) resetSelectedUserRoles();
    openRbacUserModal(user.id);
}

function closeRbacUserModal() {
    closeAppModal('rbac-user-modal');
}

function renderRbacUserRoleCheckboxes(selected) {
    const box = document.getElementById('rbac-user-role-checkboxes');
    if (!box) return;
    box.innerHTML = rbacState.roles.map(role => {
        const scope = rbacScopeInfo(role.scope);
        return `
        <label class="checkbox-label rbac-checkbox-item">
            <input type="checkbox" class="modern-checkbox" value="${rbacEscape(role.id)}" ${selected.has(role.id) ? 'checked' : ''}>
            <span class="checkbox-custom"></span>
            <span class="checkbox-text rbac-role-option-text"><strong>${rbacEscape(rbacRoleName(role))}</strong><small>${rbacEscape(scope.label)} · ${rbacEscape(rbacRoleDescription(role) || rbacT('rbac.noDescription', '无描述'))}</small></span>
        </label>`;
    }).join('');
}

async function saveRbacUser() {
    await rbacRun(async () => {
        const id = document.getElementById('rbac-user-id').value;
        const isEdit = !!id;
        const payload = {
            display_name: document.getElementById('rbac-display-name').value.trim(),
            password: document.getElementById('rbac-password').value,
            enabled: document.getElementById('rbac-user-enabled').checked,
        };
        if (!isEdit) {
            payload.roles = Array.from(document.querySelectorAll('#rbac-user-role-checkboxes input:checked')).map(el => el.value);
            payload.username = document.getElementById('rbac-username').value.trim();
        }
        let url = '/api/rbac/users';
        let method = 'POST';
        if (isEdit) {
            url += '/' + encodeURIComponent(id);
            method = 'PUT';
            if (!payload.password) delete payload.password;
        }
        const res = await apiFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.saveFailed', '保存失败'));
        closeRbacUserModal();
        await loadPlatformRbac();
        if (isEdit && rbacState.activeTab === 'audit') loadRbacUserAuditLogs();
    }, rbacT('rbac.errors.saveUserFailed', '保存用户失败'));
}

async function deleteSelectedRbacUser() {
    await rbacRun(async () => {
        const user = selectedRbacUser();
        if (!user) return;
        if (rbacUserIsBuiltin(user)) {
            rbacNotify(rbacT('rbac.deleteBuiltinUser', '内置管理员不能删除'), 'error');
            return;
        }
        const access = resolveUserEffectiveAccess(user);
        const confirmMessage = rbacT('rbac.deleteUserConfirmDetailed', '确认删除成员 {{name}}（@{{username}}）？\n\n将立即吊销其会话，并清除 {{roles}} 个角色绑定与 {{grants}} 项资源授权。', {
            name: rbacUserDisplayName(user),
            username: user.username,
            roles: access.userRoles.length,
            grants: access.assignmentCount,
        });
        if (!confirm(confirmMessage)) return;
        const res = await apiFetch(`/api/rbac/users/${encodeURIComponent(user.id)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.deleteFailed', '删除失败'));
        rbacState.selectedUserId = '';
        await loadPlatformRbac();
    }, rbacT('rbac.errors.deleteUserFailed', '删除用户失败'));
}

function openRbacRoleModal(roleId = '') {
    const role = roleId ? rbacState.roles.find(r => r.id === roleId) : null;
    document.getElementById('rbac-role-id').value = role ? role.id : '';
    document.getElementById('rbac-role-name').value = role ? rbacRoleName(role) : '';
    document.getElementById('rbac-role-description').value = role ? rbacRoleDescription(role) : '';
    document.getElementById('rbac-role-scope').value = role ? role.scope : 'assigned';
    rbacState.editingRoleIsSystem = rbacRoleIsSystem(role);
    ['rbac-role-name', 'rbac-role-description', 'rbac-role-scope'].forEach(id => {
        const field = document.getElementById(id);
        if (field) field.disabled = rbacState.editingRoleIsSystem;
    });
    const saveButton = document.getElementById('rbac-role-save-btn');
    if (saveButton) saveButton.hidden = rbacState.editingRoleIsSystem;
    document.querySelectorAll('.rbac-permission-tools button').forEach(button => {
        button.disabled = rbacState.editingRoleIsSystem;
    });
    const title = document.getElementById('rbac-role-modal-title');
    if (title) title.textContent = rbacState.editingRoleIsSystem
        ? rbacT('rbac.viewSystemRole', '查看系统角色')
        : (role ? rbacT('rbac.editRole', '编辑角色') : rbacT('rbac.createRole', '新建角色'));
    const search = document.getElementById('rbac-permission-search');
    if (search) search.value = '';
    rbacState.permissionSearch = '';
    rbacState.rolePermissionSelection = new Set((role && role.permissions) || []);
    renderRbacPermissionCheckboxes();
    initRbacSelects();
    openAppModal('rbac-role-modal');
}

function closeRbacRoleModal() {
    closeAppModal('rbac-role-modal');
}

function renderRbacPermissionCheckboxes() {
    const box = document.getElementById('rbac-permission-checkboxes');
    if (!box) return;
    const grouped = {};
    const query = rbacState.permissionSearch.trim().toLowerCase();
    Object.keys(rbacState.permissions).sort().forEach(key => {
        const desc = rbacPermissionLabel(key);
        if (query && !`${key} ${desc}`.toLowerCase().includes(query)) return;
        const module = key.split(':')[0] || 'other';
        if (!grouped[module]) grouped[module] = [];
        grouped[module].push(key);
    });
    if (!Object.keys(grouped).length) {
        box.innerHTML = `<div class="empty-state">${rbacT('rbac.empty.noMatchingPermissions', '没有匹配的权限')}</div>`;
        return;
    }
    box.innerHTML = Object.keys(grouped).sort().map(module => `
        <section class="rbac-permission-group">
            <div class="rbac-permission-group-head">
                <h4>${rbacEscape(rbacPermissionModuleLabel(module))}<small>${rbacEscape(module)}</small></h4>
                <span>${grouped[module].length}</span>
            </div>
            <div class="rbac-checkbox-grid">
                ${grouped[module].map(key => `
                    <label class="checkbox-label rbac-checkbox-item" title="${rbacEscape(rbacPermissionLabel(key))}">
                        <input type="checkbox" class="modern-checkbox" value="${rbacEscape(key)}" ${rbacState.rolePermissionSelection.has(key) ? 'checked' : ''} ${rbacState.editingRoleIsSystem ? 'disabled' : ''} onchange="setRbacPermissionSelected('${rbacEscape(key)}', this.checked)">
                        <span class="checkbox-custom"></span>
                        <span class="checkbox-text rbac-permission-option"><strong>${rbacEscape(rbacPermissionLabel(key))}</strong><code>${rbacEscape(key)}</code></span>
                    </label>`).join('')}
            </div>
        </section>`).join('');
}

function setRbacPermissionSelected(key, checked) {
    if (checked) rbacState.rolePermissionSelection.add(key);
    else rbacState.rolePermissionSelection.delete(key);
}

function filterRbacPermissions(value) {
    rbacState.permissionSearch = value || '';
    renderRbacPermissionCheckboxes();
}

function selectVisibleRbacPermissions(checked) {
    document.querySelectorAll('#rbac-permission-checkboxes input[type="checkbox"]').forEach(input => {
        input.checked = checked;
        setRbacPermissionSelected(input.value, checked);
    });
}

async function saveRbacRole() {
    await rbacRun(async () => {
        const id = document.getElementById('rbac-role-id').value;
        const payload = {
            name: document.getElementById('rbac-role-name').value.trim(),
            description: document.getElementById('rbac-role-description').value.trim(),
            scope: document.getElementById('rbac-role-scope').value,
            permissions: Array.from(rbacState.rolePermissionSelection),
        };
        const url = id ? `/api/rbac/roles/${encodeURIComponent(id)}` : '/api/rbac/roles';
        const res = await apiFetch(url, {
            method: id ? 'PUT' : 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.saveFailed', '保存失败'));
        closeRbacRoleModal();
        await loadPlatformRbac();
    }, rbacT('rbac.errors.saveRoleFailed', '保存角色失败'));
}

async function deleteRbacRole(roleId) {
    await rbacRun(async () => {
        if (!confirm(rbacT('rbac.deleteRoleConfirm', '确认删除该平台角色？'))) return;
        const res = await apiFetch(`/api/rbac/roles/${encodeURIComponent(roleId)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.deleteFailed', '删除失败'));
        await loadPlatformRbac();
    }, rbacT('rbac.errors.deleteRoleFailed', '删除角色失败'));
}

async function createRbacAssignment() {
    await rbacRun(async () => {
        const user = selectedRbacUser();
        if (!user) return;
        const resourceType = document.getElementById('rbac-assignment-type').value;
        const manualIds = document.getElementById('rbac-assignment-id').value.split(/[\s,，;；]+/).map(id => id.trim()).filter(Boolean);
        const resourceIds = Array.from(new Set([...rbacState.selectedResourceIds, ...manualIds]));
        if (!resourceIds.length) {
            rbacNotify(rbacT('rbac.errors.enterResourceId', '请输入至少一个资源 ID'), 'error');
            return;
        }
        if (resourceIds.length > 100) {
            rbacNotify(rbacT('rbac.errors.tooManyResources', '一次最多授权 100 个资源'), 'error');
            return;
        }
        const res = await apiFetch('/api/rbac/resource-assignments', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: user.id, resource_type: resourceType, resource_ids: resourceIds }),
        });
        const result = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(result.error || rbacT('rbac.errors.batchGrantFailed', '批量授权失败'));
        document.getElementById('rbac-assignment-id').value = '';
        rbacState.selectedResourceIds.clear();
        rbacState.selectedResourceMeta.clear();
        await refreshRbacAssignments();
        await loadRbacResourceOptions();
        syncRbacAssignmentSubmit();
        if (rbacState.activeTab === 'audit') loadRbacUserAuditLogs();
        const created = Number(result.created || 0);
        const skipped = Number(result.skipped || 0);
        rbacNotify(skipped
            ? rbacT('rbac.messages.grantPartial', '新增 {{created}} 项授权，{{skipped}} 项已存在或重复', { created, skipped })
            : rbacT('rbac.messages.grantSuccess', '已授权 {{count}} 项{{resource}}', { count: created, resource: rbacResourceLabel(resourceType) }), 'success');
    }, rbacT('rbac.errors.grantFailed', '授权失败'));
}

async function deleteRbacAssignment(id) {
    await rbacRun(async () => {
        const res = await apiFetch(`/api/rbac/resource-assignments/${encodeURIComponent(id)}`, { method: 'DELETE' });
        if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || rbacT('rbac.errors.revokeFailed', '撤销失败'));
        await refreshRbacAssignments();
        if (rbacState.activeTab === 'assignments') await loadRbacResourceOptions();
        if (rbacState.activeTab === 'audit') loadRbacUserAuditLogs();
    }, rbacT('rbac.errors.revokeFailed', '撤销失败'));
}

document.addEventListener('languagechange', () => {
    renderRbac();
    if (rbacState.resourceOptions.length) renderRbacResourcePicker();
    renderRbacPermissionCheckboxes();
    renderRbacEffectivePermissions(selectedRbacUser());
    if (rbacState.auditLogs.length) renderRbacAuditLogs();
    initRbacSelects();
    const roleId = document.getElementById('rbac-role-id')?.value;
    const role = roleId ? rbacState.roles.find(item => item.id === roleId) : null;
    if (role && rbacRoleIsSystem(role)) {
        const name = document.getElementById('rbac-role-name');
        const description = document.getElementById('rbac-role-description');
        const title = document.getElementById('rbac-role-modal-title');
        if (name) name.value = rbacRoleName(role);
        if (description) description.value = rbacRoleDescription(role);
        if (title) title.textContent = rbacT('rbac.viewSystemRole', '查看系统角色');
    }
});

window.openRbacRolesFromUserModal = openRbacRolesFromUserModal;
window.focusRbacRoleAssignment = focusRbacRoleAssignment;
window.toggleRbacEffectivePermissions = toggleRbacEffectivePermissions;
window.loadRbacUserAuditLogs = loadRbacUserAuditLogs;
window.clearRbacResourceSelection = clearRbacResourceSelection;
window.rbacCopyResourceId = rbacCopyResourceId;
window.initPlatformRbacPage = initPlatformRbacPage;
window.initRbacSelects = initRbacSelects;
window.loadPlatformRbac = loadPlatformRbac;
window.selectRbacUser = selectRbacUser;
window.switchRbacView = switchRbacView;
window.setRbacRoleSearch = setRbacRoleSearch;
window.setRbacUserSearch = setRbacUserSearch;
window.switchRbacTab = switchRbacTab;
window.openRbacUserModal = openRbacUserModal;
window.openRbacUserModalForSelected = openRbacUserModalForSelected;
window.closeRbacUserModal = closeRbacUserModal;
window.saveRbacUser = saveRbacUser;
window.deleteSelectedRbacUser = deleteSelectedRbacUser;
window.openRbacRoleModal = openRbacRoleModal;
window.closeRbacRoleModal = closeRbacRoleModal;
window.saveRbacRole = saveRbacRole;
window.deleteRbacRole = deleteRbacRole;
window.filterRbacPermissions = filterRbacPermissions;
window.selectVisibleRbacPermissions = selectVisibleRbacPermissions;
window.setRbacPermissionSelected = setRbacPermissionSelected;
window.createRbacAssignment = createRbacAssignment;
window.deleteRbacAssignment = deleteRbacAssignment;
window.changeRbacResourceType = changeRbacResourceType;
window.queueRbacResourceSearch = queueRbacResourceSearch;
window.loadRbacResourceOptions = loadRbacResourceOptions;
window.toggleRbacResourceSelection = toggleRbacResourceSelection;
window.changeRbacResourcePage = changeRbacResourcePage;
window.filterRbacAssignments = filterRbacAssignments;
window.changeRbacAssignmentFilter = changeRbacAssignmentFilter;
window.changeRbacAssignmentPage = changeRbacAssignmentPage;
window.syncRbacAssignmentSubmit = syncRbacAssignmentSubmit;
window.resetSelectedUserRoles = resetSelectedUserRoles;
window.saveSelectedUserRoles = saveSelectedUserRoles;
