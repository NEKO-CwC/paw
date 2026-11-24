'use strict';

const byId = id => document.getElementById(id);
const status = byId('status');
const match = /^\/assist\/([A-Za-z0-9_-]{32})$/.exec(location.pathname);
const token = match?.[1];

function launcher(url) {
    return "& { try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; " +
        "$r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 45 -Uri '" + url +
        "'; $s = $r.Content; if ($s -is [byte[]]) { $s = [Text.Encoding]::UTF8.GetString($s) }; " +
        "& ([ScriptBlock]::Create([string]$s)) } catch { Write-Warning $_.Exception.Message } }";
}

function installCommand(url) {
    return launcher(location.origin + '/session/' + new URL(url).pathname.split('/').pop() + '/bootstrap.ps1');
}

async function copy(value, note) {
    try {
        await navigator.clipboard.writeText(value);
        note.textContent = '已复制。';
    } catch {
        note.textContent = value;
    }
}

function showWindow(window) {
    status.textContent = window.active
        ? (window.connected ? 'Windows 已连接。' : '窗口已开启，等待 Windows 接入。') +
            ' 截止到 ' + new Date(window.until).toLocaleString('zh-CN')
        : '接入窗口已关闭。';
}

async function request(path, options = {}) {
    const response = await fetch(path, {cache:'no-store', ...options});
    if (response.status === 204) return {};
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || '请求失败');
    return data;
}

async function assistPage() {
    byId('assist').hidden = false;
    const feedback = byId('assist-feedback');
    try {
        const session = await request('/session/' + token + '/lease');
        showWindow({active: true, until:session.until});
        const command = installCommand(location.href);
        const setup = byId('start-command');
        setup.textContent = command;
        setup.hidden = false;
        byId('copy-start').disabled = false;
        byId('copy-start').onclick = () => copy(command, feedback);
        byId('copy-cleanup').disabled = false;
        byId('copy-cleanup').onclick = () => copy(launcher(location.origin + '/cleanup/' + session.id), feedback);
    } catch (error) {
        status.textContent = error.message;
    }
}

function adminPage() {
    byId('admin').hidden = false;
    const login = byId('login');
    const controls = byId('controls');
    const feedback = byId('feedback');
    const duration = byId('minutes');
    const proxyForm = byId('proxy');
    let credentials = '';
    let current = {};
    let busy = false;

    function buttons() {
        byId('login-button').disabled = busy;
        byId('open').disabled = busy || current.active;
        byId('extend').disabled = busy || !current.active;
        byId('close').disabled = busy || !current.active;
        byId('save-proxy').disabled = busy;
    }

    function render(window) {
        current = window;
        showWindow(window);
        byId('session-details').hidden = !window.url;
        if (window.url) {
            byId('open-link').href = window.url;
            byId('ssh').textContent = window.sshCommand + '\n密码 ' + window.password +
                (window.fingerprint ? '\n主机指纹 ' + window.fingerprint + '\nknown_hosts ' + window.knownHost : '');
        } else {
            byId('open-link').removeAttribute('href');
            byId('ssh').textContent = '';
        }
        buttons();
    }

    function authenticated(body) {
        const headers = {Authorization: credentials};
        if (!body) return request('/api/admin', {headers});
        headers['Content-Type'] = 'application/json';
        return request('/api/admin', {method:'POST', headers, body:JSON.stringify(body)});
    }

    function renderProxy(proxy, passwordStored) {
        const fields = proxyForm.elements;
        fields.host.value = proxy.host || '';
        fields.port.value = proxy.port || 22;
        fields.user.value = proxy.user || '';
        fields.hostKey.value = proxy.hostKey || '';
        fields.password.placeholder = passwordStored ? '已保存，留空沿用' : '';
    }

    login.onsubmit = async event => {
        event.preventDefault();
        if (busy) return;
        busy = true;
        buttons();
        feedback.textContent = '正在验证管理员密码…';
        let password = byId('password').value;
        byId('password').value = '';
        try {
            credentials = 'Basic ' + btoa(String.fromCharCode(...new TextEncoder().encode('admin:' + password)));
            password = '';
            const data = await authenticated();
            login.hidden = true;
            controls.hidden = false;
            renderProxy(data.proxy, data.hasProxyPassword);
            render(data.window);
            feedback.textContent = '已登录。';
        } catch (error) {
            credentials = '';
            feedback.textContent = error.message;
        } finally {
            busy = false;
            buttons();
        }
    };

    async function mutate(action, waiting, success) {
        if (busy) return;
        busy = true;
        buttons();
        feedback.textContent = waiting;
        try {
            render(await authenticated(action));
            feedback.textContent = success;
        } catch (error) {
            feedback.textContent = error.message;
        } finally {
            busy = false;
            buttons();
        }
    }

    function changeWindow(action, pending, done) {
        if (action !== 'close' && !duration.reportValidity()) return;
        return mutate({action, minutes:duration.valueAsNumber || 0}, pending, done);
    }
    byId('open').onclick = () => changeWindow('open','正在开启接入窗口…','接入命令已就绪。');
    byId('extend').onclick = () => changeWindow('extend','正在延长接入窗口…','窗口已延长。');
    byId('close').onclick = () => changeWindow('close','正在关闭接入窗口…','窗口已关闭。');
    byId('copy-link').onclick = () => copy(current.url, feedback);
    byId('copy-admin-start').onclick = () => copy(installCommand(current.url), feedback);
    byId('logout').onclick = () => {
        if (busy) return;
        credentials = '';
        controls.hidden = true;
        login.hidden = false;
        render({active:current.active, connected:current.connected, until:current.until});
        feedback.textContent = '已退出。';
    };
    proxyForm.onsubmit = async event => {
        event.preventDefault();
        const fields = proxyForm.elements;
        const proxy = {host:fields.host.value.trim(),port:fields.port.valueAsNumber || 22,user:fields.user.value.trim(),
            hostKey:fields.hostKey.value.trim(),password:fields.password.value};
        fields.password.value = '';
        await mutate({action:'proxy', proxy}, '正在保存下载代理…', '下载代理已更新。');
    };

    request('/api/status').then(window => {
        duration.value = window.defaultMinutes;
        duration.max = window.maxMinutes;
        if (!busy && !credentials) render(window);
    }).catch(error => { if (!credentials) status.textContent = error.message; });

    setInterval(async () => {
        if (busy) return;
        const previous = credentials;
        try {
            const data = previous ? (await authenticated()).window : await request('/api/status');
            if (!busy && previous === credentials) render(data);
        } catch (error) {
            if (!busy) status.textContent = error.message;
        }
    }, 5000);
}
if (token) assistPage();
else adminPage();
