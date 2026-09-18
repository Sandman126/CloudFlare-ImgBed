import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

// [临时诊断代码] 定位登录 500，修复后删除
async function handle(context) {
    const { request, env } = context;

    const { username, password } = await request.json();

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('Admin login blocked because security config could not be loaded:', error);
        return new Response(JSON.stringify({ error: 'Security config unavailable' }), {
            status: 503,
            headers: { 'Content-Type': 'application/json' },
        });
    }
    const adminUsername = securityConfig.auth.admin.adminUsername;
    const adminPassword = securityConfig.auth.admin.adminPassword;

    const usernameConfigured = !!(adminUsername && adminUsername.trim());
    const passwordConfigured = !!(adminPassword && adminPassword.trim());
    const adminConfigured = usernameConfigured || passwordConfigured;

    // 管理员未配置，无需认证，直接创建会话
    if (!adminConfigured) {
        const { cookie } = await createSession(env, 'admin');
        return new Response(JSON.stringify({ success: true }), {
            status: 200,
            headers: {
                'Content-Type': 'application/json',
                'Set-Cookie': cookie,
            },
        });
    }

    // 如果设置了用户名，则验证用户名
    if (usernameConfigured && username !== adminUsername) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
        });
    }

    // 如果设置了密码，则验证密码
    if (passwordConfigured) {
        let passwordMatch;
        try {
            passwordMatch = await verifyPassword(password, adminPassword);
        } catch (e) {
            return new Response('DIAG-CRASH: stage=verifyPassword name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
        }
        if (!passwordMatch) {
            return new Response(JSON.stringify({ error: 'Unauthorized' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' },
            });
        }

        // 登录成功后，自动升级旧版哈希为 PBKDF2
        try {
            await rehashIfNeeded(getDatabase(env), password, adminPassword, 'auth.admin.adminPassword');
        } catch (e) {
            return new Response('DIAG-CRASH: stage=rehashIfNeeded name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
        }
    }

    // 创建会话并通过 HttpOnly Cookie 返回
    let cookie;
    try {
        ({ cookie } = await createSession(env, 'admin'));
    } catch (e) {
        return new Response('DIAG-CRASH: stage=createSession name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
    }

    return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': cookie,
        },
    });
}

export async function onRequestPost(context) {
    try {
        return await handle(context);
    } catch (e) {
        console.error('[DIAG adminLogin]', e && e.stack ? e.stack : e);
        return new Response(
            'DIAG-CRASH: stage=handler name=' + (e && e.name) + ' msg=' + (e && e.message),
            { status: 500, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } }
        );
    }
}
