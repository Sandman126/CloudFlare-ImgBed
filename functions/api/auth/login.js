import { fetchSecurityConfig } from "../../utils/sysConfig.js";
import { verifyPassword, rehashIfNeeded } from "../../utils/auth/passwordHash.js";
import { createSession } from "../../utils/auth/sessionManager.js";
import { getDatabase } from "../../utils/databaseAdapter.js";

// [临时诊断代码] 定位登录 500，修复后删除
async function handle(context) {
    const { request, env } = context;

    const jsonRequest = await request.json();
    const authCode = jsonRequest.authCode;

    // 读取安全设置
    let securityConfig;
    try {
        securityConfig = await fetchSecurityConfig(env, { throwOnError: true });
    } catch (error) {
        console.error('User login blocked because security config could not be loaded:', error);
        return new Response('Security config unavailable', { status: 503 });
    }
    const rightAuthCode = securityConfig.auth.user.authCode;

    // 验证 authCode（兼容明文、SHA-256 和 PBKDF2 三种存储格式）
    if (rightAuthCode !== undefined && rightAuthCode !== '') {
        let isValid;
        try {
            isValid = await verifyPassword(authCode, rightAuthCode);
        } catch (e) {
            return new Response('DIAG-CRASH: stage=verifyPassword name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
        }
        if (!isValid) {
            return new Response('Unauthorized', { status: 401 });
        }

        // 登录成功后，自动升级旧版哈希为 PBKDF2
        try {
            await rehashIfNeeded(getDatabase(env), authCode, rightAuthCode, 'auth.user.authCode');
        } catch (e) {
            return new Response('DIAG-CRASH: stage=rehashIfNeeded name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
        }
    }

    // 创建会话并通过 HttpOnly Cookie 返回
    let cookie;
    try {
        ({ cookie } = await createSession(env, 'user'));
    } catch (e) {
        return new Response('DIAG-CRASH: stage=createSession name=' + (e && e.name) + ' msg=' + (e && e.message), { status: 500 });
    }

    return new Response('Login success', {
        status: 200,
        headers: {
            'Set-Cookie': cookie,
        },
    });
}

export async function onRequestPost(context) {
    try {
        return await handle(context);
    } catch (e) {
        console.error('[DIAG login]', e && e.stack ? e.stack : e);
        return new Response(
            'DIAG-CRASH: stage=handler name=' + (e && e.name) + ' msg=' + (e && e.message),
            { status: 500, headers: { 'Content-Type': 'text/plain;charset=UTF-8' } }
        );
    }
}
