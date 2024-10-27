// 网站反代目标
const upstream = 'ipv6.google.com'; // 反代的网页（为了突破谷歌ip限制默认自带，可修改为其他网站）
const upstream_mobile = 'ipv6.google.com'; // 反代的网页手机版本（为了突破谷歌ip限制默认自带，可修改为其他网站）
const PASSWORD = 'zju@zhejiang'; // 访问内容的密码
const SECRET_KEY = 'Kd1122211'; // HMAC 计算的加密密钥
const blocked_region = []; // 封禁的国家和地区
const blocked_ip_address = ['0.0.0.0', '127.0.0.1']; // 被禁止的IP地址

// 文本替换字典，当您要访问其他网站时，您需要同步修改成就近的反代规则字典，若有
// 如果没有这个字典，可能会缺少网站的部分源代码和资源，影响体验，这里默认为谷歌

const replace_dict = {
    '$upstream': '$custom_domain',
    '//google.com': 'ipv6.google.com',
    '//www.google.com': 'ipv6.google.com',
    'gstatic.com': 'gstatic.cn',
    'www.gstatic.com': 'www.gstatic.cn',
    'ajax.googleapis.com': 'ajax.lug.ustc.edu.cn',
    'fonts.googleapis.com': 'fonts.googleapis.cn',
    'themes.googleusercontent.com': 'google-themes.lug.ustc.edu.cn',
    'www.gravatar.com/avatar':'dn-qiniu-avatar.qbox.me/avatar',
};

// 用于生成 HMAC
async function generateHMAC(message, key) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

// 验证 HMAC 签名
async function verifyHMAC(message, signature, key) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0));
    return crypto.subtle.verify('HMAC', cryptoKey, signatureBytes, encoder.encode(message));
}

// 生成认证 Cookie
async function generateAuthCookie() {
    const timestamp = Date.now().toString();
    const signature = await generateHMAC(timestamp, SECRET_KEY);
    return `${timestamp}:${signature}`;
}

// 验证 Cookie
async function verifyAuthCookie(cookie) {
    if (!cookie) return false;
    const [timestamp, signature] = cookie.split(':');
    if (!timestamp || !signature) return false;

    const isValid = await verifyHMAC(timestamp, signature, SECRET_KEY);
    if (!isValid) return false;

    // 检查 Cookie 是否超时 (例如设置为24小时有效)
    const now = Date.now();
    const cookieAge = now - parseInt(timestamp, 10);
    const maxAge = 24 * 60 * 60 * 1000; // 24小时
    return cookieAge <= maxAge;
}

// 解析 Cookie
function parseCookies(cookieHeader) {
    const cookies = {};
    if (cookieHeader) {
        cookieHeader.split(';').forEach(cookie => {
            const [name, ...value] = cookie.split('=');
            cookies[name.trim()] = value.join('=').trim();
        });
    }
    return cookies;
}

// 处理请求
addEventListener('fetch', event => {
    event.respondWith(handleRequest(event));
});

async function handleRequest(event) {
    const request = event.request;

    // 如果是 POST 请求，则处理密码验证
    if (request.method === 'POST') {
        const formData = await request.formData();
        const userPassword = formData.get('password');

        if (userPassword === PASSWORD) {
            const authCookie = await generateAuthCookie();
            return new Response(`
                <html>
                    <head>
                        <meta charset="UTF-8">
                        <meta http-equiv="refresh" content="5;url=${request.url}">
                    </head>
                    <body>
                        <h1>好的！学长、学姐您好！</h1>
                        <p>正在进入广州中山大学镜像网页...也许5秒内成功！</p>
                        <p>如若浏览器无法加载，请重新访问，加密cookies已经写入你的浏览器了哦~</p>
                        <script>
                            setTimeout(function() {
                                window.location.href = "${request.url}";
                            }, 5000);
                        </script>
                    </body>
                </html>`, {
                status: 200,
                headers: {
                    'Set-Cookie': `auth=${authCookie}; path=/; HttpOnly`,
                    'Content-Type': 'text/html'
                }
            });
        } else {
            return new Response(getPasswordPage('Incorrect password. Please try again.'), {
                status: 401,
                headers: { 'Content-Type': 'text/html' }
            });
        }
    }

    // 验证是否有有效的 Cookie
    const cookieHeader = request.headers.get('Cookie');
    const cookies = parseCookies(cookieHeader);
    const authCookie = cookies['auth'];
    const isAuthenticated = await verifyAuthCookie(authCookie);

    if (!isAuthenticated) {
        return new Response(getPasswordPage(), {
            status: 200,
            headers: { 'Content-Type': 'text/html' }
        });
    }

    // 已认证用户，继续代理逻辑
    return await fetchAndApply(request);
}

// 代理逻辑
async function fetchAndApply(request) {
    const region = request.headers.get('cf-ipcountry').toUpperCase();
    const ip_address = request.headers.get('cf-connecting-ip');
    const user_agent = request.headers.get('user-agent');

    let response = null;
    let url = new URL(request.url);
    let url_host = url.host;

    if (url.protocol === 'http:') {
        url.protocol = 'https:';
        response = Response.redirect(url.href);
        return response;
    }

    let upstream_domain = await device_status(user_agent) ? upstream : upstream_mobile;
    url.host = upstream_domain;

    if (blocked_region.includes(region)) {
        response = new Response('Access denied: WorkersProxy is not available in your region yet.', { status: 403 });
    } else if (blocked_ip_address.includes(ip_address)) {
        response = new Response('Access denied: Your IP address is blocked by WorkersProxy.', { status: 403 });
    } else {
        let method = request.method;
        let request_headers = request.headers;
        let new_request_headers = new Headers(request_headers);

        new_request_headers.set('Host', upstream_domain);
        new_request_headers.set('Referer', url.href);

        let original_response = await fetch(url.href, { method: method, headers: new_request_headers });
        let original_response_clone = original_response.clone();
        let original_text = null;
        let response_headers = original_response.headers;
        let new_response_headers = new Headers(response_headers);
        let status = original_response.status;

        new_response_headers.set('cache-control', 'public, max-age=14400');
        new_response_headers.set('access-control-allow-origin', '*');
        new_response_headers.set('access-control-allow-credentials', true);
        new_response_headers.delete('content-security-policy');
        new_response_headers.delete('content-security-policy-report-only');
        new_response_headers.delete('clear-site-data');

        const content_type = new_response_headers.get('content-type');
        if (content_type.includes('text/html') && content_type.includes('UTF-8')) {
            original_text = await replace_response_text(original_response_clone, upstream_domain, url_host);
        } else {
            original_text = original_response_clone.body;
        }

        response = new Response(original_text, { status, headers: new_response_headers });
    }

    return response;
}

// 替换文本逻辑
async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();

    for (let i in replace_dict) {
        let j = replace_dict[i];
        if (i === '$upstream') i = upstream_domain;
        if (i === '$custom_domain') i = host_name;
        if (j === '$upstream') j = upstream_domain;
        if (j === '$custom_domain') j = host_name;

        let re = new RegExp(i, 'g');
        text = text.replace(re, j);
    }

    return text;
}

// 检查设备类型
async function device_status(user_agent_info) {
    const agents = ["Android", "iPhone", "SymbianOS", "Windows Phone", "iPad", "iPod"];
    let isDesktop = true;
    for (let v = 0; v < agents.length; v++) {
        if (user_agent_info.indexOf(agents[v]) > 0) {
            isDesktop = false;
            break;
        }
    }
    return isDesktop;
}

// 密码输入页面（html内容可改）
function getPasswordPage(message = '') {
    return `
        <html>
            <body>
                <meta charset="UTF-8">
                <h1>密码保护页面</h1>
                <p>欢迎使用广州中山大学镜像网站！需要输入学校内的密码才能访问哦</p>
                <p>${message}</p>
                <form method="POST">
                    <input type="password" name="password" placeholder="输入密码..." />
                    <button type="submit">Submit</button>
                </form>
            </body>
        </html>
    `;
}
