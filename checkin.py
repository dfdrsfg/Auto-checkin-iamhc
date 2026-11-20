#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iamhc(api.hcnsec.cn)每日自动签到。

两个坑,本脚本都已处理
--------------------
1) 登录接口开启了 Cloudflare Turnstile 校验:POST /api/user/login?turnstile=<token>
   原版把 TURNSTILE_TOKEN 写死为空串,所以报 "登录失败: Turnstile token is empty"。
2) 登录成功的返回结构变了(新版 new-api):
      data.access_token / data.token_type / data.session / data.user
   用户 id 在 data.user.id,不再是 data.id;
   老结构会报 "登录成功但未获取到用户 ID"。
   若账号开了登录二次验证,data 会变成
      {"require_verification": true, "flow_token": ..., "methods": {...}}
   脚本检测到会明确提示,不会静默失败。

Turnstile token 获取顺序:
  1) 配了 CAPTCHA_API_KEY → 调用打码平台(YesCaptcha / CapSolver / 2Captcha);
  2) 没配 → 浏览器自动化(patchright 优先,回退 playwright)打开登录页取真实 token。

用法
----
    python checkin.py                # 正常签到
    python checkin.py --token-only   # 只取 token 并打印(自检,不需要账号密码)
    python checkin.py --headed       # 有头浏览器(本地调试;CI 里配合 xvfb)

常用环境变量
------------
    EMAIL / PASSWORD                 必填,登录账号
    TG_BOT_TOKEN / TG_CHAT_ID        可选,Telegram 推送
    CAPTCHA_API_KEY                  可选,打码平台 key(配了就走打码平台)
    CAPTCHA_PROVIDER                 可选,yescaptcha(默认)/ capsolver / 2captcha
    TURNSTILE_SITEKEY                可选,默认 0x4AAAAAAFIovBqwE9xMkrm_
    TURNSTILE_WAIT                   可选,等待 token 的秒数,默认 90
    HEADLESS                         可选,1/0,默认 1;CI 里请用 0 + xvfb
"""

import json
import os
import sys
import time
import tempfile
from urllib.parse import quote

import requests

EMAIL = os.environ.get("EMAIL") or ""
PASSWORD = os.environ.get("PASSWORD") or ""
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN") or ""
TG_CHAT_ID = os.environ.get("TG_CHAT_ID") or ""

BASE_URL = "https://api.hcnsec.cn"
LOGIN_PAGE = f"{BASE_URL}/sign-in"
SITEKEY = os.environ.get("TURNSTILE_SITEKEY") or "0x4AAAAAAFIovBqwE9xMkrm_"
QUOTA_PER_UNIT = 500000  # new-api 默认额度换算比例:500000 quota = 1$

CAPTCHA_API_KEY = (os.environ.get("CAPTCHA_API_KEY") or "").strip()
CAPTCHA_PROVIDER = (os.environ.get("CAPTCHA_PROVIDER") or "yescaptcha").strip().lower()
TOKEN_WAIT = int(os.environ.get("TURNSTILE_WAIT") or "90")
HEADLESS = os.environ.get("HEADLESS", "1").strip().lower() not in ("0", "false", "no")

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36")


# ---------------------------------------------------------------------------
# 一、Turnstile token 获取
# ---------------------------------------------------------------------------

def get_token_via_solver():
    """通过打码平台获取 Turnstile token。未配置 CAPTCHA_API_KEY 时返回空串。"""
    if not CAPTCHA_API_KEY:
        return ""
    provider = CAPTCHA_PROVIDER
    print(f"[solver] 使用打码平台获取 Turnstile token: {provider}")
    try:
        if provider in ("yescaptcha", "capsolver", "capmonster"):
            base = {
                "yescaptcha": "https://api.yescaptcha.com",
                "capsolver": "https://api.capsolver.com",
                "capmonster": "https://api.capmonster.cloud",
            }[provider]
            task_type = ("AntiTurnstileTaskProxyLess"
                         if provider in ("capsolver", "capmonster")
                         else "TurnstileTaskProxyless")
            resp = requests.post(
                f"{base}/createTask",
                json={
                    "clientKey": CAPTCHA_API_KEY,
                    "task": {
                        "type": task_type,
                        "websiteURL": LOGIN_PAGE,
                        "websiteKey": SITEKEY,
                    },
                },
                timeout=30,
            ).json()
            task_id = resp.get("taskId") or (resp.get("task") or {}).get("taskId")
            if not task_id:
                print("[solver] createTask 失败:", json.dumps(resp, ensure_ascii=False)[:300])
                return ""
            for _ in range(40):
                time.sleep(3)
                res = requests.post(
                    f"{base}/getTaskResult",
                    json={"clientKey": CAPTCHA_API_KEY, "taskId": task_id},
                    timeout=30,
                ).json()
                if res.get("status") == "ready":
                    solution = res.get("solution") or {}
                    token = solution.get("token") or solution.get("gRecaptchaResponse") or ""
                    if token:
                        print(f"[solver] token 获取成功,长度 {len(token)}")
                        return token
                    print("[solver] 状态 ready 但没有 token:", json.dumps(res)[:300])
                    return ""
                if res.get("errorId"):
                    print("[solver] 出错:", json.dumps(res, ensure_ascii=False)[:300])
                    return ""
            print("[solver] 轮询超时")
            return ""

        if provider == "2captcha":
            resp = requests.post(
                "https://2captcha.com/in.php",
                data={
                    "key": CAPTCHA_API_KEY,
                    "method": "turnstile",
                    "sitekey": SITEKEY,
                    "pageurl": LOGIN_PAGE,
                    "json": 1,
                },
                timeout=30,
            ).json()
            if resp.get("status") != 1:
                print("[solver] in.php 失败:", json.dumps(resp, ensure_ascii=False)[:300])
                return ""
            request_id = resp["request"]
            for _ in range(40):
                time.sleep(5)
                res = requests.get(
                    "https://2captcha.com/res.php",
                    params={"key": CAPTCHA_API_KEY, "action": "get",
                            "id": request_id, "json": 1},
                    timeout=30,
                ).json()
                if res.get("status") == 1:
                    print(f"[solver] token 获取成功,长度 {len(res['request'])}")
                    return res["request"]
                if res.get("request") != "CAPCHA_NOT_READY":
                    print("[solver] res.php 失败:", json.dumps(res, ensure_ascii=False)[:300])
                    return ""
            print("[solver] 轮询超时")
            return ""

        print("[solver] 未知的 CAPTCHA_PROVIDER:", provider)
        return ""
    except Exception as exc:
        print("[solver] 异常:", type(exc).__name__, exc)
        return ""


READ_TOKEN_JS = """() => {
  const el = document.querySelector('input[name="cf-turnstile-response"]');
  if (el && el.value) return el.value;
  for (const node of document.querySelectorAll('*')) {
    if (node.shadowRoot) {
      const inner = node.shadowRoot.querySelector('input[name="cf-turnstile-response"]');
      if (inner && inner.value) return inner.value;
    }
  }
  return '';
}"""


def _load_sync_playwright():
    """优先 patchright(反检测更好用),没有则回退 playwright。"""
    try:
        from patchright.sync_api import sync_playwright
        print("[browser] 使用 patchright")
        return sync_playwright
    except ImportError:
        pass
    try:
        from playwright.sync_api import sync_playwright
        print("[browser] 使用 playwright")
        return sync_playwright
    except ImportError:
        return None


def get_token_via_browser(headless=None):
    """打开登录页,等站点自己的 Turnstile widget 写回 token。

    注意:Cloudflare 托管挑战在无头模式下基本拿不到 token(实测一直 "Verifying..."),
    所以 CI 里要么用 xvfb 跑有头浏览器,要么改用打码平台。
    """
    sync_playwright = _load_sync_playwright()
    if sync_playwright is None:
        print("[browser] 未安装 patchright / playwright,无法用浏览器方式取 token")
        return ""
    if headless is None:
        headless = HEADLESS
    print(f"[browser] 打开 {LOGIN_PAGE}(headless={headless})")
    profile_dir = tempfile.mkdtemp(prefix="iamhc-profile-")
    try:
        with sync_playwright() as pw:
            context = pw.chromium.launch_persistent_context(
                profile_dir,
                headless=headless,
                no_viewport=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
            try:
                page = context.pages[0] if context.pages else context.new_page()
                page.goto(LOGIN_PAGE, wait_until="domcontentloaded", timeout=60000)
                tried_click = False
                for second in range(TOKEN_WAIT):
                    page.wait_for_timeout(1000)
                    try:
                        token = page.evaluate(READ_TOKEN_JS) or ""
                    except Exception:
                        token = ""
                    if token:
                        print(f"[browser] 拿到 token(耗时 {second + 1}s,长度 {len(token)})")
                        return token
                    if not tried_click and second >= 15:
                        tried_click = True
                        for frame in page.frames:
                            if "challenges.cloudflare.com" in frame.url:
                                try:
                                    frame.locator("body").click(
                                        timeout=3000, position={"x": 30, "y": 30})
                                    print("[browser] 已尝试点击人机验证复选框")
                                except Exception:
                                    pass
                    if (second + 1) % 15 == 0:
                        print(f"[browser] 仍在等待 token({second + 1}s)")
                print("[browser] 等待超时,没有拿到 token")
                return ""
            finally:
                try:
                    context.close()
                except Exception:
                    pass
    except Exception as exc:
        print("[browser] 异常:", type(exc).__name__, exc)
        return ""


def get_turnstile_token():
    """按优先级取一个 Turnstile token。"""
    token = get_token_via_solver()
    if token:
        return token
    return get_token_via_browser()


# ---------------------------------------------------------------------------
# 二、登录 / 签到
# ---------------------------------------------------------------------------

def _extract_user(payload):
    """兼容多种返回结构,把用户信息 dict 抠出来。

    新结构:data.user.{id,username,quota,...}
    自省接口:data.{id,username,quota,...}
    旧结构:data.{id,username,...}
    """
    if not isinstance(payload, dict):
        return None
    for key in ("user", "data"):
        sub = payload.get(key)
        if isinstance(sub, dict) and sub.get("id"):
            return sub
    if payload.get("id"):
        return payload
    return None


def _api_headers(user_id, access_token, json_body=False):
    headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": UA,
        "Origin": BASE_URL,
        "Referer": f"{BASE_URL}/",
    }
    if json_body:
        headers["Content-Type"] = "application/json"
    if user_id:
        headers["New-Api-User"] = str(user_id)
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    return headers


def login(session, turnstile_token):
    """登录。返回 (用户信息 或 None, 服务端消息, access_token)。"""
    login_url = f"{BASE_URL}/api/user/login?turnstile={quote(turnstile_token)}"
    headers = {
        "Accept": "application/json, text/plain, */*",
        "Content-Type": "application/json",
        "User-Agent": UA,
        "Origin": BASE_URL,
        "Referer": LOGIN_PAGE,
    }
    resp = session.post(
        login_url,
        headers=headers,
        json={"username": EMAIL, "password": PASSWORD},
        timeout=20,
    )
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code}: {resp.text[:200]}", ""

    try:
        data = resp.json()
    except Exception:
        return None, f"返回内容不是 JSON: {resp.text[:200]}", ""

    if not data.get("success"):
        return None, str(data.get("message", "")), ""

    payload = data.get("data")
    access_token = ""
    if isinstance(payload, dict):
        access_token = payload.get("access_token") or ""
        if payload.get("require_verification"):
            methods = payload.get("methods")
            return (None,
                    f"该账号开启了登录二次验证(require_verification),需人工完成,"
                    f"脚本无法自动通过。methods={json.dumps(methods, ensure_ascii=False)[:200]}",
                    access_token)

    user = _extract_user(payload) or _extract_user(data)
    if not user:
        print("登录响应结构未识别,原始内容:",
              json.dumps(data, ensure_ascii=False)[:500])
        return None, "登录成功但没有解析出用户 ID(原始响应已打印在上方)", access_token

    user_id = user.get("id")
    username = user.get("username", str(user_id))
    print(f"✅ 登录成功 | 账户: {username} | ID: {user_id}")
    return {"id": user_id, "username": username}, "", access_token


def get_user_info(session, user_id, access_token):
    url = f"{BASE_URL}/api/user/self"
    try:
        data = session.get(url,
                           headers=_api_headers(user_id, access_token),
                           timeout=20).json()
    except Exception as exc:
        print("获取用户信息异常:", type(exc).__name__, exc)
        return None
    if not data.get("success"):
        print("获取用户信息失败:", json.dumps(data, ensure_ascii=False)[:300])
        return None
    return _extract_user(data.get("data")) or _extract_user(data)


def checkin(session, user_id, access_token):
    url = f"{BASE_URL}/api/user/checkin"
    try:
        resp = session.post(url,
                            headers=_api_headers(user_id, access_token, json_body=True),
                            json={},
                            timeout=20)
        return resp.json()
    except Exception as exc:
        return {"success": False, "message": f"签到请求异常: {type(exc).__name__} {exc}"}


def quota_to_dollar(quota):
    return round((quota or 0) / QUOTA_PER_UNIT)


def send_notification(message):
    print("\n" + "=" * 25)
    print(message)
    print("=" * 25)

    if TG_BOT_TOKEN and TG_CHAT_ID:
        try:
            resp = requests.post(
                f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
                json={"chat_id": TG_CHAT_ID, "text": message},
                timeout=10,
            )
            if resp.status_code == 200:
                print("Telegram 通知发送成功")
            else:
                print(f"Telegram 通知发送失败: {resp.status_code} {resp.text[:200]}")
        except Exception as exc:
            print("Telegram 通知发送失败:", type(exc).__name__, exc)
    else:
        print("未配置 TG_BOT_TOKEN / TG_CHAT_ID,跳过 Telegram 推送")


# ---------------------------------------------------------------------------
# 三、主流程
# ---------------------------------------------------------------------------

def main():
    global HEADLESS
    if "--headed" in sys.argv:
        HEADLESS = False

    if "--token-only" in sys.argv:
        print("自检模式:只获取 Turnstile token,不使用账号密码")
        token = get_turnstile_token()
        print(f"TOKEN_LEN={len(token)}")
        if token:
            print("RESULT: OK")
            return 0
        print("RESULT: FAILED(没拿到 token)")
        return 1

    if not EMAIL or not PASSWORD:
        print("请先设置 EMAIL 和 PASSWORD 环境变量(或在脚本中填写默认值)")
        return 1

    session = requests.Session()

    # 登录(最多两次:token 过期或服务端判空时,重新取一个 token 再试)
    user, message, access_token = None, "", ""
    for attempt in (1, 2):
        token = get_turnstile_token()
        if not token:
            message = "无法获取 Turnstile token(打码平台失败且浏览器方式也没拿到)"
            print(message)
            break
        user, message, access_token = login(session, token)
        if user:
            break
        low = (message or "").lower()
        need_retry = ("turnstile" in low or "token" in low
                      or "人机" in (message or "") or "验证" in (message or ""))
        if "二次验证" in (message or "") or "require_verification" in low:
            need_retry = False
        print(f"第 {attempt} 次登录失败: {message}")
        if attempt == 2 or not need_retry:
            break
        print("看起来是验证码问题,重新获取 token 后再试一次 ...")
        time.sleep(3)

    if not user:
        print("\n登录失败,无法继续签到")
        send_notification(
            "🎁 iamhc 签到通知\n\n"
            "❌ 登录失败,无法签到\n"
            f"原因: {message or '未知'}"
        )
        return 1

    user_id = user["id"]
    username = user.get("username", str(user_id))

    info_before = get_user_info(session, user_id, access_token)
    if not info_before:
        print("获取用户信息失败")
        return 1
    balance_before = quota_to_dollar(info_before.get("quota", 0))

    checkin_data = checkin(session, user_id, access_token)
    print("签到接口返回:", json.dumps(checkin_data, ensure_ascii=False)[:300])

    info_after = get_user_info(session, user_id, access_token)
    if not info_after:
        print("获取签到后用户信息失败")
        return 1
    balance_after = quota_to_dollar(info_after.get("quota", 0))

    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + 8 * 3600))
    success = checkin_data.get("success", False)
    msg = str(checkin_data.get("message", ""))

    header = "🎁 iamhc 签到通知\n\n"
    tail = (f"👤 登录账户: {username}\n"
            f"💰 昨日余额: {balance_before}$\n"
            f"💰 当前余额: {balance_after}$\n"
            f"⏱️ 签到时间: {now}")

    if success:
        awarded_quota = (checkin_data.get("data") or {}).get("quota_awarded", 0)
        awarded = quota_to_dollar(awarded_quota) if awarded_quota else (balance_after - balance_before)
        print(f"✅ 签到成功 | 获得: {awarded}$")
        message = header + f"✅ 签到成功,本次签到获得{awarded}$\n" + tail
    elif "已签到" in msg or "重复签到" in msg or "今天已签到" in msg:
        print(f"✅ 今日已签到 | 当前余额: {balance_after}$")
        message = header + "✅ 今天你已经签到过了!\n" + tail
    else:
        print(f"❌ 签到失败 | {msg}")
        message = header + f"❌ 签到失败: {msg}\n" + tail

    send_notification(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
