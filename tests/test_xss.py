from urllib.parse import quote

import pytest

from conftest import TARGET


def alert(m):
    return f"alert('{m}')"


def alert_bt(m):
    return f"alert(`{m}`)"


@pytest.mark.parametrize(
    "template",
    ["<script>{js}</script>", "<img src=x onerror=\"{js}\">", "<svg onload={js}>"],
    ids=["script", "img-onerror", "svg-onload"],
)
def test_v1_reflected_get_html_body(client, marker, template):
    payload = template.format(js=alert(marker))
    client.open(f"/xss_get.php?firstname={quote(payload)}&lastname=x&form=submit")
    assert marker not in client.dialogs


def test_v1_reflected_get_keeps_function(client):
    client.open("/xss_get.php?firstname=John&lastname=%3Cb%3ESmith%3C%2Fb%3E&form=submit")
    assert "Welcome John <b>Smith</b>" in client.text("#main")


@pytest.mark.parametrize(
    "template",
    ["';{js};//", "</script><script>{js}</script>", "<img src=x onerror={js_bt}>"],
    ids=["break-string", "close-script", "innerhtml"],
)
def test_v2_reflected_json_script_context(client, marker, template):
    payload = template.format(js=alert(marker), js_bt=alert_bt(marker))
    client.open(f"/xss_json.php?title={quote(payload)}&action=search")
    assert marker not in client.dialogs


def test_v2_reflected_json_keeps_function(client):
    client.open("/xss_json.php?title=Iron+Man&action=search")
    assert "Yes! We have that movie" in client.text("#result")
    client.open(f"/xss_json.php?title={quote('<b>x</b>')}&action=search")
    assert "<b>x</b>??? Sorry" in client.text("#result")


@pytest.mark.parametrize(
    "template",
    ["x><img src=x onerror={js}>", "x onfocus={js} autofocus"],
    ids=["break-tag", "event-attribute"],
)
def test_v3_reflected_href_attribute(client, marker, template):
    payload = template.format(js=alert(marker))
    page = client.open(f"/xss_href-2.php?name={quote(payload)}&action=vote")
    links = page.locator("a[href*='xss_href-3.php']")
    if links.count():
        links.first.focus()
        page.wait_for_timeout(200)
    assert marker not in client.dialogs
    for i in range(links.count()):
        href = links.nth(i).get_attribute("href")
        assert href.startswith("xss_href-3.php?")


def test_v3_reflected_href_keeps_function(client):
    page = client.open("/xss_href-2.php?name=Tony+Stark&action=vote")
    href = page.locator("a[href*='xss_href-3.php']").first.get_attribute("href")
    assert "name=Tony+Stark" in href or "name=Tony%20Stark" in href


@pytest.mark.parametrize(
    "payload",
    ["{js}", "Date());{js};(1", "x\"+{js}+\""],
    ids=["expression", "break-call", "break-string"],
)
def test_v4_reflected_eval(client, marker, payload):
    value = payload.format(js=alert(marker))
    client.open(f"/xss_eval.php?date={quote(value)}")
    assert marker not in client.dialogs


def test_v4_reflected_eval_keeps_function(client):
    client.open("/xss_eval.php?date=Date()")
    assert "GMT" in client.text("#main")


@pytest.mark.parametrize(
    "template",
    ["<script>{js}</script>", "<img src=x onerror={js}>"],
    ids=["script", "img-onerror"],
)
def test_v5_stored_blog(make_client, marker, template):
    attacker = make_client()
    attacker.context.request.post(
        "/xss_stored_1.php",
        form={"entry": template.format(js=alert(marker)), "blog": "submit", "entry_add": ""},
    )
    victim = make_client()
    victim.open("/xss_stored_1.php")
    assert marker not in victim.dialogs


def test_v5_stored_blog_keeps_function(make_client, marker):
    author = make_client()
    author.context.request.post(
        "/xss_stored_1.php",
        form={"entry": f"<b>{marker}</b> O'Reilly & Co", "blog": "submit", "entry_add": ""},
    )
    reader = make_client()
    reader.open("/xss_stored_1.php")
    assert f"<b>{marker}</b> O'Reilly & Co" in reader.text("#main")


def test_v6_stored_user_agent(make_client, marker):
    attacker = make_client(user_agent=f"<script>{alert(marker)}</script>")
    attacker.open("/xss_stored_4.php")
    victim = make_client()
    victim.open("/xss_stored_4.php")
    assert marker not in victim.dialogs


def test_v6_stored_user_agent_keeps_function(make_client, marker):
    visitor = make_client(user_agent=f"Agent<{marker}>")
    visitor.open("/xss_stored_4.php")
    assert f"Agent<{marker}>" in visitor.text("#main")


@pytest.mark.parametrize(
    "template",
    ["<img src=x onerror={js}>", "\"}}]}});{js};//"],
    ids=["innerhtml", "break-json-eval"],
)
def test_v7_dom_ajax_json(client, marker, template):
    page = client.open("/xss_ajax_2-1.php")
    page.fill("#title", template.format(js=alert(marker)))
    page.wait_for_timeout(2500)
    assert marker not in client.dialogs


def test_v7_ajax_endpoint_not_html(client, marker):
    payload = f"<script>{alert(marker)}</script>"
    response = client.context.request.get(f"/xss_ajax_2-2.php?title={quote(payload)}")
    assert response.headers["content-type"].startswith("application/json")
    client.open(f"/xss_ajax_2-2.php?title={quote(payload)}")
    assert marker not in client.dialogs


def test_v7_dom_ajax_keeps_function(client):
    page = client.open("/xss_ajax_2-1.php")
    page.fill("#title", "Iron Man")
    page.wait_for_timeout(2500)
    assert "Yes! We have that movie" in client.text("#result")
    page.fill("#title", "<b>x</b>")
    page.wait_for_timeout(2500)
    assert "<b>x</b>??? Sorry" in client.text("#result")


def test_session_cookie_httponly(browser):
    from conftest import Client

    c = Client(browser)
    response = c.context.request.get("/login.php")
    cookies = [h["value"] for h in response.headers_array if h["name"].lower() == "set-cookie"]
    session = [v for v in cookies if v.startswith("PHPSESSID=")]
    c.close()
    assert session and all("httponly" in v.lower() for v in session)
