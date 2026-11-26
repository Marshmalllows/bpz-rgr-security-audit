import os
import uuid

import pytest
from playwright.sync_api import sync_playwright

TARGET = os.environ.get("TARGET", "http://bwapp-vuln").rstrip("/")
NORMAL_UA = "Mozilla/5.0 (X11; Linux x86_64) bpz-rgr-tests"


class Client:
    def __init__(self, browser, user_agent=NORMAL_UA):
        self.context = browser.new_context(base_url=TARGET, user_agent=user_agent)
        self.page = self.context.new_page()
        self.dialogs = []
        self.page.on("dialog", self._on_dialog)

    def _on_dialog(self, dialog):
        self.dialogs.append(dialog.message)
        dialog.dismiss()

    def login(self, level="0"):
        self.context.request.post(
            "/login.php",
            form={"login": "bee", "password": "bug", "security_level": level, "form": "submit"},
        )
        return self

    def open(self, path, settle_ms=300):
        self.page.goto(path)
        self.page.wait_for_load_state("load")
        self.page.wait_for_timeout(settle_ms)
        return self.page

    def text(self, selector="body"):
        return self.page.inner_text(selector)

    def close(self):
        self.context.close()


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        b = p.chromium.launch()
        yield b
        b.close()


@pytest.fixture
def client(browser):
    c = Client(browser).login()
    yield c
    c.close()


@pytest.fixture
def make_client(browser):
    created = []

    def factory(user_agent=NORMAL_UA):
        c = Client(browser, user_agent).login()
        created.append(c)
        return c

    yield factory
    for c in created:
        c.close()


@pytest.fixture
def marker():
    return "xss-" + uuid.uuid4().hex[:12]
