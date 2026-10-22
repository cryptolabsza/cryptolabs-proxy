"""Keep managed support discoverable from the Fleet landing page."""

from html.parser import HTMLParser
from pathlib import Path

import pytest


class FooterLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_footer = False
        self.links = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        if tag == "footer":
            self.in_footer = True
        elif tag == "a" and self.in_footer:
            self.current = {"attrs": dict(attrs), "text": ""}

    def handle_data(self, data):
        if self.current is not None:
            self.current["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.current is not None:
            self.links.append(self.current)
            self.current = None
        elif tag == "footer":
            self.in_footer = False


def test_footer_has_managed_support_link():
    page = Path(__file__).parents[1] / "landing-page/index.html"
    footer = FooterLinks()
    footer.feed(page.read_text())
    support = [link for link in footer.links
               if link["text"].strip() == "Managed support by CryptoLabs"]
    assert len(support) == 1
    assert support[0]["attrs"]["href"] == "https://cryptolabs.co.za"
    assert support[0]["attrs"]["target"] == "_blank"
    assert {"noopener", "noreferrer"} <= set(support[0]["attrs"]["rel"].split())


class SupportAdvert(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.in_advert = False
        self.in_form = False
        self.text = ""
        self.links = []
        self.adverts = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.in_form = True
        if tag == "section" and attrs.get("aria-label") == "Managed support":
            assert not self.in_form
            self.in_advert = True
            self.adverts += 1
        if tag == "a" and self.in_advert:
            self.links.append(attrs)

    def handle_endtag(self, tag):
        if tag == "section":
            self.in_advert = False
        elif tag == "form":
            self.in_form = False

    def handle_data(self, data):
        if self.in_advert:
            self.text += data


def assert_support_advert(html):
    advert = SupportAdvert(html)
    assert advert.adverts == 1
    assert "Managed support by CryptoLabs" in advert.text
    assert "Need help managing your server fleet?" in advert.text
    assert "Explore managed support" in advert.text
    assert len(advert.links) == 1
    assert advert.links[0]["href"] == "https://cryptolabs.co.za"
    assert advert.links[0]["target"] == "_blank"
    assert {"noopener", "noreferrer"} <= set(advert.links[0]["rel"].split())


def test_landing_has_visible_support_advert():
    html = (Path(__file__).parents[1] / "landing-page/index.html").read_text()
    assert_support_advert(html)
    assert html.index('aria-label="Managed support"') < html.index('id="quickStats"')


@pytest.mark.parametrize("state", ["first-run", "login", "login-error"])
def test_login_has_support_advert_without_changing_form(client, state):
    if state != "first-run":
        import cryptolabs_proxy.auth as auth
        auth.create_user("admin", "synthetic-pass", "admin")
    if state == "login-error":
        response = client.post("/auth/login", data={"username": "admin", "password": "wrong"})
    else:
        response = client.get("/auth/login")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert_support_advert(html)
    assert 'autocomplete="username"' in html
    assert html.count('<form method="POST">') == 1
