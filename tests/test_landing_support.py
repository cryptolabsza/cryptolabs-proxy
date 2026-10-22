"""Keep managed support discoverable from the Fleet landing page."""

from html.parser import HTMLParser
from pathlib import Path


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
