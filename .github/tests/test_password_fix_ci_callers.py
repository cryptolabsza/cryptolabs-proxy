"""Keep the password-fix build callers on the already admitted immutable routes."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "cryptolabsza/cryptolabs-proxy/.github/workflows/"


class PasswordFixCICallers(unittest.TestCase):
    def test_callers_use_only_exact_admitted_recipes(self):
        expected = {
            "docker-build.yml": {
                "release-preflight": ("ci-image-preflight-recipe.yml", "e02ebff9390d806d06261f03ec2ff519f980800f"),
                "build": ("ci-image-build-recipe.yml", "7eb7e476b362c3f5eaeee73b05d9bf95fe508764"),
                "publish-build": ("ci-image-publish-recipe.yml", "af9d050a7ba96ab4523b5acd4bf9990c7b2c04b6"),
                "release-readback": ("ci-image-readback-recipe.yml", "e02ebff9390d806d06261f03ec2ff519f980800f"),
            },
            "publish.yml": {
                "cpu-build": ("ci-python-build-recipe.yml", "cdb50910f0bb5ad59a0e4ec0143ffc924bab0567"),
                "publish": ("ci-pypi-publish-recipe.yml", "83b0be815273cf039ea05835810c131f4d030516"),
            },
            "promote-images.yml": {
                "promote": ("ci-image-promote-recipe.yml", "e02ebff9390d806d06261f03ec2ff519f980800f"),
            },
        }
        for filename, jobs in expected.items():
            with self.subTest(workflow=filename):
                config = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
                self.assertEqual(config["permissions"], {"contents": "read"})
                self.assertEqual(set(config["jobs"]), set(jobs))
                for job_id, (recipe, sha) in jobs.items():
                    job = config["jobs"][job_id]
                    self.assertEqual(job["uses"], REPOSITORY + recipe + "@" + sha)
                    self.assertNotIn("runs-on", job)
                    self.assertNotIn("steps", job)
                    if job_id in {"build", "cpu-build"}:
                        self.assertEqual(job["permissions"], {"contents": "read"})
                        self.assertNotIn("secrets", job)
                        self.assertNotIn("with", job)


if __name__ == "__main__":
    unittest.main()
