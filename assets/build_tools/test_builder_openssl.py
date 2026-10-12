"""Check the additional trust boundaries of the OpenSSL builder bootstrap."""

import unittest
import urllib.request

import builder_openssl


class OpenSSLBootstrapTests(unittest.TestCase):
    def test_release_redirect_stays_on_official_https_asset_host(self):
        request = urllib.request.Request(builder_openssl.URL)
        redirected = builder_openssl.ReleaseRedirect().redirect_request(
            request, None, 302, "", {},
            "https://release-assets.githubusercontent.com/github-production-release-asset/file",
        )
        self.assertEqual(redirected.host, "release-assets.githubusercontent.com")

    def test_other_redirects_rejected(self):
        for url in (
            "http://release-assets.githubusercontent.com/file",
            "https://example.org/file",
            "https://release-assets.githubusercontent.com.example.org/file",
            "https://user@release-assets.githubusercontent.com/file",
            "https://release-assets.githubusercontent.com:444/file",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                builder_openssl.ReleaseRedirect().redirect_request(None, None, 302, "", {}, url)


if __name__ == "__main__":
    unittest.main()
