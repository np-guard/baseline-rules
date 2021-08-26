import unittest
from baseline_rule import BaselineRules


class TestGitHubURLs(unittest.TestCase):
    def test_allow_https_rule(self):
        good_url = 'https://github.com/shift-left-netconfig/baseline-rules/blob/master/examples/allow_https_egress.yaml'
        blr = BaselineRules([good_url])
        self.assertEqual(blr[0].port_min, 443)

    def test_failed_url_fetch(self):
        bad_url = 'https://github.com/shift-left-netconfig/baseline-rules/blob/master/examples/allow_https_egress.yam'
        blr = BaselineRules([bad_url])
        self.assertTrue(not blr)


if __name__ == '__main__':
    unittest.main()
