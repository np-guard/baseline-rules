import unittest
from os import path
from baseline_rule import BaselineRules


class TestGitHubURLs(unittest.TestCase):
    def test_allow_https_rule_from_github(self):
        good_url = 'https://github.com/np-guard/baseline-rules/blob/master/examples/allow_https_egress.yaml'
        blr = BaselineRules([good_url])
        self.assertEqual(blr[0].port_min, 443)

    def test_failed_url_fetch(self):
        bad_url = 'https://github.com/shift-left-netconfig/baseline-rules/blob/master/examples/allow_https_egress.yam'
        blr = BaselineRules([bad_url])
        self.assertTrue(not blr)

    def test_allow_http_rule_from_file(self):
        ok_file = path.join(path.dirname(path.dirname(path.realpath(__file__))), 'examples', 'allow_https_egress.yaml')
        bad_file = 'bad_file.yaml'
        blr = BaselineRules([ok_file, bad_file])
        self.assertTrue(len(blr) == 1)
        self.assertEqual(blr[0].port_min, 443)


if __name__ == '__main__':
    unittest.main()
