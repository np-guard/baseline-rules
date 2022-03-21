import unittest
from os import path
import sys
import yaml

sys.path.append(path.join(path.dirname(path.dirname(path.realpath(__file__))), 'src'))
from baseline_rule import BaselineRules

expected_netpol_allow_access_to_google = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-access-to-google
spec:
  policyTypes:
  - Egress
  podSelector:
    matchLabels:
      app: adservice
  egress:
  - ports: []
    to:
    - ipBlock:
        cidr: 172.217.0.0/16
"""

expected_netpol_allow_https_egress = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-https
spec:
  policyTypes:
  - Egress
  podSelector:
    matchLabels:
      app: account-query-selector
  egress:
  - ports:
    - protocol: TCP
      port: 443
    to:
    - ipBlock:
        cidr: 0.0.0.0/0
"""

expected_netpol_allow_load_generation = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-load-generation
spec:
  policyTypes:
  - Ingress
  podSelector:
    matchExpressions:
    - key: app
      operator: NotIn
      values:
      - paymentservice
  ingress:
  - ports:
    - protocol: TCP
      port: 32000
    from:
    - podSelector:
        matchLabels:
          app: loadgenerator
"""

expected_netpol_restrict_access_to_payments = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: require-label-to-access-payments-service
spec:
  policyTypes:
  - Ingress
  podSelector:
    matchLabels:
      app: paymentservice
  ingress:
  - ports: []
    from:
    - podSelector:
        matchExpressions:
        - key: usesPayments
          operator: NotIn
          values:
          - 'true'
          - 'True'
        - key: stage
          operator: NotIn
          values:
          - dev
"""

expected_netpol_ciso_denied_ports_no_ftp = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-ftp
spec:
  policyTypes:
  - Ingress
  podSelector: {}
  ingress:
  - ports:
    - protocol: TCP
      port: 20
      endPort: 21
"""

expected_netpol_ciso_denied_ports_no_telnet = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-telnet
spec:
  policyTypes:
  - Ingress
  podSelector: {}
  ingress:
  - ports:
    - protocol: TCP
      port: 23
"""

expected_netpol_ciso_denied_ports_no_smtp = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-smtp
spec:
  policyTypes:
  - Ingress
  podSelector: {}
  ingress:
  - ports:
    - protocol: TCP
      port: 25
"""

expected_netpol_ciso_denied_ports_no_imap = """\
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: no-imap
spec:
  policyTypes:
  - Ingress
  podSelector: {}
  ingress:
  - ports:
    - protocol: TCP
      port: 143
"""

rules_dict = dict()
rules_dict['allow_access_to_google'] = [expected_netpol_allow_access_to_google]
rules_dict['allow_https_egress'] = [expected_netpol_allow_https_egress]
rules_dict['allow_load_generation'] = [expected_netpol_allow_load_generation]
rules_dict['restrict_access_to_payment'] = [expected_netpol_restrict_access_to_payments]
rules_dict['ciso_denied_ports'] = [expected_netpol_ciso_denied_ports_no_ftp,
                                   expected_netpol_ciso_denied_ports_no_telnet,
                                   expected_netpol_ciso_denied_ports_no_smtp, expected_netpol_ciso_denied_ports_no_imap]


def compare_strings(expected, actual):
    if len(actual) != len(expected):
        return False
    # get index of the first different character of 2 strings, and None if they are the same
    index = next((i for i in range(len(expected)) if expected[i] != actual[i]), None)
    return index is None


def get_rule_url(rule_name):
    return f'https://raw.githubusercontent.com/np-guard/baseline-rules/master/examples/{rule_name}.yaml'


def get_actual_netpol_from_rule(rule):
    netpol = rule.to_netpol()
    netpol_str = yaml.dump(netpol, None, default_flow_style=False, sort_keys=False)
    # print(netpol_str)
    return netpol_str


class TestBaselineRulesToNetPols(unittest.TestCase):
    def test_rules(self):
        for rule_file_name in rules_dict:
            rule_url = get_rule_url(rule_file_name)
            blr = BaselineRules([rule_url])
            for rule_index, rule in enumerate(blr):
                expected_netpol = rules_dict[rule_file_name][rule_index]
                actual_netpol = get_actual_netpol_from_rule(rule)
                self.assertTrue(compare_strings(expected_netpol, actual_netpol))


if __name__ == '__main__':
    unittest.main()
