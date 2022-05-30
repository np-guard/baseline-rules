import unittest
from os import path
import sys
import yaml

sys.path.append(path.join(path.dirname(path.dirname(path.realpath(__file__))), 'src'))
from baseline_rule import BaselineRules

expected_netpol_allow_access_to_google_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-access-to-google
spec:
  types:
  - Egress
  selector: app in {'adservice'}
  egress:
  - action: Allow
    destination:
      nets:
      - 172.217.0.0/16
"""

expected_netpol_allow_access_to_google_namespaced_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-access-to-google
spec:
  types:
  - Egress
  selector: app in {'adservice'}
  namespaceSelector: kubernetes.io/metadata.name in {'default'}
  egress:
  - action: Allow
    destination:
      nets:
      - 172.217.0.0/16
"""

expected_netpol_allow_https_egress_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-https
spec:
  types:
  - Egress
  selector: app in {'account-query-selector'}
  egress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - 0.0.0.0/0
      ports:
      - 443
"""

expected_netpol_allow_load_generation_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-load-generation
spec:
  types:
  - Ingress
  selector: app not in {'paymentservice'}
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: app in {'loadgenerator'}
    destination:
      ports:
      - 32000
"""

expected_netpol_allow_load_generation_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-load-generation-second-direction
spec:
  types:
  - Egress
  selector: app in {'loadgenerator'}
  egress:
  - action: Allow
    destination:
      selector: app not in {'paymentservice'}
"""

expected_netpol_restrict_access_to_payments_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: require-label-to-access-payments-service
spec:
  types:
  - Ingress
  selector: app in {'paymentservice'}
  ingress:
  - action: Allow
    source:
      selector: usesPayments not in {'true', 'True'} && stage not in {'dev'}
"""

expected_netpol_restrict_access_to_payments_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: require-label-to-access-payments-service-second-direction
spec:
  types:
  - Egress
  selector: usesPayments not in {'true', 'True'} && stage not in {'dev'}
  egress:
  - action: Allow
    destination:
      selector: app in {'paymentservice'}
"""

expected_netpol_ciso_denied_ports_no_ftp_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-ftp
spec:
  types:
  - Ingress
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP
    source: {}
    destination:
      ports:
      - '20:21'
"""

expected_netpol_ciso_denied_ports_no_ftp_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-ftp-second-direction
spec:
  types:
  - Egress
  selector: all()
  egress:
  - action: Allow
    destination:
      selector: all()
"""

expected_netpol_ciso_denied_ports_no_telnet_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-telnet
spec:
  types:
  - Ingress
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP
    source: {}
    destination:
      ports:
      - 23
"""

expected_netpol_ciso_denied_ports_no_telnet_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-telnet-second-direction
spec:
  types:
  - Egress
  selector: all()
  egress:
  - action: Allow
    destination:
      selector: all()
"""

expected_netpol_ciso_denied_ports_no_smtp_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-smtp
spec:
  types:
  - Ingress
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP
    source: {}
    destination:
      ports:
      - 25
"""

expected_netpol_ciso_denied_ports_no_smtp_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-smtp-second-direction
spec:
  types:
  - Egress
  selector: all()
  egress:
  - action: Allow
    destination:
      selector: all()
"""

expected_netpol_ciso_denied_ports_no_imap_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-imap
spec:
  types:
  - Ingress
  selector: all()
  ingress:
  - action: Allow
    protocol: TCP
    source: {}
    destination:
      ports:
      - 143
"""

expected_netpol_ciso_denied_ports_no_imap_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: no-imap-second-direction
spec:
  types:
  - Egress
  selector: all()
  egress:
  - action: Allow
    destination:
      selector: all()
"""

expected_netpol_deny_circle_blue_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-circle-blue
spec:
  types:
  - Ingress
  selector: color in {'red'}
  namespaceSelector: shape not in {'circle'}
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: color in {'blue'}
      namespaceSelector: shape in {'circle'}
"""

expected_netpol_deny_circle_blue_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-circle-blue-second-direction
spec:
  types:
  - Egress
  selector: color in {'blue'}
  namespaceSelector: shape in {'circle'}
  egress:
  - action: Allow
    destination:
      selector: color in {'red'}
      namespaceSelector: shape not in {'circle'}
"""

expected_netpol_restrict_access_to_payment_namespaced_1 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: require-label-to-access-payments-service
spec:
  types:
  - Ingress
  selector: app in {'paymentservice'}
  namespaceSelector: environment in {'admin', 'prod'}
  ingress:
  - action: Allow
    source:
      selector: usesPayments not in {'true', 'True'} && stage not in {'dev'}
      namespaceSelector: has(controller-id) && run-level not in {'0', '1'}
"""

expected_netpol_restrict_access_to_payment_namespaced_2 = """\
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: require-label-to-access-payments-service-second-direction
spec:
  types:
  - Egress
  selector: usesPayments not in {'true', 'True'} && stage not in {'dev'}
  namespaceSelector: has(controller-id) && run-level not in {'0', '1'}
  egress:
  - action: Allow
    destination:
      selector: app in {'paymentservice'}
      namespaceSelector: environment in {'admin', 'prod'}
"""

rules_dict = dict()
rules_dict['allow_access_to_google'] = [(expected_netpol_allow_access_to_google_1, None)]
rules_dict['allow_access_to_google_namespaced'] = [(expected_netpol_allow_access_to_google_namespaced_1, None)]
rules_dict['allow_https_egress'] = [(expected_netpol_allow_https_egress_1, None)]
rules_dict['allow_load_generation'] = [
    (expected_netpol_allow_load_generation_1, expected_netpol_allow_load_generation_2)]
rules_dict['restrict_access_to_payment'] = [
    (expected_netpol_restrict_access_to_payments_1, expected_netpol_restrict_access_to_payments_2)]
rules_dict['ciso_denied_ports'] = [
    (expected_netpol_ciso_denied_ports_no_ftp_1, expected_netpol_ciso_denied_ports_no_ftp_2),
    (expected_netpol_ciso_denied_ports_no_telnet_1, expected_netpol_ciso_denied_ports_no_telnet_2),
    (expected_netpol_ciso_denied_ports_no_smtp_1, expected_netpol_ciso_denied_ports_no_smtp_2),
    (expected_netpol_ciso_denied_ports_no_imap_1, expected_netpol_ciso_denied_ports_no_imap_2)]
rules_dict['deny_circle_blue'] = [(expected_netpol_deny_circle_blue_1, expected_netpol_deny_circle_blue_2)]
rules_dict['restrict_access_to_payment_namespaced'] = [
    (expected_netpol_restrict_access_to_payment_namespaced_1, expected_netpol_restrict_access_to_payment_namespaced_2)]


def compare_strings(expected, actual):
    if expected is None:
        return actual is None
    if len(actual) != len(expected):
        return False
    # get index of the first different character of 2 strings, and None if they are the same
    index = next((i for i in range(len(expected)) if expected[i] != actual[i]), None)
    return index is None


def get_rule_url(rule_name):
    return f'https://github.com/np-guard/baseline-rules/blob/master/examples/{rule_name}.yaml'


def get_actual_netpol_from_rule(rule):
    policies_list = rule.to_global_netpol_calico()
    netpol1 = policies_list[0]
    netpol2 = policies_list[1] if len(policies_list) == 2 else None
    netpol_str1 = yaml.dump(netpol1, None, default_flow_style=False, sort_keys=False)
    netpol_str2 = yaml.dump(netpol2, None, default_flow_style=False, sort_keys=False)
    # print(netpol_str1)
    # print(netpol_str2)
    if netpol2 is None:
        return netpol_str1, None
    return netpol_str1, netpol_str2


class TestBaselineRulesToGlobalNetPols(unittest.TestCase):
    def test_rules(self):
        for rule_file_name in rules_dict:
            rule_url = get_rule_url(rule_file_name)
            blr = BaselineRules([rule_url])
            for rule_index, rule in enumerate(blr):
                expected_p1, expected_p2 = rules_dict[rule_file_name][rule_index]
                p1, p2 = get_actual_netpol_from_rule(rule)
                self.assertTrue(compare_strings(expected_p1, p1))
                self.assertTrue(compare_strings(expected_p2, p2))


if __name__ == '__main__':
    unittest.main()
