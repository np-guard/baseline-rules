#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
A module for storing and querying baseline rules
"""
from enum import Enum
import json
import base64
from urllib import request
from urllib.error import HTTPError
import yaml
from selector import Selector, SelectorOp, IpSelector


class BaselineRuleAction(Enum):
    """
    Allowed actions for a baseline rule
    """
    deny = 0
    allow = 1


class BaselineRule:
    """
    This class holds all relevant information about a baseline rule and provides several methods to query it
    """

    def __init__(self, rule_record):
        self.name = rule_record.get('name', '<no name>')
        print(f'processing rule {self.name}')
        self.description = rule_record.get('description', '')
        self.action = BaselineRuleAction[rule_record.get('action', 'allow')]
        self.source = Selector.parse_selectors(rule_record.get('from', ''))
        self.target = Selector.parse_selectors(rule_record.get('to', ''))
        self.source_ns = Selector.parse_selectors(rule_record.get('from_ns', ''))
        self.target_ns = Selector.parse_selectors(rule_record.get('to_ns', ''))
        self.protocol = rule_record.get('protocol')
        self.port_min = rule_record.get('port_min')
        self.port_max = rule_record.get('port_max')
        self.check_entries_validation()

    def check_entries_validation(self):
        if isinstance(self.source_ns, IpSelector) or isinstance(self.target_ns, IpSelector):
            raise Exception('A namespaceSelector can not be specified in CIDR notation', self.name)
        if isinstance(self.source, IpSelector) and self.source_ns:
            raise Exception('A source namespaceSelector can not be defined '
                            'when the source is specified in CIDR notation', self.source)
        if isinstance(self.target, IpSelector) and self.target_ns:
            raise Exception('A target NamespaceSelector can not be defined '
                            'when the target is specified in CIDR notation', self.target)

    def matches_connection(self, source_labels, target_labels, port_list, source_ns_labels=None, target_ns_labels=None):
        """
        Check whether this rule matches a given connection (and therefore allows/denies it)
        :param dict source_labels: The label of the source deployment
        :param dict target_labels: The labels of the target deployment
        :param list port_list: A list of ports on which connections should be made
        :param dict source_ns_labels: The label of the source deployment's namespace
        :param dict target_ns_labels: The labels of the target deployment's namespace
        :return: Whether the rule matched the connection
        :rtype: bool
        """
        if not self.matches_source(source_labels):
            return False
        if not self.matches_target(target_labels):
            return False
        if not self.matches_source_namespace(source_ns_labels):
            return False
        if not self.matches_target_namespace(target_ns_labels):
            return False

        for port in port_list:
            port_num = port.get('port')
            protocol = port.get('protocol', 'TCP')
            protocol_match = (not self.protocol or self.protocol == protocol)
            port_min_match = (not self.port_min or port_num >= self.port_min)
            port_max_match = (not self.port_max or port_num <= self.port_max)
            if protocol_match and port_min_match and port_max_match:
                return True

        return not bool(port_list)

    @staticmethod
    def _matches_selectors(labels, selectors):
        if isinstance(selectors, IpSelector):
            return False
        return all(selector.matches(labels) for selector in selectors)

    def matches_source(self, labels):
        """
        Check whether the given set of labels match the rule source
        :param dict labels: The labels to match
        :return: True if the labels match the rule source. False otherwise
        :rtype: bool
        """
        return BaselineRule._matches_selectors(labels, self.source)

    def matches_target(self, labels):
        """
        Check whether the given set of labels match the rule target
        :param dict labels: The labels to match
        :return: True if the labels match the rule target. False otherwise
        :rtype: bool
        """
        return BaselineRule._matches_selectors(labels, self.target)

    def matches_source_namespace(self, labels):
        """
        Check whether the given set of labels match the rule source's namespace
        NOTE: if no labels are provided, this is interpreted as "no namespace context", and the rule matches
        :param dict labels: The labels to match
        :return: True if the labels match the rule source's namespace. False otherwise
        :rtype: bool
        """
        if not labels:
            return True
        return BaselineRule._matches_selectors(labels, self.source_ns)

    def matches_target_namespace(self, labels):
        """
        Check whether the given set of labels match the rule target's namespace
        NOTE: if no labels are provided, this is interpreted as "no namespace context", and the rule matches
        :param dict labels: The labels to match
        :return: True if the labels match the rule target's namespace. False otherwise
        :rtype: bool
        """
        if not labels:
            return True
        return BaselineRule._matches_selectors(labels, self.target_ns)

    @staticmethod
    def selectors_as_netpol_peer(selectors):
        if not selectors:
            return {}
        if isinstance(selectors, IpSelector):
            return {'ipBlock': selectors.get_cidr()}
        if all(len(selector.values) == 1 and selector.operator == SelectorOp.IN for selector in selectors):
            sel = {'matchLabels': {selector.key: selector.values[0] for selector in selectors}}
        else:
            sel = {'matchExpressions': [selector.convert_to_label_selector_requirement() for selector in selectors]}
        return {'podSelector': sel}

    @staticmethod
    def _selectors_as_netpol_peer_calico(selectors, limit_to_all_expr=True, ns_selector=False):
        """
        :param Union(list[LabelSelector], IpSelector) selectors: the source or target selectors
        :param bool limit_to_all_expr: should limit calico selector to 'all()' in case of empty input selectors
        :param bool ns_selector: True when selectors refers to a namespaceSelector
        :return: calico selector dict
        :rtype dict
        """
        if not selectors:
            if ns_selector:
                return {}  # undefined namespaceSelector is equal to {'namespaceSelector': 'all()'}
            return {'selector': 'all()'} if limit_to_all_expr else {}
        if isinstance(selectors, IpSelector):
            return {'nets': selectors.get_nets_calico()}

        expr = ' && '.join(selector.convert_to_calico_selector_expression() for selector in selectors)
        if ns_selector:
            return {'namespaceSelector': expr}
        return {'selector': expr}

    def get_port_array(self):
        """
        :return: the port range specified in the baseline rule as a list of k8s port records
        :rtype: list
        """
        port_rec = {'protocol': self.protocol} if self.protocol else {}
        if not self.port_min:
            return [] if not self.protocol else [port_rec]
        if self.port_min == self.port_max:
            port_rec['port'] = self.port_min
        elif self.port_min < self.port_max:
            port_rec['port'] = self.port_min
            port_rec['endPort'] = self.port_max
        return [port_rec]

    def get_port_array_calico(self):
        """
        :return: the port range specified in the baseline rule as a list of calico ports
        :rtype: list
        """
        if not self.port_min:
            return []
        ports_array = []
        if self.port_min == self.port_max:
            ports_array = [self.port_min]
        elif self.port_min < self.port_max:
            ports_array = [f'{self.port_min}:{self.port_max}']
        return ports_array

    def _get_entity_rule_selectors_calico(self, sel, ns_sel, limit_to_all_expr=True):
        entity_dict = self._selectors_as_netpol_peer_calico(sel, limit_to_all_expr=limit_to_all_expr)
        entity_ns = self._selectors_as_netpol_peer_calico(ns_sel, ns_selector=True)
        entity_dict.update(entity_ns)
        return entity_dict

    def _get_calico_policy_spec_second_direction(self, is_ingress):
        policy_spec = {'types': ['Ingress']} if is_ingress else {'types': ['Egress']}
        if is_ingress:
            policy_selector = self._selectors_as_netpol_peer_calico(self.target)
            policy_ns_selector = self._selectors_as_netpol_peer_calico(self.target_ns, ns_selector=True)
            src_dict = self._get_entity_rule_selectors_calico(self.source, self.source_ns)
            rule_dict = {'action': 'Allow',
                         'source': src_dict}
        else:
            policy_selector = self._selectors_as_netpol_peer_calico(self.source)
            policy_ns_selector = self._selectors_as_netpol_peer_calico(self.source_ns, ns_selector=True)
            target_dict = self._get_entity_rule_selectors_calico(self.target, self.target_ns)
            rule_dict = {'action': 'Allow',
                         'destination': target_dict}

        policy_spec.update(policy_selector)
        policy_spec.update(policy_ns_selector)
        rule_type = 'ingress' if is_ingress else 'egress'
        policy_spec.update({rule_type: [rule_dict]})
        return policy_spec

    def _get_policy_type(self):
        """
        :return: a tuple of (1) is_ingress bool flag (2) str of policy type (Ingress/Egress)
        :rtype (bool, str)
        """
        is_ingress = not isinstance(self.target, IpSelector)
        return is_ingress, 'Ingress' if is_ingress else 'Egress'

    @staticmethod
    def _get_calico_policy_dict(policy_spec, policy_name):
        return {
            'apiVersion': 'projectcalico.org/v3',
            'kind': 'GlobalNetworkPolicy',
            'metadata': {'name': policy_name},
            'spec': policy_spec
        }

    def to_global_netpol_calico(self):
        """
        Create Calico GlobalNetworkPolicy resources representing the connections specified by the rule.
        Relevant for baseline rules with no namespace, thus using GlobalNetworkPolicy which applies to all namespaces.
        Note that two GlobalNetworkPolicy resources may be required for allowing both directions of a connection.

        :return: One or two Calico GlobalNetworkPolicy resources representing the connections specified by the rule
        :rtype: list[dict]
        """
        is_ingress_policy, policy_type = self._get_policy_type()
        policy_spec = {'types': [policy_type]}
        policy_selector = self._selectors_as_netpol_peer_calico(self.target if is_ingress_policy else self.source)
        policy_spec.update(policy_selector)
        policy_ns_selector = self._selectors_as_netpol_peer_calico(self.target_ns if is_ingress_policy
                                                                   else self.source_ns, ns_selector=True)
        policy_spec.update(policy_ns_selector)
        ports_list = self.get_port_array_calico()
        ports_dict = {'ports': ports_list}

        rule_to_add = {'action': 'Allow'}
        if self.protocol:
            rule_to_add['protocol'] = self.protocol
        if is_ingress_policy:
            src_dict = self._get_entity_rule_selectors_calico(self.source, self.source_ns, False)
            rule_to_add['source'] = src_dict
            if ports_list:
                rule_to_add['destination'] = ports_dict
            policy_spec['ingress'] = [rule_to_add]
        else:
            dst_dict = self._get_entity_rule_selectors_calico(self.target, self.target_ns, False)
            if ports_list:
                dst_dict.update(ports_dict)
            rule_to_add['destination'] = dst_dict
            policy_spec['egress'] = [rule_to_add]

        first_policy = self._get_calico_policy_dict(policy_spec, self.name)
        policies_list = [first_policy]
        if (is_ingress_policy and isinstance(self.source, IpSelector)) or (
                not is_ingress_policy and isinstance(self.target, IpSelector)):
            return policies_list

        second_policy_spec = self._get_calico_policy_spec_second_direction(not is_ingress_policy)
        second_policy = self._get_calico_policy_dict(second_policy_spec, f'{self.name}-second-direction')
        policies_list.append(second_policy)
        return policies_list


class BaselineRules(list):
    """
    Simply a collection of BaselineRule objects
    """
    api_github_prefix = 'https://github.com/'
    raw_github_prefix = 'https://raw.githubusercontent.com'

    def __init__(self, baseline_files):
        super().__init__()
        for baseline_file in baseline_files or []:
            if baseline_file.startswith((BaselineRules.api_github_prefix, BaselineRules.raw_github_prefix)):
                file_content = self._get_github_file_content(baseline_file)
            else:
                file_content = self._get_fs_file_content(baseline_file)

            if file_content is None:
                continue

            for rule_record in yaml.load(file_content, Loader=yaml.SafeLoader):
                self.append(BaselineRule(rule_record))

    @staticmethod
    def _get_fs_file_content(file_name):
        try:
            with open(file_name) as file_content:
                return file_content.read()
        except OSError as ose:
            print(f'Error reading file {file_name}: {ose}')
            return None

    @staticmethod
    def _get_github_file_content(url):
        if url.startswith(BaselineRules.raw_github_prefix):
            return request.urlopen(url)

        api_url = url.replace('github.com', 'api.github.com/repos', 1)
        api_url = api_url.replace('blob/master', 'contents', 1)
        req = request.Request(api_url)
        try:
            with request.urlopen(req) as response:
                data = json.loads(response.read())
                return base64.b64decode(data['content'])
        except HTTPError as http_err:
            print(f'Error fetching {api_url}. Status code: {http_err.code}')
            return None
