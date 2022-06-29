import re
from selector import IpSelector


class RuleSyntaxChecker:
    """
    This class make syntax and validity checks on baseline rule's fields
    """

    @staticmethod
    def check_keys_legality(rule_record):
        allowed_keys = {'name', 'description', 'action', 'from', 'to', 'from_ns', 'to_ns',
                        'protocol', 'port_min', 'port_max'}
        record_keys = set(rule_record.keys())
        bad_match_keys = record_keys.difference(allowed_keys)
        if bad_match_keys:
            raise Exception(f'{bad_match_keys.pop()} is not a valid entry in the specification of a baseline rule',
                            rule_record)

    @staticmethod
    def check_dns_subdomain_name(rule_name):
        if len(rule_name) > 253:
            raise Exception(f'Rule name {rule_name} does not match requirements of k8s DNS subdomain name. '
                            f'It must be no more than 253 characters')
        pattern = r"[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*"
        if re.fullmatch(pattern, rule_name) is None:
            raise Exception(f'Rule name {rule_name} does not match requirements of k8s DNS subdomain name. '
                            f'it must consist of lower case alphanumeric characters, "-" or ".", '
                            f'and must start and end with an alphanumeric character')

        return rule_name

    @staticmethod
    def check_action_validity(rule_action):
        if rule_action not in ('allow', 'deny'):
            raise Exception(f'{rule_action} action is not supported. '
                            f'Baseline rule supports only allow and deny actions')
        return rule_action

    @staticmethod
    def check_port_validity(port_num):
        if port_num is None:
            return None
        if not isinstance(port_num, int):
            raise Exception(f'Invalid {port_num}. A port must be numerical')
        if port_num not in range(1, 65536):
            raise Exception(f'Invalid {port_num}. A port must be in the range [1, 65535]')

        return port_num

    @staticmethod
    def check_protocol_validity(protocol):
        if not protocol:
            return None
        if protocol not in ('TCP', 'UDP', 'SCTP'):
            raise Exception(f'{protocol} protocol is not supported')
        return protocol

    @staticmethod
    def check_selector_validity(selectors):
        if not selectors:
            return selectors
        if isinstance(selectors, IpSelector):
            return selectors
        for sel in selectors:
            RuleSyntaxChecker._check_label_key_syntax(sel.key, sel)
            if sel.values:
                for value in sel.values:
                    RuleSyntaxChecker._check_label_value_syntax(value, sel.key, selectors)
        return selectors

    @staticmethod
    def check_namespace_selector_validity(ns_selector):
        if isinstance(ns_selector, IpSelector):
            raise Exception('A namespaceSelector can not be specified in CIDR notation')
        return RuleSyntaxChecker.check_selector_validity(ns_selector)

    @staticmethod
    def _check_label_key_syntax(key_label, key_container):
        """
        checking validity of the label's key
        :param string key_label: The key name
        :param dict key_container : The selector's part where the key appears
        :return: None
        """
        if key_label.count('/') > 1:
            raise Exception(f'Invalid key "{key_label}", a valid label key may have two segments: '
                            f'an optional prefix and name, separated by a slash (/).', key_container)
        if key_label.count('/') == 1:
            prefix = key_label.split('/')[0]
            if not prefix:
                raise Exception(f'Invalid key "{key_label}", prefix part must be non-empty',
                                key_container)
            RuleSyntaxChecker.check_dns_subdomain_name(prefix)
            name = key_label.split('/')[1]
        else:
            name = key_label
        if not name:
            raise Exception(f'Invalid key "{key_label}", '
                            f'name segment is required in label key', key_container)
        if len(name) > 63:
            raise Exception(f'Invalid key "{key_label}", '
                            f'a label key name must be no more than 63 characters', key_container)
        pattern = r"([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]"
        if re.fullmatch(pattern, name) is None:
            raise Exception(f'Invalid key "{key_label}", '
                            f'a label key name part must consist of alphanumeric characters, "-", "_" or ".", '
                            f'and must start and end with an alphanumeric character', key_container)

    @staticmethod
    def _check_label_value_syntax(val, key, key_container):
        """
        checking validity of the label's value
        :param string val : the value to be checked
        :param string key: The key name which the value is assigned for
        :param dict key_container : The label selector's part where the key and val appear
        :return: None
        """
        if val is None:
            raise Exception(f'Value label of "{key}" can not be null', key_container)
        if val:
            if len(val) > 63:
                raise Exception(f'Invalid value "{val}" for "{key}", '
                                f'a label value must be no more than 63 characters', key_container)
            pattern = r"(([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9])?"
            if re.fullmatch(pattern, val) is None:
                raise Exception(f'Invalid value "{val}" for "{key}", '
                                f'value label must be an empty string or consist of alphanumeric characters, "-", "_" '
                                f'or ".", and must start and end with an alphanumeric character ', key_container)
