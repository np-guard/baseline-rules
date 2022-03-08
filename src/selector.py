#
# Copyright 2020- IBM Inc. All rights reserved
# SPDX-License-Identifier: Apache2.0
#

"""
Various utilities to build k8s-style label selectors and check if they match  given set of labels
"""

from enum import Enum
from ipaddress import ip_network
import re


class Selector:
    """
    A base class for Selectors (either ip-based or label-based)
    """

    @staticmethod
    def parse_selectors(selectors_str):
        """
        Parses a comma-separated list of selectors expressions
        :param str selectors_str: The string to parse
        :return: A list of Selector instances, representing the selectors in the string
        :rtype: list[Selector]
        """
        selectors_str = selectors_str.strip()
        if not selectors_str:
            return []
        try:
            ipn = ip_network(selectors_str, False)
            return IpSelector(ipn)
        except ValueError:
            pass

        selectors = re.split(r',\s*(?![^()]*\))', selectors_str)  # split by commas, but not commas inside parentheses
        res = []
        for selector in selectors:
            res.append(LabelSelector.parse_selector(selector))
        return res


class IpSelector(Selector):
    """
    A class representing an ipBlock selector
    """

    def __init__(self, ipn):
        self.ipn = ipn

    def get_cidr(self):
        """
        :return: The ip range as k8s IPBlock record
        :rtype: dict
        """
        return {'cidr': str(self.ipn)}

    def get_nets_calico(self):
        """
        :return: The ip range as Calico nets
        :rtype: list
        """
        return [str(self.ipn)]


class SelectorOp(Enum):
    """
    Supported selector ops
    """
    IN = 0
    NOT_IN = 1
    EXISTS = 2
    DOES_NOT_EXIST = 3


class LabelSelector(Selector):
    """
    A class representing a single label selector as described here:
    https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement
    """

    def __init__(self, key, op, values, calico_selector_expr):
        """
        :param str key: Label key
        :param SelectorOp op: The selector operator
        :param list values: A list of label values
        :param str calico_selector_expr: the Selector expr by Calico syntax
        """
        self.key = key
        self.operator = op
        self.values = values
        self.calico_selector_expr = calico_selector_expr

    def matches(self, labels):
        """
        Check if the selector matches a given set of labels (key-value pairs)
        :param dict labels: a set of labels (as a dict)
        :return: Whether or not the selector matches the set of labels
        :rtype: bool
        """
        if self.operator == SelectorOp.EXISTS:
            return self.key in labels.keys()
        if self.operator == SelectorOp.DOES_NOT_EXIST:
            return self.key not in labels.keys()
        if self.operator == SelectorOp.IN:
            return self.key in labels.keys() and labels[self.key] in self.values
        # here self.operator == SelectorOp.NOT_IN:
        return self.key not in labels.keys() or labels[self.key] not in self.values

    def convert_to_label_selector_requirement(self):
        """
        :return: A LabelSelectorRequirement representing the selector
        https://v1-18.docs.kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#labelselectorrequirement-v1-meta
        :rtype: dict
        """
        op_to_str = {SelectorOp.IN: 'In', SelectorOp.NOT_IN: 'NotIn', SelectorOp.EXISTS: 'Exists',
                     SelectorOp.DOES_NOT_EXIST: 'DoesNotExist'}
        return {'key': self.key, 'operator': op_to_str[self.operator], 'values': self.values}

    @staticmethod
    def _parse_value_list(value_list):
        """
        Parse a list of values, given in the format: '(val1, val2, val3)'
        :param value_list: A string with the list of values
        :return: A list of strings, each representing a single value
        :rtype: list[str]
        """
        value_list = value_list[1:-1]  # chop parentheses
        values = value_list.split(',')
        return [val.strip() for val in values]

    @staticmethod
    def parse_selector(selector):
        """
        Parse a single selector, as defined in
        https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#set-based-requirement

        Add also conversion of k8s Set-based requirement to Calico selector expression:
        https://projectcalico.docs.tigera.io/reference/resources/globalnetworkpolicy#selectors
        Examples for relevant Calico selector exprs:
        k in { 'v1', 'v2' } , k not in { 'v1', 'v2' } , k == 'v' , k != 'v' , has(k) , !has(k)
        Examples for relevant k8s Set-based requirement expr:
        environment in (production, qa) , tier notin (frontend, backend) , partition , !partition , environment!=qa,
        environment=production

        :param str selector: a string with selector expression
        :return: An instance of the Selector class
        """
        selector = selector.strip()
        if selector.startswith('!'):
            calico_selector_expr = f'!has({selector[1:]})'
            return LabelSelector(selector[1:], SelectorOp.DOES_NOT_EXIST, [], calico_selector_expr)

        not_equal_pos = selector.find('!=')
        if not_equal_pos != -1:
            calico_selector_expr = f'{selector[:not_equal_pos].strip()} != \'{selector[not_equal_pos + 2:].strip()}\''
            return LabelSelector(selector[:not_equal_pos].strip(), SelectorOp.NOT_IN,
                                 [selector[not_equal_pos + 2:].strip()], calico_selector_expr)

        equal_pos = selector.find('=')
        if equal_pos != -1:
            calico_selector_expr = f'{selector[:equal_pos].strip()} == \'{selector[equal_pos + 1:].strip()}\''

            return LabelSelector(selector[:equal_pos].strip(), SelectorOp.IN, [selector[equal_pos + 1:].strip()],
                                 calico_selector_expr)

        not_in_pos = re.search(r'\s+notin\s+\(', selector)
        if not_in_pos:
            value_list = LabelSelector._parse_value_list(selector[not_in_pos.end() - 1:])
            values_expr = '{' + ', '.join(f'\'{x}\'' for x in value_list) + '}'
            calico_selector_expr = f'{selector[:not_in_pos.start()]} not in {values_expr}'
            return LabelSelector(selector[:not_in_pos.start()], SelectorOp.NOT_IN, value_list, calico_selector_expr)

        in_pos = re.search(r'\s+in\s+\(', selector)
        if in_pos:
            value_list = LabelSelector._parse_value_list(selector[in_pos.end() - 1:])
            values_expr = '{' + ', '.join(f'\'{x}\'' for x in value_list) + '}'
            calico_selector_expr = f'{selector[:in_pos.start()]} in {values_expr}'
            return LabelSelector(selector[:in_pos.start()], SelectorOp.IN, value_list, calico_selector_expr)

        calico_selector_expr = f'has({selector[1:]})'
        return LabelSelector(selector, SelectorOp.EXISTS, [], calico_selector_expr)
