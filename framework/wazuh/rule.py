# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
from glob import glob
from xml.etree.ElementTree import fromstring
import wazuh.configuration as configuration
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import cut_array, sort_array, search_array, load_wazuh_xml, filter_array_by_query
import os
from sys import version_info


class Rule:
    """
    Rule Object.
    """

    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'description', 'id', 'level', 'status']

    def __init__(self):
        self.file = None
        self.path = None
        self.description = ""
        self.id = None
        self.level = None
        self.status = None
        self.groups = []
        self.pci = []
        self.gpg13 = []
        self.gdpr = []
        self.hipaa = []
        self.nist_800_53 = []
        self.tsc = []
        self.mitre = []
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Rule):
            return self.id < other.id
        else:
            raise WazuhException(1204)

    def __le__(self, other):
        if isinstance(other, Rule):
            return self.id <= other.id
        else:
            raise WazuhException(1204)

    def __gt__(self, other):
        if isinstance(other, Rule):
            return self.id > other.id
        else:
            raise WazuhException(1204)

    def __ge__(self, other):
        if isinstance(other, Rule):
            return self.id >= other.id
        else:
            raise WazuhException(1204)

    def to_dict(self):
        return {'file': self.file, 'path': self.path, 'id': self.id, 'description': self.description,
                'level': self.level, 'status': self.status, 'groups': self.groups, 'pci': self.pci, 'gdpr': self.gdpr,
                'hipaa': self.hipaa, 'nist-800-53': self.nist_800_53, 'gpg13': self.gpg13, 'tsc': self.tsc, 'details': self.details, 'mitre': self.mitre}


    def set_group(self, group):
        """
        Adds a group to the group list.
        :param group: Group to add (string or list)
        """

        Rule.__add_unique_element(self.groups, group)

    def set_pci(self, pci):
        """
        Adds a pci requirement to the pci list.
        :param pci: Requirement to add (string or list).
        """

        Rule.__add_unique_element(self.pci, pci)

    def set_gpg13(self, gpg13):
        """
        Adds a gpg13 requirement to the gpg13 list.
        :param gpg13: Requirement to add (string or list).
        """

        Rule.__add_unique_element(self.gpg13, gpg13)

    def set_gdpr(self, gdpr):
        """
        Adds a gdpr requirement to the gdpr list.
        :param gdpr: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.gdpr, gdpr)

    def set_hipaa(self, hipaa):
        """
        Adds a hipaa requirement to the hipaa list.
        :param hipaa: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.hipaa, hipaa)

    def set_nist_800_53(self, nist_800_53):
        """
        Adds a nist_800_53 requirement to the nist_800_53 list.
        :param nist_800_53: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.nist_800_53, nist_800_53)


    def set_tsc(self, tsc):
        """
        Adds a tsc requirement to the tsc list.
        :param tsc: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.tsc, tsc)

    def set_mitre(self, mitre):
        """
        Adds a mitre requirement to the mitre list.
        :param mitre: Requirement to add (string or list).
        """
        Rule.__add_unique_element(self.mitre, mitre)

    def add_detail(self, detail, value):
        """
        Add a rule detail (i.e. category, noalert, etc.).

        :param detail: Detail name.
        :param value: Detail value.
        """
        if detail in self.details:
            # If it was an element, we create a list.
            if type(self.details[detail]) is not list:
                element = self.details[detail]
                self.details[detail] = [element]

            self.details[detail].append(value)
        else:
            self.details[detail] = value

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
    def __check_status(status):
        if status is None:
            return Rule.S_ALL
        elif status in [Rule.S_ALL, Rule.S_ENABLED, Rule.S_DISABLED]:
            return status
        else:
            raise WazuhException(1202)

    @staticmethod
    def get_rules_files(status=None, path=None, file=None, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of the rule files.

        :param status: Filters by status: enabled, disabled, all.
        :param path: Filters by path.
        :param file: Filters by filename.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        data = []
        status = Rule.__check_status(status)

        # Rules configuration
        ruleset_conf = configuration.get_ossec_conf(section='ruleset')
        if not ruleset_conf:
            raise WazuhException(1200)

        tmp_data = []
        tags = ['rule_include', 'rule_exclude']
        exclude_filenames = []
        for tag in tags:
            if tag in ruleset_conf:
                item_status = Rule.S_DISABLED if tag == 'rule_exclude' else Rule.S_ENABLED

                if type(ruleset_conf[tag]) is list:
                    items = ruleset_conf[tag]
                else:
                    items = [ruleset_conf[tag]]

                for item in items:
                    item_name = os.path.basename(item)
                    full_dir = os.path.dirname(item)
                    item_dir = os.path.relpath(full_dir if full_dir else common.ruleset_rules_path,
                                               start=common.ossec_path)
                    if tag == 'rule_exclude':
                        exclude_filenames.append(item_name)
                    else:
                        tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

        tag = 'rule_dir'
        if tag in ruleset_conf:
            if type(ruleset_conf[tag]) is list:
                items = ruleset_conf[tag]
            else:
                items = [ruleset_conf[tag]]

            for item_dir in items:
                all_rules = "{0}/{1}/*.xml".format(common.ossec_path, item_dir)

                for item in glob(all_rules):
                    item_name = os.path.basename(item)
                    item_dir = os.path.relpath(os.path.dirname(item), start=common.ossec_path)
                    if item_name in exclude_filenames:
                        item_status = Rule.S_DISABLED
                    else:
                        item_status = Rule.S_ENABLED
                    tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

        data = list(tmp_data)
        for d in tmp_data:
            if status and status != 'all' and status != d['status']:
                data.remove(d)
                continue
            if path and path != d['path']:
                data.remove(d)
                continue
            if file and file != d['file']:
                data.remove(d)
                continue

        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, sort['fields'], sort['order'])
        else:
            data = sort_array(data, ['file'], 'asc')

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}

    @staticmethod
    def get_rules(offset=0, limit=common.database_limit, sort=None, search=None, filters={}, q=''):
        """
        Gets a list of rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}.
            This filter is used for filtering by 'status', 'group', 'pci', 'gpg13', 'gdpr', 'hipaa', 'nist-800-53', 'tsc', 'mitre', 'file', 'path', 'id' and 'level'.
        :param q: Defines query to filter.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # set default values to parameters
        status = filters.get('status', None)
        group = filters.get('group', None)
        pci = filters.get('pci', None)
        gpg13 = filters.get('gpg13', None)
        gdpr = filters.get('gdpr', None)
        hipaa = filters.get('hipaa', None)
        nist_800_53 = filters.get('nist-800-53', None)
        tsc = filters.get('tsc', None)
        mitre = filters.get('mitre', None)
        path = filters.get('path', None)
        file_ = filters.get('file', None)
        id_ = filters.get('id', None)
        level = filters.get('level', None)

        all_rules = []

        if level:
            levels = level.split('-')
            if len(levels) < 0 or len(levels) > 2:
                raise WazuhException(1203)

        for rule_file in Rule.get_rules_files(status=status, limit=None)['items']:
            all_rules.extend(Rule.__load_rules_from_file(rule_file['file'], rule_file['path'], rule_file['status']))

        rules = list(all_rules)
        for r in all_rules:
            if group and group not in r.groups:
                rules.remove(r)
                continue
            elif pci and pci not in r.pci:
                rules.remove(r)
                continue
            elif gpg13 and gpg13 not in r.gpg13:
                rules.remove(r)
                continue
            elif gdpr and gdpr not in r.gdpr:
                rules.remove(r)
                continue
            elif hipaa and hipaa not in r.hipaa:
                rules.remove(r)
                continue
            elif nist_800_53 and nist_800_53 not in r.nist_800_53:
                rules.remove(r)
                continue
            elif tsc and tsc not in r.tsc:
                rules.remove(r)
                continue
            elif mitre and mitre not in r.mitre:
                rules.remove(r)
                continue
                rules.remove(r)
                continue
            elif path and path != r.path:
                rules.remove(r)
                continue
            elif file_ and file_ != r.file:
                rules.remove(r)
                continue
            elif id_ and int(id_) != r.id:
                rules.remove(r)
                continue
            elif level:
                if len(levels) == 1:
                    if int(levels[0]) != r.level:
                        rules.remove(r)
                        continue
                elif not (int(levels[0]) <= r.level <= int(levels[1])):
                    rules.remove(r)
                    continue

        if search:
            rules = search_array(rules, search['value'], search['negation'])

        if q:
            # rules contains a list of Rule objects, it is necessary to cast it into dictionaries
            rules = filter_array_by_query(q, [rule.to_dict() for rule in rules])

        if sort:
            rules = sort_array(rules, sort['fields'], sort['order'], Rule.SORT_FIELDS)
        else:
            rules = sort_array(rules, ['id'], 'asc')

        return {'items': cut_array(rules, offset, limit), 'totalItems': len(rules)}

    @staticmethod
    def get_groups(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the groups used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        groups = set()

        for rule in Rule.get_rules(limit=None)['items']:
            for group in rule.groups:
                groups.add(group)

        if search:
            groups = search_array(groups, search['value'], search['negation'])

        if sort:
            groups = sort_array(groups, order=sort['order'])
        else:
            groups = sort_array(groups)

        return {'items': cut_array(groups, offset, limit), 'totalItems': len(groups)}

    @staticmethod
    def _get_requirement(requirement, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get the requirements used in the rules

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param requirement: requirement to get (pci, gpg13 or dgpr)
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        valid_requirements = ['pci', 'gdpr', 'gpg13', 'hipaa', 'nist-800-53', 'tsc', 'mitre']

        if requirement not in valid_requirements:
            raise WazuhException(1205, requirement)

        req = list({req for rule in Rule.get_rules(limit=None)['items'] for req in rule.to_dict()[requirement]})

        if search:
            req = search_array(req, search['value'], search['negation'])

        if sort:
            req = sort_array(req, order=sort['order'])
        else:
            req = sort_array(req)

        return {'items': cut_array(req, offset, limit), 'totalItems': len(req)}

    @staticmethod
    def get_pci(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the PCI requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        return Rule._get_requirement('pci', offset=offset, limit=limit, sort=sort, search=search)

    @staticmethod
    def get_gpg13(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the GPG13 requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('gpg13', offset=offset, limit=limit, sort=sort, search=search)

    @staticmethod
    def get_gdpr(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the GDPR requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('gdpr', offset=offset, limit=limit, sort=sort, search=search)

    @staticmethod
    def get_hipaa(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the HIPAA requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('hipaa', offset=offset, limit=limit, sort=sort, search=search)

    @staticmethod
    def get_nist_800_53(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the NIST-800-53 requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('nist-800-53', offset=offset, limit=limit, sort=sort, search=search)

    @staticmethod
    def get_tsc(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the TSC requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('tsc', offset=offset, limit=limit, sort=sort, search=search)


    @staticmethod
    def get_mitre(offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Get all the Mitre requirements used in the rules.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        return Rule._get_requirement('mitre', offset=offset, limit=limit, sort=sort, search=search)


    @staticmethod
    def __load_rules_from_file(rule_file, rule_path, rule_status):
        try:
            rules = []

            root = load_wazuh_xml(os.path.join(common.ossec_path, rule_path, rule_file))

            for xml_group in list(root):
                if xml_group.tag.lower() == "group":
                    general_groups = xml_group.attrib['name'].split(',')
                    for xml_rule in list(xml_group):
                        # New rule
                        if xml_rule.tag.lower() == "rule":
                            groups = []
                            mitre = []
                            rule = Rule()
                            rule.file = rule_file
                            rule.path = rule_path
                            rule.id = int(xml_rule.attrib['id'])
                            rule.level = int(xml_rule.attrib['level'])
                            rule.status = rule_status

                            for k in xml_rule.attrib:
                                if k != 'id' and k != 'level':
                                    rule.details[k] = xml_rule.attrib[k]

                            for xml_rule_tags in list(xml_rule):
                                tag = xml_rule_tags.tag.lower()
                                value = xml_rule_tags.text
                                if value == None:
                                    value = ''
                                if tag == "group":
                                    groups.extend(value.split(","))
                                if tag == "mitre":
                                    for mitre_attack in list(xml_rule_tags):
                                        mitre.append(mitre_attack.text)
                                elif tag == "description":
                                    rule.description += value
                                elif tag == "field":
                                    rule.add_detail(xml_rule_tags.attrib['name'], value)
                                elif tag in ("list", "info"):
                                    list_detail = {'name': value}
                                    for attrib, attrib_value in xml_rule_tags.attrib.items():
                                        list_detail[attrib] = attrib_value
                                    rule.add_detail(tag, list_detail)
                                # show rule variables
                                elif tag in {'regex', 'match', 'user', 'id'} and value != '' and value[0] == "$":
                                    for variable in filter(lambda x: x.get('name') == value[1:], root.findall('var')):
                                        rule.add_detail(tag, variable.text)
                                else:
                                    rule.add_detail(tag, value)

                            # set mitre
                            rule.set_mitre(mitre)

                            # Set groups
                            groups.extend(general_groups)

                            pci_groups = []
                            gpg13_groups = []
                            gdpr_groups = []
                            hippa_groups = []
                            nist_800_53_groups = []
                            tsc_groups = []
                            ossec_groups = []
                            for g in groups:
                                if 'pci_dss_' in g:
                                    pci_groups.append(g.strip()[8:])
                                elif 'gpg13_' in g:
                                    gpg13_groups.append(g.strip()[6:])
                                elif 'gdpr_' in g:
                                    gdpr_groups.append(g.strip()[5:])
                                elif 'hipaa_' in g:
                                    hippa_groups.append(g.strip()[6:])
                                elif 'nist_800_53_' in g:
                                    nist_800_53_groups.append(g.strip()[12:])
                                elif 'tsc_' in g:
                                    tsc_groups.append(g.strip()[4:])
                                else:
                                    ossec_groups.append(g)

                            rule.set_pci(pci_groups)
                            rule.set_gpg13(gpg13_groups)
                            rule.set_gdpr(gdpr_groups)
                            rule.set_hipaa(hippa_groups)
                            rule.set_nist_800_53(nist_800_53_groups)
                            rule.set_tsc(tsc_groups)
                            rule.set_group(ossec_groups)

                            rules.append(rule)
        except Exception as e:
            raise WazuhException(1201, "{0}. Error: {1}".format(rule_file, str(e)))

        return rules
