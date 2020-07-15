# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import re
from glob import glob
from xml.etree.ElementTree import fromstring
import wazuh.configuration as configuration
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.utils import cut_array, sort_array, search_array, load_wazuh_xml, filter_array_by_query
from sys import version_info


class Decoder:
    """
    Decoder object.
    """

    S_ENABLED = 'enabled'
    S_DISABLED = 'disabled'
    S_ALL = 'all'
    SORT_FIELDS = ['file', 'path', 'name', 'position', 'status']

    def __init__(self):
        self.file = None
        self.path = None
        self.name = None
        self.position = None
        self.status = None
        self.details = {}

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'file': self.file, 'path': self.path, 'name': self.name, 'position': self.position, 'status': self.status, 'details': self.details}
        return dictionary

    def add_detail(self, detail, value):
        """
        Add a decoder detail (i.e. regex, order, prematch, etc.).

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
    def __check_status(status):
        if status is None:
            return Decoder.S_ALL
        elif status in [Decoder.S_ALL, Decoder.S_ENABLED, Decoder.S_DISABLED]:
            return status
        else:
            raise WazuhException(1202)

    @staticmethod
    def get_decoders_files(status=None, path=None, file=None, offset=0, limit=common.database_limit, sort=None, search=None):
        """
        Gets a list of the available decoder files.

        :param status: Filters by status: enabled, disabled, all.
        :param path: Filters by path.
        :param file: Filters by filename.
        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """

        status = Decoder.__check_status(status)

        ruleset_conf = configuration.get_ossec_conf(section='ruleset')
        if not ruleset_conf:
            raise WazuhException(1500)

        tmp_data = []
        tags = ['decoder_include', 'decoder_exclude']
        exclude_filenames = []
        for tag in tags:
            if tag in ruleset_conf:
                item_status = Decoder.S_DISABLED if tag == 'decoder_exclude' else Decoder.S_ENABLED

                if type(ruleset_conf[tag]) is list:
                    items = ruleset_conf[tag]
                else:
                    items = [ruleset_conf[tag]]

                for item in items:
                    item_name = os.path.basename(item)
                    full_dir = os.path.dirname(item)
                    item_dir = os.path.relpath(full_dir if full_dir else common.ruleset_rules_path,
                                               start=common.ossec_path)
                    if tag == 'decoder_exclude':
                        exclude_filenames.append(item_name)
                    else:
                        tmp_data.append({'file': item_name, 'path': item_dir, 'status': item_status})

        tag = 'decoder_dir'
        if tag in ruleset_conf:
            if type(ruleset_conf[tag]) is list:
                items = ruleset_conf[tag]
            else:
                items = [ruleset_conf[tag]]

            for item_dir in items:
                all_decoders = "{0}/{1}/*.xml".format(common.ossec_path, item_dir)

                for item in glob(all_decoders):
                    item_name = os.path.basename(item)
                    item_dir = os.path.relpath(os.path.dirname(item), start=common.ossec_path)
                    if item_name in exclude_filenames:
                        item_status = Decoder.S_DISABLED
                    else:
                        item_status = Decoder.S_ENABLED
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
    def get_decoders(offset=0, limit=common.database_limit, sort=None, search=None, filters={}, q=''):
        """
        Gets a list of available decoders.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :param filters: Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}.
            This filter is used for filtering by 'status', 'path', 'file', 'name' and 'parents'.
        :param q: Defines query to filter.

        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        # set default values to parameters
        status = filters.get('status', None)
        path = filters.get('path', None)
        file_ = filters.get('file', None)
        name = filters.get('name', None)
        parents = filters.get('parents', None)

        status = Decoder.__check_status(status)
        all_decoders = []

        for decoder_file in Decoder.get_decoders_files(status=status, limit=None)['items']:
            all_decoders.extend(Decoder.__load_decoders_from_file(decoder_file['file'], decoder_file['path'], decoder_file['status']))

        decoders = list(all_decoders)
        for d in all_decoders:
            if path and path != d.path:
                decoders.remove(d)
                continue
            if file_ and file_ != d.file:
                decoders.remove(d)
                continue
            if name and name != d.name:
                decoders.remove(d)
                continue
            if parents and 'parent' in d.details:
                decoders.remove(d)
                continue

        if search:
            decoders = search_array(decoders, search['value'], search['negation'])

        if q:
            # decoders contains a list of Decoder objects, it is necessary to cast it into dictionaries
            decoders = filter_array_by_query(q, [decoder.to_dict() for decoder in decoders])

        if sort:
            decoders = sort_array(decoders, sort['fields'], sort['order'], Decoder.SORT_FIELDS)
        else:
            decoders = sort_array(decoders, ['file', 'position'], 'asc')

        return {'items': cut_array(decoders, offset, limit), 'totalItems': len(decoders)}

    @staticmethod
    def __load_decoders_from_file(decoder_file, decoder_path, decoder_status):
        try:
            decoders = []
            position = 0

            root = load_wazuh_xml(os.path.join(common.ossec_path, decoder_path, decoder_file))

            for xml_decoder in list(root):
                # New decoder
                if xml_decoder.tag.lower() == "decoder":
                    decoder          = Decoder()
                    decoder.path     = decoder_path
                    decoder.file     = decoder_file
                    decoder.status   = decoder_status
                    decoder.name     = xml_decoder.attrib['name']
                    decoder.position = position
                    position += 1

                    for k in xml_decoder.attrib:
                        if k != 'name':
                            decoder.details[k] = xml_decoder.attrib[k]

                    for xml_decoder_tags in list(xml_decoder):
                        decoder.add_detail(xml_decoder_tags.tag.lower(), xml_decoder_tags.text)

                    decoders.append(decoder)
        except Exception as e:
            raise WazuhException(1501, "{0}. Error: {1}".format(decoder_file, str(e)))

        return decoders
