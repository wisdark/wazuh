#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest import TestCase
from unittest.mock import patch
import pytest

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh import WazuhException
        from wazuh.cdb_list import get_lists, get_path_lists, get_list_from_file

class TestCDBList(TestCase):

    def test_get_lists(self):
        result = get_lists()
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result['totalItems'], int)
        self.assertIsInstance(result['items'], list)

    def test_get_lists_limit(self):
        with self.assertRaises(WazuhException) as cm:
            get_lists(limit=0)

        self.assertEqual(cm.exception.code, 1406)

        result = get_lists(limit=1)
        self.assertEqual(result['totalItems'], 1)
        result = get_lists(limit=3)
        self.assertEqual(result['totalItems'], 3)

    def test_get_lists_offset(self):
        result_a = get_lists(offset=0)
        result_b = get_lists(offset=1)
        self.assertNotEqual(result_a, result_b)

    def test_get_lists_search(self):
        # search parameter is a dictionary with values value and negation
        result = get_lists(search={'value': 'audit-keys', 'negation': 0})
        self.assertEqual(len(result['items']), 1)

        result = get_lists(search={'value': 'AAABBBCCC', 'negation': 0})
        self.assertEqual(len(result['items']), 0)

    def test_get_lists_sort(self):
        # sort parameter is a dictionary with values fields and order
        result_a = get_lists(sort={'fields': ['path'], 'order': 'asc'})
        result_b = get_lists(sort={'fields': ['path'], 'order': 'desc'})
        self.assertNotEqual(result_a, result_b)

    def test_get_lists_path(self):
        result = get_lists(path='etc/lists/audit-keys')
        self.assertEqual(len(result['items']), 1)

        with self.assertRaises(WazuhException) as cm:
            get_lists(path='wrong_path')

        self.assertEqual(cm.exception.code, 1801)

    def test_get_path_lists(self):
        result = get_path_lists()
        self.assertIsInstance(result, dict)
        self.assertIsInstance(result['totalItems'], int)
        self.assertIsInstance(result['items'], list)

    def test_get_path_lists_limit(self):
        with self.assertRaises(WazuhException) as cm:
            get_path_lists(limit=0)

        self.assertEqual(cm.exception.code, 1406)

        result = get_path_lists(limit=1)
        self.assertEqual(result['totalItems'], 1)
        result = get_path_lists(limit=3)
        self.assertEqual(result['totalItems'], 3)

    def test_get_path_lists_offset(self):
        result_a = get_path_lists(offset=0)
        result_b = get_path_lists(offset=1)
        self.assertNotEqual(result_a, result_b)

    def test_get_path_lists_search(self):
        # search parameter is a dictionary with values value and negation
        result = get_path_lists(search={'value': 'audit-keys', 'negation': 0})
        self.assertEqual(len(result['items']), 1)

        result = get_path_lists(search={'value': 'AAABBBCCC', 'negation': 0})
        self.assertEqual(len(result['items']), 0)

    def test_get_path_lists_sort(self):
        # sort parameter is a dictionary with values fields and order
        result_a = get_path_lists(sort={'fields': ['path'], 'order': 'asc'})
        result_b = get_path_lists(sort={'fields': ['path'], 'order': 'desc'})
        self.assertNotEqual(result_a, result_b)
        result_a = get_path_lists(sort={'fields': ['name'], 'order': 'asc'})
        result_b = get_path_lists(sort={'fields': ['name'], 'order': 'desc'})
        self.assertNotEqual(result_a, result_b)

@pytest.mark.parametrize('error_type, expected_exception', [
    (IOError, 1006),
    (ValueError, 1800),
    (Exception, 1000)
])
def test_failed_get_list_from_file(error_type, expected_exception):
    with patch("wazuh.cdb_list.open", side_effect=error_type):
        with pytest.raises(WazuhException, match=f'.* {expected_exception} .*'):
            get_list_from_file('test')