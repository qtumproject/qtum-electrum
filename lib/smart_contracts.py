#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
import re
import json

from . import qtum
from .util import print_error
from .i18n import _

storage_key = 'smart_contracts'


# address: [name, type, abi]


class SmartContracts(dict):
    def __init__(self, storage):
        self.storage = storage
        d = self.storage.get(storage_key, {})
        try:
            self.update(d)
        except:
            return

    def save(self):
        self.storage.put(storage_key, dict(self))

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.save()

    def pop(self, key):
        if key in self.keys():
            dict.pop(self, key)
            self.save()

    def find_regex(self, haystack, needle):
        regex = re.compile(needle)
        try:
            return regex.search(haystack).groups()[0]
        except AttributeError:
            return None

    def import_file(self, path):
        try:
            with open(path, 'r') as f:
                d = self._validate(json.loads(f.read()))
        except:
            return
        self.update(d)
        self.save()

    def _validate(self, data):
        for k, v in list(data.items()):
            if k == storage_key:
                return self._validate(v)
            if not len(k) == 40:
                data.pop(k)
        return data
