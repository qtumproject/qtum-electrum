#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from collections import namedtuple
from .storage import ModelStorage
from . import qtum

Token = namedtuple('Token', ['contract_addr', 'bind_addr', 'name', 'symbol', 'decimals', 'balance'])


class Tokens(ModelStorage):

    # key: contract_addr + _ + bind_addr
    # value: { name, symbol, decimals, balance }

    def __init__(self, storage):
        ModelStorage.__init__(self, 'tokens', storage)

    def _validate(self, data):
        for k, v in list(data.items()):
            if k == self.name:
                return self._validate(v)

            kk = k.split('_')
            if not len(kk) == 2:
                data.pop(k)
                continue

            contract_addr, bind_addr = kk
            if not qtum.is_hash160(contract_addr) or not len(bind_addr) == 34:
                data.pop(k)
                continue

            if not len(v) == 4:
                data.pop(k)
                continue
