#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from collections import namedtuple
from .storage import ModelStorage
from . import qtum

Token = namedtuple('Token', 'contract_addr bind_addr name symbol decimals balance')


# bind_addr is base58 type


class Tokens(ModelStorage):

    # key: contract_addr + _ + bind_addr
    # value: { name, symbol, decimals, balance }

    def __init__(self, storage):
        ModelStorage.__init__(self, 'tokens', storage)

    def __getitem__(self, key):
        contract_addr, bind_addr = key.split('_')
        name, symbol, decimals, balance = ModelStorage.__getitem__(self, key)
        token = Token(contract_addr, bind_addr, name, symbol, decimals, balance)
        return token

    def __setitem__(self, key, token):
        """
        :type key: str
        :type token: Token
        """
        return ModelStorage.__setitem__(self, key, (token.name, token.symbol, token.decimals, token.balance))

    def get(self, key, d=None):
        if not ModelStorage.__getitem__(self, key):
            return d
        return self.__getitem__(key)

    def validate(self, data):
        for k, v in list(data.items()):
            if k == self.name:
                return self.validate(v)

            kk = k.split('_')
            if not len(kk) == 2:
                data.pop(k)
                continue

            contract_addr, bind_addr = kk
            if not len(bind_addr) == 34 or not qtum.is_hash160(contract_addr):
                data.pop(k)
                continue

            addr_type, __ = qtum.b58_address_to_hash160(bind_addr)
            if not addr_type == qtum.ADDRTYPE_P2PKH:
                data.pop(k)
                continue

            if not len(v) == 4:
                data.pop(k)
                continue
        return data
