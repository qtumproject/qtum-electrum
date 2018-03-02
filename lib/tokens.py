#!/usr/bin/env python
#
# -*- coding: utf-8 -*-
"""
__author__ = 'CodeFace'
"""
from .storage import ModelStorage


class Tokens(ModelStorage):

    def __index__(self, storage):
        ModelStorage.__init__(self, 'tokens', storage)

    def _validate(self, data):
        pass
