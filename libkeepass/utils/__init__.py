# -*- coding: utf-8 -*-

import datetime


def parse_timestamp(date_text):
    "Parse timestamp"
    return datetime.datetime.strptime(str(date_text), '%Y-%m-%dT%H:%M:%SZ')

def unparse_timestamp(dt):
    "Create timestamp from datetime object"
    return "{:%Y-%m-%dT%H:%M:%S}Z".format(dt)
