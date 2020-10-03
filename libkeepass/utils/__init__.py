# -*- coding: utf-8 -*-

import datetime


def parse_timestamp(date_text):
    "Parse timestamp"
    return datetime.datetime.strptime(str(date_text), '%Y-%m-%dT%H:%M:%SZ')

def unparse_timestamp(dt):
    "Create timestamp from datetime object"
    return "{:%Y-%m-%dT%H:%M:%S}Z".format(dt)

def cmp_times(self, el1, el2, timetag='LastModificationTime'):
    "Compare el1 and el2 by the specified time tag."
    el1_has_times = el1.find('./Times') is not None
    el2_has_times = el2.find('./Times') is not None
    assert el1_has_times or el2_has_times, (el1, el2)
    if not el1_has_times:
        return -2
    if not el2_has_times:
        return 2
    
    el1_modtime = parse_timestamp(getattr(el1.Times, timetag))
    el2_modtime = parse_timestamp(getattr(el2.Times, timetag))
    return (el1_modtime < el2_modtime and -1) or \
           (el1_modtime > el2_modtime and 1) or 0

