
import os

moddir = os.path.dirname(__file__)

DATAPATH = os.path.abspath(os.path.join(moddir, 'data'))

def get_datafile(datafile):
    return os.path.join(DATAPATH, datafile)

