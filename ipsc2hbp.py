#!/usr/bin/env python
#
###############################################################################
# hb_router.py -- a call routing applicaiton for hblink.py
#   Copyright (C) 2016  Cortney T. Buffington, N0MJS <n0mjs@me.com>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
###############################################################################


from __future__ import print_function

# Python modules we need
import sys
import os
import argparse
from binascii import b2a_hex as h
from bitarray import bitarray
from time import time

# Twisted is pretty important, so I keep it separate
from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor
from twisted.internet import task

# Change the current directory to the location of the application
os.chdir(os.path.dirname(os.path.realpath(sys.argv[0])))

# CLI argument parser - handles picking up the config file from the command line, and sending a "help" message
parser = argparse.ArgumentParser()
parser.add_argument('-c', '--config', action='store', dest='CONFIG_FILE', help='/full/path/to/config.file (usually hblink.cfg)')
parser.add_argument('-l', '--logging', action='store', dest='LOG_LEVEL', help='Override config file logging level.')
cli_args = parser.parse_args()

sys.path.insert(1, '../DMRlink')
sys.path.insert(1, '../HBlink')

from hblink import CONFIG, HBSYSTEM, logger, systems, hex_str_3, hex_str_4, int_id, sub_alias, peer_alias, tg_alias
from dmrlink import IPSC, NETWORK, networks

# Does anybody read this stuff? There's a PEP somewhere that says I should do this.
__author__     = 'Cortney T. Buffington, N0MJS'
__copyright__  = 'Copyright (c) 2016 Cortney T. Buffington, N0MJS and the K0USY Group'
__credits__    = 'Colin Durbridge, G4EML, Steve Zingman, N4IRS; Mike Zingman, N4IRR; Jonathan Naylor, G4KLX; Hans Barthen, DL5DI; Torsten Shultze, DG1HT'
__license__    = 'GNU GPLv3'
__maintainer__ = 'Cort Buffington, N0MJS'
__email__      = 'n0mjs@me.com'


class hbp2ipsc(HBSYSTEM):
    def __init__(self, _name, _config):
        HBSYSTEM.__init__(self, _name, _config)

    def dmrd_received(self, _radio_id, _rf_src, _dst_id, _seq, _slot, _call_type, _frame_type, _dtype_vseq, _stream_id, _data):
            dmrpkt = _data[20:53]
            _bits = int_id(_data[15])

class ipsc2hbp(IPSC):
    def __init__(self, *args, **kwargs):
        IPSC.__init__(self, *args, **kwargs)
    
    def group_voice(self, _network, _src_sub, _dst_group, _ts, _end, _peerid, _data):
        _burst_data_type = _data[30]
        _seq_id = _data[5]       


#************************************************
#      MAIN PROGRAM LOOP STARTS HERE
#************************************************
    
if __name__ == '__main__':
    logger.info('ipsc2hbp \'ipsc2hbp.py\' (c) 2016 N0MJS & the K0USY Group - SYSTEM STARTING...')
    
    # INITIALIZE AN IPSC OBJECT (SELF SUSTAINING) FOR EACH CONFIGUED IPSC
    for ipsc_network in NETWORK:
        if NETWORK[ipsc_network]['LOCAL']['ENABLED']:
            networks[ipsc_network] = ipsc2hbp(ipsc_network)
            reactor.listenUDP(NETWORK[ipsc_network]['LOCAL']['PORT'], networks[ipsc_network], interface=NETWORK[ipsc_network]['LOCAL']['IP'])
    
    # HBlink instance creation
    for system in CONFIG['SYSTEMS']:
        if CONFIG['SYSTEMS'][system]['ENABLED']:
            systems[system] = hbp2ipsc(system, CONFIG)
            reactor.listenUDP(CONFIG['SYSTEMS'][system]['PORT'], systems[system], interface=CONFIG['SYSTEMS'][system]['IP'])
            logger.debug('%s instance created: %s, %s', CONFIG['SYSTEMS'][system]['MODE'], system, systems[system])
       
    reactor.run()