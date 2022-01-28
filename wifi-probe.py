#!/usr/bin/env python3

from scapy.all import sniff, Dot11, Dot11ProbeReq
from datetime import datetime
import os
import humanize
import signal
import sys

# config
DISPLAY_PROBES_MAX = 16

# colors, control sequences
TERM_RED           = '\033[91m'
TERM_GREEN         = '\033[92m'
TERM_YELLOW        = '\033[93m'
TERM_BLUE          = '\033[94m'
TERM_MAGENTA       = '\033[95m'
TERM_BOLD          = '\033[1m'
TERM_RESET         = '\033[0m'
TERM_POS_ZERO      = '\033[0;0H'

# probe database
probes = []

def signal_handler(signal, frame):
    print(TERM_RESET)
    sys.exit(0)

def get_termsize():
    y, x = os.popen('stty size', 'r').read().split()
    return int(x), int(y)

def rssi_bars (rssi):
    if rssi < -70:
        bar = TERM_RED + "▁___" + TERM_RESET
    elif -90 <= rssi < -70:
        bar = TERM_ORANGE + "▁▃__" + TERM_RESET
    elif -70 <= rssi < -50:
        bar = TERM_YELLOW + "▁▃▅_" + TERM_RESET   
    else:
        bar =TERM_GREEN + "▁▃▅▇" + TERM_RESET
    return bar

def update_probes(probe):
    probe['last_seen'] = datetime.now()

    # if ssid in database, update
    updated = False
    for i in range(len(probes)):
        if probes[i]['ssid'] == probe['ssid']:
            probes[i] = probe
            updated = True

    # if ssid not in database, insert
    if not updated:
        if len(probes) < DISPLAY_PROBES_MAX:
            probes.append(probe)
        else:
            while len(probes) > DISPLAY_PROBES_MAX:
                oldest = 0
                for i in range(len(probes)):
                    if probes[i]['last_seen'] < probes[oldest]['last_seen']:
                        oldest = i
                del probes[oldest]
            oldest = 0
            for i in range(len(probes)):
                if probes[i]['last_seen'] < probes[oldest]['last_seen']:
                    oldest = i
            probes[oldest] = probe


def print_probes():
    termx, termy = get_termsize()
    col_width = (termx - 2 )// 2 # floor division
    DISPLAY_PROBES_MAX = termy - 2

    print(TERM_RESET + TERM_POS_ZERO + str(datetime.now().strftime("%Y-%m-%d %H:%M:%S")).center(termx) + "\n")
    
    # Sort the probes per order of last_seen
    probes_display = sorted(probes, key=lambda d: d['last_seen'], reverse=True)
    
    for i in range(len(probes_display)):
        probe = probes_display[i]
        out = ''
        out += TERM_BOLD
        # we must add 9 to col_width because of the special chars not counting
        out += (probe['ssid'] + " " + rssi_bars(probe['rssi'])).rjust(col_width + 9)
        out += '  '
        out += TERM_RESET + TERM_BLUE
        out += humanize.naturaltime(probe['last_seen']).ljust(col_width)
        out += TERM_RESET 
        print(out)


def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 4:
            ssid = pkt.getlayer(Dot11ProbeReq).info.decode("utf-8")
            if len(ssid):
                try:
                    signal_strength = pkt.dBm_AntSignal
                except:
                    signal_strength = 0
                probe = {}
                probe['ssid'] = ssid
                probe['rssi'] = signal_strength
                update_probes(probe)
                print_probes()


if __name__=="__main__":
    signal.signal(signal.SIGINT, signal_handler)
    os.system('clear')
    while(True):
        print_probes()
        sniff(iface=sys.argv[1], prn=packet_handler, count=75)
