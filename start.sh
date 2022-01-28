#!/bin/bash 

IFACE="wlx502b73db22e5"

ifconfig ${IFACE} down
iwconfig ${IFACE} mode monitor
ifconfig ${IFACE} up

./wifi-probe.py ${IFACE}
