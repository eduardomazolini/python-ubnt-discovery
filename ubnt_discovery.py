#!/usr/bin/env python3

##########################################
#   UBNT command line discovery tool     #
# Adriano Provvisiero - BV Networks 2016 #
#         www.bvnetworks.it              #
##########################################

import socket
import argparse
import json
import sys
import time

from struct import unpack
from functools import wraps

#pylint: disable=too-many-arguments
def retry(exception_to_check, default=None, tries=4, delay=3, backoff=2, logger=None):
    """Retry calling the decorated function using an exponential backoff.

    http://www.saltycrane.com/blog/2009/11/trying-out-retry-decorator-python/
    original from: http://wiki.python.org/moin/PythonDecoratorLibrary#Retry

    :param exception_to_check: the exception to check. may be a tuple of
        exceptions to check
    :type exception_to_check: Exception or tuple
    :param tries: number of times to try (not retry) before giving up
    :type tries: int
    :param delay: initial delay between retries in seconds
    :type delay: int
    :param backoff: backoff multiplier e.g. value of 2 will double the delay
        each retry
    :type backoff: int
    :param logger: logger to use. If None, print
    :type logger: logging.Logger instance
    """
    def deco_retry(func):

        @wraps(func)
        def f_retry(*args, **kwargs):
            mtries, mdelay = tries, delay
            while mtries > 1:
                try:
                    return func(*args, **kwargs)
                except exception_to_check as ex:
                    msg = "%s, Retrying in %d seconds..." % (str(ex), mdelay)
                    if logger:
                        logger.warning(msg)
                    else:
                        print(msg)
                    time.sleep(mdelay)
                    mtries -= 1
                    mdelay *= backoff
            try:
                return func(*args, **kwargs)
            except exception_to_check as ex:
                return default

        return f_retry  # true decorator

    return deco_retry

def mac_repr(data):
    return ':'.join(('%02x' % b) for b in data)

def ip_repr(data):
    return '.'.join(('%d' % b) for b in data)

# Wirelss modes
UBNT_WIRELESS_MODES = {
    0x00: "Auto",
    0x01: "adhoc",
    0x02: "Station",
    0x03: "AP",
    0x04: "Repeater",
    0x05: "Secondary",
    0x06: "Monitor",
}

# field type -> (field name; parsing function (bytes->str); \
#                is it expected to be seen multiple times?)
FIELD_PARSERS = {
    0x01: ('mac', mac_repr, False),
    0x02: ('mac_ip', lambda data: '%s;%s' % (mac_repr(data[0:6]),
                                             ip_repr(data[6:10])), True),
    0x03: ('firmware', bytes.decode, False),
    0x0a: ('uptime', lambda data: int.from_bytes(data, 'big'), False),
    0x0b: ('name', bytes.decode, False),
    0x0c: ('model_short', bytes.decode, False),
    0x0d: ('essid', bytes.decode, False),
    0x0e: ('wlan_mode', lambda data:
           UBNT_WIRELESS_MODES.get(data[0], 'unknown'), False),
    0x10: ('unknown1', str, False),
    0x14: ('model', bytes.decode, False),
}

# Basic fields: src MAC and IP of reply message; not parsed
BASIC_FIELDS = {'mac', 'ip'}

# String representation of non-basic fields
FIELD_STR = {
    'mac':     'MAC',
    'mac_ip':   'MAC-IP Pairs',
    'firmware': 'Firmware',
    'uptime':   'Uptime',
    'name':     'Name',
    'model_short':  'Model (short)',
    'essid':    'ESSID',
    'wlan_mode':'WLAN Mode',
    'model':    'Model',
}

# UBNT discovery packet payload and reply signature
UBNT_REQUEST_PAYLOAD = b'\x01\x00\x00\x00'
UBNT_REPLY_SIGNATURE = b'\x01\x00\x00'

# Discovery timeout. Change this for quicker discovery
DISCOVERY_TIMEOUT = 5

def send_udp_broadcast(port, payload, timeout=3):
    host = '255.255.255.255'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)
    sock.bind(('', 0))
    sock.sendto(payload, (host, port))
    reply_list = []
    while True:
        try:
            # this is the problem here
            reply, address = sock.recvfrom(131072)
            if not reply:
                break
            reply_list.append((reply, address))
        except (KeyboardInterrupt, socket.timeout):
            break
    sock.close()
    return reply_list

@retry((socket.timeout, ConnectionResetError))
def send_udp(host, port, payload, timeout=2):
    '''
    Monta uma conexão e envia
    :param host: IP do host
    :type host: str
    :param port: Porta UDP
    :type port: int
    :param payload: Conteudo a ser enviado
    :type payload: bytearray
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect((host, port))
    sock.send(payload)
    try:
        payload = sock.recv(131072)
    finally:
        sock.close()
    return payload

def parse_args():
    parser = argparse.ArgumentParser(
        description="Discovers ubiquiti devices on network using ubnt device discovery protocol")
    parser.add_argument(
        '--host', type=str, help="host address name or ip")
    parser.add_argument(
        '--output-format', type=str, default='text', choices=('text', 'json'),
        help="output format")

    return parser.parse_args()

def iter_fields(data, _len):
    pointer = 0
    while pointer < _len:
        field_type, field_len = unpack('>BH', data[pointer:pointer+3])
        pointer += 3
        field_data = data[pointer:pointer+field_len]
        pointer += field_len
        yield field_type, field_data

def ubnt_discovery():
    payload = send_udp_broadcast(10001, UBNT_REQUEST_PAYLOAD, DISCOVERY_TIMEOUT)
    return ubnt_discovery_payload_parser(payload)

def ubnt_discovery_host(host):
    payload = send_udp(host, 10001, UBNT_REQUEST_PAYLOAD, DISCOVERY_TIMEOUT)
    return ubnt_discovery_payload_parser([(payload, (host, 0))])

def ubnt_discovery_payload_parser(ans):
    # Loop over received packets
    radio_list = []
    for rcv in ans:

        # We received a broadcast packet in reply to our discovery
        payload = rcv[0]

        # Check for a valid UBNT discovery reply (first 3 bytes of the payload should be \x01\x00\x00)
        if payload[0:3] == UBNT_REPLY_SIGNATURE:
            radio = {} # This should be a valid discovery reply packet sent by an Ubiquiti radio
        else:
            continue   # Not a valid UBNT discovery reply, skip to next received packet

        radio['ip'] = \
            rcv[1][0]   # We avoid going through the hassle of enumerating
                        # type '02' fields (MAC+IP). There may be multiple IPs on the radio,
                        # and therefore multiple type '02' fields in the reply packet.
                        # We conveniently pick the address from which the radio replied to our
                        # discovery request directly from the reply packet, and store it.

        # Walk the reply payload, staring from offset 04 (just after reply signature and payload size).
        # Take into account the payload length in offset 3
        for field_type, field_data in iter_fields(payload[4:], payload[3]):

            if field_type not in FIELD_PARSERS:
                sys.stderr.write("notice: unknown field type 0x%x: data %s\n" %
                                 (field_type, field_data))
                continue

            # Parse the field and store in Radio
            field_name, field_parser, is_many = FIELD_PARSERS[field_type]
            if is_many:
                if field_name not in radio:
                    radio[field_name] = []
                radio[field_name].append(field_parser(field_data))
            else:
                radio[field_name] = field_parser(field_data)

        # Store the data we gathered from the reply packet
        radio_list.append(radio)

    return radio_list

def main():
    args = parse_args()
    sys.stderr.write("\nDiscovery in progress...\n")
    if args.host:
        radio_list = ubnt_discovery_host(args.host)
    else:
        radio_list = ubnt_discovery()
    found_radios = len(radio_list)
    if args.output_format == 'text':
        if not found_radios:
            sys.stderr.write("\n\nNo radios discovered\n")
            sys.exit()
        print("\nDiscovered %d radio(s):" % found_radios)
        fmt = "  %-14s: %s"
        for radio in radio_list:
            print("\n---[ %s ]---" % radio['mac'])
            print(fmt % ("IP Address", radio['ip']))
            for field in radio:
                if field in BASIC_FIELDS:
                    continue
                print(fmt % (FIELD_STR.get(field, field),
                             radio[field]))
    elif args.output_format == 'json':
        print(json.dumps(radio_list, indent=2))

if __name__ == '__main__':
    main()
