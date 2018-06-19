#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
About: SF program for SFC gap time measurements

Email: xianglinks@gmail.com
"""

import binascii
import logging
import multiprocessing
import socket
import struct
import sys
import time
import kodo

############
#  Config  #
############

# MAC address of source and destination instances in the SFC
SRC_MAC = 'fa:16:3e:04:07:36'  # MAC of the Proxy
DST_MAC = 'fa:16:3e:58:25:fb'

BUFFER_SIZE = 8192  # bytes

SRC_MAC_B = binascii.unhexlify(SRC_MAC.replace(':', ''))
DST_MAC_B = binascii.unhexlify(DST_MAC.replace(':', ''))
MAC_LEN = len(DST_MAC_B)

# Header lengths in bytes
ETH_HDL = 14
UDP_HDL = 8

#############
#  Logging  #
#############

fmt_str = '%(asctime)s %(levelname)-8s %(processName)s %(message)s'
level = {
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'ERROR': logging.ERROR
}

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter(fmt_str)
handler.setFormatter(formatter)
logger.addHandler(handler)
#logger.setLevel(level['ERROR'])
logger.setLevel(level['DEBUG'])


#####################
#  Forward Program  #
#####################

def bind_raw_sock_pair(in_iface, out_iface):
    """Create and bind raw socket pairs"""
    try:
        recv_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
        )
        send_sock = socket.socket(
            socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)
        )
    except socket.error as error:
        logger.error(error)
        sys.exit(1)

    recv_sock.bind((in_iface, 0))
    send_sock.bind((out_iface, 0))
    logger.debug('Bind in interface: %s, out interface: %s',
                 in_iface, out_iface)

    return (recv_sock, send_sock)


def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def calc_ih_cksum(hd_b_arr):
    """Calculate IP header checksum
    MARK: To generate a new checksum, the checksum field itself is set to zero

    :para hd_b_arr: Bytes array of IP header
    :retype: int
    """
    s = 0
    for i in range(0, len(hd_b_arr), 2):
        a, b = struct.unpack('>2B', hd_b_arr[i:i + 2])
        w = a + (b << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def forwards_forward(recv_sock, send_sock):
    """forwards_forward"""
    # Bytes array for a ethernet frame
    pack_arr = bytearray(BUFFER_SIZE)

    while True:
        pack_len = recv_sock.recv_into(pack_arr, BUFFER_SIZE)
        # MARK: Maybe too slow here
        recv_time = time.time()

        # Header offset
        hd_offset = 0

        eth_typ = struct.unpack('>H', pack_arr[12:14])[0]
        # IPv4 packet
        if eth_typ == 2048:
            hd_offset += ETH_HDL  # move to IP header
            # Check IP version and calc header length
            ver_ihl = struct.unpack('>B', pack_arr[hd_offset:hd_offset + 1])[0]
            ihl = 4 * int(hex(ver_ihl)[-1])
            # IP total length
            ip_tlen = struct.unpack(
                '>H', pack_arr[hd_offset + 2:hd_offset + 4])[0]
            #logger.debug(
            #    'Recv a IP packet, header len: %d, total len: %d', ihl,
            #    ip_tlen)
            proto = struct.unpack(
                '>B', pack_arr[hd_offset + 9:hd_offset + 10])[0]
            # Check if is UDP packet
            if proto == 17:
                hd_offset += ihl  # move to UDP header
                source_port = struct.unpack('>H', pack_arr[hd_offset:hd_offset+2])[0]
                dest_port = struct.unpack('>H', pack_arr[hd_offset+2:hd_offset+4])[0]
                if dest_port == CTL_PORT or source_port == CTL_PORT:
                    logger.debug("Recv CTL package. Ignoring.")
                    continue
                udp_pl_offset = hd_offset + UDP_HDL
                # Set checksum to zero
                # MARK: If the checksum is cleared to zero, then checksuming is disabled.
                pack_arr[hd_offset + 6:hd_offset + 8] = struct.pack('>H', 0)

                # UDP payload length
                udp_pl_len = struct.unpack(
                    '>H', pack_arr[hd_offset + 4:hd_offset + 6]
                )[0] - UDP_HDL
                
                udp_payload = pack_arr[udp_pl_offset:pack_len]
                udp_payload_string = udp_payload.decode('utf-8', 'backslashreplace')

                timestamps[udp_payload_string] = recv_time

                logger.debug('Recv data: %s, timestamp: %d', udp_payload_string, recv_time
                )
                
                pack_arr[0:MAC_LEN] = DST_MAC_B
                send_sock.send(pack_arr[0:pack_len])


def backwards_forward(recv_sock, send_sock):
    """backwards_forward"""

    pack_arr = bytearray(BUFFER_SIZE)

    while True:
        pack_len = recv_sock.recv_into(pack_arr, BUFFER_SIZE)

        # Check if this is a forwards packet
        cur_dst_mac_b = pack_arr[0:MAC_LEN]
        if cur_dst_mac_b == DST_MAC_B:
            logger.debug(
                'Recv a forwards packet, doing nothing, just send out...')
            continue
        else:
            logger.debug(
                'Recv a backwards packet, send to %s' % ingress_iface
            )
            pack_arr[0:MAC_LEN] = SRC_MAC_B
            send_sock.send(pack_arr[0:pack_len])

def echo_listen(socket):
    while True:
        payload, (ip, port) = socket.recvfrom(64)
        logger.debug('Pong %s', payload)
        if payload.startswith(b'PING'):
            payload = b"ACK " + payload
            socket.sendto(payload, (ip, port))


if __name__ == "__main__":

    if len(sys.argv) < 2:
        CTL_IP = '192.168.12.10'
        CTL_PORT = 6666

        ingress_iface = 'eth1'
        egress_iface = 'eth2'
    else:
        CTL_IP = sys.argv[2]
        CTL_PORT = int(sys.argv[3])

        ingress_iface = sys.argv[4]
        egress_iface = sys.argv[5]

    timestamps = dict()
    
    # Bind sockets and start forwards and backwards processes
    recv_sock, send_sock = bind_raw_sock_pair(ingress_iface, egress_iface)
    fw_proc = multiprocessing.Process(target=forwards_forward,
                                      args=(recv_sock, send_sock))

    recv_sock, send_sock = bind_raw_sock_pair(egress_iface, ingress_iface)
    bw_proc = multiprocessing.Process(target=backwards_forward,
                                      args=(recv_sock, send_sock))
    fw_proc.start()
    bw_proc.start()

    # Send a ready packet to SFC manager
    ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctl_sock.bind(('', CTL_PORT))
    ctl_sock.sendto(b'ready', (CTL_IP, CTL_PORT))
    echo_proc = multiprocessing.Process(target=echo_listen, args=(ctl_sock,))
    echo_proc.start()

    fw_proc.join()
    bw_proc.join()
    echo_proc.join()
