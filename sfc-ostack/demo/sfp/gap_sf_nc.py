#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim:fenc=utf-8

"""
About: SF program for SFC gap time measurements

Email: xianglinks@gmail.com
"""

import binascii
import logging
import multiprocessing, threading
import socket
import struct
import sys
import time
import kodo

from config import SRC_MAC, DST_MAC, BUFFER_SIZE, CTL_IP, CTL_PORT, NEXT_IP
from config import ingress_iface, egress_iface
from config import SYMBOL_SIZE, GEN_SIZE, coding_mode, chain_position

############
#  Config  #
############

SRC_MAC_B = binascii.unhexlify(SRC_MAC.replace(':', ''))
DST_MAC_B = binascii.unhexlify(DST_MAC.replace(':', ''))
MAC_LEN = len(DST_MAC_B)

# Header lengths in bytes
ETH_HDL = 14
UDP_HDL = 8
COD_HDL = 4

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



def calc_ih_cksum(hd_b_arr):
    """Calculate IP header checksum
    MARK: To generate a new checksum, the checksum field itself is set to zero

    :para hd_b_arr: Bytes array of IP header
    :retype: int
    """

    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    s = 0
    # set checksum field to zero
    hd_b_arr[10:12] = struct.pack('>H', 0)

    for i in range(0, len(hd_b_arr), 2):
        a, b = struct.unpack('>2B', hd_b_arr[i:i + 2])
        w = a + (b << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def forwards_forward(recv_sock, send_sock, coder=None):
    """forwards_forward"""
    # Bytes array for a ethernet frame
    pack_arr = bytearray(BUFFER_SIZE)
    if coding_mode == "decode":
        decoded_symbols = list()

    while True:
        pack_len = recv_sock.recv_into(pack_arr, BUFFER_SIZE)
        # MARK: Maybe too slow here
        recv_time = time.time()

        # Header offset
        hd_offset = 0
        packet_changed = False

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
                # filter out ctl packets
                if dest_port == CTL_PORT or source_port == CTL_PORT:
                    logger.debug("Recv CTL packet. Ignoring.")
                    continue
                udp_pl_offset = hd_offset + UDP_HDL
                # Set checksum to zero
                # MARK: If the checksum is cleared to zero, then checksuming is disabled.
                pack_arr[hd_offset + 6:hd_offset + 8] = struct.pack('>H', 0)

                # UDP payload length
                udp_pl_len = struct.unpack(
                    '>H', pack_arr[hd_offset + 4:hd_offset + 6]
                )[0] - UDP_HDL
                
                # extract payload
                udp_payload = pack_arr[udp_pl_offset:pack_len]
                
                if coding_mode == "encode":
                    encoder = coder
                    assert chain_position == 0
                    assert len(udp_payload) <= SYMBOL_SIZE
                    assert encoder.rank() < encoder.symbols()

                    logger.debug("Encoding...")

                    encoder.set_const_symbol(encoder.rank(), bytes(udp_payload))
                    coded_payload = encoder.write_payload()
                    
                    logger.debug("Building header...")
                    coding_header = build_header(*encoder_info,
                                                 0, # only using one generation here
                                                 GEN_SIZE,
                                                 SYMBOL_SIZE)
                    logger.debug("Header: %s", coding_header)
                                                 
                    udp_payload = coding_header + coded_payload
                    packet_changed = True
                    
                elif coding_mode == "recode":
                    decoder = coder
                    coding_header = udp_payload[0:COD_HDL]
                    if parse_header(coding_header) != \
                            (*encoder_info, 0, GEN_SIZE, SYMBOL_SIZE):
                        logger.debug("Header mismatch. Dropping packet.")
                        continue
                    
                    logger.debug("Recoding...")
                    decoder.read_payload(bytes(udp_payload[COD_HDL:]))
                    coded_payload = decoder.write_payload()
                    
                    udp_payload = coding_header + coded_payload
                    packet_changed = True
                    
                elif coding_mode == "decode":
                    decoder = coder
                    coding_header = udp_payload[0:COD_HDL]
                    if parse_header(coding_header) != \
                            (*encoder_info, 0, GEN_SIZE, SYMBOL_SIZE):
                        logger.debug("Header mismatch. Dropping packet.")
                        continue

                    logger.debug("Decoding...")
                    decoder.read_payload(bytes(udp_payload[COD_HDL:]))
                    
                    if decoder.rank() <= len(decoded_symbols):
                        logger.debug("Rank didn't increase. Waiting for more packets")
                        continue
                
                    for i in range(decoder.symbols()):
                        if i not in decoded_symbols and decoder.is_symbol_uncoded(i):
                            decoded_symbols.append(i)
                            udp_payload = decoder.copy_from_symbol(i)
                            break
                    packet_changed = True
                    
                if packet_changed:
                    udp_pl_len = len(udp_payload)
                    pack_len = udp_pl_offset+udp_pl_len
                    pack_arr[udp_pl_offset : pack_len] = udp_payload
                    
                    new_udp_tlen = struct.pack(
                            '>H', (UDP_HDL + udp_pl_len)
                    )
                    pack_arr[hd_offset+4 : hd_offset+6] = new_udp_tlen

                    hd_offset -= ihl

                    new_ip_tlen = struct.pack('>H', ihl + UDP_HDL + udp_pl_len)
                    pack_arr[hd_offset+2:hd_offset+4] = new_ip_tlen
                    
                    logger.debug(
                            'Old IP header checksum: %s',
                            binascii.hexlify(
                                pack_arr[hd_offset+10 : hd_offset+12]
                            ).decode()
                    )
                    
                    new_iph_cksum = calc_ih_cksum(pack_arr[hd_offset : hd_offset+ihl])
                    logger.debug('New IP header checksum %s', hex(new_iph_cksum))
                    pack_arr[hd_offset+10 : hd_offset+12] = struct.pack('<H', new_iph_cksum)


                # store time stamp
                udp_payload_string = udp_payload.decode('utf-8', 'backslashreplace')
                timestamps[udp_payload_string] = recv_time
                logger.debug('Recv data: %s, timestamp: %d', udp_payload, recv_time)

                
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

def test_error_rate(receiver, packet_num, timeout=0.5, wait_time=0.05):
    def wait_for_ack():
        global received_acks
        received_acks = 0
        while True:
            sock.settimeout(timeout)
            try:
                reply, sender = sock.recvfrom(64)
                if sender == receiver and reply.startswith(b"ACK PING"):
                    received_acks += 1
            except socket.timeout:
                pass
            if all_sent == True:
                return
                
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    all_sent = False
    ack_thread = threading.Thread(target=wait_for_ack)
    ack_thread.start()
    for i in range(packet_num):
        sock.sendto("PING {}".format(i).encode('ascii'), receiver)
        time.sleep(wait_time)
    all_sent = True
    ack_thread.join()
    sock.close()
    return 1-received_acks/packet_num

def build_header(encoder, field_size, gen_seq, gen_size, symbol_len):
    header = bytearray(4)
    
    assert encoder in range(8)
    assert field_size in range(4)
    assert gen_seq in range(4)
    
    first_byte = encoder<<4 | field_size<<2 | gen_seq
    
    header = struct.pack('!BBH', first_byte, gen_size, symbol_len)
    
    return header

def parse_header(header):
    first_byte, gen_size, symbol_len = struct.unpack('!BBH', header)
    
    encoder = first_byte>>4 & 0b1111
    field_size = first_byte>>2 & 0b11
    gen_seq = first_byte & 0b11
    
    return (encoder, field_size, gen_seq, gen_size, symbol_len)
    
def update_header(header, gen_seq=None):
    if gen_seq:
        assert gen_seq in range(4)
        first_byte = struct.unpack('!B', header)
        first_byte = first_byte&0b11111100 | gen_seq
    
    
def convert_encoder(kodo_object):
    if not kodo_object:
        return (0,0)
        
    name = type(kodo_object).__name__
        
    available_encoders = {
        'Fulcrum': 1,
        'FullVector': 2,
        'NoCode': 3,
        'OnTheFly': 4,
        'Perpetual': 5,
        'SlidingWindow': 6,
        'SparseFullVector': 7
    }
    available_sizes = {'4':1, '8':2, '16':3}
    
    if name[-1] in available_sizes:
        field_size = available_sizes[name[-1]]
        name = name[:-1]
    else:
        field_size = 0
    
    [encoder] = [available_encoders[i] for i in available_encoders if name.startswith(i)]

    return (encoder, field_size)
    
if __name__ == "__main__":

    if len(sys.argv) >= 7:
        CTL_IP = sys.argv[2]
        CTL_PORT = int(sys.argv[3])

        ingress_iface = sys.argv[4]
        egress_iface = sys.argv[5]
        coding_mode = sys.argv[6]

    timestamps = dict()
   
    if coding_mode == "encode":
        enc_fac = kodo.OnTheFlyEncoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
        fw_cod = enc_fac.build()
    elif coding_mode in ("decode", "recode") :
        dec_fac = kodo.OnTheFlyDecoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
        fw_cod = dec_fac.build()
    else: 
        fw_cod = None

    encoder_info = convert_encoder(fw_cod)

    # Bind sockets and start forwards and backwards processes
    recv_sock, send_sock = bind_raw_sock_pair(ingress_iface, egress_iface)
    fw_proc = multiprocessing.Process(target=forwards_forward,
                                      args=(recv_sock, send_sock, fw_cod))

    fw_proc.start()

    # Send a ready packet to SFC manager
    ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ctl_sock.bind(('', CTL_PORT))
    echo_proc = multiprocessing.Process(target=echo_listen, args=(ctl_sock,))
    echo_proc.start()
    
    error_rate = test_error_rate((NEXT_IP, CTL_PORT), 50)
    logger.debug("Error rate: {}".format(error_rate))
    
    ctl_sock.sendto(b'ready', (CTL_IP, CTL_PORT))

    fw_proc.join()
    echo_proc.join()
