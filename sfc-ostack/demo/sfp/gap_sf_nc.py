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
import json

from config import SRC_MAC, DST_MAC, BUFFER_SIZE
#from config import CTL_IP, CTL_PORT, NEXT_IP
from config import ingress_iface, egress_iface
from config import SYMBOL_SIZE, GEN_SIZE, coding_mode, chain_position
from config import monitoring_mode, JSONL_FILE_PATH, probing_enabled
from config import DECODER_IP_REWRITE

############
#  Config  #
############

SRC_MAC_B = binascii.unhexlify(SRC_MAC.replace(':', ''))
DST_MAC_B = binascii.unhexlify(DST_MAC.replace(':', ''))
MAC_LEN = len(DST_MAC_B)

# Header lengths in bytes
ETH_HDL = 14
UDP_HDL = 8
COD_HDL_MAX = 22


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
logger.setLevel(level['ERROR'])
#logger.setLevel(level['DEBUG'])


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


def forwards_forward(recv_sock, send_sock, factory=None):
    """forwards_forward"""
    # Bytes array for a ethernet frame
    pack_arr = bytearray(BUFFER_SIZE)
    current_generation = 0
    encoder = None
    decoder = None
    if coding_mode == "decode":
        decoded_symbols = list()
    if monitoring_mode:
        time_log = {'encoder': [], 'recoder': [], 'decoder': []}

    while True:
        pack_len = recv_sock.recv_into(pack_arr, BUFFER_SIZE)
        # MARK: Maybe too slow here
        recv_time = time.perf_counter()

        eth_typ = struct.unpack('>H', pack_arr[12:14])[0]
        # IPv4 packet
        if eth_typ != 2048:
            continue
        # Check IP version and calc header length
        ver_ihl = struct.unpack('>B', pack_arr[ETH_HDL:ETH_HDL + 1])[0]
        ihl = 4 * int(hex(ver_ihl)[-1])
        # IP total length
        ip_tlen = struct.unpack(
            '>H', pack_arr[ETH_HDL + 2:ETH_HDL + 4])[0]
        #logger.debug(
        #    'Recv a IP packet, header len: %d, total len: %d', ihl,
        #    ip_tlen)
        proto = struct.unpack(
            '>B', pack_arr[ETH_HDL + 9:ETH_HDL + 10])[0]
        # Check if is UDP packet
        if proto != 17:
            continue
            
        udp_hd_offset = ETH_HDL+ihl  # move to UDP header
        source_port = struct.unpack('>H', pack_arr[udp_hd_offset:udp_hd_offset+2])[0]
        dest_port = struct.unpack('>H', pack_arr[udp_hd_offset+2:udp_hd_offset+4])[0]
        # filter out ctl packets
        #if dest_port == CTL_PORT or source_port == CTL_PORT:
        #    logger.debug("Recv CTL packet. Ignoring.")
        #    continue
            
        udp_pl_offset = udp_hd_offset + UDP_HDL
        # Set checksum to zero
        # MARK: If the checksum is cleared to zero, then checksuming is disabled.
        pack_arr[udp_hd_offset + 6:udp_hd_offset + 8] = struct.pack('>H', 0)

        # UDP payload length
        udp_pl_len = struct.unpack(
            '>H', pack_arr[udp_hd_offset + 4:udp_hd_offset + 6]
        )[0] - UDP_HDL
        logger.debug("UDP Payload: %s Bytes", udp_pl_len)

        # extract payload
        udp_payload = pack_arr[udp_pl_offset:udp_pl_offset+udp_pl_len]
        
        if coding_mode == "encode":
            assert chain_position == 0
            if len(udp_payload) > SYMBOL_SIZE:
                logger.error("Packet too big. Dropping")
                continue
            
            logger.debug("Encoding...")
            if not encoder:
                encoder = factory.build()
            encoder.set_const_symbol(encoder.rank(), bytes(udp_payload))
                
            packets_to_send = 1
            if encoder.rank() == encoder.symbols():
                red_pkts = max(2, int(encoder_info['gen_size']*redundancy/100))
                logger.debug("Sending last packet + %d redundancy packets", red_pkts)
                packets_to_send += red_pkts
                
            for i in range(packets_to_send):
                coded_payload = encoder.write_payload()
                
                logger.debug("Building header...")
                coding_header = build_header(**encoder_info,
                                             redundancy=redundancy,
                                             gen_seq=current_generation,
                                             probing=probing_enabled)
                                             
                coding_time = int((time.perf_counter()-recv_time)*10**6)
                logger.debug("Coding time: %d", coding_time)
                
                udp_pl_len = len(coding_header) + len(coded_payload)
                if probing_enabled:
                    udp_pl_len += 2
                update_ip_header(pack_arr, ihl, udp_pl_len)
                
                proc_time = int((time.perf_counter()-recv_time)*10**6)
                logger.debug('Process time: %d us.', proc_time)
                if probing_enabled:
                    update_header(coding_header, proc_time=proc_time)
                
                logger.debug("Header: %s", coding_header)
                
                udp_payload = coding_header + coded_payload
                
                pack_len = udp_pl_offset+udp_pl_len
                pack_arr[udp_pl_offset : pack_len] = udp_payload

                if pack_len-ETH_HDL >= 1450:
                    logger.error("Packet too big: %s. Not sending.", pack_len-ETH_HDL)
                    continue
            
                pack_arr[0:MAC_LEN] = DST_MAC_B
                send_sock.send(pack_arr[0:pack_len])
                
                recv_time = time.perf_counter() # for multiple packets
                
            if encoder.rank() == encoder.symbols():
                logger.info("Generation full. Resetting encoder.")
                encoder = None
                current_generation = (current_generation+1)%4
                decoded_symbols = []
                logger.debug("Generation sequence number: %s", current_generation)
            
        elif coding_mode == "forward":
            coding_header = udp_payload[0:COD_HDL_MAX]
            header_info = parse_header(coding_header, get_times=monitoring_mode)
            if header_info['hop_log']['invalid']:
                logger.debug("Hop log invalid. Dropping packet.")
                continue
            cod_hdl = header_info['header_size']
            logger.debug("Coding header length: %s", cod_hdl)
            coding_header = udp_payload[0:cod_hdl]
            
            logger.debug("Forwarding...")
            coded_payload = udp_payload[cod_hdl:]
            update_header(coding_header, chain_position=chain_position)
            
            udp_pl_len = len(coding_header) + len(coded_payload)
            if header_info['probing']:
                udp_pl_len += 2
            update_ip_header(pack_arr, ihl, udp_pl_len)
            
            proc_time = int((time.perf_counter()-recv_time)*10**6)
            logger.debug('Process time: %d us.', proc_time)
            if header_info['probing']:
                update_header(coding_header, proc_time=proc_time)
            udp_payload = coding_header + coded_payload
            
            pack_len = udp_pl_offset+udp_pl_len
            pack_arr[udp_pl_offset : pack_len] = udp_payload

            if pack_len-ETH_HDL >= 1450:
                logger.error("Packet too big: %s. Not sending.", pack_len-ETH_HDL)
                continue
            
            pack_arr[0:MAC_LEN] = DST_MAC_B
            send_sock.send(pack_arr[0:pack_len])
            

        else:
            coding_header = udp_payload[0:COD_HDL_MAX]
            header_info = parse_header(coding_header, get_times=monitoring_mode)
            if not all(header_info[i] == encoder_info[i] for i in encoder_info):
                logger.debug("Header mismatch. Dropping packet.")
                continue
            if header_info['hop_log']['invalid']:
                logger.debug("Hop log invalid. Dropping packet.")
                continue
            cod_hdl = header_info['header_size']
            logger.debug("Coding header length: %s", cod_hdl)
            coding_header = udp_payload[0:cod_hdl]
            
            if header_info['gen_seq'] != current_generation:
                logger.info("Packet from new generation arrived. Resetting decoder.")
                decoder = None
                current_generation = header_info['gen_seq']
                decoded_symbols = []
                logger.debug("Generation sequence number: %s", current_generation)
            if not decoder:
                decoder = factory.build()

            if coding_mode == "recode":     
                                        
                logger.debug("Recoding...")
                decoder.read_payload(bytes(udp_payload[cod_hdl:]))
                logger.debug("Rank %s", decoder.rank())
                
                packets_to_send = 1
                if decoder.rank() == decoder.symbols():
                    red_pkts = max(2, int(header_info['gen_size']*header_info['redundancy']/100))
                    logger.debug("Sending last packet + %d redundancy packets", red_pkts)
                    packets_to_send += red_pkts
                    
                for i in range(packets_to_send):
                    coded_payload = decoder.write_payload()
                    
                    coding_time = int((time.perf_counter()-recv_time)*10**6)
                    logger.debug("Coding time: %d", coding_time)
                    
                    update_header(coding_header, chain_position=chain_position)
                    
                    udp_pl_len = len(coding_header) + len(coded_payload)
                    if header_info['probing']:
                        udp_pl_len += 2
                    update_ip_header(pack_arr, ihl, udp_pl_len)
                    
                    proc_time = int((time.perf_counter()-recv_time)*10**6)
                    logger.debug('Process time: %d us.', proc_time)
                    if header_info['probing']:
                        update_header(coding_header, proc_time=proc_time)
                    udp_payload = coding_header + coded_payload
                    
                    pack_len = udp_pl_offset+udp_pl_len
                    pack_arr[udp_pl_offset : pack_len] = udp_payload

                    if pack_len-ETH_HDL >= 1450:
                        logger.error("Packet too big: %s. Not sending.", pack_len-ETH_HDL)
                        continue
                
                    pack_arr[0:MAC_LEN] = DST_MAC_B
                    send_sock.send(pack_arr[0:pack_len])
                    
                    recv_time = time.perf_counter() # for multiple packets
                            
                if decoder.rank() == decoder.symbols():
                    logger.info("Generation full.")
                
            elif coding_mode == "decode":

                logger.debug("Decoding...")
                decoder.read_payload(bytes(udp_payload[cod_hdl:]))
                
                if decoder.rank() <= len(decoded_symbols):
                    if len(decoded_symbols) == decoder.symbols():
                        logger.debug("Generation already decoded.")
                    else:
                        logger.debug("Rank didn't increase. Waiting for more packets")
                    continue
                logger.debug("Rank %s", decoder.rank())
                
                if monitoring_mode and header_info['probing']:
                    time_log['encoder'].append(header_info['times'][0])
                    time_log['recoder'].append(header_info['times'][1])
            
                for i in range(GEN_SIZE):
                    if i not in decoded_symbols and decoder.is_symbol_uncoded(i):
                        logger.debug("Decoding symbol %s", i)
                        udp_payload = decoder.copy_from_symbol(i)
                        udp_pl_len = len(udp_payload)

                        logger.debug("Payload (%s Bytes): %s", udp_pl_len, udp_payload)
                        
                        if DECODER_IP_REWRITE:
                            pack_arr[ETH_HDL+16:ETH_HDL+20] = socket.inet_aton(DECODER_IP_REWRITE)
                        
                        update_ip_header(pack_arr, ihl, udp_pl_len)
                        
                        proc_time = int((time.perf_counter()-recv_time)*10**6)
                        logger.debug('Process time: %d us.', proc_time)
                        if monitoring_mode:
                            time_log['decoder'].append(proc_time)
                
                        pack_len = udp_pl_offset+udp_pl_len
                        pack_arr[udp_pl_offset : pack_len] = udp_payload

                        if pack_len-ETH_HDL >= 1450:
                            logger.error("Packet too big: %s. Not sending.", pack_len-ETH_HDL)
                            continue
                    
                        pack_arr[0:MAC_LEN] = DST_MAC_B
                        send_sock.send(pack_arr[0:pack_len])
                
                        decoded_symbols.append(i)
                        recv_time = time.perf_counter()
                logger.debug("Decoded symbols: %s", decoded_symbols)
                if len(decoded_symbols) == decoder.symbols():
                    logger.info("All packets decoded.")
                    if monitoring_mode:
                        logger.debug("Writing time log to %s", JSONL_FILE_PATH)
                        with open(JSONL_FILE_PATH, 'a+') as jsonl_file:
                            jsonl_file.write(json.dumps(time_log))
                            jsonl_file.write('\n')
                    

def update_ip_header(pack_arr, ihl, udp_pl_len):
    udp_hd_offset = ETH_HDL+ihl
    new_udp_tlen = struct.pack(
            '>H', (UDP_HDL + udp_pl_len)
    )
    pack_arr[udp_hd_offset+4 : udp_hd_offset+6] = new_udp_tlen

    new_ip_tlen = struct.pack('>H', ihl + UDP_HDL + udp_pl_len)
    pack_arr[ETH_HDL+2:ETH_HDL+4] = new_ip_tlen

    logger.debug(
            'Old IP header checksum: %s',
            binascii.hexlify(
                pack_arr[ETH_HDL+10 : ETH_HDL+12]
            ).decode()
    )

    cksm_start_time = time.perf_counter()
    new_iph_cksum = calc_ih_cksum(pack_arr[ETH_HDL : ETH_HDL+ihl])
    cksm_time = int((time.perf_counter()-cksm_start_time)*10**6)
    logger.debug('New IP header checksum %s, time: %d', hex(new_iph_cksum), cksm_time)
    pack_arr[ETH_HDL+10 : ETH_HDL+12] = struct.pack('<H', new_iph_cksum)

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

def build_header(encoder, field_size, gen_seq, gen_size, symbol_len, redundancy=0, probing=False, proc_time=None):
    if probing and proc_time:
        header = bytearray(8)
    else:
        header = bytearray(6)
    
    assert encoder in range(8)
    assert field_size in range(4)
    assert gen_seq in range(4)
    
    enc_info = encoder<<4 | field_size<<2 | gen_seq
    hop_log = 0b10000000
    red_prob = redundancy<<1 | bool(probing)
    
    
    header[0:6] = struct.pack('!BBBBH', enc_info, hop_log, gen_size,
                            red_prob, symbol_len)
    if probing and proc_time:
        header[6:8] = struct.pack('!H', proc_time)
    
    return header

def parse_header(header, get_times=False):
    hi = dict()
    enc_info, hop_log, hi['gen_size'], \
        red_prob, hi['symbol_len'] = struct.unpack('!BBBBH', header[0:6])
    
    hi['encoder'] = enc_info>>4 & 0b1111
    hi['field_size'] = enc_info>>2 & 0b11
    hi['gen_seq'] = enc_info & 0b11
    
    hi['hop_log'] = {'invalid': False, 'total_hops': 0}
    for i in range(8):
        hi['hop_log'][i] = bool(hop_log>>(7-i) & 0b1)
        if hi['hop_log'][i]:
            hi['hop_log']['total_hops'] += 1
            if i>0 and not hi['hop_log'][i-1]:
                hi['hop_log']['invalid'] == True
    
    hi['probing'] = red_prob&0b1
    hi['redundancy'] = red_prob>>1
    
    hi['header_size'] = 6
    
    if hi['probing']:
        hi['header_size'] += 2*hi['hop_log']['total_hops']
        if get_times:
            pattern = '!'+'H'*hi['hop_log']['total_hops']
            hi['times'] = struct.unpack(pattern, header[6:hi['header_size']])
    
    return hi
    
def update_header(header, gen_seq=None, chain_position=None, proc_time=None):
    if gen_seq != None:
        assert gen_seq in range(4)
        [first_byte] = struct.unpack('!B', header[:1])
        first_byte = first_byte&0b11111100 | gen_seq
        header[:1] = struct.pack('!B', first_byte)
    if chain_position != None:
        assert chain_position in range(8)
        [hop_log] = struct.unpack('!B', header[1:2])
        hop_log |= 0b1<<(7-chain_position)
        header[1:2] = struct.pack('!B', hop_log)
    if proc_time != None:
        header.extend(struct.pack('!H', proc_time))
        
    return header
        
    
    
def convert_encoder(kodo_object):
    if not kodo_object:
        return {'encoder': 0, 'field_size':0, 'symbol_len':0, 'gen_size':0}
        
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

    result = {'encoder': encoder, 'field_size': field_size}
    result['symbol_len'] = kodo_object.symbol_size()
    result['gen_size'] = kodo_object.symbols()
    return result
    
if __name__ == "__main__":

    if len(sys.argv) > 2:
        encoder_decoder = sys.argv[1]
        SYMBOL_SIZE = int(sys.argv[2])

    if coding_mode == "encode":
        if encoder_decoder == "FullVector":
            fw_fac = kodo.FullVectorEncoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
        elif encoder_decoder == "SlidingWindow":
            fw_fac = kodo.SlidingWindowEncoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
        redundancy = 10
    elif coding_mode in ("decode", "recode") :
        if encoder_decoder == "FullVector":
            fw_fac = kodo.FullVectorDecoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
        elif encoder_decoder == "SlidingWindow":
            fw_fac = kodo.SlidingWindowEncoderFactoryBinary(GEN_SIZE, SYMBOL_SIZE)
    else:
        fw_fac = None

    encoder_info = convert_encoder(fw_fac)

    JSONL_FILE_PATH = "dt_{}_{}_{}.jsonl".format(encoder_decoder, SYMBOL_SIZE, GEN_SIZE)

    # Bind sockets and start forwards and backwards processes
    recv_sock, send_sock = bind_raw_sock_pair(ingress_iface, egress_iface)
    fw_proc = multiprocessing.Process(target=forwards_forward,
                                      args=(recv_sock, send_sock, fw_fac))

    fw_proc.start()

    # Send a ready packet to SFC manager
    #ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #ctl_sock.bind(('', CTL_PORT))
    #echo_proc = multiprocessing.Process(target=echo_listen, args=(ctl_sock,))
    #echo_proc.start()
    
    #error_rate = test_error_rate((NEXT_IP, CTL_PORT), 50)
    #logger.debug("Error rate: {}".format(error_rate))
    
    #ctl_sock.sendto(b'ready', (CTL_IP, CTL_PORT))

    fw_proc.join()
    #echo_proc.join()
