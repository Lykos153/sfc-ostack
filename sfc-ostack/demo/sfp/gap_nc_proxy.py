import struct
import os
import socket
import time
import threading

PACKET_COUNT = 5
PACKET_SIZE = 500
PORT = 1234
CTL_PORT = 6666
DEST_IP = "192.168.122.224"

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
    
if __name__ == '__main__':
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    for count in range(PACKET_COUNT):
        payload = os.urandom(PACKET_SIZE)
        send_sock.sendto(payload, (DEST_IP, PORT))
        time.sleep(0.1)
        
    ctl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ctl_sock.bind((socket.gethostname(), CTL_PORT))
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
