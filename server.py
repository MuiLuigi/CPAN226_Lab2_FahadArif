# This program was modified by Fahad Arif / N01729165

import socket
import argparse
import struct

# Protocol Costants
PACKET_DATA = 0
PACKET_ACK = 1
PACKET_FIN = 2

DATA_HDR_FMT = "!BIH"
ACK_HDR_FMT = "!BI"

DATA_HDR_SIZE = struct.calcsize(DATA_HDR_FMT)
ACK_SIZE = struct.calcsize(ACK_HDR_FMT)

RECV_MAX = 65535

# Packet Helpers
def build_ack(seq: int) -> bytes: 
    return struct.pack(ACK_HDR_FMT, PACKET_ACK, seq)

def parse_packet(packet: bytes):  
    if len(packet) < DATA_HDR_SIZE:  
        return None  
    ptype, seq, length = struct.unpack(DATA_HDR_FMT, packet[:DATA_HDR_SIZE]) 
    payload = packet[DATA_HDR_SIZE:DATA_HDR_SIZE + length]  
    if len(payload) != length:
        return None 
    return ptype, seq, payload

# Buffer Flush Logic
def flush_buffer(f, buffer, expected_seq: int):
    while expected_seq in buffer:
        ptype, payload = buffer.pop(expected_seq) 
        if ptype == PACKET_DATA: 
            f.write(payload) 
        expected_seq += 1  
    return expected_seq

# Main Server Logic
def run_server(port, output_file):
    # 1. Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # 2. Bind the socket to the port (0.0.0.0 means all interfaces)
    server_address = ('', port)
    print(f"[*] Server listening on port {port}")
    print(f"[*] Server will save each received file as 'received_<ip>_<port>.jpg' based on sender.")
    sock.bind(server_address)

    # 3. Keep listening for new transfers
    try:
        while True:
            f = None
            sender_filename = None
            buffer = {}
            expected_seq = 0
            reception_started = False
            fin_received = False
            fin_seq = None

            while True:
                packet, addr = sock.recvfrom(RECV_MAX)
                decode = parse_packet(packet)
                if decode is None:
                    continue

                ptype, seq, payload = decode
                sock.sendto(build_ack(seq), addr)

                # Protocol: If we receive an empty packet, it means "End of File"
                if not reception_started:
                    print("-------- Start of Reception --------")
                    ip, sender_port = addr
                    sender_filename = f"received_{ip.replace('.', '_')}_{sender_port}.jpg"
                    f = open(sender_filename, 'wb')
                    reception_started = True
                    print(f"[*] First packet received from {addr}. File opened for writing as '{sender_filename}'.")

                if expected_seq > seq:
                    continue
                
                if expected_seq == seq:
                    if ptype == PACKET_DATA:
                        f.write(payload)
                        expected_seq += 1
                    elif ptype == PACKET_FIN:
                        fin_received = True
                        fin_seq = seq
                        expected_seq += 1
                    else:
                        expected_seq += 1

                    expected_seq = flush_buffer(f, buffer, expected_seq)

                    if fin_received and expected_seq > fin_seq:
                        print(f"[*] End of file signal received from {addr}. Closing.")
                        break

                else:
                    buffer[seq] = (ptype, payload)
                
            if f:
                f.close()
            print("==== End of reception ====")
            
    except KeyboardInterrupt:
        print("\n[!] Server stopped manually.")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        sock.close()
        print("[*] Server socket closed.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Naive UDP File Receiver")
    parser.add_argument("--port", type=int, default=12001, help="Port to listen on")
    parser.add_argument("--output", type=str, default="received_file.jpg", help="File path to save data")
    args = parser.parse_args()

    try:
        run_server(args.port, args.output)
    except KeyboardInterrupt:
        print("\n[!] Server stopped manually.")
    except Exception as e:
        print(f"[!] Error: {e}")