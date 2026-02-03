# This program was modified by Fahad Arif / N01729165

import socket
import argparse
import time
import os
import struct

PACKET_DATA = 0
PACKET_ACK = 1
PACKET_FIN = 2

DATA_HDR_FMT = "!BIH"
ACK_HDR_FMT = "!BI"

DATA_HDR_SIZE = struct.calcsize(DATA_HDR_FMT)
ACK_HDR_SIZE = struct.calcsize(ACK_HDR_FMT)

DEFAULT_TIMEOUT = 0.20
DEFAULT_RETRIES = 50

CHUNK_SIZE = 1024
DEFAULT_WINDOW = 10

def build_data_packet(seq: int, payload: bytes) -> bytes:
    header = struct.pack(DATA_HDR_FMT, PACKET_DATA, seq, len(payload))
    return header + payload

def build_fin_packet(seq: int) -> bytes:
    header = struct.pack(DATA_HDR_FMT, PACKET_FIN, seq, 0)
    return header

def parse_ack(packet: bytes):
    if len(packet) < ACK_HDR_SIZE:
        return None
    ptype, seq = struct.unpack(ACK_HDR_FMT, packet[:ACK_HDR_SIZE])
    if ptype != PACKET_ACK:
        return None
    return seq

def run_client(target_ip, target_port, input_file, timeout=DEFAULT_TIMEOUT, retries=DEFAULT_RETRIES, window=DEFAULT_WINDOW):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    server_address = (target_ip, target_port)

    print(f"[*] Sending file '{input_file}' to {target_ip}:{target_port}")

    if not os.path.exists(input_file):
        print(f"[!] Error: File '{input_file}' not found.")
        return

    chunks = []
    with open(input_file, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            chunks.append(chunk)

    total_packets = len(chunks)
    fin_seq = total_packets

    base = 0
    next_seq = 0
    acked = set()
    retries_left = retries
    last_progress = time.time()

    while base < total_packets:
        while next_seq < total_packets and next_seq < base + window:
            pkt = build_data_packet(next_seq, chunks[next_seq])
            sock.sendto(pkt, server_address)
            next_seq += 1

        try:
            ack_raw, _ = sock.recvfrom(2048)
            ack_seq = parse_ack(ack_raw)
            if ack_seq is not None and 0 <= ack_seq < total_packets:
                if ack_seq not in acked:
                    acked.add(ack_seq)
                while base in acked:
                    base += 1
                    last_progress = time.time()
        except socket.timeout:
            pass

        if time.time() - last_progress >= timeout:
            if retries_left <= 0:
                raise RuntimeError("Too many retries sending data")
            for s in range(base, min(next_seq, base + window)):
                if s not in acked:
                    pkt = build_data_packet(s, chunks[s])
                    sock.sendto(pkt, server_address)
            retries_left -= 1
            last_progress = time.time()

    fin_pkt = build_fin_packet(fin_seq)
    fin_attempts = 0
    while fin_attempts < retries:
        sock.sendto(fin_pkt, server_address)
        try:
            ack_raw, _ = sock.recvfrom(2048)
            ack_seq = parse_ack(ack_raw)
            if ack_seq == fin_seq:
                print("[*] File transmission complete.")
                sock.close()
                return
        except socket.timeout:
            fin_attempts += 1

    sock.close()
    raise RuntimeError("FIN not acknowledged")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Naive UDP File Sender")
    parser.add_argument("--target_ip", type=str, default="127.0.0.1", help="Destination IP (Relay or Server)")
    parser.add_argument("--target_port", type=int, default=12000, help="Destination Port")
    parser.add_argument("--file", type=str, required=True, help="Path to file to send")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="ACK timeout seconds")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Max retransmissions per packet")
    parser.add_argument("--window", type=int, default=DEFAULT_WINDOW, help="Window size")
    args = parser.parse_args()

    run_client(args.target_ip, args.target_port, args.file, args.timeout, args.retries, args.window)