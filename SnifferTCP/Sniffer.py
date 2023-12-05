from scapy.all import *
from scapy.layers.inet import TCP
from enum import IntEnum

class TcpFlags(IntEnum):
    CWR = 0x80
    ECE = 0x40
    URG = 0x20
    ACK = 0x10
    PSH = 0x08
    RST = 0x04
    SYN = 0x02
    FIN = 0x01

def get_tcp_flags_names(flags):
    nomes = [flag.name for flag in TcpFlags if flags & flag.value]
    return ', '.join(nomes)

def process_tcp_packet(pacote):
    if TCP in pacote:
        pacoteTcp = pacote[TCP]
        print(f"Porta de Origem: {pacoteTcp.sport}")
        print(f"Porta de Destino: {pacoteTcp.dport}")
        print(f"Número de Sequência: {pacoteTcp.seq}")
        print(f"Número de Confirmação: {pacoteTcp.ack}")
        print(f"Offset: {pacoteTcp.dataofs}")
        print(f"Reservados: {pacoteTcp.reserved}")
        flags = get_tcp_flags_names(pacoteTcp.flags)
        print(f"Flags TCP: {flags}")
        print(f"Tamanho da Janela: {pacoteTcp.window}")
        print(f"Ponteiro de Urgência: {pacoteTcp.urgptr}")
        print(f"Opções: {pacoteTcp.options}")
        data = pacote.payload
        print(f"Dados: {data}")
        print(f"***************************************")
sniff(filter="tcp", prn=process_tcp_packet)
