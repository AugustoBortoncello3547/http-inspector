import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from collections import defaultdict, Counter
import re
import argparse

class HTTPTrafficAnalyzer:
    def __init__(self):
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.http_lengths = []
        self.http_requests = 0
        self.sensitive_data = []
        self.malformed_packets = []
        self.traffic_volume = defaultdict(int)

    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            self.ip_counter[ip_src] += 1

            if packet.haslayer(scapy.TCP):
                tcp = packet[scapy.TCP]
                self.port_counter[(tcp.sport, tcp.dport)] += 1
                self.traffic_volume[ip_src] += len(packet)
                if tcp.flags not in range(0, 256):
                    self.malformed_packets.append(packet)

                if packet.haslayer(HTTPRequest):
                    http = packet[HTTPRequest]
                    self.http_requests += 1
                    self.http_lengths.append(len(http))

                    payload = bytes(packet[scapy.Raw]).decode(errors='ignore') if packet.haslayer(scapy.Raw) else ''
                    if re.search(r'(username|user|login|senha|password)=\w+', payload, re.IGNORECASE):
                        self.sensitive_data.append((ip_src, payload))

    def detect_traffic_spike(self, threshold=100):
        return [ip for ip, volume in self.traffic_volume.items() if volume > threshold * 1000]

    def print_summary(self):
        print("--- Análise HTTP ---")
        print("IPs com mais requisições:", self.ip_counter.most_common(5))
        print("Portas mais utilizadas:", self.port_counter.most_common(5))
        if self.http_lengths:
            print("Tamanho médio dos pacotes HTTP:", sum(self.http_lengths)/len(self.http_lengths))
        print("Total de requisições HTTP:", self.http_requests)
        print("Pacotes com possíveis credenciais:", len(self.sensitive_data))
        print("Pacotes malformados:", len(self.malformed_packets))
        print("Endereços com tráfego anormal:", self.detect_traffic_spike())

    def analyze_pcap(self, filename):
        packets = scapy.rdpcap(filename)
        for pkt in packets:
            self.analyze_packet(pkt)
        self.print_summary()

    def analyze_live(self, iface="eth0", timeout=60):
        print(f"Capturando por {timeout}s na interface {iface}...")
        scapy.sniff(iface=iface, prn=self.analyze_packet, timeout=timeout)
        self.print_summary()

def choose_interface():
    from scapy.arch.windows import get_windows_if_list
    interfaces = get_windows_if_list()
    print("Interfaces disponíveis:")
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface['name']} - {iface['description']}")
    while True:
        try:
            choice = int(input("Escolha o número da interface: "))
            if 0 <= choice < len(interfaces):
                return interfaces[choice]['name']
            else:
                print("Opção inválida. Tente novamente.")
        except ValueError:
            print("Entrada inválida. Digite um número.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analisador de tráfego HTTP em tempo real ou via pcap.")
    parser.add_argument("--pcap", help="Arquivo .pcap para analisar")
    parser.add_argument("--iface", help="Interface de rede para captura ao vivo")
    parser.add_argument("--timeout", type=int, default=60, help="Tempo de captura ao vivo")
    args = parser.parse_args()

    analyzer = HTTPTrafficAnalyzer()

    if args.pcap:
        analyzer.analyze_pcap(args.pcap)
    else:
        iface = args.iface if args.iface else choose_interface()
        analyzer.analyze_live(iface, args.timeout)
