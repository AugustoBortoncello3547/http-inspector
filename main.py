import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from collections import defaultdict, Counter
import re
import argparse
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.express as px
from datetime import datetime
import os
from jinja2 import Environment, FileSystemLoader


class HTTPTrafficAnalyzer:
    def __init__(self):
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.http_lengths = []
        self.http_requests = 0
        self.sensitive_data = []
        self.malformed_packets = []
        self.traffic_volume = defaultdict(int)
        self.packet_timestamps = []
        self.packet_sizes = []

    def analyze_packet(self, packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            self.ip_counter[ip_src] += 1
            
            # Captura timestamp se disponível
            if hasattr(packet, 'time'):
                self.packet_timestamps.append(packet.time)
            
            self.packet_sizes.append(len(packet))

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

    def create_unified_html_report(self, filename="relatorio_trafego_completo.html"):
        fig = make_subplots(
            rows=3, cols=2,
            subplot_titles=(
                'Top 10 IPs por Requisições', 
                'Top 10 Portas Mais Utilizadas',
                'Distribuição do Tamanho dos Pacotes',
                'Volume de Tráfego por IP',
                'Timeline de Tráfego',
                'Comparação de Protocolos'
            ),
            specs=[[{"type": "bar"}, {"type": "bar"}],
                   [{"type": "histogram"}, {"type": "pie"}],
                   [{"type": "scatter"}, {"type": "bar"}]],
            vertical_spacing=0.08,
            horizontal_spacing=0.1
        )

        top_ips = self.ip_counter.most_common(10)
        if top_ips:
            ips, counts = zip(*top_ips)
            fig.add_trace(
                go.Bar(x=list(ips), y=list(counts), name="Requisições por IP",
                       marker_color='#3498db', text=list(counts), textposition='auto'),
                row=1, col=1
            )

        top_ports = self.port_counter.most_common(10)
        if top_ports:
            port_labels = [f"{src}→{dst}" for (src, dst), _ in top_ports]
            port_counts = [count for _, count in top_ports]
            fig.add_trace(
                go.Bar(x=port_labels, y=port_counts, name="Uso de Portas",
                       marker_color='#e74c3c', text=port_counts, textposition='auto'),
                row=1, col=2
            )

        if self.packet_sizes:
            fig.add_trace(
                go.Histogram(x=self.packet_sizes, name="Tamanho dos Pacotes",
                           marker_color='#2ecc71', nbinsx=30, opacity=0.7),
                row=2, col=1
            )

        if self.traffic_volume:
            top_traffic = sorted(self.traffic_volume.items(), key=lambda x: x[1], reverse=True)[:8]
            if top_traffic:
                traffic_ips, traffic_volumes = zip(*top_traffic)
                fig.add_trace(
                    go.Pie(labels=list(traffic_ips), values=list(traffic_volumes),
                           name="Volume de Tráfego", hole=0.4,
                           marker_colors=px.colors.qualitative.Set3),
                    row=2, col=2
                )

        if self.packet_timestamps:
            timestamps_formatted = [datetime.fromtimestamp(float(ts)) for ts in self.packet_timestamps]
            fig.add_trace(
                go.Scatter(x=timestamps_formatted, y=list(range(len(timestamps_formatted))),
                          mode='lines+markers', name="Timeline de Pacotes",
                          line=dict(color='#9b59b6', width=2)),
                row=3, col=1
            )

        protocol_counts = {
            'HTTP': self.http_requests,
            'TCP (outros)': sum(self.ip_counter.values()) - self.http_requests,
            'Malformados': len(self.malformed_packets)
        }
        
        if any(protocol_counts.values()):
            fig.add_trace(
                go.Bar(x=list(protocol_counts.keys()), y=list(protocol_counts.values()),
                       name="Protocolos", marker_color=['#f39c12', '#95a5a6', '#e67e22'],
                       text=list(protocol_counts.values()), textposition='auto'),
                row=3, col=2
            )

        fig.update_layout(
            height=1000,
            title_text="",
            showlegend=False,
            template="plotly_white",
            font=dict(size=12)
        )

        graph_html = fig.to_html(include_plotlyjs='cdn', div_id="charts-container")
        
        security_alerts = self._generate_security_alerts()
        top_ips_data = self.ip_counter.most_common(15)
        statistics = self._generate_statistics()
        
        env = Environment(loader=FileSystemLoader('templates'))
        template = env.get_template('report_template.html')

        html_content = template.render(
            timestamp=datetime.now().strftime('%d/%m/%Y às %H:%M:%S'),
            
            
            http_requests=self.http_requests,
            unique_ips=len(self.ip_counter),
            packages=sum(self.ip_counter.values()),
            malformed_packages=len(self.malformed_packets),
            total=self._format_bytes(sum(self.traffic_volume.values())),
            
            graph_html=graph_html,
            security_alerts=self._generate_security_section(security_alerts),
            statistics=self._generate_stats_cards(statistics),
            ip_table=self._generate_ip_table_rows(top_ips_data),
            ports_table=self._generate_ports_table_rows()
        )
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n✅ Relatório HTML completo salvo em: {os.path.abspath(filename)}")
        return filename

    def _generate_security_alerts(self):
        alerts = []
        
        if self.sensitive_data:
            alerts.append({
                'type': 'high',
                'icon': '🔒',
                'title': 'Credenciais Detectadas',
                'description': f'{len(self.sensitive_data)} possíveis vazamentos de credenciais encontrados no tráfego.',
                'count': len(self.sensitive_data)
            })
        
        if self.malformed_packets:
            alerts.append({
                'type': 'medium',
                'icon': '⚠️',
                'title': 'Pacotes Malformados',
                'description': f'{len(self.malformed_packets)} pacotes com estrutura anômala detectados.',
                'count': len(self.malformed_packets)
            })
        
        traffic_spikes = self.detect_traffic_spike()
        if traffic_spikes:
            alerts.append({
                'type': 'medium',
                'icon': '📈',
                'title': 'Tráfego Anormal',
                'description': f'{len(traffic_spikes)} IPs com volume de tráfego suspeito detectados.',
                'count': len(traffic_spikes)
            })
        
        if not alerts:
            alerts.append({
                'type': 'low',
                'icon': '✅',
                'title': 'Sistema Normal',
                'description': 'Nenhuma anomalia significativa detectada no tráfego analisado.',
                'count': 0
            })
        
        return alerts

    def _generate_security_section(self, alerts):
        if not alerts:
            return ""
        
        alert_html = '<div class="section">\n<h2>🚨 Alertas de Segurança</h2>\n'
        
        for alert in alerts:
            alert_class = f"alert-{alert['type']}"
            alert_html += f"""
            <div class="section {alert_class}" style="margin: 15px 0;">
                <h3>{alert['icon']} {alert['title']}</h3>
                <p>{alert['description']}</p>
            </div>
            """
        
        alert_html += '</div>\n'
        return alert_html

    def _generate_statistics(self):
        stats = []
        
        if self.http_lengths:
            avg_http_size = sum(self.http_lengths) / len(self.http_lengths)
            stats.append(('Tamanho Médio HTTP', f'{avg_http_size:.2f} bytes'))
        
        if self.packet_sizes:
            avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes)
            stats.append(('Tamanho Médio Pacote', f'{avg_packet_size:.2f} bytes'))
        
        total_traffic = sum(self.traffic_volume.values())
        stats.append(('Volume Total', self._format_bytes(total_traffic)))
        
        unique_ports = len(set([port for (src, dst) in self.port_counter.keys() for port in [src, dst]]))
        stats.append(('Portas Únicas', str(unique_ports)))
        
        return stats

    def _generate_stats_cards(self, statistics):
        cards_html = ""
        for stat_name, stat_value in statistics:
            cards_html += f"""
            <div class="stat-card">
                <h4>{stat_name}</h4>
                <p>{stat_value}</p>
            </div>
            """
        return cards_html

    def _generate_ip_table_rows(self, top_ips_data):
        rows_html = ""
        total_requests = sum(self.ip_counter.values())
        
        for i, (ip, count) in enumerate(top_ips_data, 1):
            volume = self.traffic_volume.get(ip, 0)
            percentage = (count / total_requests) * 100 if total_requests > 0 else 0
            
            if volume > 1000000:  # > 1MB
                status = '<span class="status-danger">Alto</span>'
            elif volume > 100000:  # > 100KB
                status = '<span class="status-warning">Médio</span>'
            else:
                status = '<span class="status-normal">Normal</span>'
            
            rows_html += f"""
            <tr>
                <td>#{i}</td>
                <td><strong>{ip}</strong></td>
                <td>{count:,}</td>
                <td>{self._format_bytes(volume)}</td>
                <td>{percentage:.1f}%</td>
                <td>{status}</td>
            </tr>
            """
        
        return rows_html

    def _generate_ports_table_rows(self):
        rows_html = ""
        
        for (src_port, dst_port), count in self.port_counter.most_common(15):
            service_type = self._get_service_type(dst_port)
            rows_html += f"""
            <tr>
                <td>{src_port}</td>
                <td><strong>{dst_port}</strong></td>
                <td>{count:,}</td>
                <td>{service_type}</td>
            </tr>
            """
        
        return rows_html

    def _get_service_type(self, port):
        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            110: "POP3",
            143: "IMAP",
            993: "IMAPS",
            995: "POP3S"
        }
        return common_ports.get(port, "Outros")

    def _format_bytes(self, bytes_value):
        """Formata bytes em formato legível"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} TB"

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
        
        self.create_unified_html_report()

    def analyze_pcap(self, filename):
        packets = scapy.rdpcap(filename)
        for pkt in packets:
            self.analyze_packet(pkt)
        self.print_summary()

    def analyze_live(self, iface="eth0", timeout=5):
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
    parser.add_argument("--timeout", type=int, default=5, help="Tempo de captura ao vivo")
    args = parser.parse_args()

    analyzer = HTTPTrafficAnalyzer()

    if args.pcap:
        analyzer.analyze_pcap(args.pcap)
    else:
        iface = args.iface if args.iface else choose_interface()
        analyzer.analyze_live(iface, args.timeout)

    print("\n🎉 Análise concluída! Verifique o arquivo HTML gerado para visualização completa.")