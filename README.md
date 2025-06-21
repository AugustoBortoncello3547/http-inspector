# HTTP Analyzer (Python)

Um analisador de tráfego HTTP em tempo real (ou via arquivos `.pcap`), desenvolvido em Python com a biblioteca `scapy`. O foco é facilitar a visualização de métricas relevantes e auxiliar na detecção de comportamentos suspeitos em redes locais.

O projeto foi desenvolvido em ambiente acadêmico, na cadeira de Redes para o curso de Ciência da Computação da Universidade de Caxias do Sul.

---

## 🚀 Funcionalidades

- 📡 Captura pacotes HTTP ao vivo ou de arquivos `.pcap`
- 🔍 Analisa cabeçalhos IP, TCP e HTTP
- 📊 Métricas por camada:

  - IPs com mais requisições
  - Portas mais utilizadas
  - Tamanho médio dos pacotes HTTP

- ⚠️ Identifica:

  - Credenciais em texto plano (ex: `username`, `password`)
  - Pacotes malformados (flags inválidas)
  - Tráfego anormal de um único IP

---

## 🛠️ Requisitos

- Python 3.8 ou superior

- Bibliotecas Python:

  ```bash
  pip install scapy
  ```

- No **Windows**:

  - Instale o [Npcap](https://nmap.org/npcap/) com a opção `WinPcap API-compatible mode`

---

## ⚙️ Como usar

### 1. Captura ao vivo:

```bash
python main.py --timeout 30
```

> Será exibida uma lista de interfaces de rede. Escolha a desejada para iniciar a análise.

### 2. Analisar um arquivo `.pcap`:

```bash
python main.py --pcap exemplo.pcap
```

### 3. Especificar interface diretamente (avançado):

```bash
python main.py --iface "Realtek Gaming GbE Family Controller" --timeout 30
```

---

## 🧾 Licença

Este projeto é open source sob a licença MIT.

---

## 👨‍💻 Autor

Desenvolvido por Augusto Zanesco Bortoncello e Gabriel Gallina Moscone como parte de um projeto acadêmico para a cadeira de Redes no curdo de Ciência da Computação.
