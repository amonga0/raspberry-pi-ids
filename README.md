🛡️ Raspberry Pi Intrusion Detection System (IDS)

This project is a lightweight IDS built using a Raspberry Pi 5 that captures and analyzes network packets, detects suspicious activity, and displays real-time data on a live dashboard.

📊 Features
- Real-time packet sniffing using Scapy
- Logs data to CSV (timestamp, IPs, ports, size, protocol)
- Basic anomaly detection and alerts for suspicious ports and unknown IPs
- Flask dashboard with:
  - Recent alerts
  - Protocols pie chart
  - Top ports bar chart

 📁 Project Structure
 - 'packet_sniffer.py' - Captures and logs packets
 - 'ids_dashboard.py' - Displays live dashboard using Flask
 - 'documentation/'
     - 'requirements.txt' - Needed libraries
     - 'setup_instructions.md' - How to run the project
     - 'images/' - Screenshots of outputs
  

🚀 Getting Started

Full instructions: [documentation/setup_instructions.md](documentation/setup_instructions.md)

🧑‍💻 Author

Aaditya Monga

[LinkedIn](https://www.linkedin.com/in/aaditya-monga/)
