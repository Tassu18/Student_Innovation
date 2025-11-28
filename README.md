🕵️ Network Sniffer Application :
A simple yet powerful Python-based Network Packet Sniffer that captures live network traffic, stores packets in a .pcap file, and analyzes them with a protocol distribution pie chart.
This project also includes a Tkinter GUI for easy usage.

🚀 Features
✔ Live Packet Capture (using Scapy)
✔ Saves packets to captured_packets.pcap
✔ Protocol detection: TCP, UDP, ICMP, Others
✔ Visual analysis using matplotlib pie chart
✔ Clean and interactive GUI application
✔ Multithreaded capture (does not freeze UI)
✔ Beginner-friendly and simple to use

📂 Project Structure
NetworkSnifferApp/
│── app.py           # GUI Application (Main App)
│── capture.py       # Packet capturing script
│── analyzer.py      # Packet analyzer + Pie chart
│── captured_packets.pcap (auto-created after capture)
│── README.md

🛠️ Requirements
Install dependencies:
pip install scapy matplotlib
Also ensure Python 3.8+ is installed.

▶️ How to Run the App
1. Start the Application
Go to the project folder and run:
python app.py

2. In the GUI:
🔵 Start Capture
Click "Start Capture"
Captures live packets for 10 seconds
Saves them as captured_packets.pcap

🟢 Analyze Packets
Click "Analyze Packets"
Opens a pie chart showing protocol usage:
TCP
UDP
ICMP
Other

🧭 How it Works (Simple Explanation)
capture.py
Uses Scapy’s sniff() function to capture live network packets.

analyzer.py
Reads the .pcap file and counts protocol types, then visualizes them.

app.py
Provides the GUI interface for easy use by non-technical users.

📊 Output Example
The analysis generates a pie chart similar to:
TCP – 60%
UDP – 30%
ICMP – 5%
Other – 5%

(Percentages vary based on your network.)

🎯 Project Scope

This project demonstrates:
✔ Network monitoring
✔ Live traffic capture
✔ Data visualization
✔ GUI development
✔ Python scripting
✔ Real-world cybersecurity concepts

Perfect for B.Tech, MCA, and Engineering final projects.
