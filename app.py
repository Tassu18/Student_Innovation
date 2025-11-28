import tkinter as tk
from tkinter import messagebox, scrolledtext
from capture import capture_packets
from analyzer import analyze_packets, get_protocol_counts
import matplotlib.pyplot as plt

root = tk.Tk()
root.title("Network Sniffer & Analyzer")
root.geometry("400x400")

def capture_button():
    try:
        capture_packets()
        messagebox.showinfo("Success", "Packets captured successfully!")
    except PermissionError:
        messagebox.showerror("Error", "Run Python as administrator to capture packets.")

def analyze_button():
    try:
        analyze_packets()
        messagebox.showinfo("Success", "Check console for analysis output!")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def show_packets():
    try:
        from scapy.all import rdpcap
        packets = rdpcap("captured_packets.pcap")
        win = tk.Toplevel(root)
        win.title("Captured Packets")
        txt = scrolledtext.ScrolledText(win, width=100, height=30)
        txt.pack()
        for i, pkt in enumerate(packets, start=1):
            txt.insert(tk.END, f"Packet {i}: {pkt.summary()}\n")
    except FileNotFoundError:
        messagebox.showwarning("Warning", "No packets captured yet!")

def show_pie_chart():
    data = get_protocol_counts()
    if not data:
        messagebox.showwarning("Warning", "No packets captured yet!")
        return

    labels = list(data.keys())
    sizes = list(data.values())
    plt.figure(figsize=(6,6))
    plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
    plt.title("Protocol Distribution")
    plt.show()

btn_capture = tk.Button(root, text="Start Capture", command=capture_button, width=20)
btn_capture.pack(pady=10)

btn_analyze = tk.Button(root, text="Analyze Packets", command=analyze_button, width=20)
btn_analyze.pack(pady=10)

btn_show = tk.Button(root, text="Show Captured Packets", command=show_packets, width=20)
btn_show.pack(pady=10)

btn_pie = tk.Button(root, text="Show Pie Chart", command=show_pie_chart, width=20)
btn_pie.pack(pady=10)

root.mainloop()
