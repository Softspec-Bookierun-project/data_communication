from tkinter import *
from tkinter.filedialog import *
import tkinter as tk
import socket;
import struct;
import random;
import time;
import select;
import math;
import sys;
import os;


def cbc(id, tex):
    if id==1:
        return lambda: nslookup(id, tex)
    if id == 2:
        return lambda: trace(id , tex)
    if id==4:
        return lambda: save(id, tex)

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp');

def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = (source_string[count + 1])*256 + (source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + (source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def create_packet(id):
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = ''
    my_checksum = checksum(header + data.encode('utf-8'))
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
            socket.htons(my_checksum), id, 1)
    return header + data.encode('utf-8')

def receive_ping(my_socket, packet_id, time_sent, timeout):
    time_left = timeout
    while True:
        started_select = time.time()
        ready = select.select([my_socket], [], [], time_left)
        how_long_in_select = time.time() - started_select
        if ready[0] == []: # Timeout
            return 0
        time_received = time.time()
        rec_packet, addr = my_socket.recvfrom(1024)
        icmp_header = rec_packet[-8:]
        type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
        if p_id == packet_id:
            total_time_ms = (time_received - time_sent) * 1000
            total_time_ms = math.ceil(total_time_ms * 1000) / 1000
            return (addr[0], total_time_ms)
        time_left -= time_received - time_sent
        if time_left <= 0:
            return 0

def echo_one(host, ttl):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)
    while packet:
        sent = my_socket.sendto(packet, (host, 1))
        packet = packet[sent:]

    ping_res = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return ping_res

def echo_three(host, ttl):
    try1 = echo_one(host, ttl)
    try2 = echo_one(host, ttl)
    try3 = echo_one(host, ttl)

    if try1 == 0:
        try1str = '*'
    else:
        try1str = try1[0] + ' - ' + str(try1[1]) + ' ms'
    if try2 == 0:
        try2str = '*'
    else:
        try2str = try2[0] + ' - ' + str(try2[1]) + ' ms'
    if try3 == 0:
        try3str = '*'
    else:
        try3str = try3[0] + ' - ' + str(try3[1]) + ' ms'

    final_string = try1str + ', ' + try2str + ', ' + try3str
    final_string = str(ttl) + '  ' + final_string

    if try1 == 0:
        destination_reached = False
    else:
        destination_reached = try1[0] == host

    return (final_string, destination_reached)

top = tk.Tk()
top.title("Datacom")
topFrame = Frame(top,height = 500,width=200)
topFrame.pack()


lblInfo = tk.Label(topFrame,font=('arial',30,'bold'),text = "Comparator").grid(row=0,pady=10)
lblInfo = tk.Label(topFrame,font=('arial',15,'normal'),text = "This tool can compare between nslookup and traceroute").grid(row=1,pady=5)

middleFrame = Frame(top,height = 500,width=200)
middleFrame.pack()

tex = tk.Text(master=top)
textCompare = tk.Text(master=top)
tex.pack(side=tk.LEFT)
textCompare.pack(side=tk.RIGHT)
bop = tk.Frame()
bop.pack(side=tk.LEFT)
v = StringVar()
scanner = Entry(middleFrame, textvariable=v , width=25)
scanner.pack(side=tk.LEFT,padx=5)

timeout = 3
max_tries = 30

def trace(id,tex):
    dest_addr = scanner.get()
    host = socket.gethostbyname(dest_addr)
    s = '\n    Welcome to Traceroute \n'
    s += ('myTraceRoute to ' + scanner.get() + ' (' + host + '), ' + str(max_tries) +
         ' hops max.\n')

    try:
        for x in range(1, max_tries + 1):
            (line, destination_reached) = echo_three(host, x)
            s += line + '\n'

            if destination_reached:
                break

    except Exception as err:
        print(err)
    except KeyboardInterrupt as err:
        print(err)

    tex.delete("1.0",END)
    tex.insert(tk.END, s)
    tex.see(tk.END)

def nslookup(id,tex):
    s = '   Welcome to nslookup \n'
    for i in range(0, 255):
        addr1 = socket.gethostbyname(scanner.get())
        data = addr1.split('.')
        addr = data[0] + "." + data[1] + "." + data[2] + "."

        ipa = addr + str(i)
        try:
            a = socket.gethostbyaddr(ipa)
            s += ipa + ' ' + a[0] + '\n'
        except socket.herror:
            pass
    tex.delete("1.0",END)
    tex.insert(tk.END, s)
    tex.see(tk.END)

def compare():
    filename = askopenfilename()
    file = open(filename, 'r')
    s = file.read()
    s = "Compare :\n" + s
    textCompare.delete("1.0",END)
    textCompare.insert(tk.END, s)
    textCompare.see(tk.END)
    file.close()

def save(id,tex):
    f = asksaveasfile(mode='w', defaultextension=".txt")
    if f is None: 
        return
    text2save = tex.get("1.0", END)
    f.write(text2save)
    f.close() 

k=1

b = tk.Button(middleFrame, text="Nslookup", command=cbc(k,tex))
b.pack(side=tk.LEFT)

k=2

b = tk.Button(middleFrame, text="Traceroute", command=cbc(k,tex))
b.pack(side=tk.LEFT)

k = 4

r = tk.Button(middleFrame, text="SaveData", command=cbc(k,tex))
r.pack(side=tk.LEFT)

choose = tk.Button(middleFrame, text="Compare", command=compare)
choose.pack(side=tk.LEFT)

tk.Button(middleFrame, text='Exit', command=top.destroy).pack()
top.mainloop()