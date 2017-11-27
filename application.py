# from tkinter import *
# from tkinter import ttk
#
# int a=0
# root = Tk()
# Label(root, text="Hello, Tkinter").pack()
# root.mainloop()
# !/usr/bin/env python
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


def callback(id, tex):
    s = 'At {} f is {}\n'.format(id, id ** id / 0.987)
    tex.insert(tk.END, s)
    tex.see(tk.END)  # Scroll if necessary

ICMP_ECHO_REQUEST = 8
ICMP_CODE = socket.getprotobyname('icmp');

"""
Given the bytes array, it calculates the checksum and returns it.
"""
def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
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
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

"""
Create a new echo request packet based on the given "id".
"""
def create_packet(id):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0, 0, id, 1)
    data = ''
    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data.encode('utf-8'))
    # Now that we have the right checksum, we put that in. It's just easier
    # to make up a new header than to stuff it into the dummy.
    header = struct.pack('bbHHh', ICMP_ECHO_REQUEST, 0,
            socket.htons(my_checksum), id, 1)
    return header + data.encode('utf-8')

"""
Receive the ping from the socket.
Returns 0 if a timeout occurs.
Returns (src_ip_address, ping_time_milliseconds) if successful.
"""
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
        # The last 8 bytes are the header of the packet we sent to the server
        icmp_header = rec_packet[-8:]
        type, code, checksum, p_id, sequence = struct.unpack(
                'bbHHh', icmp_header)
        if p_id == packet_id:
            total_time_ms = (time_received - time_sent) * 1000
            # Round to 3 decimal places:
            total_time_ms = math.ceil(total_time_ms * 1000) / 1000
            return (addr[0], total_time_ms)
        time_left -= time_received - time_sent
        if time_left <= 0:
            return 0

"""
Sends an ICMP ping to the given host, and gets the response for that ping.
It sets the TTL in the IP header of the packet to the given value.
Returns 0 if a timeout occurs.
Returns (src_ip_address, ping_time_milliseconds) if successful.
"""
def echo_one(host, ttl):
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP_CODE)
    my_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)

    # Maximum for an unsigned short int c object counts to 65535 so
    # we have to sure that our packet id is not greater than that.
    packet_id = int(random.random() * 65535)
    packet = create_packet(packet_id)
    while packet:
        # The icmp protocol does not use a port, but the function
        # below expects it, so we just give it a dummy port.
        sent = my_socket.sendto(packet, (host, 1))
        packet = packet[sent:]

    ping_res = receive_ping(my_socket, packet_id, time.time(), timeout)
    my_socket.close()
    return ping_res

"""
Given the host and a TTL value, it sends 3 pings.
Formats a nice user friendly string.
Returns (user_friendly_string, destination_reached).
destination_reached is True if the IP address who replied matches the host,
and False otherwise.
"""
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

# -------------------------- #
# Main execution starts here #
# -------------------------- #

top = tk.Tk()
tex = tk.Text(master=top)
textCompare = tk.Text(master=top)
tex.pack(side=tk.RIGHT)
textCompare.pack(side=tk.RIGHT)
bop = tk.Frame()
bop.pack(side=tk.LEFT)
v = StringVar()
scanner = Entry(bop, textvariable=v)
scanner.pack(padx=5)

# if len(sys.argv) <= 1:
#     print('Bad usage. Provide a hostname.')
#     sys.exit(1)

# Domain name to IP address conversion:
timeout = 3
max_tries = 30

def trace(id,tex):
    dest_addr = scanner.get()
    host = socket.gethostbyname(dest_addr)
    s = '\n    Welcome to Traceroute \n'
    s += ('myTraceRoute to ' + scanner.get() + ' (' + host + '), ' + str(max_tries) +
         ' hops max.\n')

    try:
        # Loop until we hit the maximum number of hops, or until we reach the
        # final destination host:
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
    tex.delete("1.0",END)
    tex.insert(tk.END, s)
    tex.see(tk.END)
    file.close()

def save(id,tex):
    f = asksaveasfile(mode='w', defaultextension=".txt")
    if f is None: # asksaveasfile return `None` if dialog closed with "cancel".
        return
    text2save = tex.get("1.0", END) # starts from `1.0`, not `0.0`
    f.write(text2save)
    f.close() # `()` was missing.

k=1

b = tk.Button(bop, text="nslookup", command=cbc(k,tex))
b.pack()

k=2

b = tk.Button(bop, text="traceroute", command=cbc(k,tex))
b.pack()

k = 4

r = tk.Button(bop, text="saveData", command=cbc(k,tex))
r.pack()

choose = tk.Button(bop, text="compare", command=compare)
choose.pack()

tk.Button(bop, text='Exit', command=top.destroy).pack()
top.mainloop()