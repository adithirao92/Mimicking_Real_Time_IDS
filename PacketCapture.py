# from scapy.all import sniff, IP, TCP
# from collections import defaultdict
# import threading
# import queue

# class PacketCapture:
#     def __init__(self):
#         self.packet_queue = queue.Queue()
#         self.stop_capture = threading.Event()

#     def packet_callback(self, packet):
#         if IP in packet and TCP in packet:
#             self.packet_queue.put(packet)

#     def start_capture(self, interface="eth0"):
#         def capture_thread():
#             sniff(iface=interface,
#                   prn=self.packet_callback,
#                   store=0,
#                   stop_filter=lambda _: self.stop_capture.is_set())

#         self.capture_thread = threading.Thread(target=capture_thread)
#         self.capture_thread.start()

#     def stop(self):
#         self.stop_capture.set()
#         self.capture_thread.join()

from scapy.all import sniff, IP, TCP
import threading
import queue
from datetime import datetime

class PacketCapture:
    def __init__(self, test_mode=False):
        self.packet_queue = queue.Queue()   #self.packet_queue refers to an instance of queue.Queue().
        self.stop_capture = threading.Event()
        self.test_mode = test_mode

    def packet_callback(self, packet):   #Puts the packet in the queue for processing.
     if IP in packet and TCP in packet:
        if not hasattr(packet, 'timestamp'):
            packet.timestamp = datetime.now()
        self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        if self.test_mode:
            return
            
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,  #prn stands for "print" or "process". It is used to specify a callback function that will be executed every time a packet is captured.
                  store=0,  #store=0 avoids memory bloat.
                  stop_filter=lambda _: self.stop_capture.is_set()) #stops whenever stop_capture is set

        self.capture_thread = threading.Thread(target=capture_thread)  ##Starts capture in a separate thread to avoid blocking the main program.
        self.capture_thread.start()

    def inject_test_packet(self, packet_data):
        """For testing purposes"""  #Allows you to simulate packet injection manually during testing.   
        if self.test_mode:
            self.packet_queue.put(packet_data)

    def stop(self):
        self.stop_capture.set()
        if hasattr(self, 'capture_thread'):
            self.capture_thread.join()