import pyshark
import json
import time


""" Constants """
LVL1A = "SUMMARY"
LVL1B = "DETAILS"


class PacketBucket(object):
    """
    Class to store an report all packets recorded during the capture cycle.
    """
    def __init__(self):
        """
        Bucket_dict is the dict structure in which data from the packets is recorded.
        """
        self.set_count = 0
        self.bucket_dict = {
            LVL1A: {
                "DestinationIP": [],
                "SourceIP": [],
                "Transport_Protocol": {
                    "TCP": {
                        "DstPort": []
                    },
                    "UDP": {
                        "DstPort": []
                    }
                }
            },
            LVL1B: {
                "Packets": []
            }
        }
        self.unique_dst_ports = []
        self.unique_src_ports = []
        self.unique_dst_ip = []

    def add_packet_set(self, packet_set=None, verbose=False):
        """
        Method to add a unique packet set od class MyPacket
        :param packet_set:
        :param verbose:
        :return:
        """
        if verbose:
            print(packet_set.ip_packet_set)
        self.unique_extract(packet_set)

        """ 
        This next bit removes the protocol key from the kv pair which I sent in error.
        It should really be removed, but it's as quick to use an iterator over the values()
        """
        kv_pair = {}    # Use a dictionary to store a packet counter with data
        for value in packet_set.ip_packet_set.values():
            kv_pair[self.set_count] = value
            self.bucket_dict[LVL1B]['Packets'].append(kv_pair)

        self.bucket_dict[LVL1A]['PacketCount'] = self.set_count
        self.set_count += 1
        return

    def unique_extract(self, packet_set):
        """
        Class method used to extract attributes and store as unique in list
        :param packet_set:
        :return:
        """
        dict_vals = (packet_set.ip_packet_set.values())
        for val in dict_vals:
            if val['src_ip'] not in self.bucket_dict[LVL1A]['SourceIP']:
                self.bucket_dict[LVL1A]['SourceIP'].append(val['src_ip'])
            if val['dst_ip'] not in self.bucket_dict[LVL1A]['DestinationIP']:
                self.bucket_dict[LVL1A]['DestinationIP'].append(val['dst_ip'])

            if val['dst_port'] not in self.bucket_dict[LVL1A]['Transport_Protocol'][val['transport_proto']]['DstPort']:
                self.bucket_dict[LVL1A]['Transport_Protocol'][val['transport_proto']]['DstPort'].append(val['dst_port'])

        return


class MyPacket(object):
    """
    Class used to process a pyshark packet, essentially pulls out the interesting data and dumps the rest.
    """

    def __init__(self, packet=None):
        self.ip_packet_set = {}
        self.packet = packet
        if self.packet.transport_layer == "TCP" or self.packet.transport_layer == "UDP":
            self.protocol = self.packet.transport_layer
            self.src_ip = self.packet.ip.src
            self.dst_ip = self.packet.ip.dst
            self.src_port = self.packet[self.protocol].srcport
            self.dst_port = self.packet[self.protocol].dstport
            self.ip_packet = {}

            if self.src_ip and self.dst_ip:
                self.ip_packet = {
                    "src_ip": self.src_ip, "src_port": self.src_port,
                    "dst_ip": self.dst_ip, "dst_port": self.dst_port,
                    "transport_proto": self.packet.transport_layer
                }
                self.ip_packet_set[self.packet.transport_layer] = self.ip_packet


def main():
    run = True
    data_bucket = PacketBucket()
    capture = pyshark.LiveCapture(interface='en0')
    while run:
        for packet in capture.sniff_continuously(packet_count=50):
            try:
                simple_packet = MyPacket(packet=packet)
                data_bucket.add_packet_set(packet_set=simple_packet, verbose=False)

            except AttributeError as e:
                print(e)

        run = False

    c = json.dumps(data_bucket.bucket_dict, indent=5, sort_keys=True)
    print(c)

    return


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    main()
