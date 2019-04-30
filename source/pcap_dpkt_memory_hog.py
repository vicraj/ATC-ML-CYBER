#! /usr/bin/python3
"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import argparse, sys
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord
import pandas as pd
from datetime import datetime
from datetime import timedelta

from IPython.display import display, HTML
from multiprocessing.pool import ThreadPool


def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def get_event_by_timestamp(dt_timestamp, metadata_list):
    for event_metadata in metadata_list:
        event_start = event_metadata['start']
        event_end = event_metadata['end']
        event_id = event_metadata['id']
        attack_name = event_metadata['attack_name']

        if dt_timestamp >= event_start and dt_timestamp <= event_end and attack_name != '-':
            return event_metadata

    return None


def extract_packet_data(event_metadata):
    """Print out information about each packet in a pcap

       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
           event_metadata: python list collection of dictionary objects containing metadata in the following format:
           [{'id': id,
             'start': datetime_start,
             'end': datetime_end,
             'duration': duration_sec,
             'service': service,
             'attack_name': attack_name}
             ,{
             ...
             },....]
    """

    # print('Starting to parse EVENT...')
    # print('Events to be considered(From Metadata): %s' % len(metadata_list))
    # For each packet in the pcap process the contents

    event_start = event_metadata['start']
    event_end = event_metadata['end']
    event_id = event_metadata['id']
    attack_name = event_metadata['attack_name']
    # print("Processing event", event_id)

    csv_metadata = {'duration': event_metadata['duration'],
                    'service': event_metadata['service'],
                    'attack_name': event_metadata['attack_name'],
                    'num_fin_flag': 0,
                    'num_rst_flag': 0,
                    'num_syn_flag': 0,
                    'num_psh_flag': 0,
                    'num_ack_flag': 0,
                    'num_urg_flag': 0,
                    'num_ece_flag': 0,
                    'num_cwr_flag': 0,
                    'num_do_not_fragment': 0,
                    'num_more_fragments': 0
                    }

    global num_processed
    global filedata
    for timestamp, buf in filedata.items():
        current_timestamp = datetime.utcfromtimestamp(timestamp)

        if current_timestamp < event_start:
            continue

        event_start = event_metadata['start']
        event_end = event_metadata['end']
        event_id = event_metadata['id']

        # print("Processing event: ", event_id)
        # Print out the timestamp in UTC
        #print('Timestamp: ', str(datetime.utcfromtimestamp(timestamp)))


        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            # print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue

        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data

        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)
        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK

        # Extract TCP Flags
        if ip.p==dpkt.ip.IP_PROTO_TCP:
            tcp = ip.data

            csv_metadata['num_fin_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_FIN)  != 0 else 0)
            csv_metadata['num_rst_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_RST)  != 0 else 0)
            csv_metadata['num_syn_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_SYN)  != 0 else 0)
            csv_metadata['num_psh_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_PUSH)  != 0 else 0)
            csv_metadata['num_ack_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_ACK)  != 0 else 0)
            csv_metadata['num_urg_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_URG)  != 0 else 0)
            csv_metadata['num_ece_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_ECE)  != 0 else 0)
            csv_metadata['num_cwr_flag'] += (1 if (tcp.flags & dpkt.tcp.TH_CWR)  != 0 else 0)

            csv_metadata['num_do_not_fragment'] += (1 if do_not_fragment != 0 else 0)
            csv_metadata['num_more_fragments'] += (1 if more_fragments != 0 else 0)
            # print ("Packet is urgent")
            # print(urg_flag)


        # print (csv_metadata)
        # Print out the info
        # print('IP: %s -> %s   (len=%d ttl=%d DF=%d MF=%d offset=%d)\n' % \
        #       (inet_to_str(ip.src), inet_to_str(ip.dst), ip.len, ip.ttl, do_not_fragment, more_fragments, fragment_offset))
        if current_timestamp > event_end:
            break

    num_processed += 1
    global num_events




    print("Processed", "{:3.4f}".format((num_processed / num_events) * 100), "% (", num_processed, "of", num_events,")")
    return csv_metadata


def generate_attack_collection(file_name):
    """
    This method generates a python list of metadata for the attacks to be consumed by the PCAP parser.
    :param file_name:
    :return: collection of dictionaries of metadata for PCAP parser in the form of:
            [{'id': id,
              'start': datetime_start,
              'end': datetime_end,
              'duration': duration_sec,
              'service': service,
              'attack_name': attack_name}
              ,{
              ...
              },....]
    """
    df = pd.read_csv(file_name, delim_whitespace=True)

    # Get unique attack names and display for our script purposes
    print('Available attacks names:\n')
    df_attacks = df[['attack_name']].drop_duplicates()
    display(df_attacks)

    # Get only port scans
    df2 = df  # .loc[df['service'] == "telnet"]

    # Output this table into an html file.
    df2.to_html('filename.html')

    metadata = []

    print("Generating commands to run...")
    for index, row in df2.iterrows():
        #
        # Parse start and end time of the events into datetime object for easier manipulation.
        #

        # Hardcode ETC since that's what metadata comes in
        time_string = ("%s GMT-0500") % (row['time'])
        # print(time_string)
        # print(row['date'])
        datetime_start = datetime.strptime(("%s %s") % (row['date'], time_string), '%m/%d/%Y %H:%M:%S GMT%z')
        duration = row['duration'].split(':')
        hours = int(duration[0])
        minutes = int(duration[1])
        seconds = int(duration[2])

        # Convert timezone aware time to unix
        datetime_start = datetime_start.timestamp()
        # Convert to UTC to match PCAP
        datetime_start = datetime.utcfromtimestamp(datetime_start)

        datetime_end = datetime_start + timedelta(hours=hours, minutes=minutes, seconds=seconds)
        duration_sec = abs((datetime_end - datetime_start).seconds)

        # Extract metadata fields to be passed to the main parser ie. id, attack name and service
        id = row['id']
        attack_name = row['attack_name']
        service = row['service']

        # Return necessary data fields to the parent
        metadata.append({'id': id,
                         'start': datetime_start,
                         'end': datetime_end,
                         'duration': duration_sec,
                         'service': service,
                         'attack_name': attack_name})

    print('Done.')
    return metadata


def load_pcap_into_ram(file_name):
    global filedata
    global num_processed

    num_processed = 0
    filedata = {}
    with open(file_name, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for timestamp, buf in pcap:
            filedata[timestamp] = buf


# def parse_pcap_and_extract_data(event_metadata, file_name):
#     with open(file_name, 'rb') as f:
#         pcap = dpkt.pcap.Reader(f)
#         return extract_packet_data(pcap, event_metadata)


def parse(metadata_file_name, pcap_file_name, threads):
    # metadata_file_name = '../sample_data/wednesday/tcpdump.list'
    # pcap_file_name = '../sample_data/wednesday/outside.tcpdump'

    metadata_list = generate_attack_collection(metadata_file_name)

    load_pcap_into_ram(pcap_file_name)
    # for event_metadata in metadata_list:
    #
    #     """Open up a test pcap file and print out the packets"""
    #     # with open('../sample_data/sample_data01.tcpdump', 'rb') as f:
    #     with open('sample_data01.tcpdump', 'rb') as f:
    #         pcap = dpkt.pcap.Reader(f)
    #         extract_packet_data(pcap, event_metadata)

    print("Threads start....")
    pool = ThreadPool(threads)
    file_names  = [pcap_file_name] * len(metadata_list)
    global num_events
    num_events = len(metadata_list)
    # We need to zip together the two lists because map only supports calling functions
    # with one argument. In Python 3.3+, you can use starmap instead.
    results = pool.starmap(extract_packet_data, zip(metadata_list))

    # print results
    # print(results)
    pool.close()
    pool.join()

    print("Wrinting CSV")
    for result in results:
        print(result)

    df = pd.DataFrame(results)
    df.to_csv("output.csv")

    print("The end.")
if __name__ == '__main__':
    # metadata_file_name = '../sample_data/tcpdump.list'
    # pcap_file_name = 'sample_data01.tcpdump'

    parser = argparse.ArgumentParser()
    # parser.add_argument('--verbosity', type=int, help='Verbosity level. ex. --verbosity=1')
    parser.add_argument('--metadata', help='Metadata file to use ex. --metadata=tcpdump.list', required=True)
    parser.add_argument('--pcap', help='PCAP file to use ex. --pcap=sample_data01.tcpdump', required=True)
    parser.add_argument('--threads', default=4, type=int, help='Number of threads to use --threads=4')

    args = parser.parse_args()
    parse(args.metadata, args.pcap, args.threads)