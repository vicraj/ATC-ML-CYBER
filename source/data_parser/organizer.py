"""
Organizer is used to split up the massive 'kddcup.data.corrected'
file into more manageable pieces. This script additionally maps
all string formats to integer formats, as tensorflow only works
on numeric data

This file requires that the 'kddcup.data.corrected' is in the
same directory as this file at execution.

See README for more details
"""

import csv

# Data in from kddcup.data.corrected
rawData = open('kddcup.data.corrected', 'r')
reader = csv.reader(rawData, lineterminator='.')

# Data out to various different directories
# Used to build 'library' of attacks
out0 = open('data/normal.txt', 'w', newline='')
norWri = csv.writer(out0)

out1 = open('data/u2r/buffer_overflow.txt', 'w', newline='')
bufWri = csv.writer(out1)

out2 = open('data/u2r/loadmodule.txt', 'w', newline='')
loaWri = csv.writer(out2)

out3 = open('data/u2r/perl.txt', 'w', newline='')
perWri = csv.writer(out3)

out4 = open('data/dos/neptune.txt', 'w', newline='')
nepWri = csv.writer(out4)

out5 = open('data/dos/smurf.txt', 'w', newline='')
smuWri = csv.writer(out5)

out6 = open('data/r2l/guess_password.txt', 'w', newline='')
gueWri = csv.writer(out6)

out7 = open('data/dos/pod.txt', 'w', newline='')
podWri = csv.writer(out7)

out8 = open('data/dos/teardrop.txt', 'w', newline='')
teaWri = csv.writer(out8)

out9 = open('data/probing/portsweep.txt', 'w', newline='')
porWri = csv.writer(out9)

out10 = open('data/probing/ipsweep.txt', 'w', newline='')
ipsWri = csv.writer(out10)

out11 = open('data/dos/land.txt', 'w', newline='')
lanWri = csv.writer(out11)

out12 = open('data/r2l/ftp_write.txt', 'w', newline='')
ftpWri = csv.writer(out12)

out13 = open('data/dos/back.txt', 'w', newline='')
bacWri = csv.writer(out13)

out14 = open('data/r2l/imap.txt', 'w', newline='')
imaWri = csv.writer(out14)

out15 = open('data/probing/satan.txt', 'w', newline='')
satWri = csv.writer(out15)

out16 = open('data/r2l/phf.txt', 'w', newline='')
phfWri = csv.writer(out16)

out17 = open('data/probing/nmap.txt', 'w', newline='')
nmaWri = csv.writer(out17)

out18 = open('data/r2l/multihop.txt', 'w', newline='')
mulWri = csv.writer(out18)

out19 = open('data/r2l/warezmaster.txt', 'w', newline='')
wamWri = csv.writer(out19)

out20 = open('data/r2l/warezclient.txt', 'w', newline='')
wacWri = csv.writer(out20)

out21 = open('data/r2l/spy.txt', 'w', newline='')
spyWri = csv.writer(out21)

out22 = open('data/u2r/rootkit.txt', 'w', newline='')
rooWri = csv.writer(out22)

def getSpot(label):
    """
    The getSpot method is used to select the writer for the specific attack
    name.

    Args:
        label (string): This is the name of the attack as it will appear in the
        final column of the csv. Note that records in the kddcup.data.corrected
        file are separated by periods.

    Returns:
        csv.writer: The csv.writer object associated with the attack label
    """
    # Using a dictionary as a switch statement
    return {
        'normal.'          : norWri,
        'buffer_overflow.' : bufWri,
        'loadmodule.'      : loaWri,
        'perl.'            : perWri,
        'neptune.'         : nepWri,
        'smurf.'           : smuWri,
        'guess_passwd.'    : gueWri,
        'pod.'             : podWri,
        'teardrop.'        : teaWri,
        'portsweep.'       : porWri,
        'ipsweep.'         : ipsWri,
        'land.'            : lanWri,
        'ftp_write.'       : ftpWri,
        'back.'            : bacWri,
        'imap.'            : imaWri,
        'satan.'           : satWri,
        'phf.'             : phfWri,
        'nmap.'            : nmaWri,
        'multihop.'        : mulWri,
        'warezmaster.'     : wamWri,
        'warezclient.'     : wacWri,
        'spy.'             : spyWri,
        'rootkit.'         : rooWri}[label]

# Dictionary of attack types
Attacks = {
    'normal.'          : 0,
    'buffer_overflow.' : 1,
    'loadmodule.'      : 2,
    'perl.'            : 3,
    'neptune.'         : 4,
    'smurf.'           : 5,
    'guess_passwd.'    : 6,
    'pod.'             : 7,
    'teardrop.'        : 8,
    'portsweep.'       : 9,
    'ipsweep.'         : 10,
    'land.'            : 11,
    'ftp_write.'       : 12,
    'back.'            : 13,
    'imap.'            : 14,
    'satan.'           : 15,
    'phf.'             : 16,
    'nmap.'            : 17,
    'multihop.'        : 18,
    'warezmaster.'     : 19,
    'warezclient.'     : 20,
    'spy.'             : 21,
    'rootkit.'         : 22}

# Dictionary of flag types
Flags = {
    'SF'     : 0,
    'S2'     : 1,
    'S1'     : 2,
    'S3'     : 3,
    'OTH'    : 4,
    'REJ'    : 5,
    'RSTO'   : 6,
    'S0'     : 7,
    'RSTR'   : 8,
    'RSTOS0' : 9,
    'SH'     : 10}

# Dictionary of protocols
Protocols = {
    'tcp'  : 0,
    'udp'  : 1,
    'icmp' : 2}

# Dictionary of Services
Services = {
    'http'        : 0,
    'smtp'        : 1,
    'domain_u'    : 2,
    'auth'        : 3,
    'finger'      : 4,
    'telnet'      : 5,
    'eco_i'       : 6,
    'ftp'         : 7,
    'ntp_u'       : 8,
    'ecr_i'       : 9,
    'other'       : 10,
    'urp_i'       : 11,
    'private'     : 12,
    'pop_3'       : 13,
    'ftp_data'    : 14,
    'netstat'     : 15,
    'daytime'     : 16,
    'ssh'         : 17,
    'echo'        : 18,
    'time'        : 19,
    'name'        : 20,
    'whois'       : 21,
    'domain'      : 22,
    'mtp'         : 23,
    'gopher'      : 24,
    'remote_job'  : 25,
    'rje'         : 26,
    'ctf'         : 27,
    'supdup'      : 28,
    'link'        : 29,
    'systat'      : 30,
    'discard'     : 31,
    'X11'         : 32,
    'shell'       : 33,
    'login'       : 34,
    'imap4'       : 35,
    'nntp'        : 36,
    'uucp'        : 37,
    'pm_dump'     : 38,
    'IRC'         : 39,
    'Z39_50'      : 40,
    'netbios_dgm' : 41,
    'ldap'        : 42,
    'sunrpc'      : 43,
    'courier'     : 44,
    'exec'        : 45,
    'bgp'         : 46,
    'csnet_ns'    : 47,
    'http_443'    : 48,
    'klogin'      : 49,
    'printer'     : 50,
    'netbios_ssn' : 51,
    'pop_2'       : 52,
    'nnsp'        : 53,
    'efs'         : 54,
    'hostnames'   : 55,
    'uucp_path'   : 56,
    'sql_net'     : 57,
    'vmnet'       : 58,
    'iso_tsap'    : 59,
    'netbios_ns'  : 60,
    'kshell'      : 61,
    'urh_i'       : 62,
    'http_2784'   : 63,
    'harvest'     : 64,
    'aol'         : 65,
    'tftp_u'      : 66,
    'http_8001'   : 67,
    'tim_i'       : 68,
    'red_i'       : 69}

# foreach entry in kddcup.data.corrected
for row in reader:
    # attack label
    tempAttack = row[41]

    # protocol label
    tempProtocol = row[1]

    # service label
    tempService = row[2]

    # flag labbel
    tempFlag = row[3]
    temp = row

    # mapping strings to ints based on dictionaries above
    temp[1] = Protocols[tempProtocol]
    temp[2] = Services[tempService]
    temp[3] = Flags[tempFlag]
    temp[41] = Attacks[tempAttack]

    # writing to specific reader using switch statement method getSpot
    getSpot(tempAttack).writerow(temp)

# Close all files
rawData.close()
out0.close()
out1.close()
out2.close()
out3.close()
out4.close()
out5.close()
out6.close()
out7.close()
out8.close()
out9.close()
out10.close()
out11.close()
out12.close()
out13.close()
out14.close()
out15.close()
out16.close()
out17.close()
out18.close()
out19.close()
out20.close()
out21.close()
out22.close()
