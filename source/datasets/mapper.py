import csv

rawData = open('kddcup.data.corrected', 'r')
reader = csv.reader(rawData, lineterminator='.')

outputData0 = open('data/training0.txt', 'w', newline='')
writer0 = csv.writer(outputData0)

outputData1 = open('data/training1.txt', 'w', newline='')
writer1 = csv.writer(outputData1)

outputData2 = open('data/training2.txt', 'w', newline='')
writer2 = csv.writer(outputData2)

outputData3 = open('data/training3.txt', 'w', newline='')
writer3 = csv.writer(outputData3)

outputData4 = open('data/training4.txt', 'w', newline='')
writer4 = csv.writer(outputData4)

outputData5 = open('data/training5.txt', 'w', newline='')
writer5 = csv.writer(outputData5)

outputData6 = open('data/training6.txt', 'w', newline='')
writer6 = csv.writer(outputData6)

outputData7 = open('data/training7.txt', 'w', newline='')
writer7 = csv.writer(outputData7)

outputData8 = open('data/training8.txt', 'w', newline='')
writer8 = csv.writer(outputData8)

outputData9 = open('data/training9.txt', 'w', newline='')
writer9 = csv.writer(outputData9)

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

Protocols = {
    'tcp'  : 0,
    'udp'  : 1,
    'icmp' : 2}

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

counter = 1

for row in reader:
    tempAttack = row[41]
    tempProtocol = row[1]
    tempService = row[2]
    tempFlag = row[3]
    temp = row
    temp[1] = Protocols[tempProtocol]
    temp[2] = Services[tempService]
    temp[3] = Flags[tempFlag]
    temp[41] = Attacks[tempAttack]
    if(counter <= 500000):
        writer0.writerow(temp)
    elif(counter <= 1000000):
        writer1.writerow(temp)
    elif(counter <= 1500000):
        writer2.writerow(temp)
    elif(counter <= 2000000):
        writer3.writerow(temp)
    elif(counter <= 2500000):
        writer4.writerow(temp)
    elif(counter <= 3000000):
        writer5.writerow(temp)
    elif(counter <= 3500000):
        writer6.writerow(temp)
    elif(counter <= 4000000):
        writer7.writerow(temp)
    elif(counter <= 4500000):
        writer8.writerow(temp)
    else:
        writer9.writerow(temp)
    counter = counter + 1
    
rawData.close()
outputData0.close()
outputData1.close()
outputData2.close()
outputData3.close()
outputData4.close()
outputData5.close()
outputData6.close()
outputData7.close()
outputData8.close()
outputData9.close()
