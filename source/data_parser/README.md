### Data Parsing Scripts

### 1998 DARPA INTRUSION DETECTION EVALUATION DATASET

`alternatives/` 

*folder contains parser scripts that didn't quite cut it for performance purposes or other problems.*

`pcap.py`

*Simply takes a pcap file and outputs some statistics (uses dpkt library)*

`pcap_dpkt.py`

*Is the script the current version of the parse is based on but has a limitation of being slow due to the fact that dpkt library is reading **pcap** data from the hard drive and its performance is inadequate when running on the large files.*

This script takes the metadata from the `.list` file correllates it with data in `.tcpdump` file and outputs a `.csv` with features. For every event found in the `.list` it looks through pcap file, due to inability of dpkt library to seek. Multiple threads are used.

`pcap_dpkt_reverse.py`

Almost the same as `pcap_dpkt.py` except for every packet parsed we try to find events related to each packet. Faster but still not good enough.

`output/`

Contains the output files `csv` and `html` representation of feature set.

`pcap_parser_dpkt_memory_hog.py`

The main functional parser script, based off `pcap_dpkt.py` uses threads and loads PCAP into mamory to speed up the process.

*Note: this script performance can significantly be improved by creating a separate indexing array on truncated dates and using isplit to seek to needed timestamp in the main pcap loop*
##### Description of parameters
```
usage: pcap_parser_dpkt_memory_hog.py [-h] --metadata METADATA --pcap PCAP
                                      [--threads THREADS] [--csv CSV]
                                      [--html HTML] [--tz TZ]

optional arguments:
  -h, --help           show this help message and exit
  --metadata METADATA  Metadata file to use ex. --metadata=tcpdump.list
  --pcap PCAP          PCAP file to use ex. --pcap=sample_data01.tcpdump
  --threads THREADS    Number of threads to use --threads=8
  --csv CSV            CSV Filename to output --csv=output/output.csv
  --html HTML          HTML Filename to output --html=output/output.html
  --tz TZ              Timezone of the metadata file --tz="GMT-0500"
```
##### How to run
From the VM

```
vagrant@debian9:~$ cd source/data_parser/
./pcap_parser_dpkt_memory_hog.py --metadata="../../sample_data/small/tcpdump.list" --pcap="../../sample_data/small/sample_data01.tcpdump" --tz="GMT-0500"
```



pcap_splitter.py	


### KDD Cup 1999 Datasets
#### organizer.py      
##### Description
In order to generate a full list of the attack types, flag types, protocol 
types, and service types present in the kddcup.data.corrected file, simple 
scripts were run to generate a complete list of them. Total numbers of each:

Attack types:   23
Flag types:     11
Protocol types:  3
Service types:  70 

*It should be noted that attack types includes an entry for 'normal' traffic.*

After this, the values were mapped to integer values. These specific integer 
values can be seen within the organizer.py dictionaries. After mapping of all
string values is done, the entries are then written to specific files, defined
below. 

For example:

An entry from kddcup.data.corrected has the format of the following:
```
[0,tcp,http,SF,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.00,0.00,0.00,
0.00,1.00,0.00,0.00,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,normal.]
```
After the mapping process, this entry would have the following format:
```
[0,0,0,0,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.00,0.00,0.00,
0.00,1.00,0.00,0.00,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0]
```
This would then be added to the normal.txt file, as this is the label of this
data entry. 
##### Execution
In order to execute organizer.py, verify that kddcup.data.corrected file is 
in the same directory. Execute the organizer file from the command line:
```
organizer.py
```
##### Output
The final output of an organizer.py execution should be a directory labelled 
data. Within this directory are four more directories labelled dos, probing,
r2l, and u2r. There should also be an additional file called normal.txt. The 
four subdirectories hold txt files containing the entries for attacks that are 
of the type indicated by the subdirectory lables. The following is the final 
output structure:
```
data
------------------------------
	normal.txt
	dos
	--------------------------
		back.txt
		land.txt
		neptune.txt
		pod.txt
		smurf.txt
		teardrop.txt
	probing
	--------------------------
		ipsweep.txt
		nmap.txt
		portsweep.txt
		satan.txt
	r2l
	--------------------------
		ftp_write.txt
		guess_password.txt
		imap.txt
		multihop.txt
		phf.txt
		spy.txt
		warezclient.txt
		warezmaster.txt
	u2r
	--------------------------
		buffer_offerflow.txt
		loadmodule.txt
		perl.txt
		rootkit.txt
		
 ```
#### builder.py                                                                  
##### Description
The builder function performs further mapping to place attack types on specific
labels from 0 to 5, as tensorflow would fill out a total of x different output
nodes depending on the largest arbitrary label for the attack type. 

The attack types selected, their final label and their approximate percentages 
in the testing and training sets are list below.

Attack    | Label | Percentage
---------|:------:|----------
Normal    |     0 |        50%
Neptune   |     1 |        10%
Smurf     |     2 |        10%
Portsweep |     3 |        10%
Back      |     4 |        10%
Nmap      |     5 |        10%

The attack types were initially narrowed down by total representation in total 
number of records. The initial goal for the semester was to detect types of DOS
attacks, so the DOS attacks with enough records were all selected (Neptune, 
Smurf, Back) and then the remaining two were simply selected as probing is the 
easiest way to detect attacks. 
 ##### Execution
 Verify that builder.py is in the same directory as organizer.py, and that 
 organizer.py has been executed. Execute the script from the command line:
 ```
 builder.py
 ```
 ##### Output
 The resulting output from builder.py will be two data files labelled
 testing3.txt and training3.txt. One representing training data, with one
 representing testing data to be analyzed by the machine learning module.
 
