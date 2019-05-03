### Data Parsing Scripts

*******************************************************************************
* organizer.py                                                                *
*******************************************************************************
In order to generate a full list of the attack types, flag types, protocol 
types, and service types present in the kddcup.data.corrected file, simple 
scripts were run to generate a complete list of them. Total numbers of each:

Attack types:   23*
Flag types:     11
Protocol types:  3
Service types:  70 

* It should be noted that attack types includes an entry for 'normal' traffic.

After this, the values were mapped to integer values. These specific integer 
values can be seen within the organizer.py dictionaries. After mapping of all
string values is done, the entries are then written to specific files, defined
below. 

For example:

An entry from kddcup.data.corrected has the format of the following:

[0,tcp,http,SF,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.00,0.00,0.00,
0.00,1.00,0.00,0.00,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,normal.]

After the mapping process, this entry would have the following format:

[0,0,0,0,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.00,0.00,0.00,
0.00,1.00,0.00,0.00,0,0,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0.00,0]

This would then be added to the normal.txt file, as this is the label of this
data entry. 

In order to execute this script correctly, organizer.py must be within the 
same directory as kddcup.data.corrected, so the kddcup.data.zip must be
unzipped.

The final output of an organizer.py execution should be a directory labelled 
data. Within this directory are four more directories labelled dos, probing,
r2l, and u2r. There should also be an additional file called normal.txt. The 
four subdirectories hold txt files containing the entries for attacks that are 
of the type indicated by the subdirectory lables. The following is the final 
output structure:

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
		
 
*******************************************************************************
* builder.py                                                                  *
*******************************************************************************
The builder function performs further mapping to place attack types on specific
labels from 0 to 5, as tensorflow would fill out a total of x different output
nodes depending on the largest arbitrary label for the attack type. 

The attack types selected, their final label and their approximate percentages 
in the testing and training sets are list below.

Attack    | Label | Percentage
------------------------------
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
