import pandas as pd
from IPython.display import display, HTML
from datetime import datetime
from datetime import timedelta
import subprocess


def main():
    df = pd.read_csv('tcpdump.list', delim_whitespace=True)

    # Get unique attack names and display for our script purposes
    print('Available attacks names:\n')
    df_attacks = df[['attack_name']].drop_duplicates()
    display(df_attacks)

    # Get only port scans
    df2 = df#.loc[df['service'] == "telnet"]

    # Output this table into an html file.
    df2.to_html('filename.html')

    for index, row in df2.iterrows():
        datetime_start = datetime.strptime(("%s %s") % (row['date'], row['time']), '%m/%d/%Y %H:%M:%S')
        duration = row['duration'].split(':')
        hours = int(duration[0])
        minutes = int(duration[1])
        seconds = int(duration[2])
        datetime_end = datetime_start + timedelta(hours=hours, minutes=minutes, seconds=seconds)

        #print(row['attack_name'], datetime_start, datetime_end)
        #print()
        #editcap -v  -A "1998-01-23 16:03:52" -B "1998-01-23 16:03:58"  sample_data01.tcpdump /dev/null
        file_name = "%s_%s.pcap" % (row['id'], row['attack_name'])
        command = ("editcap -v -A \"%s\" -B \"%s\"  sample_data01.tcpdump output/%s") % (datetime_start, datetime_end, file_name)
        #command = ("editcap -v -A \"%s\" -B \"%s\"  ../sample_data/sample_data01.tcpdump /dev/null") % ("1998-01-23 16:03:52", datetime_end)


        #command = "editcap -v  -A \"1998-01-23 16:03:52\" -B \"1998-01-23 16:03:58\"  ../sample_data/sample_data01.tcpdump /dev/null"
        print(command)

        #print("'%s'" % datetime_start)

        subprocess.run(command, shell=True)


if __name__ == "__main__":
    main()