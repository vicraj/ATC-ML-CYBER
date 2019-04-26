import pandas as pd
from IPython.display import display, HTML
from datetime import datetime
from datetime import timedelta
import subprocess
import re
from multiprocessing.dummy import Pool as ThreadPool

def run_command(command):
    print("Starting command: " + command)
    subprocess.run(command, shell=True)
    print("Finished command: " + command)

def get_valid_filename(s):
    """
    Return the given string converted to a string that can be used for a clean
    filename. Remove leading and trailing spaces; convert other spaces to
    underscores; and remove anything that is not an alphanumeric, dash,
    underscore, or dot.
    >>> get_valid_filename("john's portrait in 2004.jpg")
    'johns_portrait_in_2004.jpg'
    """
    s = str(s).strip().replace(' ', '_')
    return re.sub(r'(?u)[^-\w.]', '', s)

def main():
    metadata_file_name = '../sample_data/wednesday/tcpdump.list'
    pcap_file_name = '../sample_data/wednesday/outside.tcpdump'

    # metadata_file_name = 'tcpdump.list'
    df = pd.read_csv(metadata_file_name, delim_whitespace=True)

    # Get unique attack names and display for our script purposes
    print('Available attacks names:\n')
    df_attacks = df[['attack_name']].drop_duplicates()
    display(df_attacks)

    # Get only port scans
    df2 = df#.loc[df['service'] == "telnet"]

    # Output this table into an html file.
    df2.to_html('filename.html')

    commands = []

    print("Generate commands to run...")
    for index, row in df2.iterrows():
        datetime_start = datetime.strptime(("%s %s") % (row['date'], row['time']), '%m/%d/%Y %H:%M:%S')
        duration = row['duration'].split(':')
        hours = int(duration[0])
        minutes = int(duration[1])
        seconds = int(duration[2])
        datetime_end = datetime_start + timedelta(hours=hours, minutes=minutes, seconds=seconds)

        #editcap -v  -A "1998-01-23 16:03:52" -B "1998-01-23 16:03:58"  sample_data01.tcpdump /dev/null
        file_name = "%s_%s.pcap" % (row['id'], row['attack_name'])
        file_name = "%s.pcap" % (row['id'])
        file_name = get_valid_filename(file_name)
        command = ("editcap -A \"%s\" -B \"%s\"  %s output/%s") % (datetime_start, datetime_end, pcap_file_name,file_name)

        #print(command)

        #print("'%s'" % datetime_start)
        commands.append(command)

    print("Starting Multithreaded Splitting...")
    pool = ThreadPool(8)

    # split datasets in their own threads
    # and return the results
    pool.starmap(run_command, zip(commands))

    # close the pool and wait for the work to finish
    pool.close()
    pool.join()

    # 1.) Session duration, int
    # 2.) Service (http, ftp, etc), symbolic
    # 3.) Status flag, symbolic
    # 4.) bytes sent to destination, int
    # 5.) bytes sent to source, int
    # 6.) Source/destination addresses are the same, boolean
    # 7.) Number of urgent packets, int
    # 8.) Number of wrong fragments, int --- NO ?
    # 9.) Protocol (tcp, udp, icmp), symbolic --- no
    # 10.) Both Syn & RST set (syn rst attack
    # tcpdump 'tcp[13] = 6'


if __name__ == "__main__":
    main()


