#!/bin/bash

# ./run_receiver.sh ../Data/50k/attr3/ PDQ_intersection.csv intersection.csv final_result.csv receiver_log_PDQ.txt 127.0.0.1 > ../Data/50k/attr3/receiver_log_PDQ2.txt


if [ "$#" -lt "6" ]
  then echo "Usage: $0 <data path> <input file> <intersection file> <final result file> <log file> <ip address>"
  exit
fi

./APSIPeripheral/receiver_transform $1$2 $1tempIoC.csv

../APSI/build/bin/receiver_cli -t 1 -f $1$5 -q $1tempIoC.csv  -o $1$3 -a $6

./APSIPeripheral/receiver_decrypt $1$4 $1

pkill -f ../APSI/build/bin/sender_cli
