#!/bin/bash

# Example usage
# ./receiver.sh ../Data/5k/ IoC.csv intersection.csv final_result.csv ../Data/5k/receiver_log.txt 127.0.0.1 ../Attributes/NF-UQ-NIDS-v2_columns6.csv

if [ "$#" -lt "7" ]
  then echo "Usage: $0 <data path> <input file> <intersection file> <final result file> <log file> <ip address> <column_ids_csv>"
  exit
fi

./receiver_transform $1../$2 $1tempIoC.csv $7

../APSI/build/bin/receiver_cli -t 1 -f $5 -q $1tempIoC.csv -o $1$3 -a $6

./receiver_decrypt $1$4 $1

pkill -f ../APSI/build/bin/sender_cli
