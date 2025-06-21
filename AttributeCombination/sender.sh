#!/bin/bash

# Example usage
# ./sender.sh ../Data/5k/ NetworkData5k.csv ../Attributes/NF-UQ-NIDS-v2_columns6.csv ../Data/5k/sender_log.txt

if [ "$#" -lt "4" ]
  then echo "Usage: $0 <data path> <input file> <column_ids_csv> <log file>"
  exit
fi

./sender_transform $1$2 $1 $3

../APSI/build/bin/sender_cli -t 1 -f $4 -d $1tempNetworkData.csv -p ../APSI/parameters/16M-4096-32.json 
