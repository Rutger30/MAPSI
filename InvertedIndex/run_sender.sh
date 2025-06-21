#!/bin/bash

# ./run_sender.sh ../Data/50k/attr3/ ../Data/50k/NetworkData50k.csv ../Data/50k/attr3/sender_log_II.txt

if [ "$#" -lt "3" ]
  then echo "Usage: $0 <data path> <input file> <log file>"
  exit
fi

./APSIPeripheral/sender_transform $2 $1

../APSI/build/bin/sender_cli -t 1 -f $3 -d $1tempNetworkData.csv -p ../APSI/parameters/16M-4096-32.json