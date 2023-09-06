#!/bin/bash
rm -rf /tmp/ida

if [ -z $3 ]; then
	echo "Usage ./do_angry_ida_things.bash <frame_no> <malware> <remote_vm_ip>"
	exit
fi
#to just load the dumps that exist locally into IDA
/home/moses/ida-7.0/ida64 -A -c  -S"/home/moses/forsee/forsee/angry_ida.py  $1 $2 $3" -b0x0 -pmetapc -Tbinary /home/moses/forsee/workspace/empty_file.dmp
#/home/moses/ida-7.0/ida64 -A -a -c -B -P -S/home/moses/ida-7.0/moses_custom/beast.py -b0x0 -pmetapc -Tbinary /home/moses/forsee/workspace/empty_file.dmp

#rm -rf /tmp/ida
#echo "opening the previously saved database"
#/home/moses/ida-7.0/ida64 -A  -P -pmetapc -Tbinary /home/moses/forsee/workspace/empty_file.dmp

