if [[ -z $1 ]];then
	echo "specify an IP address"
	exit
fi

rm /home/moses/forsee/forsee/vm_decom_list/$1
