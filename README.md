## Automated Reverse Engineering of Malicious Behaviors in Malwawre via Selective Symbolic Execution of Memory Execution States


This framework enables the execution of malware samples in a several Windows VMs pre-configured and started from a snapshot. Upon execution, a WinDBG is run to take a memory execution dump of the malware after it makes a network activity. This dump is then transfered to a linux machine via SCP, where symbolic execution is initiated to analyze the captured states from the last instruction pointer of the execution state. 

FORECAST VM Config

ulimit -n 65000 #to allow many open files since each of the memory segments are loaded as blobs by both IDA and ange

