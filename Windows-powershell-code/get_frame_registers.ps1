#Usage echo ./get_frame_registers -malware <malware.exe> -frame_no <frame_no_in_hex>  -arch <64|32>| powershell -file -

param(
    [Parameter(Mandatory=$true)][string]$frame_no,
    [Parameter(Mandatory=$true)][string]$malware,
    [Parameter(Mandatory=$true)][string]$arch
)


$dump_file = "C:\Users\moses\Documents\from_windbg\$malware\$malware.dmp"
$log_file = "C:\Users\moses\Documents\from_windbg\$malware\dumps\frame_registers-$frame_no-$malware.log"

if ($arch.CompareTo("64")){ #if equal it returns a 0
    windbg -c " .effmach x86 ; ~0 s; .frame /c $frame_no; k; q" -z $dump_file -logo $log_file
}else{
    windbg -c "~0 s; .frame /c $frame_no; k; q" -z $dump_file -logo $log_file
}
