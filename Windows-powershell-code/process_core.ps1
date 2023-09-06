#usage: echo ./process_core.ps1 -malware <malware> -writer <cmd_writer_script> | powershell -file -

param(
    [Parameter(Mandatory=$true)][string]$malware,
    [Parameter(Mandatory=$true)][string]$writer
)



$malware_dir = "C:\Users\moses\Documents\from_windbg\$malware"
$dumps_dir = $malware_dir + "\dumps"
$dump_file = $malware_dir + "\$malware" + ".dmp"
$log_file = $dumps_dir + "\windbg.log"
$command_file = $malware_dir + "\command.txt"

#check if previously created dumps already exist
if (Test-Path $dumps_dir) {
    Write-host "deleting existing $dumps_dir" 
    Remove-Item $dumps_dir -recurse
}

#create a directory to store the to-be-extracted dumps
New-Item $dumps_dir -type directory -force

#The command_writes the commands to command.txt in $malware_dir
powershell -file ./$writer $malware


#windbg -c $<C:\Users\moses\Documents\from_windbg\command.txt  -z C:\Users\moses\Documents\from_windbg\$args\$args.dmp -logo C:\Users\moses\Documents\from_windbg\$args\dumps\windbg.log

windbg -c $><$command_file  -z $dump_file -logo $log_file
