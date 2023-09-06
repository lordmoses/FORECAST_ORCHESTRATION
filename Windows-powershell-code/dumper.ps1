
if ($args) {
    Write-Host "running dumper.ps1"
}else{
    Write-Host "no argument was given, exiting..."
    exit
}

$malware_dir = "C:\Users\moses\Documents\from_windbg\$args"
$dump_file = "C:\Users\moses\Documents\from_windbg\$args\$args.dmp"
$log_file = "C:\Users\moses\Documents\from_windbg\$args\dump-$args.log"

#Delete the directory if it exists for a fresh start
if (Test-Path $malware_dir) {
    Write-Host "deleting existing $malware"
    Remove-Item $malware_dir -recurse
}

New-Item $malware_dir -type directory -force

windbg -c ".dump /ma $dump_file; q" -pn $args -logo $log_file
#windbg -c ".dump /ma C:\Users\moses\Documents\from_windbg\$args\$args.dmp; q" -pn $args -logo C:\Users\moses\Documents\from_windbg\$args\dump-$args.log
