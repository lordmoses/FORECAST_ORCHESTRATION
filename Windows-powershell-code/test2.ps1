
#This is the right way to run a PS script in cygwin
#echo ./test.ps1 -arg kk -arg2 2 | powershell -file -




Write-Host "This is a test"

Write-Host $args[0]
Write-Host $args[1]
New-Item C:\Users\moses\Documents\from_windbg\test -type directory -force

#running the malware 

C:\Users\moses\Documents\crackme.exe jj


$time = $args[1]

Write-Host "I am sleeping for $time seconds"
Start-Sleep -s $time
Write-Host "I am done sleeping"
exit
