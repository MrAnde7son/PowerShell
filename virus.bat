echo off

for /l %x in (1, 1, 100) do echo %x > %userprofile%\%x.txt
for /l %x in (1, 1, 100) do reg add hklm\software\windows\microsoft /v Data%x /d %x /f
for /l %i in (1,1,255) do ping -n 1 192.168.0.%i 
for /l %i in (1,1,255) do ping -n 1 10.0.0.%i 

