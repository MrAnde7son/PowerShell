

for /l %%x in (1, 1, 100) do echo %%x > %userprofile%\%%x.txt

for /l %%x in (1, 1, 100) do reg add hklm\software\windows\microsoft /v Data%%x /d %%x /f

