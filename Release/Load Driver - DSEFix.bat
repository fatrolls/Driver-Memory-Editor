SET CurrentDir=%~dps0
cd %CurrentDir%
%CurrentDir%dsefix.exe
timeout /t 2
sc create csgo binPath= "%CurrentDir%Driver.sys" type= kernel
sc start csgo
timeout /t 2
%CurrentDir%dsefix.exe -e
echo Restored DSE controlling variable to default state.
timeout /t 2
pause