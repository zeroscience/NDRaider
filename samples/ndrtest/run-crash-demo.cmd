@echo off
title NDRaider crash demo - NdrTestServer (auto-restart)
echo(
echo  Keeping NdrTestServer.exe alive so you can fuzz it from the GUI and see red.
echo(
echo  It hosts the NdrTest RPC interface on ncalrpc:ndrtestalpc and has a planted
echo  /GS stack overflow (the VulnCopy method). When the fuzzer hits it, the server
echo  crashes and exits - this script restarts it so you can fuzz again and again.
echo(
echo  In the GUI:  Folder...  ^-^>  pick this folder  ^-^>  select NdrTestServer.exe  ^-^>  FUZZ
echo  Press Ctrl+C here to stop the demo.
echo(
:loop
"%~dp0NdrTestServer.exe"
echo  [demo] server exited (likely a caught crash) - restarting in 1s...
timeout /t 1 /nobreak >nul
goto loop
