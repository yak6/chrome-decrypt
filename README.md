# Chrome decrypt

This program is used to decrypt Google Chrome saved login credentials and print them on screen or save to file.
## Requirements
- MinGW gcc compiler
- MSYS2 packages:
```
mingw-w64-x86_64-nlohmann-json
mingw-w64-ucrt-x86_64-openssl
mingw-w64-ucrt-x86_64-sqlite3
```
If these are installed, you should compile without a problem.

## Compile
Compile with mingw gcc compiler:
```powershell
g++ src/main.cpp -o decrypt.exe -lssl -lcrypto -lsqlite3 -lbcrypt -lcrypt32 -lws2_32
```

## Usage
Decrypt passwords and print them:
```powershell
.\decrypt.exe
```
If you wish to have them in file, simply use one argument:
```powershell
.\decrypt.exe -o mypasswords.txt
```
