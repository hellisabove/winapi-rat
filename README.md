[![justforfunnoreally.dev badge](https://img.shields.io/badge/justforfunnoreally-dev-9ff)](https://justforfunnoreally.dev)
# winapi-rat
This is a simple remote access trojan made in c++ using the windows api.

## Dll
This is a DLL that is used as the payload. At the moment it can start and inject itself into a process and open a reverse shell.

## Injector
This is a DLL injector which we use to inject our payload into a section header of another pe file

## Loader
This is the distribution method of our payload. It will extract the payload out of the last section header and move it with a random generated name into the %appdata% folder. After that it executes the payload, sets up persistance by use of registry keys and deletes itself.

## Compile
For compiling you will need at least the normal Visual Studio 2017 toolchain along the vs2017 toolchain with windows xp compatibility plus the windows 7 wdk(windows-driver-kit) which you can get from [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=11800). After installing everything, just hit the build solution and you should be done.
