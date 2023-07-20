[![justforfunnoreally.dev badge](https://img.shields.io/badge/justforfunnoreally-dev-9ff)](https://justforfunnoreally.dev)
# winapi-rat
This is a simple remote access trojan made in c++ using the windows api.

# Dll
This is a DLL that is used as the payload. At the moment it can start and inject itself into a process and open a reverse shell.

# Injector
This is a DLL injector which we use to inject our payload into a section header of another pe file

# Loader
This is the distribution method of our payload. It will extract the payload out of the last section header and move it with a random generated name into the %appdata% folder. After that it executes the payload, sets up persistance by use of registry keys and deletes itself.
