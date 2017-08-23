Dumper
======

This is fairly simple tool to dump portion of process memory under Windows operating system.
It's intended usage is to augment somewhat limited Memory View in Visual Studio in terms of copying process memory contents.

Command syntax:
```
dumper.exe <debugged process id or name> <memory_start_addr> <memory_length>
```

Example usage:
```
Dumper.exe notepad 0x24D3EF98 0x17
```

This will find process called notepad.exe, open it, create file called notepad-0x24D3EF98-0x17.dmp and copy 23 bytes of data into file starting and memory address 0x24D3EF98.

Both address and length can be hex or decimal sting, instead of process name it's possible to supply process ID in decimal format.

Inspired by [StackOverflow answer](https://stackoverflow.com/a/8017023) and long gone user142207 (whoever that is!) 