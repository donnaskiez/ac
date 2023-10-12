# ac

some things to note:

- open source anticheat (oxymoron)
- currently only tested on 10 19045 and since offsets are currently hardcoded u may experience technical difficulties. This will be fixed in the future when i either finish the debuglib or just use a pdb parser or maybe another method ;)
- as a passion project i am really only implementing methods which i find enjoyable to either research or build which is why you see a lack of hooks and other such. Maybe in the future c:

# how 2 use

1. use the osr loader to load the driver at "system" load.
2. inject dll into program you want to protect, i used notepad for testing
3. logs will be printed to dbgview and the usermode dll via stdout

driver must be named "driver.sys" (sorry..)