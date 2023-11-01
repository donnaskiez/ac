# ac

# features

- Attached thread detection
- Process module .text section integrity checks
- NMI and APC stackwalking
- IPI stackwalking which is a relatively unknown method compared to NMIs and APCs
- Handle stripping via obj callbacks
- Process handle table enumeration
- System module verification
- System module .text integrity checks (see known issues)
- Unlinked process detection
- Hidden thread detection via KPRCB
- Hidden thread detection via PspCid table
- Dispatch routine validation
- Extraction of hardware identifiers
- EPT hook detection (currently detects hyperdbg and DdiMon)
- Driver integrity checks both locally and over server
- Test signing detection
- Hypervisor detection

# planned features

- Heartbeat between components
- ntoskrnl integrity checks (currently in progress)
- some way of identifying spoofed stacks
- some way of dynamically resolving offsets. Will probably use a pdb parser but i am working on a debuglib atm using the windows debug api. We will see.
- some form of cr3 protection
- some more detection methods other then stackwalking xD
- various forms of encryption and other things 

# known issues

- the system module validation works on my vm but not on my main pc, not sure if others will experience the same issues. am however working on a fix

feel free to open any issues if you find more.

# some things to note:

- open source anticheat (oxymoron)
- currently only tested on 10 19045 and since offsets are currently hardcoded u may experience technical difficulties. This will be fixed in the future when i either finish the debuglib or just use a pdb parser or maybe another method ;)
- as a passion project i am really only implementing methods which i find enjoyable to either research or build which is why you see a lack of hooks and other such. Maybe in the future c:
- There is still a plethora of work to do with regards to anti tamper, such as packet encryption, string encryption, binary virtualization etc.
- There is also still much work to be done with regards to the prevention toolset, I would like to implement some form of cr3 protection in the near future.

# how 2 use

1. use the osr loader to load the driver at "system" load.
	- driver must be named "driver.sys" (sorry.. will be fixed soon (i am lazy))
	- NOTE: its important that you only click "Register" in the OSR loader, dont actually load the driver only register it. Then restart. This is very important as the driver needs an accurate representation of system threads and processes in order for many of the detection methods to work.
2. inject dll into program you want to protect, i used notepad for testing. 
	- NOTE: it is important that this process is started as administrator, which in turn means the injector you use must also be started as administrator. This is a design flaw. Will be fixed in the future.
	- Obviously in a "real" program, the dll would be embedded into the application - for now this is what we work with.
3. Logs can be seen both in the terminal and either dbgview or WinDbg depending on what you use. 
	- If for some reason you can't see logs in DbgView, you may need to properly set your debugging mask. Tutorial here: https://www.osronline.com/article.cfm%5Earticle=295.htm
4. The server and service arent needed, youll just see a bunch of "failed to write to pipe" if you dont launch the service, this is fine and the core anti cheat + user mode is still working.

If you have any suggestions / need help feel free to dm me on discord or uc @donnaskiez