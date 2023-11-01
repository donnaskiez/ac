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

- The system module integrity checks on win11 fail due to MmCopyMemory error for around 80% of the modules. While it doesn't cause a blue screen, this is a pretty pathetic success rate. Am looking into it.
- KPRCB thread check rn is kinda broken

Ive thoroughly tested the driver with verifier in addition to extended testing on my main pc (non vm) so at the least there shouldn't be any bluescreens (hopefully...). If you do find any, feel free to open an issue with the minidump :)

# windows versions tested:

- Win10 22H2
- Win11 22H2

# logs example

video of example logs + running on my machine no vm: [video](https://youtu.be/htY83WsMEcc)

# how 2 use

1. Build the project in visual studio, if you experience any build issues - check the drivers project settings are the following:
	- `Inf2Cat -> General -> Use Local Time` to `Yes`
	- `C/C++ -> Treat Warnings As Errors` to `No`
	- `C/C++ -> Spectre Mitigation` to `Disabled`
2. Move the `driver.sys` file into `Windows/System32/Drivers` directory
3. Use the osr loader to load the driver at "system" load.
	- Osr loader can be found here: https://www.osronline.com/article.cfm%5Earticle=157.htm
	- driver must be named "driver.sys" (sorry.. will be fixed soon (i am lazy))
	- IMPORTANT: its important that you only click "Register" in the OSR loader, dont actually load the driver only register it. Then restart. This is very important as the driver needs an accurate representation of system threads and processes in order for many of the detection methods to work.
4. inject dll into program you want to protect, i used notepad for testing. 
	- IMPORTANT: it is important that this process is started as administrator, which in turn means the injector you use must also be started as administrator. This is a design flaw. Will be fixed in the future.
	- Obviously in a "real" program, the dll would be embedded into the application - for now this is what we work with.
5. Logs can be seen both in the terminal and either dbgview or WinDbg depending on what you use. 
	- If for some reason you can't see logs in DbgView, you may need to properly set your debugging mask. Tutorial here: https://www.osronline.com/article.cfm%5Earticle=295.htm
6. The server and service arent needed, youll just see a bunch of "failed to write to pipe" if you dont launch the service, this is fine and the core anti cheat + user mode is still working.

# contact

feel free to dm me on discord or uc @donnaskiez