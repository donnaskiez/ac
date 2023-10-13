# ac

# features

- Attached thread detection
- Process module .text section integrity checks
- NMI and APC stackwalks (to allow excellent system coverage)
- Handle stripping via obj callbacks
- Process handle table enumeration
- System module verification
- Unlinked process detection via PTE walking and checking against a robust process structure signature
- Hidden thread detection via KPRCB
- Dispatch routine validation
- Extraction of hardware identifiers via SMBIOS parsing and PhysicalDriveN querying
- EPT hook detection (currently detects hyperdbg and DdiMon)
- Driver integrity checks both locally and over server
- Test signing detection
- Hypervisor detection via instruction emulation testing and timing checks

# some things to note:

- open source anticheat (oxymoron)
- currently only tested on 10 19045 and since offsets are currently hardcoded u may experience technical difficulties. This will be fixed in the future when i either finish the debuglib or just use a pdb parser or maybe another method ;)
- as a passion project i am really only implementing methods which i find enjoyable to either research or build which is why you see a lack of hooks and other such. Maybe in the future c:
- There is still a plethora of work to do with regards to anti tamper, such as packet encryption, string encryption, binary virtualization etc.
- There is also still much work to be done with regards to the prevention toolset, I would like to implement some form of cr3 protection in the near future.

# how 2 use

1. use the osr loader to load the driver at "system" load.
2. inject dll into program you want to protect, i used notepad for testing
3. logs will be printed to dbgview and the usermode dll via stdout

driver must be named "driver.sys" (sorry.. will be fixed soon (i am lazy))