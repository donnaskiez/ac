# ac

open source anti cheat (lol) which I made for fun.

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

- Heartbeat
- ntoskrnl integrity checks, or atleast a small subset of the kernel encompasing critical functions
- spoofed stack identifier
- process module inline hook detection (this would include checking whether the hook is valid, as many legimate programs hook user mode modules such as discord, nvidia overlay etc.)
- cr3 protection 
- string, packet and other encryption
- tpm ek extraction
- tpm spoofer detection
- pcileech firmware detection 
- testing program to test the features

# known issues

- [See the issues page](https://github.com/donnaskiez/ac/issues)
- Feel free to open a new issue if you find any bugs

# windows versions tested:

- Win10 22H2
- Win11 22H2

# how to build

Requires [Visual Studio](https://visualstudio.microsoft.com/downloads/) and the [WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) for compilation.

1. Build the project in visual studio, if you experience any build issues - check the drivers project settings are the following:
	- `Inf2Cat -> General -> Use Local Time` to `Yes`
	- `C/C++ -> Treat Warnings As Errors` to `No`
	- `C/C++ -> Spectre Mitigation` to `Disabled`
2. Move the `driver.sys` file located in `ac\x64\Release` into the `Windows\System32\Drivers` directory
3. Use the [OSR Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) and select `driver.sys` that you moved to the Windows drivers folder. DO NOT REGISTER THE SERVICE YET.
	- driver must be named "driver.sys" (sorry.. will be fixed soon (i am lazy))
4. Under `Service Start` select `System`. This is VERY important!
5. Click `Register Service`. *Do NOT click* `Start Service`!
6. Restart Windows. 
7. Once restarted, open the program you would like to protect as Administrator.
	- Yes I understand this is not realistic
8. Open your dll injector program of choice as administrator (I simply use [Process Hacker](https://processhacker.sourceforge.io/))
9. Inject the dll found in `ac\x64\Release` named `user.dll` into the target program

Logs will be printed to both the terminal output and the kernel debugger. See below for configuring kernel debugger output.

Note: The server is not needed for the program to function properly.

# how to configure kernel debugging output

The kernel driver is setup to log at 4 distinct levels:

```C
#define DPFLTR_ERROR_LEVEL  
#define DPFLTR_WARNING_LEVEL
#define DPFLTR_INFO_LEVEL   
#define DPFLTR_VERBOSE_LEVEL
```

As the names suggest, `ERROR_LEVEL` is for errors, `WARNING_LEVEL` is for warnings. `INFO_LEVEL` is for general information regarding what requests the driver is processing and `VERBOSE_LEVEL` contains very detailed information for each request.

## creating the registry key

If you are unfamiliar with the kernel debugging mask, you probably need to set one up. If you already have a debugging mask setup, you can skip to `setting the mask` below.

1. Open the Registry Editor
2. Copy and pase `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager` into the bar at the top and press enter
3. On the left hand side, right click `Session Manager` and select `New -> Key`
4. Name the key `Debug Print Filter`
5. On the left hand side you should now see `Debug Print Filter`, right click and select `New -> DWORD (32 bit) Value`
6. Name the key `DEFAULT`

## setting the mask

1. Within the `Debug Print Filter` registry, double click the key named `DEFAULT`
2. Determine the level(s) of logging you would like to see. For most people interested I would set either `INFO_LEVEL` or `VERBOSE_LEVEL`. Remember that if you set `INFO_LEVEL`, you will see all `INFO_LEVEL`, `WARNING_LEVEL` and `ERROR_LEVEL` logs. Ie you see all logs above and including your set level.

```
ERROR_LEVEL    = 0x2
WARNING_LEVEL  = 0x8
INFO_LEVEL     = 0xf
VERBOSE_LEVEL  = 0x1f
```

3. Enter the value for the given logging level (seen above)
4. Click `Ok` and restart Windows.

## filtering debug output

If you choose to use `INFO_LEVEL` or `VERBOSE_LEVEL` there may be many logs from the kernel so we want to filter them out.

### windbg

With WinDbg connected to the target:

1. Pause the target using the `Break` button
2. Use the command: `.ofilter donna-ac*`

### debugview

1. Click `Edit -> Filter/Highlight`
2. Set the `Include` string to `donna-ac*`

# contact

feel free to dm me on discord or uc @donnaskiez