# ac

open source anti cheat (lol) which I made for fun.

# features

- Attached thread detection
- Process module .text section integrity checks
- NMI stackwalking via isr iretq
- APC, DPC stackwalking
- Return address exception hooking detection
- Chained .data pointer detection (iffy)
- Handle stripping via obj callbacks
- Process handle table enumeration
- System module device object verification
- System module .text integrity checks
- Removal of threads cid table entry detection
- Driver dispatch routine validation
- Extraction of various hardware identifiers
- EPT hook detection
- Various image integrity checks both of driver + module
- Hypervisor detection
- HalDispatch and HalPrivateDispatch routine validation
- Dynamic import resolving & encryption
- Malicious PCI device detection via configuration space scanning
- Win32kBase_DxgInterface routine validation

# architecuture

- todo!

# planned features

Theres a long list of features I still want to implement, the question is whether I can be bothored implementing them. I would say I'd accept pull requests for new features but I would expect high quality code and thorough testing with verifier (both inside a vm and bare metal).

# example

- I have recorded an example of the program running with CS2. Note that vac was obviously disabled. *If you decide to test with a steam game do not forget to launch in insecure mode*
- Shown are the kernel `VERBOSE` level logs in DebugView along with the usermode application console and some additional performance benchmarking things.
- (You can find the video here)[https://youtu.be/b3mH7w8pOxs]

# known issues

- [See the issues page](https://github.com/donnaskiez/ac/issues)
- Feel free to open a new issue if you find any bugs

# windows versions tested:

- Win10 22H2
- Win11 22H2

# how to build

Requires [Visual Studio](https://visualstudio.microsoft.com/downloads/) and the [WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk) for compilation.

## test signing mode

Before we continue, ensure you enable test signing mode as this driver is not signed.

1. Open a command prompt as Administrator
2. Enter the following commands:

```bash
bcdedit -set TESTSIGNING on
bcdedit /debug on
```

3. Restart Windows

## building and running the project

1. Clone the project i.e `git clone git@github.com:donnaskiez/ac.git`
2. Open the project in visual studio
3. Select `Release - No Server - Win10` or `Release - No Server - Win11` depending on the version of Windows you will be running the driver on.
4. Build the project in visual studio, if you experience any build issues - check the drivers project settings are the following:
	- `Inf2Cat -> General -> Use Local Time` to `Yes`
	- `C/C++ -> Treat Warnings As Errors` to `No`
	- `C/C++ -> Spectre Mitigation` to `Disabled`
5. Move the `driver.sys` file located in `ac\x64\Release - No Server\` into the `Windows\System32\Drivers` directory
	- You can rename the driver if you would like
6. Use the [OSR Loader](https://www.osronline.com/article.cfm%5Earticle=157.htm) and select `driver.sys` (or whatever you named it) that you moved to the Windows drivers folder. *DO NOT REGISTER THE SERVICE YET*.
7. Under `Service Start` select `System`. This is VERY important!
8. Click `Register Service`. *Do NOT click* `Start Service`!
9. Restart Windows. 
10. Once restarted, open the program you would like to protect. This could be anything i.e cs2, notepad etc.
	- if you do use a game to test, ensure the games anti-cheat is turned off before testing
11. Open your dll injector of choice (I simply use [Process Hacker](https://processhacker.sourceforge.io/))
12. Inject the dll found in `ac\x64\Release - No Server\` named `user.dll` into the target program

Logs will be printed to both the terminal output and the kernel debugger. See below for configuring kernel debugger output.

Note: The server is not needed for the program to function properly.

# how to configure kernel debugging output

The kernel driver is setup to log at 4 distinct levels:

```C
#define LOG_ERROR_LEVEL  
#define LOG_WARNING_LEVEL
#define LOG_INFO_LEVEL   
#define LOG_VERBOSE_LEVEL
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
ERROR_LEVEL    = 0x3
WARNING_LEVEL  = 0x7
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

## License

We have decided to put this Project under **AGPL-3.0**!
https://choosealicense.com/licenses/agpl-3.0/

# contact

feel free to dm me on discord or uc @donnaskiez
