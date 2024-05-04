new feature notes:

- random heartbeat timer event callback. These timers should be single shot events, once fired we get a new random time and insert that. This way the timer objects are always fresh and we dont use a global timer object.
- session cookie new value per session
- session statistics need to be updated each time a new irp is inserted into the queue
- same with when we receive an irp
- this information can be used to detect malicious interferrence with the system
- use a reverse irp method, user mode program receives and irp and checks if it contains a special code indicating it must send an irp to tthe driver ?