# Access-Token-Manipulation

Access Token Manipulation is a technique commonly use in privilege escalation. This program will use ATM technique to create a new process with a stolen token from other process. The target process is a high-level process running by system so that the program will take it's token, duplicate it then create process with that duplicated token, making the new process assume the privileges of that stolen token. In this case, the purpose is to call cmd.exe as system (NT-Authority-System) user. Detail steps:

* First, set SeDubugPrivilege for current process with AdjustTokenPrivileges(). This privilege is needed
* Next, get handle of target process and then use it to get the token handle with OpenProcessToken(). The target process must be a high-level (system process) process to make the technique works
* Then, duplicate the token with DuplicateTokenEx(), now we got a token of NT-Authority-System
* Finnally, create new process with duplicated token using CreatProcessWithToken() to call cmd.exe as system. 

After run the program, we will get a cmd.exe of user NT-Authority-System, privilege escalation phase done.

Usage:
```ATM.exe <process's name>```

Example:
```ATM.exe winlogon.exe```
