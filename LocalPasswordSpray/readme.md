# Invoke-LocalPasswordSpray
Invoke-LocalPasswordSpray is the local equivalent to tools like [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray). 
It performs multiple checks to verify that the desired user is not disabled or locked out and tries to avoid the lockout of the user during the attack.
(May add an option to spray all local accounts later on, to actual fit the name lol)

The script extracts the local lockout policy via `net accounts` - This method isn't perfect, but was the only option I came up with, which does not rely on elevated privileges or specific languages.

## Usage

### Username
The parameter webhook where data gets send to. Define the URL simply after the paramter and get the incoming clipboard content.

### PasswordList
This method required an HIDX poc to be successfully imported on the system. In addition to that, an OMG Elite device with actived HIDX is required. (This method is seen as a work in progress POC)

### LockoutThreshold (optional)
Override the system-defined lockout threshold in seconds.

### LockoutDuration (optional)
Override the system-defined lockout duration in seconds.

### LockoutWindow (optional)
Override the system-defined lockout window in seconds.

### EXAMPLES
Target the user "admin" with the passwords located in "C:\wordlists\common.txt"
 `Invoke-LocalPasswordSpray -Username "admin" -PasswordList "C:\wordlists\common.txt"`
Target the user "test" with the password list "pwlist.txt" in the current directory, while manually setting the lockout policy to 5 attempts and a lockout duration of 30min.
`Invoke-LocalPasswordSpray -Username "test" -PasswordList ".\pwlist.txt" -LockoutThreshold 5 -LockoutDuration 1800`