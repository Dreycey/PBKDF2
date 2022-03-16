# PBKDF2

## Before optimization (-O0)
	1. Running Time - over 8 seconds
	2. Code size - 21056
	
## After optimization (-O0)
	1. Running Time - 2618 msec
	2. Code Size - 21920 bytes (using objdump on .text segment within Debug/PBKDF2.axf)
	
## How code changed

#### hmac_isha()
This functions while loop was completely unraveled, and the 'A' variable was put onto a register for speed improvements. The variable t was removed. Bswap32 is used to turn the array into the correct endian. 

#### ISHAPadMessage()
memset used to rid of for-loops and the length of the message is stored from bytes into bits.

#### ISHAResult()
The for-loop was unraveled for speed gains. 

#### ISHAInput()
Here one length is used, and the entire message block is processed once full, minimizing the number of calls and ridding of if statements that originally caused overhead.

#### F()
The while loop was unravelled so that way the inner loop did not need to be used. 
