.data
    PromptForPlaintext:
        .asciz  "Please enter the plaintext: "
        lenPromptForPlaintext = .-PromptForPlaintext

    PromptForShiftValue:
        .asciz  "Please enter the shift value: "
        lenPromptForShiftValue = .-PromptForShiftValue

    Newline:
        .asciz  "\n"

    ShiftValue:
        .int    0
.bss
    .comm   buffer, 102     # Buffer to read in plaintext/output ciphertext
    .comm   intBuffer, 4    # Buffer to read in shift value
                            # (assumes value is 3 digits or less)

.text

    .globl _start

    .type PrintFunction, @function
    .type ReadFromStdin, @function
    .type GetStringLength, @function
    .type AtoI, @function
    .type CaesarCipher, @function


    PrintFunction:
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        # Write syscall
        movl $4, %eax           # syscall number for write()
        movl $1, %ebx           # file descriptor for stdout
        movl 8(%ebp), %ecx      # Address of string to write
        movl 12(%ebp), %edx     # number of bytes to write
        int $0x80

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return

    ReadFromStdin:
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        # Read syscall
        movl $3, %eax
        movl $0, %ebx
        movl 8(%ebp), %ecx      # address of buffer to write input to
        movl 12(%ebp), %edx     # number of bytes to write
        int  $0x80

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return


    GetStringLength:

        # Strings which are read through stdin will end with a newline character. (0xa)
        # So look through the string until we find the newline and keep a count
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack

        movl 8(%ebp), %esi      # Store the address of the source string in esi
        xor %edx, %edx          # edx = 0

        Count:
	    inc %edx            # increment edx
            lodsb               # load the first character into eax
            cmp $0xa, %eax  	# compare the newline character vs eax
            jnz Count           # If eax != newline, loop back

        dec %edx                # the loop adds an extra one onto edx
        movl %edx, %eax          # return value

        movl %ebp, %esp         # Restore the old value of ESP
        popl %ebp               # Restore the old value of EBP
        ret                     # return


    
    AtoI:
        pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack
        movl 8(%ebp), %esi      # esi -> string
        movl 12(%ebp), %ecx     # ecx is the length               

        xor %eax, %eax         # Clearing out EAX (will hold the result)
	xor %ebx, %ebx 

        ConvertingTheDigits:
            	lodsb 
            	cmpb $0x0A, %al          # Check for new line
            	je Finisher               # If null, we are done

            	subb $0x30, %al        # Convert ASCII character to integer (BL = char - '0')

                imul $10, %ebx
            	addl %eax, %ebx       # Add the new digit to EAX

		jmp ConvertingTheDigits

	Finisher: # Clean up and return
        	#move return value into eax
        	movl %ebx, %eax
        	movl %ebp, %esp         # Restore the old value of ESP
        	popl %ebp               # Restore the old value of EBP
        	ret                     # return


    CaesarCipher:
	pushl %ebp              # store the current value of EBP on the stack
        movl %esp, %ebp         # Make EBP point to top of stack
        movl 8(%ebp), %esi      # esi -> address of plaintext
	movl 8(%ebp), %edi      # edi -> address of ciphertext
        movl 12(%ebp), %eax     # edx -> shift value
       

	# Compute shift value modulo 26
	xor %edx, %edx
	movl $26, %ecx
	divl %ecx               # EAX = shift / 26, EDX = shift % 26

	cipher_loop:
        	movb (%esi), %al
        	cmpb $0xa, %al          # Check for newline
        	je cipherFinish		# Jumps to end

        	cmpb $'A', %al		# Check for less than "A"
        	jl store_char		# Skip if so
        	cmpb $'Z', %al		# Check for more than "z"
		jle uppercase		# Skip if so

		cmpb $'a', %al          # Check for less than or equal to "Z"
                jl store_char           # Uppercase letter if so
                cmpb $'z', %al          # Check for more than or equal to "a"
                jle lowercase           # Lowercase letter if so

        	jmp store_char		# Store shifted character

    	uppercase:
		subb $'A', %al          # Normalize to 0-25
                addb %dl, %al           # Add shift (using lower byte of edx)
                cmpb $25, %al
                jbe no_wrap_upper
                subb $26, %al           # Wrap around if necessary
        no_wrap_upper:
                addb $'A', %al
                jmp store_char

	lowercase:
		subb $'a', %al          # Normalize to 0-25
    		addb %dl, %al           # Add shift (using lower byte of edx)
    		cmpb $25, %al
    		jbe no_wrap_lower
    		subb $26, %al           # Wrap around if necessary
	no_wrap_lower:
    		addb $'a', %al
                jmp store_char


    	store_char:
		movb %al, (%edi)
	        incl %esi
	        incl %edi
	        jmp cipher_loop


	cipherFinish: # Clean up and return
                #move return value into eax
                movl %ebp, %esp         # Restore the old value of ESP
                popl %ebp               # Restore the old value of EBP
                ret                     # return


    _start:

        # Print prompt for plaintext
        pushl   $lenPromptForPlaintext
        pushl   $PromptForPlaintext
        call    PrintFunction
        addl    $8, %esp

        # Read the plaintext from stdin
        pushl   $102
        pushl   $buffer
        call    ReadFromStdin
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp


        # Get input string and adjust the stack pointer back after
        pushl   $lenPromptForShiftValue
        pushl   $PromptForShiftValue
        call    PrintFunction
        addl    $8, %esp

        # Read the shift value from stdin
        pushl   $4
        pushl   $intBuffer
        call    ReadFromStdin
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp



        # Convert the shift value from a string to an integer.

	#Convert shift value
        pushl   $4    	 	# push the max length of the string
        pushl   $intBuffer     # push the string
        call    AtoI
        addl    $8, %esp


        # Perform the caesar cipheR
	movl    %eax, ShiftValue
	pushl   ShiftValue      #push shift value
	pushl	$buffer
	call CaesarCipher
	addl $8, %esp


        # Get the size of the ciphertext
        # The ciphertext must be referenced by the 'buffer' label
        pushl   $buffer
        call    GetStringLength
        addl    $4, %esp

        # Print the ciphertext
        pushl   %eax
        pushl   $buffer
        call    PrintFunction
        addl    $8, %esp

        # Print newline
        pushl   $1
        pushl   $Newline
        call    PrintFunction
        addl    $8, %esp

        # Exit the program
        Exit:
            movl    $1, %eax
            movl    $0, %ebx
            int     $0x80
