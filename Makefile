CC = gcc
EXECSTACK = -z execstack
NOSTACKPROTECT = -fno-stack-protector
32BIT= -m32
OMITFRAMEPOINTER = -fomit-frame-pointer

SRC := src/stack_vuln.c
CLEAN_TARGETS = *_level*

SOURCES := $(wildcard $(SRC)/*.c)
OBJECTS := $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
# $RANDOM -- TODO RANDOM BUFFER SIZES

all: $(SOURCES)
	$(CC) $< -o $@
	
$(OBJ)/%.o: $(SRC)/%.c
	$(CC) -I$(SRC) -c $< -o $@

aslr_off : 
	echo 0 | sudo tee /proc/sys/kernel/randomize_va_space 

aslr_on : 
	echo 2 | sudo tee /proc/sys/kernel/randomize_va_space 

###########################################
#     Intro to Manipulating the Stack     # 
###########################################
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Part A : Modifying a variable within the same stack frame
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# Modify a simple variable
stack_level1 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=10' \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) \
	-D PRINT_BUFFER_SIZE  \
	-D PRINT_INITIAL_STACK \
	    -D 'PRINT_STACK_RANGE_HIGH=10' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_DESCRIPTION="\tTry to modify the value of i on the stack. See if you can make it the number 65.\nThe byte you want to edit should have the hex value of `aa`\n\n\n"' \
	-D ECHO_RETURN_ENABLED \
	    -D 'ECHO_RETURN_TYPE=BYTE' \
	    -D 'ECHO_RETURN_ARG=ret_arg' \
	    -D 'ECHO_RETURN_ARG_DECL=BYTE ret_arg' \
	    -D 'ECHO_RETURN_ARG_INITIAL_VALUE=170' \
	    -D 'ECHO_RETURN_ARG_FINAL_VALUE=65' \
	    -D ECHO_RETURN_CORRECTION_PRINT_OUTPUT \
	    -D ECHO_RETURN_CORRECTION_PRINT_CORRECT

# Same as before, this time the buffer is bigger
stack_level2 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=30' \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D PRINT_BUFFER_SIZE \
	-D PRINT_INITIAL_STACK \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D 'PRINT_STACK_RANGE_HIGH=10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER  \
	    -D 'PRINT_DESCRIPTION="\tTry to modify the value of i on the stack. See if you can make it the number 42.\nThe byte you want to edit should have the hex value of `aa`\n\n\n"' \
	-D ECHO_RETURN_ENABLED \
	-D 'ECHO_RETURN_TYPE=BYTE' \
	-D 'ECHO_RETURN_ARG=ret_arg' \
	-D 'ECHO_RETURN_ARG_DECL=BYTE ret_arg' \
	-D 'ECHO_RETURN_ARG_INITIAL_VALUE=170' \
	-D 'ECHO_RETURN_ARG_FINAL_VALUE=42' \
	-D ECHO_RETURN_CORRECTION_PRINT_OUTPUT \
	-D ECHO_RETURN_CORRECTION_PRINT_CORRECT

# Try it for an integer this time
stack_level3 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=10' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_BUFFER_SIZE \
	-D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D 'PRINT_STACK_RANGE_HIGH=10' \
	    -D PRINT_FINAL_STACK  \
	    -D CLEAR_INITIAL_BUFFER \
	    -D 'PRINT_DESCRIPTION="\tTry to modify the value of i on the stack. See if you can make it the number 9001.\n\n\n"' \
	-D ECHO_RETURN_ENABLED \
	    -D 'ECHO_RETURN_TYPE=int' \
	    -D 'ECHO_RETURN_ARG=ret_arg' \
	    -D 'ECHO_RETURN_ARG_DECL=int ret_arg' \
	    -D 'ECHO_RETURN_ARG_INITIAL_VALUE=2863311530' \
	    -D 'ECHO_RETURN_ARG_FINAL_VALUE=9001' \
	    -D ECHO_RETURN_CORRECTION_PRINT_OUTPUT

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Part B : Jumping the return address
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Overflow the return address and jump to the hidden function
stack_level4 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=20' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-8' \
	    -D 'PRINT_STACK_RANGE_HIGH=40' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tTry to jump to the hidden function, most of the data you need has been provided.\n\n\n"'

# Again to the hidden function, different buffer size
stack_level5 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=43' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	-D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D 'PRINT_STACK_RANGE_LOW=-8' \
	    -D 'PRINT_STACK_RANGE_HIGH=40' \
	    -D CLEAR_INITIAL_BUFFER \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tTry to jump to the hidden function, you may find that the buffer has changed.\n\n\n"' 

# Again to the hidden function, different buffer size
stack_level6 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=67' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	-D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D PRINT_STACK_RANGE_LOW=-8 \
	    -D PRINT_STACK_RANGE_HIGH=40 \
	    -D CLEAR_INITIAL_BUFFER \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tTry to jump to the hidden function, different buffer now.\n\n\n"' 

# Let's try to pass arguments to the secret function now, start with something easy
stack_level7 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=12' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D PRINT_INITIAL_STACK \
	    -D 'PRINT_STACK_RANGE_LOW=-8' \
	    -D 'PRINT_STACK_RANGE_HIGH=60'  \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D FUNCTION_VARIABLE_ENABLED \
	    -D 'N_FUNCTION_VARIABLES=1' \
	    -D 'FUNCTION_ARGS_DECL= BYTE arg' \
	    -D 'FUNCTION_VARIABLE_FINAL_VALUE = {3}' \
	    -D 'FUNCTION_ARGS_PTR = &arg' \
	    -D 'N_FUNCTION_BYTES=1' \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tThe hidden function again, this time you need to set an argument, the secret value is 3.\n\n"'

# Two arguments
stack_level8 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=80' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=20' \
        -D 'PRINT_STACK_RANGE_HIGH=60' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {BYTE a; BYTE b;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
        -D 'N_FUNCTION_VARIABLES=2' \
        -D 'N_FUNCTION_BYTES = 8' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x07', '\x00', '\x00', '\x00', '\x06', '\x00', '\x00', '\x00'}" \
        -D 'FUNCTION_ARGS_PTR= &arg' \
    -D FUNCTION_JUMP \
    -D 'PRINT_DESCRIPTION="\tTwo arguments this time, a 6 and a 7 with the arguments passed in that order.\n\tOf course, just because you pass them in that order, doesn`t mean they get stored on the stack that way...\n\n\n"'

# Multiple arguments
stack_level9 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=15' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=20' \
        -D 'PRINT_STACK_RANGE_HIGH=60' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {BYTE a; BYTE b; BYTE c; BYTE d; BYTE e;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
        -D 'N_FUNCTION_VARIABLES=5' \
        -D 'N_FUNCTION_BYTES = 20' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x04', '\x00', '\x00', '\x00', '\x11', '\x00', '\x00', '\x00', '\x08', '\x00', '\x00', '\x00', '\x07', '\x00', '\x00', '\x00', '\x06', '\x00', '\x00', '\x00'}" \
        -D 'FUNCTION_ARGS_PTR= &arg' \
    -D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tFive arguments now, 6, 7, 8, 17 and 4\n\n\n"'

# Changing types
stack_level10 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=80' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=20' \
        -D 'PRINT_STACK_RANGE_HIGH=60' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {int a; int b;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
        -D 'N_FUNCTION_VARIABLES=2' \
        -D 'N_FUNCTION_BYTES = 8' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\xaa', '\xaa', '\xaa', '\xaa', '\x00', '\x01', '\x00', '\x00'}" \
        -D 'FUNCTION_ARGS_PTR=&arg' \
    -D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tLet`s try some different types: (int a, int b), and the values are 256 and 2863311530\n\n\n"'

# A pointer
stack_level11 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=80' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_BUFFER_ADDRESS \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=20' \
        -D 'PRINT_STACK_RANGE_HIGH=60' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {int* a;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
    -D 'HELP_STRING_FUNCT = printf("Your pointer is currently looking at %p\n", arg.a);' \
        -D 'N_FUNCTION_VARIABLES = 1' \
        -D 'N_FUNCTION_BYTES = 4' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x39', '\x05', '\x00', '\x00'}" \
        -D 'FUNCTION_ARGS_PTR=arg.a' \
    -D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tThis time we`re passing an int* pointer.\n\tThe pointer should point to some address in memory storing the integer value 1337. \n You should have a good long think about what happens to the stack when RET is called.\n\n\n"'


# An array 
stack_level12 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=120' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_BUFFER_ADDRESS \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=-120' \
        -D 'PRINT_STACK_RANGE_HIGH=60' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {int* a;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
    -D 'HELP_STRING_FUNCT = printf("Your pointer is currently looking at %p\n", arg.a);' \
        -D 'N_FUNCTION_VARIABLES = 1' \
        -D 'N_FUNCTION_BYTES = 12' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x69', '\x7a', '\x00', '\x00', '\x39', '\x05', '\x00', '\x00', '\x00', '\x00', '\xa0', '\x00'}" \
        -D 'FUNCTION_ARGS_PTR=arg.a' \
    -D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tThis time we`re passing an array of integers.\n\tThe pointer should point to some address in memory storing the integer values [31337, 1337, 10485760].\n\n\n"'

# A larger array
stack_level13 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=20' \
    $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
    -D PRINT_SECRET_LOCATION \
    -D PRINT_BUFFER_SIZE \
    -D PRINT_BUFFER_ADDRESS \
    -D PRINT_INITIAL_STACK \
        -D 'PRINT_STACK_RANGE_LOW=0' \
        -D 'PRINT_STACK_RANGE_HIGH=200' \
        -D PRINT_FINAL_STACK \
        -D CLEAR_INITIAL_BUFFER \
    -D 'STRUCT_DEF= typedef struct {int* a;} arg_t' \
    -D FUNCTION_VARIABLE_ENABLED \
    -D 'HELP_STRING_FUNCT = printf("Your pointer is currently looking at %p\n", arg.a);' \
        -D 'N_FUNCTION_VARIABLES = 1' \
        -D 'N_FUNCTION_BYTES = 40' \
        -D 'FUNCTION_ARGS_DECL= arg_t arg' \
        -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x01', '\x01', '\x01', '\x01', '\x02', '\x02', '\x02', '\x02', '\x03', '\x03', '\x03', '\x03', '\x04', '\x04', '\x04', '\x04', '\x05', '\x05', '\x05', '\x05', '\x06', '\x06', '\x06', '\x06', '\x07', '\x07', '\x07', '\x07', '\x08', '\x08', '\x08', '\x08', '\x10', '\x10', '\x10', '\x10', '\x11', '\x11', '\x11', '\x11'}" \
        -D 'FUNCTION_ARGS_PTR=arg.a' \
    -D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\tAlright, you may have found some ways to keep secrets before, but this time it`s a bit bigger; we want an array of 10 integers.\n The first integer should contains \\x01\\x01\\x01\\x01, the second \\x02\\x02\\x02\\x02 and so on up to \\x11 and skipping \\x09.\n\t The buffer is only 20 bytes in total. Good luck. \n\n\n"'


# # A Struct Packing
# level14 : $(SRC)
# 	$(CC) $(SRC) -o $@ \
# 	-D 'BUFFER_SIZE=20' \
#     $(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) \
#     -D PRINT_SECRET_LOCATION \
#     -D PRINT_BUFFER_SIZE \
#     -D PRINT_BUFFER_ADDRESS \
#     -D PRINT_INITIAL_STACK \
#         -D 'PRINT_STACK_RANGE_LOW=-120' \
#         -D 'PRINT_STACK_RANGE_HIGH=60' \
#         -D PRINT_FINAL_STACK \
#         -D CLEAR_INITIAL_BUFFER \
#     -D 'STRUCT_DEF= typedef struct {int* a;} arg_t' \
#     -D FUNCTION_VARIABLE_ENABLED \
#     -D 'HELP_STRING_FUNCT = printf("Your pointer is currently looking at %p\n", arg.a);' \
#         -D 'N_FUNCTION_VARIABLES = 1' \
#         -D 'N_FUNCTION_BYTES = 40' \
#         -D 'FUNCTION_ARGS_DECL= arg_t arg' \
#         -D "FUNCTION_VARIABLE_FINAL_VALUE = {'\x01', '\x01', '\x01', '\x01', '\x02', '\x02', '\x02', '\x02', '\x03', '\x03', '\x03', '\x03', '\x04', '\x04', '\x04', '\x04', '\x05', '\x05', '\x05', '\x05', '\x06', '\x06', '\x06', '\x06', '\x07', '\x07', '\x07', '\x07', '\x08', '\x08', '\x08', '\x08', '\x10', '\x10', '\x10', '\x10', '\x10'  '\x10', '\x11', '\x11', '\x11', '\x11'} \
#         -D 'FUNCTION_ARGS_PTR=arg.a' \
#     -D FUNCTION_JUMP \
# 	-D 'PRINT_DESCRIPTION="\tThe last one of these sorts of problems. This time we want an array of structs.  \n\n\n"'

# Struct containing a function pointer?

# Memcpy as the secret


###########################################
#  Smashing the Stack for Fun and Profit  # 
#        Aleph One, Phrack 49, 66k        #
###########################################

# Shellcode to /bin/bash and return to main

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Part A : Execed stack
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Calling Code
shellcode_level1: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=256' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D RETURN_TO_BUFFER \
		-D 'RETURN_TO_BUFFER_OFFSET=0' \
	-D 'PRINT_DESCRIPTION="\t Something a bit different this time; you don`t need to overflow the buffer, you`ve been given 256 bytes of buffer space to write whatever you want, and the function will call the buffer automatically."'

# Calling Code
shellcode_level2: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=256' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D RETURN_TO_BUFFER \
		-D 'RETURN_TO_BUFFER_OFFSET=0' \
	-D 'PRINT_DESCRIPTION="\t Let`s make this a bit harder, rather than returning from the buffer can you print your own level completion message?."'

# Calling Code
shellcode_level3: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=256' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D RETURN_TO_BUFFER \
		-D 'RETURN_TO_BUFFER_OFFSET=0' \
	-D 'PRINT_DESCRIPTION="\t Let`s skip to the end shall we. We`ll return to the start of the buffer again, and you need to provide some working shell code."'

# Calling Code Sledding
shellcode_level4: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=256' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D RETURN_TO_BUFFER \
	    -D 'RETURN_TO_BUFFER_OFFSET=72' \
	-D 'PRINT_DESCRIPTION="\t This is like the last one, except we`re not returning to the start of the buffer, we`re going to a random address within the buffer. \n\t You`re going to want to put your shell code at the end of the buffer and have a NOP sled take you there"'

# Danger Zone
shellcode_level5: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=128' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=196' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_DESCRIPTION="\t We`ve decided not to return you to the buffer anymore, that`s your job now. Get a shell."'

# Red Zone I
shellcode_level6: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=32' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=96' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_DESCRIPTION="\t We`ve decided to reduce your buffer size, you need to find your own memory to play with now. \n\t Look into what the red zone is if you`re stuck"'

# Red Zone II
shellcode_level7: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=8' \
	-D PRINT_BUFFER_ADDRESS \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=96' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_DESCRIPTION="\t If the last one didn`t squeeze you, this one will \n\t Look into what the red zone is if you`re stuck"'


###########################################
#             Format String               # 
###########################################

# Format String
fstring_level1: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=256' \
	-D FSTRING_ENABLED \
	    -D 'FSTRING_FIXED_ITERATIONS=10' \
	-D FUNCTION_JUMP \
	-D PRINT_BUFFER_LITERAL 
	-D 'PRINT_DESCRIPTION="\t Lets make life a little harder, we`ve decided to stop telling you where the buffer starts.\n\t Or indeed give you any pointer addresses at all. \n\t If you need help, look up what a format string vulnerability is. Try to jump to the secret function."'

# Format String II
fstring_level2: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=64' \
	-D FSTRING_ENABLED \
	    -D 'FSTRING_FIXED_ITERATIONS=10' \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\t As before, but with fewer iterations."'

# Format String III
fstring_level3: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=8' \
	-D FSTRING_ENABLED \
	    -D FSTRING_ARB_ITERATIONS \
	-D NO_SCANF \
	-D 'PRINT_DESCRIPTION="\t Now you get as many iterations as you want, but no final buffer overflow."'

fstring_level4: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=8' \
	-D PRINT_BUFFER_LITERAL \
	-D FSTRING_ENABLED \
	-D NO_SCANF \ 
	-D 'PRINT_DESCRIPTION="\t A single shot. Pop a shell."'


fstring_level5: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(EXECSTACK) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=64' \
	-D PRINT_BUFFER_LITERAL \
	-D SANITISED_BUFFER \ 
	-D 'PRINT_DESCRIPTION="\t One shot, and the buffer is actually limited."'

###########################################
#  Return to Lib C                  
###########################################

# Return to Lib C I
rlibc_level1: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=8' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_FUNCTION_POINTER=execl' \
	-D 'PRINT_DESCRIPTION="\t Oh dear, it seems that somebody has disabled stack execution. We won`t be dropping easy shellcodes anymore.\n\t Let`s give you those addresses back through, and we`ll give you the address of execl"'


# Return to Lib C II
rlibc_level2: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=16' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D 'PRINT_DESCRIPTION="\t No more execl addressing, you`ll need to figure it out."'




###########################################
#  GOT                  
###########################################

# GOT Part 1
got_level1: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=9' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=12' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D GOT_LEAK \
		-D 'GOT_CPY=4' \
		-D GOT_SRC_BUF \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D 'N_GLOBAL_VARIABLES=128' \
		-D 'GLOBAL_VARIABLE_INITIAL_VALUE={0}' \
		-D 'GLOBAL_VARIABLE_TARGET_INDEX=67' \
		-D 'GLOBAL_VARIABLE_TARGET=0xFF' \
		-D 'GLOBAL_VARIABLE_TARGET_FINAL_VALUE=0xAA' \
	-D SANITISED_BUFFER \
	-D 'PRINT_DESCRIPTION="\t Something different here, your buffer really contains two pointers, the first pointer is going to be copied to the address of the second pointer, you have a few bytes of space in your buffer to play with. Set the target value in the GOT to 0xAA."'


# GOT Part 2
got_level2: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=9' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=12' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D GLOBAL_VARIABLE_ENABLED \
		-D 'N_GLOBAL_VARIABLES=12' \
		-D 'GLOBAL_VARIABLE_INITIAL_VALUE={0}' \
	-D GOT_LEAK \
		-D 'GOT_CPY=4' \
		-D GOT_SRC_BUF \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\t Same deal as before, this time try to get to the secret function"'



# GOT Part 3
got_level3: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=9' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=12' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D GLOBAL_VARIABLE_ENABLED \
		-D 'N_GLOBAL_VARIABLES=18' \
		-D 'GLOBAL_VARIABLE_INITIAL_VALUE={0}' \
	-D GOT_LEAK \
		-D 'GOT_CPY=4' \
	-D FUNCTION_JUMP \
	-D 'PRINT_DESCRIPTION="\t Slight modification, we`re now setting dst to be the first four bytes and src to be the second four"'


# GOT Part 4
got_level4: $(SRC)
	$(CC) $(SRC) -o $@ \
	$(32BIT) $(OMITFRAMEPOINTER) \
	-D 'BUFFER_SIZE=9' \
	-D PRINT_INITIAL_STACK \
	-D 'PRINT_STACK_RANGE_HIGH=256' \
	    -D 'PRINT_STACK_RANGE_LOW=0' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D GLOBAL_VARIABLE_ENABLED \
		-D 'N_GLOBAL_VARIABLES=1024' \
		-D 'GLOBAL_VARIABLE_INITIAL_VALUE={0}' \
	-D GOT_LEAK \
		-D 'GOT_CPY=4' \
	-D 'PRINT_DESCRIPTION="\t Finally, let`s see if you can pop a shell"'

###########################################
#  ROP Chaining
#  Need to add gadget functions, better with 64 bit                  
###########################################

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~s
# Part A : Starting to ROP
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Get the function to return from the secret function to main
rop_level1 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-g \
	-D 'BUFFER_SIZE=20' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-16' \
	    -D 'PRINT_STACK_RANGE_HIGH=64' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D PRINT_ECHO_FRAME \
	    -D "PRINT_ECHO_FRAME_INITIAL = -20" \
	    -D "PRINT_ECHO_FRAME_FINAL = 80" \
	-D PRINT_REG \
	    -D PRINT_ESP_INITIAL \
	    -D PRINT_EBP_INITIAL \
	    -D PRINT_ESP_FINAL \
	    -D PRINT_EBP_FINAL \
	    -D PRINT_ESP_ECHO \
	    -D PRINT_EBP_ECHO \
	    -D PRINT_ESP_MAIN \
        -D PRINT_EBP_MAIN \
	-D PRINT_MAIN_LOCATION \
	-D FUNCTION_JUMP \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D "N_GLOBAL_VARIABLES = 1" \
	    -D "GLOBAL_VARIABLE_INITIAL_VALUE = {'\x01'}" \
	    -D "GLOBAL_VARIABLE_FINAL_VALUE = {'\x02'}" \
	    -D "HELP_STRING_FUNCT = global_variables[0]++" \
	    -D GLOBAL_CORRECTION_PRINT_OUTPUT \
	-D 'PRINT_DESCRIPTION="\tThis time, you need to jump to the secret function, then convince it to return to main.\n\tRunning the entire main function again is not good enough, you should return to exactly where you left off.\n\n\n"'

# Now we care about doing this cleanly
rop_level2 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=124' \
	-g \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-16' \
	    -D 'PRINT_STACK_RANGE_HIGH=64' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D PRINT_EXIT \
	-D PRINT_ECHO_FRAME \
	    -D "PRINT_ECHO_FRAME_INITIAL = -20" \
	    -D "PRINT_ECHO_FRAME_FINAL = 80" \
	-D PRINT_REG \
	    -D PRINT_ESP_INITIAL \
	    -D PRINT_EBP_INITIAL \
	    -D PRINT_ESP_FINAL \
	    -D PRINT_EBP_FINAL \
	    -D PRINT_ESP_ECHO \
	    -D PRINT_EBP_ECHO \
	    -D PRINT_ESP_MAIN \
        -D PRINT_EBP_MAIN \
	-D PRINT_MAIN_LOCATION \
	-D FUNCTION_JUMP \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D "N_GLOBAL_VARIABLES = 1" \
	    -D "GLOBAL_VARIABLE_INITIAL_VALUE = {'\x01'}" \
	    -D "GLOBAL_VARIABLE_FINAL_VALUE = {'\x02'}" \
	    -D "HELP_STRING_FUNCT = global_variables[0]++" \
	    -D GLOBAL_CORRECTION_PRINT_OUTPUT \
	-D 'PRINT_DESCRIPTION="\tSimilar to last time, you need to jump to the secret function, then convince it to return to main.\n\tThis time you should ensure that the program does not segfault when it exits.\n\n\n"'

# Now we start chaining properly
rop_level3 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=256' \
	-g \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-16' \
	    -D 'PRINT_STACK_RANGE_HIGH=64' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D PRINT_EXIT \
	-D PRINT_ECHO_FRAME \
	    -D "PRINT_ECHO_FRAME_INITIAL = -20" \
	    -D "PRINT_ECHO_FRAME_FINAL = 80" \
	-D PRINT_REG \
	    -D PRINT_ESP_INITIAL \
	    -D PRINT_EBP_INITIAL \
	    -D PRINT_ESP_FINAL \
	    -D PRINT_EBP_FINAL \
	    -D PRINT_ESP_ECHO \
	    -D PRINT_EBP_ECHO \
	    -D PRINT_ESP_MAIN \
        -D PRINT_EBP_MAIN \
	-D PRINT_MAIN_LOCATION \
	-D FUNCTION_JUMP \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D "N_GLOBAL_VARIABLES = 1" \
	    -D "GLOBAL_VARIABLE_INITIAL_VALUE = {'\x01'}" \
	    -D "GLOBAL_VARIABLE_FINAL_VALUE = {'\x05'}" \
	    -D "HELP_STRING_FUNCT = global_variables[0]++" \
	    -D GLOBAL_CORRECTION_PRINT_OUTPUT \
	-D 'PRINT_DESCRIPTION="\tYou may have noticed that entering the secret function increments the global value.\n\t This time you need to get the global value to `\\x05`, it starts at `\\x01`.\n\t Good luck!\n\n\n"'

# Passing arguments through the chain
rop_level4 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=69' \
	-g \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-16' \
	    -D 'PRINT_STACK_RANGE_HIGH=64' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D PRINT_EXIT \
	-D PRINT_ECHO_FRAME \
	    -D "PRINT_ECHO_FRAME_INITIAL = -20" \
	    -D "PRINT_ECHO_FRAME_FINAL = 80" \
	-D PRINT_REG \
	    -D PRINT_ESP_INITIAL \
	    -D PRINT_EBP_INITIAL \
	    -D PRINT_ESP_FINAL \
	    -D PRINT_EBP_FINAL \
	    -D PRINT_ESP_ECHO \
	    -D PRINT_EBP_ECHO \
	    -D PRINT_ESP_MAIN \
        -D PRINT_EBP_MAIN \
	-D PRINT_MAIN_LOCATION \
	-D FUNCTION_JUMP \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D "N_GLOBAL_VARIABLES = 1" \
	    -D "GLOBAL_VARIABLE_INITIAL_VALUE = {'\x01'}" \
	    -D "GLOBAL_VARIABLE_FINAL_VALUE = {'\x05'}" \
	    -D "HELP_STRING_FUNCT = if (arg='\x42') { global_variables[0]++;}" \
	    -D GLOBAL_CORRECTION_PRINT_OUTPUT \
	-D 'PRINT_DESCRIPTION="\tThis time our hidden function takes a one byte input.\n\t It will need to be equal to `\\x42` for the global value to increment.\n\n\n"'


# Just calling our own functions, nobody mind us
rop_level5 : $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=420' \
	-g \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_SECRET_LOCATION \
	-D PRINT_BUFFER_SIZE \
	    -D 'PRINT_STACK_RANGE_LOW=-16' \
	    -D 'PRINT_STACK_RANGE_HIGH=64' \
	    -D PRINT_INITIAL_STACK \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D PRINT_EXIT \
	-D PRINT_ECHO_FRAME \
	    -D "PRINT_ECHO_FRAME_INITIAL = -20" \
	    -D "PRINT_ECHO_FRAME_FINAL = 80" \
	-D PRINT_REG \
	    -D PRINT_ESP_INITIAL \
	    -D PRINT_EBP_INITIAL \
	    -D PRINT_ESP_FINAL \
	    -D PRINT_EBP_FINAL \
	    -D PRINT_ESP_ECHO \
	    -D PRINT_EBP_ECHO \
	    -D PRINT_ESP_MAIN \
        -D PRINT_EBP_MAIN \
	-D PRINT_MAIN_LOCATION \
	-D FUNCTION_JUMP \
	-D GLOBAL_VARIABLE_ENABLED \
		-D GLOBAL_VARIABLE_CMP \
		-D "N_GLOBAL_VARIABLES = 1" \
	    -D "GLOBAL_VARIABLE_INITIAL_VALUE = {'\x01'}" \
	    -D "GLOBAL_VARIABLE_FINAL_VALUE = {'\xff'}" \
	    -D "HELP_STRING_FUNCT = global_variables[0]--" \
	    -D GLOBAL_CORRECTION_PRINT_OUTPUT \
	-D 'PRINT_DESCRIPTION="Calling functions is an incredibly useful skill for ROP chaining.\n\t However, there are more functions than just those in the code.\n\t Get the global counter to have a value of `\\xff`.\n\n\n"'

# Passing bad values
rop_level6 :  $(SRC)
	$(CC) $(SRC) -o $@ \
	-D 'BUFFER_SIZE=10' \
	$(NOSTACKPROTECT) $(32BIT) $(OMITFRAMEPOINTER) \
	-D PRINT_BUFFER_SIZE  \
	-D PRINT_INITIAL_STACK \
	    -D 'PRINT_STACK_RANGE_HIGH=10' \
	    -D 'PRINT_STACK_RANGE_LOW=-10' \
	    -D PRINT_FINAL_STACK \
	    -D CLEAR_INITIAL_BUFFER \
	-D ECHO_RETURN_ENABLED \
	    -D 'ECHO_RETURN_TYPE=BYTE' \
	    -D 'ECHO_RETURN_ARG=ret_arg' \
	    -D 'ECHO_RETURN_ARG_DECL=BYTE ret_arg' \
	    -D 'ECHO_RETURN_ARG_INITIAL_VALUE=170' \
	    -D 'ECHO_RETURN_ARG_FINAL_VALUE=9' \
	    -D ECHO_RETURN_CORRECTION_PRINT_OUTPUT \
	    -D ECHO_RETURN_CORRECTION_PRINT_CORRECT\ 
	-D 'PRINT_DESCRIPTION="\tLet`s wind back a little bit. all you need to do this time is get the value x09 onto the stack and return it.\n The byte you`re trying to target should be pre-filled with xAA. This likely won`t help you at all.\n\n\n"' \
	


###########################################
#            Exec on the Heap             # 
###########################################



#~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Part A : Canary Evasion
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~



###########################################
#                64 Bits                  # 
###########################################




###########################################
#                 ASLR                    # 
###########################################


.PHONY: clean
clean:
	rm -f $(CLEAN_TARGETS)
