#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BYTE char

/* This one is always going to be needed
  #define BUFFER_SIZE 40
*/

/* These variables relate to the calls to "secret function"
   They should be passed as arguments to the function
    #define FUNCTION_VARIABLE_ENABLED
    #define N_FUNCTION_VARIABLES 
    #define FUNCTION_ARGS
    #define FUNCTION_ARGS_DECL
    #define FUNCTION_VARIABLE_FINAL_VALUE
*/

/* These variables relate to the main function
   You should find some way to return 
    #define MAIN_VARIABLE_ENABLED
    #define N_MAIN_VARIABLES
    #define MAIN_VARIABLE_INITIAL_VALUES
    #define MAIN_VARIABLE_FINAL_VALUES
*/

/* These variables relate to enabling format strings
    #define FSTRING_ENABLED
    #define FSTRING_FIXED_ITERATIONS <N ITERATIONS>
    #define FSTRING_ARB_ITERATIONS <END CONDITION>
*/


/* And these are the global variables
    #define GLOBAL_VARIABLE_ENABLED :: Enables global variables
    #define N_GLOBAL_VARIABLES :: 
    #define GLOBAL_VARIABLE_INITIAL_VALUE
    #define GLOBAL_VARIABLE_FINAL_VALUE
*/

/* GOT variables
    #define GOT_LEAK
*/

/* Arguments to echo() flags
    #define ECHO_ARGS_ENABLED :: A switch to enable passing arguments to echo
    #define ECHO_ARG_STRING :: The string of arguments passed to echo
    #define ECHO_ARGS_FROM_MAIN_DECL :: Declare the relevant arguments in main
    #define ECHO_ARGS_FROM_MAIN_PASS ::Passing the arguments from main
    #define ECHO_ARGS_FUNCT_DECL :: The function declaration string that specifies the arguments

    #define ECHO_RETURN_ENABLED :: A switch to enable argument returns from echo()
    #define ECHO_RETURN_TYPE :: The type returned by the echo function
    #define ECHO_RETURN_ARG :: Called return ECHO_RETURN_ARG and the same name in ECHO_RETURN_ARG = echo()
    #define ECHO_RETURN_ARG_DECL :: Declares the args that are needed
    #define ECHO_RETURN_ARG_INITIAL_VALUE
    #define ECHO_RETURN_ARG_FINAL_VALUE

    #define RETURN_TO_BUFFER :: Call the buffer when returning from the function
    #define RETURN_TO_BUFFER_OFFSET :: The offset of the jump when returning to the buffer
*/

/* Visibility flags
    #define PRINT_SECRET_LOCATION
    #define PRINT_BUFFER_SIZE
    #define PRINT_MAIN_LOCATION
    #define PRINT_STACK_ADDRESS
    #define PRINT_HEAP_ADDRESS

    #define PRINT_INITIAL_STACK
    #define PRINT_FINAL_STACK
    #define PRINT_STACK_RANGE_LOW
    #define PRINT_STACK_RANGE_HIGH

    #define PRINT_BUFFER_ADDRESS :: Prints the address of the start of the buffer

    #define CLEAR_INITIAL_BUFFER :: Writes \x00 over each byte in the buffer

    #define HELP_STRING_FUNCT :: A help string for once you've hit the "secret function"

    #define PRINT_EBP_INITIAL :: Prints the ESB at the start of the echo function
    #define PRINT_ESP_INITIAL :: Prints the ESB at the start of the echo function
	
    #define PRINT_EBP_FINAL
    #define PRINT_ESP_FINAL

	#define PRINT_EBP_ECHO
    #define PRINT_ESP_ECHO


    #define PRINT_EXIT

    #define PRINT_BUFFER_LITERAL :: Prints the buffer directly allowing for format string vulns

    #define PRINT_FUNCTION_POINTER :: Prints a function pointer

*/

#ifdef GLOBAL_VARIABLE_ENABLED
    BYTE global_variables[N_GLOBAL_VARIABLES] = GLOBAL_VARIABLE_INITIAL_VALUE;
#endif

// If you need to define a struct
#ifdef STRUCT_DEF
    STRUCT_DEF;
#endif

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// JUMP FUNCTION  
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


#ifdef FUNCTION_JUMP
    #ifdef FUNCTION_VARIABLE_ENABLED
        void secret_function(FUNCTION_ARGS_DECL)
    #else
        void secret_function()
    #endif
    {
        printf("You have entered the secret function!\n");

        #ifdef PRINT_ECHO_FRAME
        	BYTE frame_var = '\xaa';
        	printf("The stack around the echo function:\n");
        	for (int i = PRINT_ECHO_FRAME_INITIAL; i < PRINT_ECHO_FRAME_FINAL; i++)
        	{
        		printf("%.2x ", ((1 << 8) - 1) & (int)(&frame_var)[i]);
        	}
        	printf("\n");
        #endif

        #ifdef PRINT_ESP_ECHO
    		register int sp_e  asm ("sp");
    		printf("SP in secret function: %x\n", sp_e);
    	#endif

    	#ifdef PRINT_EBP_ECHO
    		register int bp_e  asm ("bp");
    		printf("BP in secret function: %x\n", bp_e);
    	#endif


            #ifdef HELP_STRING_FUNCT
                HELP_STRING_FUNCT;
            #endif

        #ifdef FUNCTION_VARIABLE_ENABLED
            printf("But can you get the secret variable?\n");


            BYTE function_variable_test[N_FUNCTION_BYTES] = FUNCTION_VARIABLE_FINAL_VALUE;
            BYTE variable_match = '\x01';
            for (int i = 0; i < N_FUNCTION_BYTES; i++) {
                printf("Your current value is: %x\n", ((1 << 8) - 1) & ((BYTE*)FUNCTION_ARGS_PTR)[i]);
                if (((BYTE*)FUNCTION_ARGS_PTR)[i] != function_variable_test[i])
                {
                    variable_match = '\x00';
                }
            }
            if (variable_match)
            {
                printf("Values matched in secret function!\n");
            }
            else
            {
                printf("Your value doesn't match the secret value, try again!\n");
            }
        #endif
        printf("Secret function finished\n");
        return;
    }
#endif

//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// ECHO FUNCTION  
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#ifdef ECHO_ARGS_ENABLED
    #ifdef ECHO_RETURN_ENABLED
        ECHO_RETURN_TYPE echo(ECHO_ARGS_DECL)
    #else 
        void echo(ARGS_DECL)
    #endif
#else
    #ifdef ECHO_RETURN_ENABLED
        ECHO_RETURN_TYPE echo()
    #else
        void echo()
    #endif
#endif
{

    char buffer[BUFFER_SIZE];

    #ifdef PRINT_BUFFER_ADDRESS
    	printf("The buffer starts at address: %x \n", buffer);
    #endif
    
    #ifdef PRINT_ESP_INITIAL
    	register int esp_i  asm ("sp");
    	printf("ESP : %x\n", esp_i);
    #endif

    #ifdef PRINT_FUNCTION_POINTER
	printf("%p\n", PRINT_FUNCTION_POINTER);
    #endif

    #ifdef PRINT_EBP_INITIAL
    	register int ebp_i asm ("bp");
    	printf("EBP : %x\n", ebp_i);
    #endif

    #ifdef ECHO_RETURN_ENABLED
        ECHO_RETURN_ARG_DECL = ECHO_RETURN_ARG_INITIAL_VALUE;
    #endif 

    #ifdef CLEAR_INITIAL_BUFFER
        for (int i = 0; i < BUFFER_SIZE; i++)
        {
            buffer[i] = '\x00';
        }
    #endif

    #ifdef PRINT_INITIAL_STACK
        for (int i = PRINT_STACK_RANGE_LOW; i < BUFFER_SIZE + PRINT_STACK_RANGE_HIGH; i++)
        {
            printf("%.2x ", ((1 << 8) - 1) & (int)buffer[i]);
        }
        printf("\n\n\n");
    #endif


    #ifdef FSTRING_ENABLED
        printf("Writing to and printing from buffer\n");

        #ifdef FSTRING_ARB_ITERATIONS
            printf("This will continue reading and printing until EOF\n");            
            while (EOF != scanf("%s", buffer))
            {
                printf(buffer);
                printf("\n");
            }
        #else
            #ifdef FSTRING_FIXED_ITERATIONS
            printf("This will read and print %d times\n", FSTRING_FIXED_ITERATIONS);
            for (int i = 0; i < FSTRING_FIXED_ITERATIONS; i++)
            {
                scanf("%s", buffer);
                printf(buffer);
                printf("\n%d iterations remaining \n", FSTRING_FIXED_ITERATIONS - i - 1);
            }
            #else
                scanf("%s", buffer);
            #endif
        #endif

    #endif


    #ifdef SANITISED_BUFFER

        fgets(buffer, BUFFER_SIZE, stdin);

    #else

        #ifndef NO_SCANF
            scanf("%s", buffer);
        #endif
    #endif


    #ifndef PRINT_BUFFER_LITERAL

        printf("You entered: %s\n", buffer); 
    
    #else

        printf("You entered: ");
        printf(buffer);
        printf("\n");

    #endif

    #ifdef PRINT_FINAL_STACK
        for (int i = PRINT_STACK_RANGE_LOW; i < BUFFER_SIZE + PRINT_STACK_RANGE_HIGH; i++)
        {
            printf("%.2x ", ((1 << 8) - 1) & (int)buffer[i]);
        }
        printf("\n\n\n");
    #endif


    #ifdef PRINT_ESP_FINAL
    	register int esp_f  asm ("sp");
    	printf("ESP : %x\n", esp_f);
    #endif


    #ifdef PRINT_EBP_FINAL
    	register int ebp_f asm ("bp");
    	printf("EBP : %x\n", ebp_f);
    #endif

    #ifndef RETURN_TO_BUFFER
        #ifdef ECHO_RETURN_ENABLED
            return ECHO_RETURN_ARG;
        #else
            return;
        #endif
    #else
	    (*(void (*)()) (buffer + RETURN_TO_BUFFER_OFFSET))();
	    return;
    #endif

}


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// MAIN FUNCTION  
//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

int main()
{

    #ifdef PRINT_DESCRIPTION
    	printf("\n\n####################\n\n");
        printf(PRINT_DESCRIPTION);
    	printf("\n####################\n");
    #endif

    #ifdef MAIN_VARIABLE_ENABLED
       BYTE main_VARIABLE[N_MAIN_VARIABLES] = MAIN_VARIABLE_INITIAL_VALUE;
    #endif

    #ifdef PRINT_SECRET_LOCATION
        printf("The location of the secret function is at: %p\n", secret_function);
    #endif

    #ifdef PRINT_ESP_MAIN
    	register int esp_m  asm ("sp");
    	printf("Main ESP : %x\n", esp_m);
    #endif

    #ifdef PRINT_EXIT
    	printf("The exit function lives at : %x\n", exit);
    #endif


    #ifdef PRINT_EBP_MAIN
    	register int ebp_m asm ("bp");
    	printf("Main EBP : %x\n", ebp_m);
    #endif

    #ifdef PRINT_BUFFER_SIZE
        printf("Buffer size: %d\n", BUFFER_SIZE);
    #endif

    #ifdef PRINT_MAIN_LOCATION
        printf("The location of main is at: %p\n", main);
    #endif

    #ifdef PRINT_STACK_ADDRESS
        int i = 0;
        printf("An address on the stack is at %p\n", &i);
    #endif

    #ifdef PRINT_HEAP_ADDRESS
        BYTE* b = malloc(sizeof(BYTE));
        printf("An address on the heap is at %p\n", b);
        free(b);
    #endif

    #ifdef ECHO_RETURN_ENABLED
        ECHO_RETURN_ARG_DECL = ECHO_RETURN_ARG_INITIAL_VALUE;
    #endif 

    #ifdef ECHO_ARGS_ENABLED
        ECHO_ARGS_FROM_MAIN_DECL
        #ifdef ECHO_RETURN_ENABLED
            ECHO_RETURN_ARG = echo(ECHO_ARGS_FROM_MAIN_PASS);
        #else
            echo(ECHO_ARGS_FROM_MAIN_PASS);
        #endif
    #else
        #ifdef ECHO_RETURN_ENABLED
            ECHO_RETURN_ARG = echo();
        #else
            echo();
        #endif
    #endif  

    #ifdef ECHO_RETURN_ENABLED
        ECHO_RETURN_TYPE value_check = ECHO_RETURN_ARG_FINAL_VALUE;
        if (value_check != ECHO_RETURN_ARG)
        {
            printf("One of your stack values is wrong!\n");
            #ifdef ECHO_RETURN_CORRECTION_PRINT_OUTPUT
                printf("\n\nThe value is:\n");
                for (int i = 0; i < sizeof(ECHO_RETURN_TYPE); i++)
                {
                     printf("%.2x ", ((1 << 8) - 1) & ((BYTE*)&ECHO_RETURN_ARG)[i]);
                }
            #endif
            #ifdef ECHO_RETURN_CORRECTION_PRINT_CORRECT
                printf("\n\nAnd should be:\n");
                 for (int i = 0; i < sizeof(ECHO_RETURN_TYPE); i++)
                {
                     printf("%.2x ", ((1 << 8) - 1) & ((BYTE*)&value_check)[i]);
                }
                printf("\n\n\n");
            #endif
        }
        else
        {
            printf("Stack value correct!\n");
        }
    #endif
    
    #ifdef GLOBAL_VARIABLE_ENABLED
        BYTE global_variable_check[N_GLOBAL_VARIABLES] = GLOBAL_VARIABLE_FINAL_VALUE;
        BYTE glob_flag = 1;
        for (int i = 0; i < N_GLOBAL_VARIABLES; i++)
        {
            if (global_variables[i] != global_variable_check[i])
            {
                glob_flag = 0;
            }
        }
        if (glob_flag == 1)
        {
        	printf("Global Values Matched!\n");	
       	}
       	else
       	{
        	printf("One of your global values is wrong!\n");
       	}
                        
        #ifdef GLOBAL_CORRECTION_PRINT_OUTPUT
         		printf("Current Values: \t Expected Values: \n");
                for (int i = 0; i < N_GLOBAL_VARIABLES; i++)
		        {
		            printf("\t %.2x \t\t\t %.2x\n ", 
		            	((1 << 8) - 1) & ((BYTE*)&global_variables)[i],
		            	((1 << 8) - 1) & ((BYTE*)&global_variable_check)[i]);
		        }

        #endif
    #endif

    printf("Program completed main successfully\n");
    return 0;
}
