# Function-hooking
Dirty implementation of some techniques of function hooking by injected .dll.
You will need the injector to use it.

# Idea
Idea was to be able to call and track internal functions with injected dll. It is possible to log data that the program sends to the method. This data is printed to console. This code does not need any external dependencies.

The biggest thing here is the 

# Implementation methods
## CALL INTERNAL METHOD BY IT'S POINTER
```c++
auto ret =  // Can use this if it is return type
call_internal_method_by_its_pointer<int, int>(0x1486, 4000);
```
## INLINE REPLACE OPCODE CALL FROM CALL TO func_1() TO CALL TO func_2()
```c++
inline_hook_by_replace_opcode_to_call_different_address(0x1486, 0x154f);	// AT 0x154f CALL 0x1486 func_2()
```
## REPLACE CALL FUNCTION ADDRESS TO ANOTHER FUNCTION (for internally defined functions only)
```c++
Test_Add(10, 2);                                      // this runs original Test_add()
WriteRelativeJump_5bytes(Test_Add, Test_Subtract);    // this writes jump from Test_Add() to Test_Subtract()
Test_Add(10, 2);                                      // this runs Test_Add() but then imeadiatelly jumps to Test_Subtract()
```
## HOOK FUNCTION TO HOOKER WITH TRAMPOLINE
```c++
hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(
  add_offset_plus_module_base_address(
    0x1470                                // offset of the hooked function
  ),
  hooker_method<char*, char*>,            // Hooker method signature reflects hooked method
  12                                      // Number of bytes to copy from hooked method to hooker method
);                                        // Hooks CRYPT method
```
