
#include "pch.h"


#include <string>
#include <iostream>
#include <Windows.h>
#include <vector>
#include <iomanip>
#include <errhandlingapi.h>
#include <libloaderapi.h>
#include <memoryapi.h>
#include <utilapiset.h>
#include <winternl.h>
#include <exception>
#include <ios>
#include <vadefs.h>
#include <cstdio> 
#include <fstream>
#include <sstream>

#include "FunctionRedirectionUtillity.h"

#include <cstdint>

#include <memoryapi.h>
#include <wow64apiset.h> 
#include <TlHelp32.h> // needs to be included after windows.h
#include <Psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <utility>
#include <optional>


#include <cstring>
#include <array>
#include <map>
#include <functional> 
#include <tuple> 
#include <thread>
#include <chrono> 
#include <consoleapi.h>
#include <iomanip>
#include <type_traits>
#include <__msvc_string_view.hpp>
#include <memory>



void* add_offset_plus_module_base_address(const uint64_t method_offset_address) {
	HMODULE hModule = GetModuleHandle(0);
	void* method_address_offsetPtr = (void*)((uintptr_t)hModule + method_offset_address);
	std::cout << "method_address_offsetPtr: " << method_address_offsetPtr << std::endl;
	return method_address_offsetPtr;
}

// This writes jump so when calling func2hook method the jumpTarget will be executed
uint32_t WriteRelativeJump_5bytes(void* func2hook, void* jumpTarget) {
	std::cout << "========WriteRelativeJump_5bytes========\n";
	uint8_t jmpInstruction[5] = { 0xE9, 0x0, 0x0, 0x0, 0x0 };

	int64_t relativeToJumpTarget64 = (int64_t)jumpTarget - ((int64_t)func2hook + 5);
	check(relativeToJumpTarget64 < INT32_MAX);

	int32_t relativeToJumpTarget = (int32_t)relativeToJumpTarget64;

	memcpy(jmpInstruction + 1, &relativeToJumpTarget, 4);

	DWORD oldProtect;
	bool err = VirtualProtect(func2hook, 1024, PAGE_EXECUTE_READWRITE, &oldProtect);
	check(err);

	memcpy(func2hook, jmpInstruction, sizeof(jmpInstruction));
	return sizeof(jmpInstruction);
}

// Function to write opcode to memory
void writeOpcodeToMemory(const uint64_t address, const std::string& opcode) {
	// Convert the opcode string to bytes
	std::vector<uint8_t> bytes;
	for (size_t i = 0; i < opcode.length(); i += 2) {
		uint8_t byte = std::stoul(opcode.substr(i, 2), nullptr, 16);
		bytes.push_back(byte);
		//std::cout << std::hex << (int)byte;
	}
	std::cout << "Writing opcode to address: " << std::hex << address << std::endl;
	// Change memory protection to allow writing
	DWORD oldProtect;
	if (!VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::cerr << "[!] Failed to change memory protection\n" << GetLastError() << std::endl;
		return;
	}
	std::cout << "oldProtect: " << oldProtect << std::endl;

	std::cout << "Write the bytes to memory ...\n";
	std::memcpy(reinterpret_cast<void*>(address), bytes.data(), bytes.size());

	std::cout << "Restore the original memory protection ...\n";
	VirtualProtect(reinterpret_cast<void*>(address), bytes.size(), oldProtect, &oldProtect);

	// Verify that the opcode was written correctly by reading that memory
	uint8_t* memPtr = reinterpret_cast<uint8_t*>(address);
	std::cout << "Opcode written to memory (Read): ";
	for (size_t i = 0; i < opcode.length() / 2; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(memPtr[i]);
	}
	std::cout << std::endl;

	// Free the allocated memory
	VirtualFree(reinterpret_cast<void*>(address), 0, MEM_RELEASE);
}

template <typename T>
void print_buffer(void* buffer) {
	T* typed_buffer = static_cast<T*>(buffer);
	size_t data_size = sizeof(buffer);
	/*for (size_t i = 0; i != '\n'; ++i) {
		std::cerr << typed_buffer[i];
	}*/
	//for (size_t i = 0; typed_buffer[i] < 5000; ++i) {			// THIS CAUSES BUFFER OVERFLOW -> YOU SEE MORE DATA THAN INTENDED
	//	std::cerr << typed_buffer[i];
	//}
	for (size_t i = 0; typed_buffer[i] < 1000; ++i) {
		std::cerr << typed_buffer[i];
	}
	std::cerr << std::endl;
}
template <typename T>											// This should be better than upper, check ..
void print_buffer(void* buffer, size_t size) {
	std::cout << "print_buffer:\n";
	T* typed_buffer = static_cast<T*>(buffer);
	for (size_t i = 0; i < size; ++i) {
		//std::cerr << std::hex << (int)typed_buffer[i] << " ";
		//printf("%x", typed_buffer[i]);
		std::cerr << std::setw(2) << std::setfill('0') << std::hex << (unsigned int)(unsigned char)typed_buffer[i] << " ";
	}
	std::cerr << std::dec << std::endl;
}

/// <summary>
/// define 1. the return type ((void*, int, ... )), and 2. the arguments'es type
/// </summary>
/// <typeparam name="ReturnType"></typeparam>
/// <typeparam name="...Args">-> enter any number of arguments</typeparam>
/// <param name="method_address_offset">-> offset from main exe to the method we want to call</param>
/// <param name="...args">-> enter any number of argumets</param>
/// <returns></returns>
template <typename ReturnType, typename... Args>
std::optional <ReturnType> call_internal_method_by_its_pointer(
	uintptr_t method_address_offset,
	Args&&... args
) {
	std::cout << "******************************************\n";
	std::cout << "   call_internal_method_by_its_pointer\n";
	std::cout << "******************************************\n";
	try {
		// Printing all arguments using a fold expression 
		std::cout << "Passed arguments:\n";
		((std::cout << args << '\n'), ...);

		HMODULE hModule = GetModuleHandle(0);		//GetModuleHandle(targetProgram);		// GETS OWN HANDLE
		if (hModule == NULL) {
			std::cerr << "[!] Failed to get module handle." << std::endl;
			return std::nullopt;
		}
		//std::cout << "<<Module handle: " << hModule << std::endl;

		//// Calculate the address of method_addressPtr relative to the module base
		void* method_address_offsetPtr = (void*)((uintptr_t)hModule + method_address_offset);

		// Check if the memory at method_addressPtr is executable
		DWORD oldProtection;
		if (!VirtualProtect(method_address_offsetPtr, 1, PAGE_EXECUTE_READ, &oldProtection)) {
			std::cerr << "[!] Failed to change memory protection: " << GetLastError() << std::endl;
			return std::nullopt;
		}

		// Reinterpret the method address as a function pointer
		auto func_ptr = reinterpret_cast<ReturnType(*)(Args...)>(method_address_offsetPtr);
		std::cout << "Function pointer: " << func_ptr << std::endl;

		std::cout << "Call the function with forwarded arguments depending on it's type ... ";
		if constexpr (std::is_void_v<ReturnType>) {
			std::cout << "void" << std::endl;
			func_ptr(std::forward<Args>(args)...);
		}
		else {
			std::cout << "function with return" << std::endl;
			return func_ptr(std::forward<Args>(args)...);
		}
	}
	catch (const std::exception& e) {
		std::cerr << "[!] Error calling the function: " << e.what() << std::endl;
	}
}

/// <summary>
/// (B.) :: INLINE REPLACE OPCODE CALL FROM CALL TO func_1() TO CALL TO func_2()
/// 1. Set target program ==> Get current module address
/// 2. Set method address offset relative to base addres (Ghidra) ==> Get pointer to that method
/// 3. Set call address (Ghidra) ==> Get opcode for call instruction
/// 4. ==> Write and replace opcode at call memory address
/// </summary>
/// <param name="hook_method_address_offset">-> address of the function we want to call</param>
/// <param name="inline_callAddress_offset">-> the line where we want to make a call to our method address</param>
/// <param name="targetModule">->[Optional] by default (0), or set for example: TargetProgram.exe</param>
void inline_hook_by_replace_opcode_to_call_different_address(
	uintptr_t hook_method_address_offset,
	uint64_t inline_callAddress_offset,
	LPCWSTR targetModule = 0
) {
	std::cout << "*************************************************************\n";
	std::cout << "   inline_hook_by_replace_opcode_to_call_different_address\n";
	std::cout << "*************************************************************\n";

	// 1.
	// Set target program, get modul handle
	HMODULE hModule = GetModuleHandle(targetModule);		//GetModuleHandle(0);		// GETS OWN HANDLE
	std::cout << "Module handle: " << std::hex << hModule << std::endl;
	if (hModule == NULL) {
		std::cerr << "[!] Failed to get module handle." << std::endl;
		return;
	}

	// 2.
	// Calculate the address of method_addressPtr relative to the module base
	void* targetMethod_address_offsetPtr = (void*)((uintptr_t)hModule + hook_method_address_offset);
	std::cout << "targetMethod_address_offsetPtr ->: " << targetMethod_address_offsetPtr << std::endl;
	/*
							 *************************************************************
							 *                           FUNCTION
							 *************************************************************
							 undefined  __fastcall  func_2 (int  param_1 )
			 undefined         AL:1           <RETURN>
			 int               ECX:4          param_1
			 undefined4        Stack[0x8]:4   local_res8                              XREF[3]:     14000148e (W) ,
																								   140001491 (RW),
																								   140001498 (R)
								 func_2                                          XREF[5]:     main:1400014e7 (*) ,
		> THIS <																			  main:1400014ee (*) ,
			\																				  main:14000150f (c) , 140005070 (*) ,
			 _\|																				   140005078 (*)
		   140001486 55              PUSH     RBP
	*/

	// 3.
	// Make opcode for relative CALL (5 bytes)
	//////////////////////////////////////////////////
	// INPUT		
	uint64_t callAddress = {};
	uint64_t targetAddress = {};
	std::string new_opcode = {};
	int callOpcodeSize = 5;
	uint8_t opcode_CALL = 0xE8;					// CALL opcode instruction (in 5 Byte instruction)

	// Calculate absolute memory address of the call opcode					// from GHIDRA (ONLY LAST BYTES, 0x151f NOT 0x14000151f)
	callAddress = inline_callAddress_offset + (uint64_t)hModule;
	std::cout << "callAddress:   " << std::hex << callAddress << std::endl;
	targetAddress = reinterpret_cast<uint64_t>(targetMethod_address_offsetPtr);// 0x140001460;
	std::cout << "targetAddress: " << std::hex << targetAddress << std::endl;

	// Calculate offset between 2 addresses (pay attention that offset is calculated from end of 1st address 
	// till start of target address, hence 5 bytes offset)
	uint64_t offset = static_cast<uint64_t>(targetAddress - (callAddress + callOpcodeSize));
	std::cout << "Calculate offset: callAddress -> targetAddress: 0x" << std::uppercase << std::hex << offset << std::endl;

	// Combine opcode for CALL with relative address that we previously calculated
	std::stringstream ss;
	ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(opcode_CALL);
	for (int i = 0; i < 4; ++i) {
		ss << std::setw(2) << (offset & 0xFF);
		offset >>= 8;
	}
	new_opcode = ss.str();
	std::cout << "Full opcode: " << std::uppercase << std::hex << new_opcode << std::endl;

	// 4.
	// Write and replace opcode at call memory address
	//////////////////////////////////////////////////
	writeOpcodeToMemory(callAddress, new_opcode);

	std::cout << "------------------------------------------\n";
}

// Store last pointer to a hooked_method so we can retrive it in hooker_method
// This is just for temporary use when creating trampoline_byte_buffer so we can reference to existing buffer
void* last_pointer_to_hooked_method = {};

// Define a global map to store trampoline byte buffers
std::map<void*, std::array<uint8_t, 50>> trampoline_byte_buffers_map;

// Function to get or create a trampoline byte buffer for a given function
// if passed pointer to the hooked function was already created, you get existing trampoline_buffer
std::array<uint8_t, 50>& get_trampoline_buffer(void* function_address) {
	// Store last pointer to be used globally
	last_pointer_to_hooked_method = function_address;
	// Check if a buffer already exists for this function
	auto buffer = trampoline_byte_buffers_map.find(function_address);
	if (buffer != trampoline_byte_buffers_map.end()) {
		std::cout << "Returning existing trampoline_byte_buffers ...\n";
		return buffer->second;
	}
	std::cout << "Creating new trampoline_byte_buffers ...\n";
	std::array<uint8_t, 50> new_buffer({ 0 });
	trampoline_byte_buffers_map[function_address] = new_buffer;
	return trampoline_byte_buffers_map[function_address];
}

template <typename Type, typename Manipulator>
void print_chars_with_type(const std::string& input, Manipulator manip) {
	for (auto& c : input) {
		if (std::is_same<Type, int>::value) {
			std::cout << manip << std::setw(2) << std::setfill('0') << static_cast<Type>(c);
		}
		else {
			std::cout << manip << static_cast<Type>(c);
		}
	}
	std::cout << std::endl;
}

/// <summary>
/// This debugs all the input data from hooked method and passes them to waypoint_to_trampoline_method
/// This is the function that gets executed by the written opcode
/// </summary>
/// <typeparam name="...Args"></typeparam>
/// <param name="...args"></param>
template <typename ReturnType, typename... Args>
ReturnType hooker_method(Args... args) {
	std::cout << "\nHOOKER WITH TRAMPOLINE METHOD\n";

	// Printing all arguments using a fold expression 
	std::cout << "Hooked (stollen) arguments (DEC):\n";
	((std::cout << std::dec << args << '\n'), ...);
	std::cout << "Hooked (stollen) arguments <int> (HEX):\n";
	(print_chars_with_type<int>(args, std::hex), ...);
	//std::cout << "Hooked (stollen) arguments <char> (HEX):\n";
	//(print_chars_with_type<char>(args, std::hex), ...);
	std::cout << std::endl;

	// Get or assign new function buffer
	std::array<uint8_t, 50>& trampoline_bytes_buffer_for_function = get_trampoline_buffer(last_pointer_to_hooked_method);

	// Print the bytes in the trampoline for debugging
	std::cout << "Trampoline bytes:\n";
	for (int i = 0; i < std::size(trampoline_bytes_buffer_for_function); ++i) {
		printf("%02X ", trampoline_bytes_buffer_for_function[i]);
	}
	std::cout << std::endl;

	std::cout << "Going back to normal function ...\n";
	std::cout << "Executing trampoline_bytes_buffer_for_function by jumping back to original hooked method + offset ..." << std::endl;

	// Cast method based on number of arguments and arguments types
	auto hooked_func = std::function<ReturnType(Args...)>(reinterpret_cast<ReturnType(__cdecl*)(Args...)>((void*)(trampoline_bytes_buffer_for_function.data())));

	// Print the type of ReturnType
	std::cout << "Return Type: " << typeid(ReturnType).name() << std::endl;

	// Run the casted function
	auto result = std::apply(hooked_func, std::make_tuple(args...));

	std::cout << "\nReturn Value size: " << sizeof(ReturnType) << " bytes" << std::endl;
	std::cout << "Return Value (DEC): \"" << std::dec << result << "\"" << std::endl;
	std::cout << "Return Value (HEX): \"" << std::hex << result << "\"" << std::endl;

	if constexpr (std::is_same_v<ReturnType, std::string>) {
		std::cout << "String length: " << result.length() << std::endl;
	}
	else if constexpr (std::is_same_v<ReturnType, char*>) {
		std::cout << "Char* length: " << strlen(result) << std::endl;
	}
	/*else if constexpr (std::is_pointer_v<ReturnType>) {
		std::cout << "Size of pointed-to type: " << sizeof(*std::declval<ReturnType>()) << " bytes\n\n";
	}*/
	else {
		std::cout << "ReturnType is not a pointer or std::string. Cannot determine length in this case." << std::endl;
	}

	std::cout << "Executed trampoline_bytes_buffer_for_function successfully. Returning ..." << std::endl;
	std::cout << "------------------------------------------\n";

	return result;
}


//////////////////////////////////////////////////
// (E.) :: HOOK FUNCTION TO HOOKER WITH TRAMPOLINE
// TODO:
// Get at least 5 bytes + additional bytes so opcode instructions are complete from the hooked method.
// Write a jump to (2)hooker method at the start of (1)hooked method.
// At (2)hooker method print all input arguments that were passed to (1)hooked method
// At the end of (2)hooker method Write a jump to (3)trampoline method
// Write (5+) 12+ bytes from the original method to the trampoline method.
// After that Write jump to (1)hooked method from (3)trampoline method and continue normally.
//////////////////////////////////////////////////

/// <summary>
/// 
/// </summary>
/// <param name="hooked_method"></param>
/// <param name="hooker_method"> => pass it with types that ! HOOKED method originally has, ex.: hooker_method /int/</param>
/// <param name="numOfBytesToCopy"> => at least 12 bytes, ex.: (18) untill the end of current opcode at our method</param>
void hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(void* hooked_method, void* hooker_method, int numOfBytesToCopy) {
	std::cout << "******************************************************************\n";
	std::cout << "   hook_function_to_hooker_with_trampoline_absoluteCall_12bytes\n";
	std::cout << "******************************************************************\n";

	// Prepare opcode for Absolute jump to hooker method
	uint8_t asm_jumpToHooker[12] = {
		0x48, 0xB8,                 // MOV RAX, [target_address]
		0, 0, 0, 0, 0, 0, 0, 0,     // placeholder for target address
		0xFF, 0xE0                  // JMP RAX
	};

	// Copy the hooker_method address into the jump code
	*(uint64_t*)&asm_jumpToHooker[2] = (uint64_t)hooker_method;

	std::cout << "Prepared asm_jumpToHooker opcode:\n";
	for (size_t i = 0; i < numOfBytesToCopy; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(asm_jumpToHooker[i]) << " ";
	}
	std::cout << std::endl;

	// Save bytes from original hooked method to be later copied to trampoline_bytes_buffer_for_function
	uint8_t asm_originalHookedCode[64] = {};		// size xx is now set as max size for original opcode

	// Copy data from vector to array
	memcpy(asm_originalHookedCode, hooked_method, numOfBytesToCopy);


	std::cout << "Read bytes in hooked method at: " << hooked_method << std::endl;
	for (size_t i = 0; i < numOfBytesToCopy; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(((uint8_t*)hooked_method)[i]) << " ";
	}
	std::cout << std::endl;

	// Write jump from hooked method to our hooker method, now that we have stored the original opcode
	DWORD oldProtect;
	// Change the memory protection to allow writing
	if (!VirtualProtect(hooked_method, numOfBytesToCopy, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::cerr << "Failed to change memory protection" << std::endl;
		return;
	}

	// Copy the "jump to hooker" code to hooked method
	memcpy(hooked_method, asm_jumpToHooker, numOfBytesToCopy);

	// Restore the original memory protection
	if (!VirtualProtect(hooked_method, numOfBytesToCopy, oldProtect, &oldProtect)) {
		std::cerr << "Failed to restore memory protection" << std::endl;
	}
	std::cout << "Jump code written from hooked method (source) to hooker method (target) address.\n";

	std::cout << "Read bytes in hooked method at: " << hooked_method << std::endl;
	for (size_t i = 0; i < numOfBytesToCopy; ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(((uint8_t*)hooked_method)[i]) << " ";
	}
	std::cout << std::endl;


	/////// CREATE OPCODE INSTRUCTIONS ON EMPTY BUFFER trampoline_bytes_buffer_for_function 
	// THAT WILL:
	// 1. execute the original code that we have overwritten on beginning of hooked function
	// 2. jump to original hooked fuction

	// Get or assign new function buffer
	std::array<uint8_t, 50>& trampoline_bytes_buffer_for_function = get_trampoline_buffer(last_pointer_to_hooked_method);

	// 1.)
	// Change memory protection to allow writing
	if (!VirtualProtect(trampoline_bytes_buffer_for_function.data(), std::size(trampoline_bytes_buffer_for_function), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::cerr << "Failed to change memory protection" << std::endl;
		return;
	}

	// Copy bytes from original method that we overwritten to the trampoline buffer
	std::cout << "Writing Trampoline bytes from original method (asm_originalHookedCode) that we overwritten to the trampoline buffer ...\n";
	memcpy(trampoline_bytes_buffer_for_function.data(), asm_originalHookedCode, std::size(asm_originalHookedCode));

	std::cout << "Read trampoline_bytes_buffer_for_function:\n";
	for (size_t i = 0; i < std::size(trampoline_bytes_buffer_for_function); ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(trampoline_bytes_buffer_for_function[i]) << " ";
	}
	std::cout << std::endl;

	// 2.)
	// Create a jump opcode that will jump to the original (hooked) function with offset of xx (12) 18 bytes
	uint8_t asm_jumpToOriginalHookedFunction[12] = {
		0x48, 0xB8,                 // MOV RAX, [original_method_address + numOfBytesToCopy]
		0, 0, 0, 0, 0, 0, 0, 0,     // placeholder for original method address
		0xFF, 0xE0                  // JMP RAX
	};

	// Write the absolute jump code from original method + offset (numOfBytesToCopy)
	*(uint64_t*)&asm_jumpToOriginalHookedFunction[2] = (uint64_t)hooked_method + (uint64_t)numOfBytesToCopy;

	std::cout << "Read asm_jumpToOriginalHookedFunction:\n";
	for (size_t i = 0; i < std::size(asm_jumpToOriginalHookedFunction); ++i) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(asm_jumpToOriginalHookedFunction[i]) << " ";
	}
	std::cout << std::endl;

	// Copy the jump "jump to hooked method" code
	std::cout << "Writing jump to Trampoline bytes starting at index: " << std::dec << numOfBytesToCopy + 4 << std::endl;
	memcpy(
		trampoline_bytes_buffer_for_function.data() + numOfBytesToCopy + 4,		// +4 (NOP bytes) for allignment
		asm_jumpToOriginalHookedFunction,
		std::size(asm_jumpToOriginalHookedFunction));

	// Restore the original memory protection
	if (!VirtualProtect(trampoline_bytes_buffer_for_function.data(), numOfBytesToCopy + numOfBytesToCopy, oldProtect, &oldProtect)) {
		std::cerr << "Failed to restore memory protection" << std::endl;
	}

	// Change memory protection to allow EXECUTING THE BLOCK OF CODE -> trampoline_bytes_buffer_for_function
	if (!VirtualProtect(trampoline_bytes_buffer_for_function.data(), std::size(trampoline_bytes_buffer_for_function), PAGE_EXECUTE_READWRITE, &oldProtect)) {
		std::cerr << "Failed to change memory protection" << std::endl;
		return;
	}

	// Print the trampoline bytes for debugging
	std::cout << "Read trampoline_bytes_buffer_for_function:\n";
	for (int i = 0; i < std::size(trampoline_bytes_buffer_for_function); ++i) {
		printf("%02X ", trampoline_bytes_buffer_for_function[i]);
	}
	std::cout << std::endl;

	std::cout << "Jump pointing to original hooked function + offset at address: " << std::hex << ((uint64_t)hooked_method + (uint64_t)numOfBytesToCopy) << std::endl;
	std::cout << "Trampoline code written successfully" << std::endl;
}




BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH: {
		std::cout << "_case process attach" << std::endl;
		std::cout << "\n<< INJECTED DLL >>\n";
		get_self_data_for_info();

		//////////////////////////////////////////////////
		// (B.) :: CALL INTERNAL METHOD BY IT'S POINTER (name is just for debug)
		auto ret =				// Can use this if it is return type
		call_internal_method_by_its_pointer<int, int>(0x1486, 4000);

		std::cout << "------------------------------------------\n";
		//////////////////////////////////////////////////
		/// (C.) :: INLINE REPLACE OPCODE CALL FROM CALL TO func_1() TO CALL TO func_2()
		inline_hook_by_replace_opcode_to_call_different_address(0x1486, 0x154f);	// AT 0x154f CALL 0x1486 func_2()


		//////////////////////////////////////////////////
		// (D.) :: REPLACE CALL FUNCTION ADDRESS TO ANOTHER FUNCTION (for internally defined functions only)
		Test_Add(10, 2);								// this runs original Test_add()
		WriteRelativeJump_5bytes(Test_Add, Test_Subtract);		// this writes jump from Test_Add() to Test_Subtract()
		Test_Add(10, 2);								// this runs Test_Add() but then imeadiatelly jumps to Test_Subtract()

		//////////////////////////////////////////////////
		// (E.) :: HOOK FUNCTION TO HOOKER WITH TRAMPOLINE
		hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(add_offset_plus_module_base_address(0x1240), hooker_method<void*, char*, char*, char*>, 16); // unxor_and_dehex_string
		hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(add_offset_plus_module_base_address(0x1570), hooker_method<int*, char*, char*>, 18); // try_activate_license
		hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(add_offset_plus_module_base_address(0x18c0), hooker_method<std::string&, char*, char*>, 14); // CRYPT
		hook_function_to_hooker_with_trampoline_absoluteCall_12bytes(add_offset_plus_module_base_address(0x1720), hooker_method<void*, char*, char*>, 14); // text_to_hex


		std::cout << "... COMPLETED" << std::endl;
	}
	case DLL_THREAD_ATTACH: {
		std::cout << "_case thread attach" << std::endl;
	}
	case DLL_THREAD_DETACH: {
		std::cout << "_case thread detach" << std::endl;
	}
	case DLL_PROCESS_DETACH: {
		std::cout << "_case process detach" << std::endl;
	}
						   break;
	}
	return TRUE;
}

