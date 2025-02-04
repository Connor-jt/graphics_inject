// graphics_inject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "../DirectXModdy/globals.h"

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <iostream>
#include <fstream>

#include <vector>

using namespace std;

const char* target_process = "DirectX11_Sample2.exe";
const unsigned long long d3d11_checksum = 0xa0a241b9b7d37785ull;
const unsigned long long dxgi_checksum  = 0xe709c1ef94866bc4ull;

const unsigned long long D3D11_DrawIndexed_offset           = 0x12dc30;
const unsigned long long D3D11_VSSetShader_offset           = 0x12a740;
const unsigned long long D3D11_VSSetConstantBuffers_offset  = 0x12ad30;
const unsigned long long DXGI_Present_offset                = 0x0018c0;

const unsigned long long D3D11_DrawIndexed_inject_size = 18;
const unsigned long long D3D11_VSSetShader_inject_size = 14;
const unsigned long long D3D11_VSSetConstantBuffers_inject_size = 16;
const unsigned long long DXGI_Present_inject_size = 14;


unsigned long long calculateChecksum(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Unable to open file for checksum'ing: " << filename << std::endl;
        return 0;
    }
    unsigned long long checksum = 0;
    unsigned long long buffer;
    while (file.read((char*)(&buffer), 8))
        checksum ^= buffer;
    return checksum;
}


class datapage {
public:
    char d3d11_DrawIndexed_func_page[256];
    char d3d11_VSSetShader_func_page[256];
    char d3d11_VSSetConstantBuffers_func_page[256];
    char dxgi_Present_func_page[256];
};
datapage* datapage_ptr = 0;
DLLGLobals* globals_ptr = 0;

__attribute__((naked)) void InjectedFunc_DllCall() {
    __asm {
        ;// save registers
        push rax
        push rcx
        push rdx
        push rdi
        push rsi
        push  r8
        push  r9
        push r10
        push r11
        ;// make a call to DLL function
        mov rax, 0x1020304050607080
        call rax
        ;// restore registers
        pop r11
        pop r10
        pop  r9
        pop  r8
        pop rsi
        pop rdi
        pop rdx
        pop rcx
        pop rax
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    }
}
__attribute__((naked)) void InjectedFunc_D3D11_DrawIndexed(){
    __asm {
        ;// write device ptr into global slot
        mov rax, 0x1020304050607080
        mov qword ptr[rax], rcx
        ;// increment global counter
        mov rax, 0x1020304050607080
        inc qword ptr[rax]
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
        NOP
    }
}

class PtrFixups {
public:
    int offset;
    void* ptr;
};

// NOTE: max size of 256 right now, must include injected_func_dst_size if we want to support more
bool hook_function(HANDLE process_id, char* hook_address, int hook_size, void* injected_func, void* injected_func_dst, 
    vector<PtrFixups> ptr_fixups) {

    char intermediate_buffer[256];

    if (hook_size < 3) {
        cout << "failed to inject: hook size is too small.\n";
        return false;}

    // if hook size is less than 13, then we need to use a small hook, also we need to verify that theres enough space
    bool is_using_hook = false;
    if (hook_size < 13) {
        is_using_hook = true;
        // NOTE: we could improve this algorithm to search for any match within the neighboring 255 bytes, but this could introduce issues with CC bytes that may not be used for 'int 3'
        // grab the function's 12 proceeding bytes
        if (!ReadProcessMemory(process_id, hook_address-12, intermediate_buffer, 12, 0)) {
            cout << "failed to inject: could not read bytes proceding d3d11_DrawIndexed.\n";
            return false;}

        // check the proceding 12 bytes from the function ptr, to make sure that they're all free to use
        for (int i = 11; i >= 0; i--) {
            if (intermediate_buffer[i] != (char)0xCC) {
                cout << "failed to inject: not enough blank space before function to fit short hook jump.\n";
                return false;
    }}}

    // copy over our function (and instructions overwritten by the hook) to process memory
    {
        // loop through function until we find the 90909090909090 signature
        char* last_instruction_ptr = (char*)injected_func;
        while (*((unsigned long long*)last_instruction_ptr) != 0x9090909090909090)
            last_instruction_ptr++;

        UINT64 function_size = (UINT64)last_instruction_ptr - (UINT64)injected_func;

        int buffer_size = function_size + hook_size + 13;
        if (sizeof(intermediate_buffer) <= buffer_size) {
            cout << "failed to inject: not enough intermediate buffer space for d3d11_DrawIndexed injection.\n";
            return false;}

        memcpy(intermediate_buffer, injected_func, function_size);

        // insert ptrs to globals references
        for (auto& element : ptr_fixups)
            *(UINT64*)(intermediate_buffer + element.offset) = (UINT64)(element.ptr);
    
        // copy over instructions that get overwritten by detour hook
        if (!ReadProcessMemory(process_id, hook_address, intermediate_buffer + function_size, hook_size, 0)) {
            cout << "failed to inject: could not read d3d11_DrawIndexed opcodes.\n";
            return false;}

        // then append our jmp return code (13 bytes)
        intermediate_buffer[function_size + hook_size] = 0x50; // push rax
        intermediate_buffer[function_size + hook_size + 1] = 0x48; // rex.W
        intermediate_buffer[function_size + hook_size + 2] = 0xB8; // mov rax, imm64
        *(UINT64*)(intermediate_buffer + function_size + hook_size + 3) = (UINT64)(hook_address + (is_using_hook? 2 : 12) ); // imm64, either 12/2 depending on what kind of hook patch we use
        intermediate_buffer[function_size + hook_size + 11] = 0xFF; // jmp
        intermediate_buffer[function_size + hook_size + 12] = 0xE0; // rax

        // copy generated assembly code to pagefile
        if (!WriteProcessMemory(process_id, injected_func_dst, intermediate_buffer, buffer_size, 0)) {
            cout << "failed to inject: could not write d3d11_DrawIndexed injected function.\n";
            return false;}
    }

    //write all the hook detour opcodes into a buffer to write to the process
    


    // bytes for regular hook patch
    intermediate_buffer[0] = 0x48; // rex
    intermediate_buffer[1] = 0xB8; // mov rax, imm64
    *(UINT64*)(intermediate_buffer + 2) = (UINT64)(injected_func_dst); // imm64
    intermediate_buffer[10] = 0xFF; // jmp
    intermediate_buffer[11] = 0xE0; // rax
    // this part executes after we return from the function (also this gets overwritten in the func below)
    intermediate_buffer[12] = 0x58; // pop rax

    int total_patch_bytes_size = 13;
    // mini hook patch
    if (is_using_hook) {
        hook_address -= 12;
        hook_size += 12;
        total_patch_bytes_size = 15;
        // write our mini hook
        intermediate_buffer[12] = 0xEB; // jmp rel8
        intermediate_buffer[13] = 0xF2; // -14
        intermediate_buffer[14] = 0x58; // pop rax
    }


    // NOP out any loose bytes
    while (total_patch_bytes_size < hook_size) intermediate_buffer[total_patch_bytes_size++] = 0x90;

    // pause process
    if (!DebugActiveProcess(GetProcessId(process_id))) {
        std::cerr << "failed to inject: could not (debug) pause thread.\n";
        return false;}

    if (!DebugSetProcessKillOnExit(false)) {
        std::cerr << "failed to inject: could not set debug pause value.\n";
        return false;}

    // clear page protection
    DWORD oldProtect;
    if (!VirtualProtectEx(process_id, hook_address, hook_size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "failed to inject: could not clear memory protection.\n";
        return false;}

    // write opcode changes
    if (!WriteProcessMemory(process_id, hook_address, intermediate_buffer, hook_size, 0)) {
        cout << "failed to inject: could not read d3d11_DrawIndexed opcodes.\n";
        return false;}

    // restore page protection
    if (!VirtualProtectEx(process_id, hook_address, hook_size, oldProtect, &oldProtect)) {
        cout << "[CRITICAL] failed to inject: could not reapply memory protection.\n";
        return false;}

    // resume process
    if (!DebugActiveProcessStop(GetProcessId(process_id))) {
        std::cerr << "[CRITICAL] failed to inject: could not (debug) resume thread.\n";
        return false;}

    return true;
}


class FuncLookups {
public:
    char* name;
    void* ptr;
};

HMODULE load_dll(HANDLE process_id, char* dll_path, char* dll_name, vector<FuncLookups>& lookups, void** globals) {
    LPVOID path_str_ptr = VirtualAllocEx(process_id, 0, strlen(dll_path) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!path_str_ptr) {
        cout << "failed to load dll: could not allocate path string memory.\n";
        return 0;}

    if (!WriteProcessMemory(process_id, path_str_ptr, dll_path, strlen(dll_path) + 1, NULL)) {
        cout << "failed to load dll: could not write to path string memory.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    HANDLE hThread = CreateRemoteThread(process_id, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"), path_str_ptr, 0, NULL);
    if (!hThread) {
        cout << "failed to load dll: could not create remote thread.\n";
        VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
        return 0;}

    WaitForSingleObject(hThread, INFINITE);
    VirtualFreeEx(process_id, path_str_ptr, 0, MEM_RELEASE);
    CloseHandle(hThread);

    // then we get the module 
    HMODULE modules_array[256];
    DWORD mods_buffersize_used;
    if (!EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)){
        cout << "failed to load dll: could not iterate modules.\n";
        return 0;}

    // if current process matches target process by name
    char process_name[MAX_PATH];
    // iterate through modules to find matching
    int modules_count = mods_buffersize_used / sizeof(HMODULE);

    HMODULE hooked_dll = 0; // invalid pointer becuase its memory belongs to the other process
    for (int j = 1; j < modules_count; j++) {
        GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
        if (!strcmp(process_name, dll_name))
            hooked_dll = modules_array[j];
    }
    if (!hooked_dll) {
        cout << "failed to load dll: could not find our module via iteration.\n";
        return 0;}

    // load a copy of the module to this process so we can map offsets
    HMODULE query_module = LoadLibraryA(dll_path);
    if (!query_module) {
        std::cerr << "failed to inject: could not load moddy DLL to our own process to query function offsets.\n";
        return 0;}

    // get offset of globals struct
    if (globals) {
        typedef void*(__stdcall* DLLGlobals)();
        DLLGlobals globals_func = (DLLGlobals)GetProcAddress(query_module, "DLLGlobals");
        if (!globals_func) {
            std::cerr << "failed to inject: could not find address of a fetch globals function.\n";
            cout << GetLastError();
            return 0;}

        // convert address found in query module to offset, then apply that offset to the external module
        *globals = (void*)((UINT64)hooked_dll + ((UINT64)(globals_func()) - (UINT64)query_module));
    }

    // figure out offsets of all requested functions
    for (auto& element : lookups) {
        void* func_address = GetProcAddress(query_module, element.name);
        if (!func_address) {
            std::cerr << "failed to inject: could not find address of a specified function.\n";
            return 0;}
        // convert address found in query module to offset, then apply that offset to the external module
        element.ptr = (void*)((UINT64)hooked_dll + ((UINT64)func_address - (UINT64)query_module));
    }

    // release query module
    if (!FreeLibrary(query_module)) {
        std::cerr << "failed to inject: failed to release query module.\n";
        return 0;}

    return hooked_dll;
}

int main()
{
    cout << "Hello World!\n";

    DWORD proc_id_array[1024], cbNeeded;
    if (!EnumProcesses(proc_id_array, sizeof(proc_id_array), &cbNeeded)) {
        cout << "couldn't find target process: failed to enumerate.\n";
        return 1;}

    HANDLE process_id;
    HMODULE d3d11_module = 0;
    HMODULE dxgi_module = 0;

    DWORD processes_count = cbNeeded / sizeof(DWORD);
    for (int i = 0; i < processes_count; i++) {
        if (!proc_id_array[i]) continue;

        //process_id = OpenProcess(PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, proc_id_array[i]);
        process_id = OpenProcess(PROCESS_ALL_ACCESS, FALSE, proc_id_array[i]);
        if (!process_id) continue;

        HMODULE modules_array[256];
        DWORD mods_buffersize_used;
        if (EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {

            // if current process matches target process by name
            char process_name[MAX_PATH];
            GetModuleBaseNameA(process_id, modules_array[0], process_name, sizeof(process_name));
            if (strcmp(process_name, target_process)) continue;

            // iterate through modules to find matching
            int modules_count = mods_buffersize_used / sizeof(HMODULE);
            for (int j = 1; j < modules_count; j++) {

                GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
                // check for d3d11.dll match
                if (!strcmp(process_name, "d3d11.dll")) {
                    GetModuleFileNameExA(process_id, modules_array[j], process_name, sizeof(process_name));
                    if (calculateChecksum(process_name) == d3d11_checksum)
                         d3d11_module = modules_array[j];
                    else {
                        cout << "bad checksum for found d3d11.dll module.\n";
                        return -1;}
                }
                // check for dxgi.dll match
                else if (!strcmp(process_name, "dxgi.dll")) {
                    GetModuleFileNameExA(process_id, modules_array[j], process_name, sizeof(process_name));
                    if (calculateChecksum(process_name) == dxgi_checksum)
                        dxgi_module = modules_array[j];
                    else {
                        cout << "bad checksum for found dxgi.dll module.\n";
                        return -1;}
            }}
            goto found_target_proc;
        }
        CloseHandle(process_id);
    }
    cout << "could not find target process.\n";
    return -1;

    found_target_proc:
    // check to make sure we loaded the graphics modules
    if (!d3d11_module) {
        cout << "no d3d11 module found.\n";
        return -1;}
    if (!dxgi_module) {
        cout << "no dxgi module found.\n";
        return -1;}

    // get function addressed
    char* draw_indexed_address  = (char*)d3d11_module + D3D11_DrawIndexed_offset;
    char* set_shader_address    = (char*)d3d11_module + D3D11_VSSetShader_offset;
    char* set_constants_address = (char*)d3d11_module + D3D11_VSSetConstantBuffers_offset;
    char* dxgi_present_address  = (char*)dxgi_module  + DXGI_Present_offset;

    
    // test loading the moddy module
    vector<FuncLookups> lookups = { {"DLLRun", 0} };
    HMODULE moddy_module = load_dll(process_id, "D:\\Projects\\VS\\graphics_inject\\x64\\Debug\\DirectXModdy.dll", "DirectXModdy.dll", lookups, (void**)&globals_ptr);
    if (!moddy_module) {
        std::cerr << "failed to inject: could not load moddy DLL.\n";
        return -1;}



    // allocate pagefile
    datapage_ptr = (datapage*)VirtualAllocEx(process_id, NULL, sizeof(datapage), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!datapage_ptr) {
        std::cerr << "failed to inject: could not (inject) allocate data chunk.\n";
        return -1;}


    // testing the short hook
    //hook_function(process_id, draw_indexed_address, 4, InjectedFunc_D3D11_DrawIndexed, &datapage_ptr->d3d11_DrawIndexed_func_page,
    //    {{2, &globals_ptr->debug1}, {15, &globals_ptr->debug2}});
    
    // testing global data access hook
    //hook_function(process_id, draw_indexed_address, D3D11_DrawIndexed_inject_size, InjectedFunc_D3D11_DrawIndexed, &datapage_ptr->d3d11_DrawIndexed_func_page,
    //    {{2, &globals_ptr->debug1}, {15, &globals_ptr->debug2}});

    // testing DLL run call hook
    hook_function(process_id, draw_indexed_address, D3D11_DrawIndexed_inject_size, InjectedFunc_DllCall, &datapage_ptr->d3d11_DrawIndexed_func_page,
        { {15, lookups[0].ptr} });


    while (true) {
        Sleep(500);
        cout << "running\n";
        UINT64 debug_values[4];
        if (ReadProcessMemory(process_id, &globals_ptr->debug1, debug_values, 32, 0)) {
            cout << "debug1: " << debug_values[0] << " debug2: " << debug_values[1] << " debug3: " << debug_values[2] << " debug4: " << debug_values[3] << endl;
        } else {
            cout << "failed loop memcheck.\n";
        }
    }
    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
