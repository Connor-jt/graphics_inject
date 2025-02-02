// graphics_inject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <iostream>
#include <fstream>

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
    char d3d11_VSSetConstantBuffers_func_page[512];
    char dxgi_Present_func_page[4096];

    void* last_d3d11DeviceContext;
    void* last_ID3D11Buffer; // from VSSetConstantBuffers
    void* last_ID3D11VertexShader; // from VSSetShader

    unsigned long long debug1; // func 1 rcx
    unsigned long long debug2; // func 1 incrementor
    unsigned long long debug3; // func 3 access count
    unsigned long long debug4; // func 4 access count
};
datapage* datapage_ptr = 0;

void InjectedFunc_D3D11_DrawIndexed(){
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


int main()
{
    cout << "Hello World!\n";

    DWORD proc_id_array[1024], cbNeeded;
    if (!EnumProcesses(proc_id_array, sizeof(proc_id_array), &cbNeeded)) {
        cout << "couldn't find target process: failed to enumerate.\n";
        return 1;
    }

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


    // create pagefile
    datapage_ptr = (datapage*)VirtualAllocEx(process_id, NULL, sizeof(datapage), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!datapage_ptr) {
        std::cerr << "failed to inject: could not (inject) allocate data chunk.\n";
        cout << GetLastError() << endl;
        return -1;}


    char intermediate_buffer[256];

    void* function_ptr = InjectedFunc_D3D11_DrawIndexed;
    
    // loop through function until we find the 90909090909090 signature
    char* last_instruction_ptr = (char*)function_ptr;
    while (*((unsigned long long*)last_instruction_ptr++) != 0x9090909090909090);
    last_instruction_ptr--;

    UINT64 function_size = (UINT64)last_instruction_ptr - (UINT64)function_ptr;

    int buffer_size = function_size + D3D11_DrawIndexed_inject_size + 13;
    if (sizeof(intermediate_buffer) <= buffer_size) {
        cout << "failed to inject: not enough buffer space for d3d11_DrawIndexed injection.\n";
        return -1;}

    memcpy(intermediate_buffer, function_ptr, function_size);
    // get the bytes from our injection spot to write to the end of our injected function

    // insert ptrs to globals references
    // +2
    *(UINT64*)(intermediate_buffer + 2) = (UINT64)(&datapage_ptr->debug1);
    // +15
    *(UINT64*)(intermediate_buffer + 15) = (UINT64)(&datapage_ptr->debug2);


    if (!ReadProcessMemory(process_id, draw_indexed_address, intermediate_buffer + function_size, D3D11_DrawIndexed_inject_size, 0)) {
        cout << "failed to inject: could not read d3d11_DrawIndexed opcodes.\n";
        return -1;}

    // then append our jmp return code (13 bytes)
    intermediate_buffer[function_size + D3D11_DrawIndexed_inject_size     ] = 0x50; // push rax
    intermediate_buffer[function_size + D3D11_DrawIndexed_inject_size + 1 ] = 0x48; // rex.W
    intermediate_buffer[function_size + D3D11_DrawIndexed_inject_size + 2 ] = 0xB8; // mov rax, imm64
    *(UINT64*)(intermediate_buffer + function_size + D3D11_DrawIndexed_inject_size + 3) = (UINT64)(draw_indexed_address + 12); // imm64
    intermediate_buffer[function_size + D3D11_DrawIndexed_inject_size + 11] = 0xFF; // jmp
    intermediate_buffer[function_size + D3D11_DrawIndexed_inject_size + 12] = 0xE0; // rax


    // copy generated assembly code to pagefile
    if (!WriteProcessMemory(process_id, &datapage_ptr->d3d11_DrawIndexed_func_page, intermediate_buffer, buffer_size, 0)) {
        cout << "failed to inject: could not write d3d11_DrawIndexed injected function.\n";
        cout << GetLastError();
        return -1;}


    // then make the actual hook into the function

    // push data into the intermediate buffer before pushing
    intermediate_buffer[0] = 0x48; // rex
    intermediate_buffer[1] = 0xB8; // mov rax, imm64
    *(UINT64*)(intermediate_buffer + 2) = (UINT64)(&datapage_ptr->d3d11_DrawIndexed_func_page); // imm64
    intermediate_buffer[10] = 0xFF; // jmp
    intermediate_buffer[11] = 0xE0; // rax
    // this part executes after we return from the function
    intermediate_buffer[12] = 0x58; // pop rax

    // NOP out any loose bytes
    int i = 13;
    while (i < D3D11_DrawIndexed_inject_size) intermediate_buffer[i++] = 0x90;
    
    // pause process
    //if (!DebugActiveProcess(GetProcessId(process_id))) {
    //    std::cerr << "failed to inject: could not (debug) pause thread.\n";
    //    return -1;}
    
    //if (!DebugSetProcessKillOnExit(false)) {
    //    std::cerr << "failed to inject: could not set debug pause value.\n";
    //   return -1;}


    // clear page protection
    DWORD oldProtect;
    if (!VirtualProtectEx(process_id, draw_indexed_address, D3D11_DrawIndexed_inject_size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "failed to inject: could not clear memory protection.\n";
        return -1;}

    // write opcode changes
    if (!WriteProcessMemory(process_id, draw_indexed_address, intermediate_buffer, D3D11_DrawIndexed_inject_size, 0)) {
        cout << "failed to inject: could not read d3d11_DrawIndexed opcodes.\n";
        return -1;}

    // restore page protection
    if (!VirtualProtectEx(process_id, draw_indexed_address, D3D11_DrawIndexed_inject_size, oldProtect, &oldProtect)) {
        cout << "[CRITICAL] failed to inject: could not reapply memory protection.\n";
        return -1;}
    
    // resume process
    //if (!DebugActiveProcessStop(GetProcessId(process_id))) {
    //    std::cerr << "failed to inject: could not (debug) resume thread.\n";
    //    return -1;
    //}


    while (true) {
        Sleep(500);

        UINT64 debug_values[4];
        if (ReadProcessMemory(process_id, &datapage_ptr->debug1, debug_values, 32, 0)) {
            cout << "debug1: " << debug_values[0] << " debug2: " << debug_values[1] << " debug3: " << debug_values[2] << " debug4: " << debug_values[3] << endl;
        } else {
            cout << "failed loop memcheck.\n";
        }
    }


    string test;
    cin >> test;

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
