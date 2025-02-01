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
const unsigned long long DXGI_Present_inject_size = 12;


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
    char d3d11_DrawIndexed_func_page[256];
    char d3d11_VSSetShader_func_page[256];
    char d3d11_VSSetConstantBuffers_func_page[512];
    char dxgi_Present_func_page[4096];

    void* last_d3d11DeviceContext;
    void* last_ID3D11Buffer; // from VSSetConstantBuffers
    void* last_ID3D11VertexShader; // from VSSetShader

    unsigned long long debug1; // func 1 access count
    unsigned long long debug2; // func 2 access count
    unsigned long long debug3; // func 3 access count
    unsigned long long debug4; // func 4 access count
};

// 16x NOP instruction so we can correctly identify the end of the function
//#define INJECT_CONCLUDE NOP 

void InjectedFunc_D3D11_DrawIndexed(){
    __asm {
        ;// write device ptr into global slot
        mov rax, 0x1020304050607080
        mov qword ptr[rax], rcx
        ;// increment global counter
        mov rax, 0x1020304050607080
        mov qword ptr[rax], rcx
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

        process_id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_id_array[i]);
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






    char intermediate_buffer[512];

    void* function_ptr = &InjectedFunc_D3D11_DrawIndexed;
    
    // loop through function until we find the 90909090909090 signature
    char* last_instruction_ptr = (char*)function_ptr;
    while (*((unsigned long long*)last_instruction_ptr++) != 0x9090909090909090);

    UINT8 function_size = (UINT8)last_instruction_ptr - (UINT8)function_ptr;

    memcpy(intermediate_buffer, function_ptr, function_size);
    // get the bytes from our injection spot to write to the end of our injected function


    if (!ReadProcessMemory(process_id, draw_indexed_address, intermediate_buffer + function_size, D3D11_DrawIndexed_inject_size, 0)) {
        cout << "failed to inject: could not read d3d11_DrawIndexed opcodes.\n";
        return -1;
    }

    // then append our jmp return code (12 bytes)




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
