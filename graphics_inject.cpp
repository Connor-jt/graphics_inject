// graphics_inject.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>

#include <iostream>
#include <fstream>

using namespace std;

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
    class globals {

    };

    //void*;

};



int main()
{
    cout << "Hello World!\n";

    DWORD proc_id_array[1024], cbNeeded;
    if (!EnumProcesses(proc_id_array, sizeof(proc_id_array), &cbNeeded)){
        cout << "couldn't find target process: failed to enumerate.\n";
        return 1;}


    HANDLE process_id;
    HMODULE d3d11_module = 0;
    HMODULE dxgi_module = 0;

    DWORD processes_count = cbNeeded / sizeof(DWORD);
    for (int i = 0; i < processes_count; i++){
        if (!proc_id_array[i]) continue;

        // Get a handle to the process.
        process_id = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc_id_array[i]);
        if (!process_id) continue;

        HMODULE modules_array[256];
        DWORD mods_buffersize_used;
        if (EnumProcessModules(process_id, modules_array, sizeof(modules_array), &mods_buffersize_used)) {

            // if current process matches target process by name
            char process_name[MAX_PATH];
            GetModuleBaseNameA(process_id, modules_array[0], process_name, sizeof(process_name));
            if (process_name != "") continue;

            // iterate through modules to find matching
            int modules_count = mods_buffersize_used / sizeof(HMODULE);
            for (int j = 1; j < modules_count; j++) {

                GetModuleBaseNameA(process_id, modules_array[j], process_name, sizeof(process_name));
                if (process_name == "d3d11.dll")
                    d3d11_module = modules_array[j];
                else if (process_name == "dxgi.dll")
                    dxgi_module = modules_array[j];
            }
            break; // also skipping the part where we close the handle
        }
                
        CloseHandle(process_id);
    }

    // look for supported dlls


    // attempt to hook functions??


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
