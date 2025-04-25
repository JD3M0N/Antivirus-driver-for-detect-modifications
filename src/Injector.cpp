// Injector.cpp
#include <windows.h>
#include <iostream>
#include <sstream>

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cout << "Uso: Injector <PID> <DirecciónHex> <NuevoValor>\n"
                     "Ejemplo: Injector 1234 0x7FF6ABCDE123 42\n";
        return 1;
    }

    // Parsear argumentos
    DWORD pid;
    std::istringstream(argv[1]) >> pid;
    LPVOID addr = reinterpret_cast<LPVOID>(std::stoull(argv[2], nullptr, 0));
    int newValue;
    std::istringstream(argv[3]) >> newValue;

    // Abrir el proceso con permisos de VM ops
    HANDLE hProc = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc)
    {
        std::cerr << "OpenProcess falló (¿permiso administrador?): " << GetLastError() << "\n";
        return 1;
    }

    // Hacer la región escribible
    DWORD oldProt;
    if (!VirtualProtectEx(hProc, addr, sizeof(newValue),
                          PAGE_EXECUTE_READWRITE, &oldProt))
    {
        std::cerr << "VirtualProtectEx falló: " << GetLastError() << "\n";
        CloseHandle(hProc);
        return 1;
    }

    // Modificar con el nuevo valor
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProc, addr, &newValue,
                            sizeof(newValue), &bytesWritten))
    {
        std::cerr << "WriteProcessMemory falló: " << GetLastError() << "\n";
        // Restaurar protección antes de salir
        VirtualProtectEx(hProc, addr, sizeof(newValue), oldProt, &oldProt);
        CloseHandle(hProc);
        return 1;
    }
    std::cout << "Escritos " << bytesWritten << " bytes en PID " << pid
              << " @ " << addr << "\n";

    // Restaurar la protección original
    VirtualProtectEx(hProc, addr, sizeof(newValue), oldProt, &oldProt);

    // (Opcional) Leer de nuevo para verificar
    int readBack = 0;
    SIZE_T bytesRead = 0;
    if (ReadProcessMemory(hProc, addr, &readBack,
                          sizeof(readBack), &bytesRead))
    {
        std::cout << "Valor leído de vuelta: " << readBack << "\n";
    }
    else
    {
        std::cerr << "ReadProcessMemory falló: " << GetLastError() << "\n";
    }

    CloseHandle(hProc);
    return 0;
}
