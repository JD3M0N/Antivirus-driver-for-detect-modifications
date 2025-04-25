#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
#include <cstdint> // para uintptr_t

int main()
{
    volatile int value = 0;
    DWORD pid = GetCurrentProcessId();

    // Imprime PID
    std::cout << "TestTarget PID: " << pid << "\n";

    // Imprime dirección en hexadecimal:
    std::cout << "Dirección de 'value': 0x"
              << std::hex
              << reinterpret_cast<uintptr_t>(&value)
              << std::dec << "\n\n";

    // Bucle de estado
    while (true)
    {
        std::cout << "Valor actual de 'value': " << value << "\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    return 0;
}
