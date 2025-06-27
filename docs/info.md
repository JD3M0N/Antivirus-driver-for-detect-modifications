
## 1. Headers

```cpp
#include <windows.h>
#include <iostream>
#include <sstream>
```
- **`<windows.h>`**  
  Proporciona la **API de Win32**: declaraciones de funciones (p.ej. `OpenProcess`, `WriteProcessMemory`), tipos (`HANDLE`, `DWORD`, `LPVOID`), constantes (`PROCESS_VM_WRITE`, `PAGE_EXECUTE_READWRITE`, …) y macros necesarias para programar en Windows .  
- **`<iostream>`**  
  Librería estándar de C++ para entrada/salida en consola: `std::cout`, `std::cerr`.  
- **`<sstream>`**  
  Permite usar flujos basados en cadenas (`std::istringstream`) para convertir cadenas (`argv[...]`) a tipos numéricos de forma segura.

---

## 2. Inputs

```cpp
int main(int argc, char *argv[])
```
- **`main`**: main  
- **`argc`** (`argument count`): la cantidad de argumentos a recibir 
- **`argv`** (`argument vector`): arreglo de punteros a C-strings (`char*`), donde:
  - `argv[0]` ruta o nombre del programa.
  - `argv[1]`…`argv[argc-1]`  PID, dirección y valor.

---

## 3. Check de argumentos

```cpp
if (argc != 4)
{
    std::cout << "Uso: Injector <PID> <DirecciónHex> <NuevoValor>\n"
                 "Ejemplo: Injector 1234 0x7FF6ABCDE123 42\n";
    return 1;
}
```
- Verifica que se hayan pasado exactamente 3 parámetros adicionales al programa (`argc == 4`).  
- Si no, imprime el formato correcto de uso y sale con `return 1;` 

---

## 4. Parseo

```cpp
DWORD pid;
std::istringstream(argv[1]) >> pid;

LPVOID addr = reinterpret_cast<LPVOID>( std::stoull(argv[2], nullptr, 0) );

int newValue;
std::istringstream(argv[3]) >> newValue;
```
1. **PID**:  
   - Se declara `DWORD pid;` (`DWORD` es un entero de 32 bits sin signo).  
   - `std::istringstream(argv[1]) >> pid;` convierte la cadena `argv[1]` a número decimal y lo guarda en `pid`.  
   - **PID** (_Process Identifier_) es el identificador único que Windows asigna a cada proceso en ejecución.
2. **Dirección de memoria**:  
   - `std::stoull(argv[2], nullptr, 0)` convierte la cadena (por ejemplo `"0x7FFA1234"`) a un entero de 64 bits (`unsigned long long`), detectando el prefijo `0x` para hexadecimal.  
   - `reinterpret_cast<LPVOID>(…)` convierte ese entero en un puntero genérico `LPVOID` (_Long Pointer to VOID_), es decir, la **dirección de memoria** donde vamos a escribir.
3. **Valor a inyectar**:  
   - Se declara `int newValue;` y se parsea con otro `std::istringstream` desde `argv[3]`, esperando un número entero.

---

## 5. Abrir el proceso destino

```cpp
HANDLE hProc = OpenProcess(
    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
    FALSE, pid
);
if (!hProc)
{
    std::cerr << "OpenProcess falló (¿permiso administrador?): " << GetLastError() << "\n";
    return 1;
}
```
- **`OpenProcess`** abre un **handle** (_HANDLE_) al proceso cuyo PID se paso en los argumentos.  
  - **Flags de acceso**:
    - `PROCESS_VM_OPERATION`: permite cambiar protecciones y demás operaciones de VM.
    - `PROCESS_VM_WRITE`: permite escribir en la memoria del proceso.
    - `PROCESS_VM_READ`: permite leer de esa memoria.  
  - El segundo parámetro (`FALSE`) indica que el handle **no** se hereda a procesos hijos.  
- Si `OpenProcess` devuelve `NULL`, significa **error**:
  - `GetLastError()` recupera el **código de error** de la última llamada Win32 fallida.
  - Se imprime en `std::cerr` y se sale con código `1`.

---

## 6. Cambiar la protección de memoria

```cpp
DWORD oldProt;
if (!VirtualProtectEx(hProc, addr, sizeof(newValue),
                      PAGE_EXECUTE_READWRITE, &oldProt))
{
    std::cerr << "VirtualProtectEx falló: " << GetLastError() << "\n";
    CloseHandle(hProc);
    return 1;
}
```
- **`VirtualProtectEx`** modifica la **protección** (lectura/escritura/ejecución) de una región de memoria en **otro proceso**:
  - `hProc`: handle al proceso destino.
  - `addr`: dirección base.
  - `sizeof(newValue)`: tamaño en bytes (4 bytes para un `int`).
  - `PAGE_EXECUTE_READWRITE`: nueva protección, permite lectura, escritura y ejecución.
  - `&oldProt`: almacena la protección **anterior** para restaurarla después.  
- Si falla, imprime el error, cierra el handle (`CloseHandle`) y sale.

---

## 7. Escribir el nuevo valor

```cpp
SIZE_T bytesWritten = 0;
if (!WriteProcessMemory(hProc, addr, &newValue,
                        sizeof(newValue), &bytesWritten))
{
    std::cerr << "WriteProcessMemory falló: " << GetLastError() << "\n";
    VirtualProtectEx(hProc, addr, sizeof(newValue), oldProt, &oldProt);
    CloseHandle(hProc);
    return 1;
}
std::cout << "Escritos " << bytesWritten << " bytes en PID " << pid
          << " @ " << addr << "\n";
```
- **`WriteProcessMemory`**:
  - `hProc`: handle al proceso.
  - `addr`: dirección de destino.
  - `&newValue`: puntero al buffer en tu proceso (kernel tiene su propia vista de memoria).
  - `sizeof(newValue)`: cuántos bytes copiar.
  - `&bytesWritten`: recibe cuántos bytes realmente se escribieron.  
- Si falla, restaura la protección original con otra llamada a `VirtualProtectEx`, cierra el handle y sale.  
- Si tiene éxito, imprime cuántos bytes escribió, en qué PID y en qué dirección.

---

## 8. Restaurar protección original

```cpp
VirtualProtectEx(hProc, addr, sizeof(newValue), oldProt, &oldProt);
```
- Vuelve a dejar la memoria tal como estaba (la protección anterior), evitando dejar regiones inseguras.

---

## 9. Leer para verificar (opcional)

```cpp
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
```
- **`ReadProcessMemory`** lee desde `addr` en el proceso destino al buffer `&readBack` en tu propio espacio.  
- Así confirmas que efectivamente se escribió el valor correcto (`1337` en tu prueba).

---

## 10. Cierre de recursos y salida

```cpp
CloseHandle(hProc);
return 0;
```
- **`CloseHandle`** libera el handle al proceso.  
- `return 0;` indica **éxito** al sistema operativo.

---

### Conceptos clave

- **PID (Process Identifier)**: número único que Windows asigna a cada proceso en ejecución. Permite referirse al proceso en llamadas como `OpenProcess`.  
- **HANDLE**: tipo genérico (un puntero o descriptor) que representa recursos del sistema (procesos, archivos, hilos…).  
- **LPVOID**: puntero a memoria genérica (`void*`), usado cuando no queremos especificar tipo.  
- **DWORD**: entero sin signo de 32 bits (`unsigned long`).  
- **SIZE_T**: entero sin signo con el tamaño suficiente para representar una cantidad de bytes en memoria (en x64, 64 bits).  
- **GetLastError()**: devuelve el **código de error** de la última llamada Win32 que falló, para diagnóstico.  
- **VirtualProtectEx**: cambia permisos de una región de memoria (lectura/escritura/ejecución).  
- **Write/ReadProcessMemory**: funciones que permiten, respectivamente, escribir y leer memoria de **otro** proceso (si tienes permisos adecuados).  
- **CloseHandle**: libera recursos del sistema asociados a un handle.
- **VM**: es la abreviatura de Virtual Memory (Memoria Virtual). Es un mecanismo que usan los sistemas operativos modernos para dar a cada proceso la ilusión de contar con un bloque contiguo y privado de memoria, aunque en realidad:

