# Antivirus-driver-for-detect-modifications

---

### 1. Requisitos

#### 1.1 Requisitos funcionales

* **Monitoreo en tiempo real** de:

  * Creación y terminación de procesos.
  * Carga de imágenes (DLLs, .exe).
  * Apertura de handles con permisos de inyección o escritura en memoria.
* **Análisis de comportamiento**:

  * Identificar patrones de inyección (WriteProcessMemory + CreateRemoteThread).
  * Validar firmas de módulos cargados.
* **Bloqueo automático** de:

  * Cualquier intento de inyección de código o DLL.
  * Apertura de handles con acceso `PROCESS_CREATE_THREAD` o `PROCESS_VM_WRITE`.
* **Comunicación con espacio usuario** para logs y configuración.

#### 1.2 Requisitos no funcionales

* **Estabilidad**: no causar BSOD; manejar fallos internamente.
* **Desempeño**: latencia mínima en callbacks (< 100 µs).
* **Seguridad**: evitar vulnerabilidades tipo TOCTOU.
* **Mantenibilidad**: código modular, bien documentado.
* **Portabilidad**: soportar Windows 10 y posteriores (x64).

---

### 2. Arquitectura de alto nivel

```
┌───────────────────────────┐
│       Espacio Usuario     │
│ – ShellcodeInjection.cpp  │
│ – targetProc.exe          │
│      │
└────────────┬──────────────┘
             │ IOCTL / ALPC
             ▼
┌───────────────────────────┐
│   Driver Antivirus KM     │
│ ┌───────────────────────┐ │
│ │ NotifyModule          │ │
│ │ – PsSetCreateProcess… │ │
│ │ – PsSetLoadImage…     │ │
│ └───────────────────────┘ │
│ ┌───────────────────────┐ │
│ │ ObjectFilterModule    │ │
│ │ – ObRegisterCallbacks │ │
│ └───────────────────────┘ │
│ ┌───────────────────────┐ │
│ │ AnalyzerModule        │ │
│ │ – Validación firmas   │ │
│ └───────────────────────┘ │
│ ┌───────────────────────┐ │
│ │ BlockerModule         │ │
│ │ – OB_PREOP…           │ │
│ └───────────────────────┘ │
└───────────────────────────┘
             │
             ▼
┌───────────────────────────┐
│      APIs Kernel (NT)     │
└───────────────────────────┘
```

---

### 3. Estructura de carpetas

```
MyAVDriver/
├─ include/                  # headers públicos
│  └─ avdriver.h
├─ src/                      
│  ├─ DriverEntry.cpp        # punto de entrada + DriverUnload
│  ├─ Notify.cpp             # callbacks de proceso e imagen
│  ├─ ObjectFilter.cpp       # ObRegisterCallbacks
│  ├─ Analyzer.cpp           # firma y heurísticas
│  └─ Blocker.cpp            # lógica de bloqueo
├─ build/                    # salida de compilación (.obj, .sys)
├─ MyAVDriver.inf            # INF de instalación
├─ MyAVDriver.cat            # Catálogo de firma
├─ tasks.json                # tareas de VS Code
├─ c_cpp_properties.json     # includePath y defines
└─ README.md
```

---

## 4. ¿Qué hace cada módulo?

1. **DriverEntry & DriverUnload**

   * Punto de entrada del driver.
   * Crea el dispositivo, el enlace simbólico (`\DosDevices\MyAVDriver`), y registra los callbacks de proceso e imágen.

2. **Notify.cpp**

   * **ProcessNotifyCallback**: intercepta cada creación de proceso. Si `Analyzer_VerifySignature` falla, cancela la creación estableciendo `CreateInfo->CreationStatus = STATUS_ACCESS_DENIED`.
   * **ImageLoadCallback**: intercepta cargas de DLL/EXE. Si la ruta no es de sistema o la firma falla, llama a `KillProcess()`.

3. **ObjectFilter.cpp**

   * Usa **ObRegisterCallbacks** para filtrar cualquier intento de abrir un handle con permisos de escritura en memoria o creación de hilos remotos en otro proceso: revoca esos permisos en pre-op, haciendo que `CreateRemoteThread` (u otras operaciones) fallen.

4. **Analyzer.cpp**

   * Módulo de “heurísticas” y firma: aquí, de forma simplificada, cualquier binario **fuera de** `\Windows\System32\` se considera sospechoso.
   * En producción deberías extraer y validar el certificado digital del PE, comprobar hashes contra una base de datos, o emplear un HSM.

5. **Blocker.cpp**

   * Funciones de apoyo para terminar procesos maliciosos (`PsTerminateProcess`) tras una detección.
   * Inicializa y desinicializa el filtrado de objetos.

---

## 5. Paso a paso de implementación

1. **Copiar los ficheros**

   * Crea `include/avdriver.h` con el contenido ya visto.
   * En `src/`, pega cada uno de: `DriverEntry.cpp`, `Notify.cpp`, `ObjectFilter.cpp`, `Analyzer.cpp`, `Blocker.cpp`.

2. **Ajustar nombres**

   * En `avdriver.h`, cambia `MyAVDriver` y constantes por el nombre de tu proyecto si lo deseas.
   * Asegúrate de que `DEVICE_NAME` y `SYMLINK_NAME` coinciden con tu INF.

3. **Proyecto MSBuild**

   * Crea un `.vcxproj` con plantilla de “Kernel Mode Driver, Empty (KMDF)” o “WDK Driver”.
   * Añade al `<ClCompile>` los includes de tu carpeta `include`.

4. **Configurar tareas en VS Code**

   * `tasks.json` para compilar:

     ```json
     {
       "label": "Build Driver",
       "type": "shell",
       "command": "msbuild",
       "args": [
         "/t:Build",
         "/p:Configuration=Debug",
         "${workspaceFolder}\\MyAVDriver.vcxproj"
       ]
     }
     ```
   * Ejecuta `Ctrl+Shift+B` para compilar. El `.sys` resultante irá a `build\\Debug\\MyAVDriver.sys`.

---

## 6. Generación del catálogo y firma

1. **Inf**: asegúrate de tener `MyAVDriver.inf` en la raíz, con la sección `[MyAVDriver_CopyFiles]` apuntando a tu `.sys`.
2. **Generar catálogo**

   ```bat
   cd path\to\MyAVDriver
   inf2cat /driver:"." /os:10_X64
   ```

   → crea `MyAVDriver.cat`.
3. **Firma (modo test signing)**

   ```bat
   signtool sign /fd SHA256 /a /f MiCert.pfx MyAVDriver.cat
   bcdedit /set testsigning on
   ```
4. **Instalación**

   ```bat
   pnputil /add-driver MyAVDriver.inf /install
   sc start MyAVDriver
   ```

---

## 7. Pruebas y depuración

1. **WinDbg**

   * Conecta a la máquina objetivo (VM) con kernel debugging.
   * Carga símbolos (`.sympath srv*c:\sym*https://msdl.microsoft.com/download/symbols`).
   * Coloca breakpoints en tus callbacks:

     ```none
     bu avdriver!ProcessNotifyCallback
     bu avdriver!ImageLoadCallback
     ```

2. **Driver Verifier**

   * En la VM: `verifier /standard /driver MyAVDriver.sys`.
   * Reinicia y revisa errores con WinDbg.

3. **Sysinternals**

   * **ProcMon**: filtra por evento de creación de proceso o acceso a WriteProcessMemory.
   * **ProcExp**: observa handles abiertos a procesos y comprueba que `PROCESS_VM_WRITE` ya no está permitido.

4. **Medición de latencia**

   * En tus callbacks usa:

     ```cpp
     LARGE_INTEGER start = KeQueryPerformanceCounter(NULL);
     // … lógica …
     LARGE_INTEGER end = KeQueryPerformanceCounter(NULL);
     DbgPrint("Callback tardó %llu ticks\n", end.QuadPart - start.QuadPart);
     ```
   * Ajusta para que cada callback sea ≤ 100 µs en escenarios normales.

---

## 8. Teoría clave

* **PsSetCreateProcessNotifyRoutineEx**

  * Se invoca **antes** de crear el objeto proceso. Puedes cancelar la creación.
* **PsSetLoadImageNotifyRoutine**

  * Llamado **justo antes** de mapear un PE en memoria (DLL/EXE). Ideal para detección de inyecciones vía DLL hijacking.
* **ObRegisterCallbacks**

  * Intercepta cualquier creación/duplicado de handle a objetos kernel (p. ej. procesos). Si revocas permisos de escritura o creación de hilos, impides técnicas como WriteProcessMemory+CreateRemoteThread.
* **Firmas digitales PE**

  * Un ejecutable o DLL alojará su certificado en la sección de atributos firmados. Validarlo requiere parsear el PE y usar CryptoAPI/BCrypt.
* **BSOD y estabilidad**

  * Nunca llames a paged pool desde IRQL ≥ DISPATCH\_LEVEL. Todas estas notificaciones son a IRQL = DISPATCH\_LEVEL, por lo que tu lógica debe evitar accesos a paged memory o llamadas que puedan bloquear.

---

## 9. Buenas prácticas y siguientes pasos

1. **Entorno aislado**

   * Usa snapshots de tu VM para volver tras cada prueba fallida.
2. **Logging estructurado**

   * Sustituye `DbgPrintEx` por un anillo en memoria circular y exporta logs vía IOCTL a una aplicación en user-mode.
3. **Actualización de heurísticas**

   * Diseña un mecanismo para actualizar desde user-mode tu base de hashes/firma.
4. **Hardening**

   * Protege tu driver contra manipulaciones: firma obligatoria, verifica integridad de tu propio código (PatchGuard).
5. **Documentación**

   * Mantén tu README con diagramas y flujos, y versiona tu INF y certificados.

---