// Blocker.cpp
// Implementación del módulo de bloqueo: registra los filtros de objeto y proporciona utilidades de bloqueo

#include <ntddk.h>
#include "../include/adriver.h"

//-----------------------------------------------------------------------------
// Forward declarations
//-----------------------------------------------------------------------------
VOID KillProcess(
    _In_ HANDLE ProcessId);

//-----------------------------------------------------------------------------
// Blocker_Initialize
// Registra los filtros de objeto (ObRegisterCallbacks).
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    NTSTATUS
    Blocker_Initialize()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "Blocker: inicializando módulo de bloqueo\n");

    // Registrar los callbacks de objeto para filtrar creaciones de handle
    NTSTATUS status = RegisterObjectCallbacks();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "Blocker: fallo RegisterObjectCallbacks 0x%X\n",
                   status);
    }
    return status;
}

//-----------------------------------------------------------------------------
// Blocker_Uninitialize
// Desregistra los filtros de objeto.
//-----------------------------------------------------------------------------
VOID Blocker_Uninitialize()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               "Blocker: desinicializando módulo de bloqueo\n");

    UnregisterObjectCallbacks();
}

//-----------------------------------------------------------------------------
// KillProcess
// Termina un proceso detectado como malicioso.
//-----------------------------------------------------------------------------
VOID KillProcess(
    _In_ HANDLE ProcessId)
{
    PEPROCESS targetProc = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &targetProc);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   "Blocker: PsLookupProcessByProcessId(%llu) falló 0x%X\n",
                   (ULONG_PTR)ProcessId,
                   status);
        return;
    }

    // Forzar la terminación
    status = PsTerminateProcess(targetProc, STATUS_ACCESS_DENIED);
    ObDereferenceObject(targetProc);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               NT_SUCCESS(status) ? DPFLTR_INFO_LEVEL : DPFLTR_ERROR_LEVEL,
               "Blocker: PsTerminateProcess(%llu) -> 0x%X\n",
               (ULONG_PTR)ProcessId,
               status);
}

//-----------------------------------------------------------------------------
// Ejemplo de uso en un callback de detección (p.ej. tras ImageLoadCallback)
//-----------------------------------------------------------------------------
// if (!Analyzer_VerifySignature(&FullImageName)) {
//     ReportSuspiciousImage(ProcessId, &FullImageName);
//     KillProcess(ProcessId);
// }
