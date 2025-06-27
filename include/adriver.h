// avdriver.h
// Header principal para el driver antivirus en modo kernel

#ifndef AVDRIVER_H
#define AVDRIVER_H

#include <ntddk.h>

//-----------------------------------------------------------------------------
// Macros y definiciones globales
//-----------------------------------------------------------------------------
#define DRIVER_TAG 'vdrA' // 'Ardv' en little-endian

//-----------------------------------------------------------------------------
// Globals
//-----------------------------------------------------------------------------
extern PDRIVER_OBJECT g_DriverObject;
extern PUNICODE_STRING g_RegistryPath;

// Cookie para ObRegisterCallbacks
extern PVOID g_ObjectCallbackCookie;

//-----------------------------------------------------------------------------
// Funciones de inicialización y descarga
//-----------------------------------------------------------------------------
extern "C" NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);

VOID DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject);

//-----------------------------------------------------------------------------
// Callbacks de notificación
//-----------------------------------------------------------------------------

// PsSetCreateProcessNotifyRoutineEx
VOID NTAPI
ProcessNotifyCallback(
    _Inout_ PEPROCESS ParentProcess,
    _Inout_ PEPROCESS Process,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

// PsSetLoadImageNotifyRoutine
VOID NTAPI
ImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);

// ObRegisterCallbacks — pre-op handle filter
OB_PREOP_CALLBACK_STATUS
PreOpHandleCallback(
    _In_opt_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OpInfo);

// Registra y desregistra callbacks de objetos
NTSTATUS
RegisterObjectCallbacks();

VOID UnregisterObjectCallbacks();

//-----------------------------------------------------------------------------
// Módulo de análisis (Analyzer)
//-----------------------------------------------------------------------------

// Inicializa estructuras (listas de hashes, certificados, etc.)
NTSTATUS
Analyzer_Initialize();

// Verifica heurística y/o firma digital de un binario
BOOLEAN
Analyzer_VerifySignature(
    _In_ PUNICODE_STRING ImagePath);

//-----------------------------------------------------------------------------
// Módulo de bloqueo (Blocker)
//-----------------------------------------------------------------------------

// Inicializa cualquier infraestructura de bloqueo (si procede)
NTSTATUS
Blocker_Initialize();

// Limpia recursos usados por el bloqueador
VOID Blocker_Uninitialize();

//-----------------------------------------------------------------------------
// Utilidades internas
//-----------------------------------------------------------------------------
LARGE_INTEGER
GetTimeStamp();

#endif // AVDRIVER_H
