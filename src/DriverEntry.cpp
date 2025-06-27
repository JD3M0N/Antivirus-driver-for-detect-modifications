// DriverEntry.cpp
// Punto de entrada y salida del driver antivirus

#include <ntddk.h>
#include "../include/adriver.h"

// Globals definidos en avdriver.h
PDRIVER_OBJECT g_DriverObject = nullptr;
PUNICODE_STRING g_RegistryPath = nullptr;
PVOID g_ObjectCallbackCookie = nullptr;

// Nombre del dispositivo y enlace simbólico
static const UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\MyAVDriver");
static const UNICODE_STRING SYMLINK_NAME = RTL_CONSTANT_STRING(L"\\DosDevices\\MyAVDriver");

// Prototipo de función de descarga
VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject);

extern "C" NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = nullptr;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "MyAVDriver: DriverEntry iniciando\n");

    // Guardar globals
    g_DriverObject = DriverObject;
    g_RegistryPath = RegistryPath;

    // Registrar rutina de unload
    DriverObject->DriverUnload = DriverUnload;

    // Crear objeto de dispositivo
    status = IoCreateDevice(
        DriverObject,
        0, // sin área de dispositivo privada
        const_cast<PUNICODE_STRING>(&DEVICE_NAME),
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE, // no exclusivo
        &deviceObject);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: IoCreateDevice falló 0x%X\n", status);
        return status;
    }

    // Crear enlace simbólico para espacio usuario
    status = IoCreateSymbolicLink(
        const_cast<PUNICODE_STRING>(&SYMLINK_NAME),
        const_cast<PUNICODE_STRING>(&DEVICE_NAME));
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: IoCreateSymbolicLink falló 0x%X\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Inicializar módulo de análisis
    status = Analyzer_Initialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: Analyzer_Initialize falló 0x%X\n", status);
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&SYMLINK_NAME));
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Inicializar módulo de bloqueo (registra Ob callbacks)
    status = Blocker_Initialize();
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: Blocker_Initialize falló 0x%X\n", status);
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&SYMLINK_NAME));
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Registrar notificación de creación/terminación de procesos
    status = PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, FALSE);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: PsSetCreateProcessNotifyRoutineEx falló 0x%X\n", status);
        Blocker_Uninitialize();
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&SYMLINK_NAME));
        IoDeleteDevice(deviceObject);
        return status;
    }

    // Registrar notificación de carga de imágenes
    status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "MyAVDriver: PsSetLoadImageNotifyRoutine falló 0x%X\n", status);
        PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
        Blocker_Uninitialize();
        IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&SYMLINK_NAME));
        IoDeleteDevice(deviceObject);
        return status;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "MyAVDriver: DriverEntry completado con éxito\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
    VOID
    DriverUnload(
        PDRIVER_OBJECT DriverObject)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "MyAVDriver: DriverUnload iniciado\n");

    // Quitar notificaciones de proceso e imagen
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyCallback, TRUE);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);

    // Desregistrar callbacks de objetos
    Blocker_Uninitialize();

    // Eliminar enlace simbólico y objeto de dispositivo
    IoDeleteSymbolicLink(const_cast<PUNICODE_STRING>(&SYMLINK_NAME));
    if (DriverObject->DeviceObject)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "MyAVDriver: DriverUnload completado\n");
}
