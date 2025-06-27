// Notify.cpp
// Callbacks de notificación: creación de procesos e imágenes

#include <ntddk.h>
#include "../include/adriver.h"

//-----------------------------------------------------------------------------
// ProcessNotifyCallback
// Llamado en creación y terminación de procesos.
//-----------------------------------------------------------------------------

_Use_decl_annotations_
    VOID NTAPI
    ProcessNotifyCallback(
        PEPROCESS ParentProcess,
        PEPROCESS Process,
        PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(ParentProcess);

    // Si CreateInfo != nullptr, es creación de proceso; si es nullptr, es terminación
    if (CreateInfo)
    {
        // Obtener nombre de imagen del proceso que se va a crear
        if (CreateInfo->ImageFileName)
        {
            PUNICODE_STRING imageName = CreateInfo->ImageFileName;

            // Verificar firma/heurística
            if (!Analyzer_VerifySignature(imageName))
            {
                // Log de detección
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_ERROR_LEVEL,
                           "Notify: Proceso no confiable detectado: %wZ (PID %llu). Bloqueando creación.\n",
                           imageName,
                           (ULONG_PTR)PsGetProcessId(Process));

                // Cancelar la creación del proceso
                CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;
            }
        }
    }
    // Para terminación de proceso (CreateInfo == nullptr), no hacemos nada
}

//-----------------------------------------------------------------------------
// ImageLoadCallback
// Llamado cuando un módulo (exe/DLL) se carga en un proceso.
//-----------------------------------------------------------------------------

_Use_decl_annotations_
    VOID NTAPI
    ImageLoadCallback(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(ImageInfo);

    if (FullImageName && FullImageName->Buffer)
    {
        // Verificar firma/heurística de la imagen cargada
        if (!Analyzer_VerifySignature(FullImageName))
        {
            // Log de detección
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_ERROR_LEVEL,
                       "Notify: Módulo no confiable cargado en PID %llu: %wZ. Terminando proceso.\n",
                       (ULONG_PTR)ProcessId,
                       FullImageName);

            // Forzar terminación del proceso que cargó la imagen sospechosa
            KillProcess(ProcessId);
        }
    }
}
