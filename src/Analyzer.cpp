// Analyzer.cpp
// Implementación del módulo de análisis de firmas y heurísticas

#include <ntddk.h>
#include "../include/adriver.h"

#define SYSTEM32_PATH L"\\Windows\\System32\\"

//-----------------------------------------------------------------------------
// Prototipos internos
//-----------------------------------------------------------------------------
static BOOLEAN
IsTrustedPath(
    _In_ PUNICODE_STRING ImagePath);

static VOID
ReportSuspiciousImage(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ImagePath);

//-----------------------------------------------------------------------------
// Inicialización del módulo de análisis
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    NTSTATUS
    Analyzer_Initialize()
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "Analyzer: inicializando módulo de análisis\n");
    // Aquí podrías cargar una lista de hashes o certificados de confianza
    return STATUS_SUCCESS;
}

//-----------------------------------------------------------------------------
// Comprueba si la ruta de la imagen está en un directorio de sistema conocido
//-----------------------------------------------------------------------------
static BOOLEAN
IsTrustedPath(
    _In_ PUNICODE_STRING ImagePath)
{
    if (ImagePath->Length == 0 || ImagePath->Buffer == nullptr)
    {
        return FALSE;
    }

    // Todo binario en System32 se considera 'trusted' por defecto
    if (wcsstr(ImagePath->Buffer, SYSTEM32_PATH) != nullptr)
    {
        return TRUE;
    }

    // Agregar aquí más rutas permitidas si es necesario
    return FALSE;
}

//-----------------------------------------------------------------------------
// Verificación de firma digital (placeholder / heurística básica)
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    BOOLEAN
    Analyzer_VerifySignature(
        PUNICODE_STRING ImagePath)
{
    // Placeholder: delegar sólo a comprobación de ruta
    // Para firma real, habría que parsear el PE y validar el Certificado
    return IsTrustedPath(ImagePath);
}

//-----------------------------------------------------------------------------
// Reporta una imagen sospechosa y notifica (por DbgPrint o espacio usuario)
//-----------------------------------------------------------------------------
static VOID
ReportSuspiciousImage(
    _In_ HANDLE ProcessId,
    _In_ PUNICODE_STRING ImagePath)
{
    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_ERROR_LEVEL,
               "Analyzer: imagen sospechosa cargada en PID %llu -> %wZ\n",
               (ULONG_PTR)ProcessId,
               ImagePath);

    // TODO: enviar evento a espacio usuario vía IOCTL o ALPC si lo deseas
}

//-----------------------------------------------------------------------------
// Punto de entrada de análisis invocado desde ImageLoadCallback
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    VOID
    Analyzer_OnImageLoad(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId)
{
    if (FullImageName == nullptr || FullImageName->Buffer == nullptr)
    {
        return;
    }

    if (!Analyzer_VerifySignature(FullImageName))
    {
        // Reportar y bloquear
        ReportSuspiciousImage(ProcessId, FullImageName);

        PEPROCESS proc = nullptr;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &proc)))
        {
            // Terminar proceso para evitar ejecución de código no autorizado
            PsTerminateProcess(proc, STATUS_ACCESS_DENIED);
            ObDereferenceObject(proc);
        }
    }
}
