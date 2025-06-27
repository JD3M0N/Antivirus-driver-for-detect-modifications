// ObjectFilter.cpp
// Módulo de filtrado de objetos: regsitro de callbacks para revocar handles de inyección

#include <ntddk.h>
#include "../include/adriver.h"

// Altitude para el filtro de objetos (debe ser único y mayor que cero)
static UNICODE_STRING g_Altitude = RTL_CONSTANT_STRING(L"\\BaseNamedObjects\\AVFilter");

// Cookie devuelta por ObRegisterCallbacks
PVOID g_ObjectCallbackCookie = nullptr;

//-----------------------------------------------------------------------------
// Pre-op callback: intercepta la creación y duplicado de handles sobre procesos
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    OB_PREOP_CALLBACK_STATUS
    PreOpHandleCallback(
        PVOID RegistrationContext,
        POB_PRE_OPERATION_INFORMATION OperationInformation)
{
    UNREFERENCED_PARAMETER(RegistrationContext);

    // Solo interesa filtrar handles a objetos de tipo proceso
    if (OperationInformation->ObjectType == *PsProcessType)
    {
        auto &info = OperationInformation->Parameters->CreateHandleInformation;

        // Si el solicitante pide permisos de inyección (hilos remotos o escritura de memoria)
        if (info.DesiredAccess & (PROCESS_CREATE_THREAD | PROCESS_VM_WRITE))
        {
            // Revocar todos los permisos solicitados
            info.DesiredAccess = 0;
            // Indicar fallo en la creación del handle
            return OB_PREOP_HANDLE_CREATE_FAILED;
        }
    }

    return OB_PREOP_SUCCESS;
}

//-----------------------------------------------------------------------------
// RegisterObjectCallbacks:
//   Registra el callback PreOpHandleCallback para creación/duplicado de handles
//-----------------------------------------------------------------------------
_Use_decl_annotations_
    NTSTATUS
    RegisterObjectCallbacks()
{
    OB_OPERATION_REGISTRATION operations = {0};
    operations.ObjectType = PsProcessType;
    operations.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    operations.PreOperation = PreOpHandleCallback;
    operations.PostOperation = nullptr;

    OB_CALLBACK_REGISTRATION registration = {0};
    registration.Version = OB_FLT_REGISTRATION_VERSION;
    registration.OperationRegistration = &operations;
    registration.OperationRegistrationCount = 1;
    registration.Altitude = g_Altitude;

    NTSTATUS status = ObRegisterCallbacks(&registration, &g_ObjectCallbackCookie);
    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                   "ObjectFilter: ObRegisterCallbacks falló 0x%X\n", status);
    }
    else
    {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "ObjectFilter: ObRegisterCallbacks OK\n");
    }
    return status;
}

//-----------------------------------------------------------------------------
// UnregisterObjectCallbacks:
//   Desregistra el filtro de objetos usando la cookie guardada
//-----------------------------------------------------------------------------
VOID UnregisterObjectCallbacks()
{
    if (g_ObjectCallbackCookie)
    {
        ObUnRegisterCallbacks(g_ObjectCallbackCookie);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
                   "ObjectFilter: ObUnRegisterCallbacks completado\n");
        g_ObjectCallbackCookie = nullptr;
    }
}
