# Chrome

## DLL

Dynamic link library. It is loaded when called rather than created.

### Advantage

1. Uses fewer resources
2. Promotes modular architecture
3. Aids easy developtment and instollation

### Dll Files

- **COMDLG32.DLL** − Controls the dialog boxes.
- **GDI32.DLL** − Contains numerous functions for drawing graphics, displaying text, and managing fonts.
- **KERNEL32.DLL** − Contains hundreds of functions for the management of memory and various processes.
- **USER32.DLL** − Contains numerous user interface functions. Involved in the creation of program windows and their interactions with each other.

### Write Dll

```c++
BOOL APIENTRY DllMain(
   HANDLE hModule,	   // Handle to DLL module 
   DWORD ul_reason_for_call, 
   LPVOID lpReserved )     // Reserved
{
   switch ( ul_reason_for_call )
   {
      case DLL_PROCESS_ATTACHED:
      // A process is loading the DLL.
      break;
      
      case DLL_THREAD_ATTACHED:
      // A process is creating a new thread.
      break;
      
      case DLL_THREAD_DETACH:
      // A thread exits normally.
      break;
      
      case DLL_PROCESS_DETACH:
      // A process unloads the DLL.
      break;
   }
   return TRUE;
}
```

