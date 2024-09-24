# DLL Injection into a Target Process

This project demonstrates a basic DLL injection into a target process (such as `notepad.exe`) using Python and the Windows API. The script allocates memory in the target process, writes the DLL path to the allocated memory, and creates a remote thread to load the DLL using `LoadLibraryA`. 

**⚠️ Disclaimer: This code is for educational purposes only. Unauthorized use of DLL injection is illegal and unethical. Do not use this project for malicious purposes.**

## Features

- Retrieves the process ID (PID) of a target process (e.g., `notepad.exe`).
- Opens the target process with full access.
- Allocates memory in the target process for storing the DLL path.
- Writes the DLL path into the allocated memory.
- Creates a remote thread in the target process to execute `LoadLibraryA` and load the DLL.
- Uses Windows API functions through the `ctypes` library in Python.

## Prerequisites

- Python 3.x
- Windows OS
- Admin rights to access and manipulate target processes
- A DLL file to inject

## Dependencies

This project uses the `ctypes` library to interact with Windows API functions. The following system functions are used:
- `OpenProcess`
- `VirtualAllocEx`
- `WriteProcessMemory`
- `GetModuleHandleA`
- `GetProcAddress`
- `CreateRemoteThread`

You also need the `get_pid` function from the `GetPid` module to retrieve the PID of the target process.

## How It Works

1. **Retrieve the Process ID (PID)**: The script uses the `get_pid()` function to retrieve the PID of the target process (e.g., `notepad.exe`).
2. **Open the Process**: The script opens the target process with full access using `OpenProcess`.
3. **Allocate Memory in the Target Process**: The script allocates memory in the target process using `VirtualAllocEx` to store the path of the DLL to inject.
4. **Write DLL Path to Memory**: The DLL path is written to the allocated memory using `WriteProcessMemory`.
5. **Load the DLL**: The script gets the address of `LoadLibraryA` in `kernel32.dll` and creates a remote thread in the target process using `CreateRemoteThread` to call `LoadLibraryA` with the DLL path.

## Code Explanation

### Key Components

- **Opening the Target Process**:
    ```python
    handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    ```
    This opens the target process (identified by `pid`) with full access permissions.

- **Memory Allocation in Target Process**:
    ```python
    remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    ```
    This allocates memory in the target process to store the DLL path.

- **Writing the DLL Path**:
    ```python
    write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)
    ```
    Writes the DLL path (`dll`) to the allocated memory in the target process.

- **Creating a Remote Thread**:
    ```python
    rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)
    ```
    Creates a remote thread in the target process that calls `LoadLibraryA` to load the DLL.

## How to Run

1. Clone this repository:
    ```bash
    git clone https://github.com/Seifbes01/remote-dll-injection.git
    ```

2. Ensure you have the `GetPid.py` file in the same directory, with a `get_pid()` function that can retrieve the PID of the target process (e.g., `notepad.exe`).

3. Modify the DLL path (`dll`) in the script to point to your desired DLL:
    ```python
    dll= b"D:\\Path\\To\\Your\\DLL.dll"
    ```

4. Run the script:
    ```bash
    python dll_injection.py
    ```

5. The script will inject the specified DLL into the target process.

