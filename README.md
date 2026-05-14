# ConfidentialComputing
# Intel SGX Development: Core Concepts & Environment Setup

This guide explains the architecture, build process, and workflow for developing Intel SGX applications.

---

## 1. Core Architecture: The Enclave Model

Intel SGX partitions an application into two distinct parts:

### **The Untrusted Part (App)**
- **Role:** The standard application running in the normal OS environment.
- **Responsibility:** Manages the enclave's lifecycle (creation, initialization, and destruction).
- **File:** `App.cpp`.

### **The Trusted Part (Enclave)**
- **Role:** A secure, hardware-encrypted memory region (EPC).
- **Responsibility:** Executes sensitive logic and protects data from the OS, BIOS, and other applications.
- **File:** `Enclave.cpp`.

### **The Interface (EDL)**
- **File:** `Enclave.edl` (Enclave Definition Language).
- **Function:** Acts as the "contract" between the App and the Enclave.
- **ECALL:** Functions defined in the `trusted` block; called by the App to enter the Enclave.
- **OCALL:** Functions defined in the `untrusted` block; called by the Enclave to request services from the App (e.g., printing to screen).



---

## 2. The Build Process

Compiling an SGX application involves several specialized steps to ensure security:

1.  **Edger8r Tool:** Parses the `.edl` file to generate "Proxy" and "Bridge" C code. These files handle the low-level transitions between secure and non-secure modes.
2.  **Compilation:** The `Enclave.cpp` is compiled into a Shared Object (`.so`).
3.  **Signing Tool:** The `.so` file is signed using a private key to produce `enclave.signed.so`. 
    - **Note:** Only the `.signed.so` file can be loaded into a real enclave. The hardware verifies the signature before execution.

---

## 3. Development Workflow

### **Environment Initialization**
In every new terminal session, you must load the SGX SDK environment variables:
```bash
source /home/owner/natallie/confiden_comp/sgxsdk/environment
```

# Intel SGX Iterative Development Workflow

This document outlines the standard process for modifying, building, and testing an Intel SGX application. Follow these steps whenever you add new functionality, such as encryption logic or secure data processing.

---

## The 5-Step Development Cycle

When you need to add a new feature (e.g., Task 4: Adding Encryption), follow this specific sequence:

### 1. Modify the Interface (`Enclave.edl`)
You must first declare your new function so the App can "see" it inside the Enclave. 
- Add your function prototype inside the `trusted { ... };` block.
- **Example:** `public void ecall_encrypt_data([in, size=len] uint8_t* data, size_t len);`

### 2. Implement Logic (`Enclave.cpp`)
Write the actual C/C++ code that will execute inside the secure environment.
- Implement the function you just declared in the `.edl` file.
- Since this is inside the enclave, you can only use trusted libraries (e.g., `sgx_tcrypt` for encryption).

### 3. Update the Host App (`App.cpp`)
Trigger the secure logic from the untrusted world.
- In your `main()` function or a helper function, call the ECALL using the generated proxy header.
- **Note:** Remember to pass the `global_eid` as the first argument to every ECALL.

### 4. Rebuild the Project
Use the `make` command to re-compile both the App and the Enclave, and to re-sign the enclave binary.
```bash
# We use Simulation Mode (SIM) if hardware SGX is not available
make clean
make SGX_MODE=SIM
```
