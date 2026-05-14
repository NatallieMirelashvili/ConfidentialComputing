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
source ~/path/to/your/sgxsdk/environment
