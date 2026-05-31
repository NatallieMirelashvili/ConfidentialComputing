# Confidential IoT Device Management — Research Proposal

**Course project proposal**
**Team:** 4 students (M.Sc.)
**Timeline:** 8 weeks

---

## 1. Problem

IoT cameras are managed through cloud servers that the device owner does not fully control. Today, this means the company running the server can read every piece of footage and metadata the cameras send, and can push software updates to devices without any verification on the device side.

This creates two distinct problems:

- **The server reads everything.** Footage, motion alerts, camera-offline events — all arrive at the server in plain readable form.
- **The device trusts the server blindly.** A compromised or malicious server can push tampered software to every camera in the fleet.

Neither problem is solved by standard encryption, because the server decrypts data the moment it arrives.

---

## 2. Goal

Build a system where a cloud server manages a fleet of IoT cameras — but cannot read the data those cameras produce, and cannot silently tamper with their software.

We use a **hardware-isolated execution environment inside the chip** (ARM TrustZone, emulated via QEMU + OP-TEE) to enforce these guarantees at the hardware level, independently of the operating system running on the device.

---

## 3. System Overview

The system has three parts:

| Part | What it is | Role |
|---|---|---|
| Simulated camera | A process on a PC running QEMU (ARM emulation) | Produces footage and telemetry; enforces security locally |
| Cloud server | Azure IoT Hub | Manages device fleet, routes messages, delivers updates — but sees only scrambled data |
| Operator client | The legitimate viewer's machine | Holds the only key that can unlock the data; verifies camera authenticity |

### What runs inside the chip's locked area

The camera chip contains a hardware-isolated region the operating system cannot access, even with administrator privileges. Four components run there:

1. **Camera's secret key** — proves this specific camera is genuine; signs every outgoing message
2. **Data scrambler** — locks footage and telemetry before they touch the operating system or network
3. **Software update checker** — computes a fingerprint of any incoming update and refuses to install it if the fingerprint does not match the operator's signed authorisation
4. **Proof generator** — produces a signed certificate stating which code is running inside the locked area, so the operator can verify the camera before trusting it

### What the cloud server receives

The server receives only:
- Scrambled (encrypted) telemetry and footage
- The camera's signed identity token
- The proof-of-integrity certificate

It cannot decrypt any of this. It stores and routes it onward to the operator.

### What the operator receives

The operator holds a private key that never leaves their machine. They use it to unscramble the data locally. Before accepting any data, their client verifies the camera's proof certificate to confirm the locked area is genuine and unmodified.

---

## 4. Use Cases

### Use Case 1 — Protect data from the device's own operating system

**Scenario:** A camera runs a general-purpose Linux OS. The OS could be compromised by malware, a rogue process, or a local attacker with physical access.

**What we protect against:** Any process on the device — including root — reading footage or telemetry in plain form before it is sent.

**How:** The footage and motion events are scrambled inside the chip's locked area before they are handed to the OS's network stack. The OS moves ciphertext it cannot read.

**What we demonstrate:** A root-level process scanning the device's memory finds only scrambled bytes. The operator, using their private key on their own machine, decrypts the same data correctly.

---

### Use Case 2 — Protect data all the way through the server (server-side SGX)

**Scenario:** The cloud server itself is untrusted — either the cloud provider is curious, or the server has been breached.

**What we protect against:** The server reading, modifying, or leaking footage while processing it.

**How:** The server-side processing (e.g. motion analytics, storage indexing) runs inside an Intel SGX enclave on the server machine. Data is decrypted only inside this enclave, processed, and re-encrypted before being written to disk or forwarded. Even someone with full server admin access sees only ciphertext in memory and on disk.

**What we demonstrate:** An end-to-end confidential pipeline — the data is protected inside the device chip, protected in transit, and protected inside the server chip. The cloud provider at no point holds plaintext.

**Note:** This use case requires SGX-capable server hardware (Intel 8th/9th gen or newer), which the team has available.

---

### Use Case 3 — Reject a tampered software update

**Scenario:** The server is compromised, and an attacker pushes a modified firmware image to the camera fleet — for example, to disable recording or to exfiltrate footage to a third party.

**What we protect against:** The camera silently accepting and running malicious software delivered by the server.

**How:** The operator signs every legitimate firmware image with their private key. The software update checker inside the camera's locked area verifies this signature before applying any update. The server delivers the update package but cannot modify it without invalidating the signature.

**What we demonstrate:** A legitimately signed update is accepted and applied. A byte-modified version of the same update is rejected by the checker, and the camera sends an alert to the server log.

---

### Use Case 4 — Detect a fake camera connecting to the fleet

**Scenario:** An attacker builds a software process that pretends to be a registered camera — to inject false footage, fake motion alerts, or gain access to operator commands.

**What we protect against:** Impersonation of a genuine device.

**How:** Each real camera generates its identity key inside the locked area at first boot; the key is never extractable. Every message the camera sends is signed with this key. The operator's client verifies both the signature and the proof certificate before accepting any message as genuine.

**What we demonstrate:** A genuine camera connects and communicates normally. A simulated fake process — even one with the correct device ID — fails authentication because it cannot produce a valid signature from the locked area.

---

## 5. Technical Approach

| Component | Technology |
|---|---|
| Device emulation | QEMU (ARM Cortex-A) |
| Secure execution environment | OP-TEE (open-source TrustZone OS) |
| Trusted applications | C, GlobalPlatform TEE API |
| Cloud backend | Azure IoT Hub (free tier) |
| Server-side confidential compute (Use Case 2) | Intel SGX (8th/9th gen hardware available) |
| Device–cloud communication | MQTT over TLS, X.509 device certificates |
| Operator client | Python or Node.js command-line tool |

---

## 6. What We Will Deliver

1. **Working demo** — QEMU-emulated camera connecting to Azure IoT Hub, with all four locked-area components running under OP-TEE
2. **Three live experiments** demonstrating the security guarantees (fake camera rejection, plaintext inaccessibility, tampered update rejection)
3. **Optional extension** — server-side SGX enclave for Use Case 2, if time permits
4. **Written report** covering the threat model, system design, experimental results, and analysis of what TrustZone protects against vs what remains out of scope (e.g. inference attacks, physical chip decapping)

---

## 7. What Is Out of Scope

- **Statistical inference attacks** — an operator with many queries could potentially reconstruct sensitive patterns even from encrypted results. This is a known open problem (addressed by differential privacy) and is explicitly out of scope.
- **Physical hardware attacks** — chip decapping, cold-boot attacks, and side-channel attacks on TrustZone are documented research areas. We assume physical access is prevented.
- **Real camera hardware** — all devices are simulated processes on PC hardware running QEMU.
- **Production-grade key management** — key provisioning is handled with a simplified setup flow sufficient to demonstrate the security model.

---

## 8. Work Division

| Person | Owns |
|---|---|
| 1 | QEMU build environment, OP-TEE boot, first "Hello World" trusted application running |
| 2 | The four trusted applications (identity key, data scrambler, update checker, proof generator) |
| 3 | Azure IoT Hub integration — device registration, MQTT connection, Device Twin, OTA job delivery |
| 4 | Operator client, integration across all components, demo scripts, attestation verification |

Person 1's work is the critical path. Nothing else can be tested on real emulation until QEMU + OP-TEE boots successfully. Persons 2 and 3 can develop in parallel using OP-TEE simulation mode and a mock camera process respectively until that milestone is reached.

---

*Proposal prepared for advisor review.*

---

## 9. Implementation Steps

### Global setup (prerequisite for all use cases)

These steps must be completed before any use case can be implemented or tested.

**Step 1 — Build the QEMU + OP-TEE environment**
- Clone the OP-TEE project manifest repository (`optee_os`, `optee_client`, `optee_examples`, ARM Trusted Firmware, U-Boot, Linux kernel) using Google's `repo` tool
- Install the ARM cross-compilation toolchain (`aarch64-linux-gnu-gcc` and `arm-linux-gnueabihf-gcc`)
- Run `make toolchains` then `make PLATFORM=vexpress-qemu_virt` (or the equivalent target for your manifest version)
- Boot QEMU and verify OP-TEE is running: `optee_example_hello_world` should print a response from the Secure World
- **Milestone:** Normal World (Linux) and Secure World (OP-TEE) are both running inside QEMU and can communicate

**Step 2 — Understand the Trusted Application structure**
- A Trusted Application (TA) has two parts: a Secure World binary (`.ta` file, compiled for ARM, loaded by OP-TEE) and a Normal World client library (compiled for Linux, calls into the TA via the GlobalPlatform TEE API)
- Each TA is identified by a UUID; the client uses this UUID to open a session
- Key API calls: `TEEC_OpenSession`, `TEEC_InvokeCommand`, `TEEC_CloseSession`
- Study `optee_examples/hello_world` as the template — every TA you write follows the same structure

**Step 3 — Generate the operator keypair**
- On the operator's machine (not inside QEMU), generate an RSA or ECC keypair: `openssl ecparam -name prime256v1 -genkey -noout -out operator_private.pem` and `openssl ec -in operator_private.pem -pubout -out operator_public.pem`
- This public key will be provisioned into the TAs at setup time
- The private key never leaves the operator's machine

**Step 4 — Create an Azure IoT Hub instance**
- Create a free-tier Azure IoT Hub in the Azure portal (F1 tier: 8,000 messages/day, sufficient for a demo)
- Generate an X.509 certificate for each simulated camera device: `openssl req -new -x509 -key device_key.pem -out device_cert.pem`
- Register each device in the IoT Hub using the certificate thumbprint
- Install the Azure IoT Device SDK for C or Python inside the QEMU Linux environment
- **Milestone:** A plain Linux process (no OP-TEE yet) connects to IoT Hub via MQTT and sends a test message

---

### Use Case 1 — Protect data from the device's own operating system

**Goal:** Footage and telemetry are encrypted inside the TrustZone Secure World before the Linux OS ever sees them.

**Step 1 — Write the Telemetry TA (Secure World)**
- Create a new TA project based on the `hello_world` template
- Implement a `ENCRYPT_TELEMETRY` command: accepts a plaintext telemetry struct as input, encrypts it using the operator's public key (provisioned at setup), returns ciphertext as output
- Use OP-TEE's built-in cryptographic API (`TEE_AllocateOperation`, `TEE_AsymmetricEncrypt`) — no external crypto library needed
- For bulk data (footage), implement hybrid encryption: generate a random AES-256 key inside the TA, encrypt the payload with AES-GCM, encrypt the AES key with the operator's RSA/ECC public key, return both

**Step 2 — Write the Normal World client for telemetry**
- In the Linux-side camera application, replace every direct `send()` call with a call to the TA: open a session, pass the plaintext to `ENCRYPT_TELEMETRY`, receive ciphertext, close session
- The Linux process only ever holds ciphertext after this point

**Step 3 — Send encrypted telemetry to Azure IoT Hub**
- Pass the ciphertext blob to the MQTT client as the message payload
- Azure IoT Hub receives and stores it without being able to read it

**Step 4 — Operator decrypts locally**
- Write a small operator client script (Python) that receives the message from IoT Hub, decrypts the AES key using `operator_private.pem`, then decrypts the payload with the recovered AES key

**Step 5 — Demonstrate the guarantee**
- While the camera process is running, attach `gdb` or scan `/proc/[pid]/mem` from a root shell inside QEMU Linux for the plaintext telemetry string
- Show it cannot be found in any readable form outside the Secure World
- Show the operator client successfully reads the same data

---

### Use Case 2 — Protect data all the way through the server (server-side SGX)

**Goal:** Even after the encrypted data reaches the Azure-connected server, it is only ever decrypted inside an SGX enclave. The server machine's OS and admin cannot read it.

**Step 1 — Verify SGX availability on your server machine**
- Check BIOS: SGX must be enabled (look for "Software Guard Extensions" in BIOS security settings)
- Run `cpuid | grep SGX` or check `/dev/sgx_enclave` exists on Linux
- Install the Intel SGX SDK and PSW (Platform Software): follow Intel's guide for your Linux distro

**Step 2 — Write the server-side SGX enclave**
- Create a new SGX project using the SGX SDK template (`sgx_edger8r` generates the trusted/untrusted boundary)
- Implement one enclave function: `decrypt_and_process(encrypted_blob, operator_private_key_inside_enclave) → result`
- The operator's private key is sealed to the enclave at provisioning time using `sgx_seal_data` — it is stored encrypted on disk and only the enclave can unseal it
- Inside the enclave: unseal the private key, decrypt the AES key, decrypt the payload, run any processing (e.g. motion detection on a frame), re-encrypt the result or output a summary

**Step 3 — Provision the operator private key into the SGX enclave**
- This is a one-time setup: the operator connects directly to the enclave, verifies its attestation quote (proving which code is running), then passes their private key over an attested TLS channel
- The enclave seals the key to its own identity — only this exact enclave binary can unseal it later

**Step 4 — Connect the pipeline**
- The server application receives encrypted messages from Azure IoT Hub, passes each blob to the SGX enclave function, receives the processed result, and writes only the result (never the plaintext) to storage or forwards it to the operator

**Step 5 — Demonstrate the guarantee**
- Show the server-side database and log files contain only ciphertext
- Attempt to read enclave memory from a root process on the server (via `/proc/[pid]/mem`) — show it returns garbage
- Show the operator receives correct, processed results

---

### Use Case 3 — Reject a tampered software update

**Goal:** The camera verifies every incoming firmware update was signed by the operator before applying it. A server-modified update is detected and refused.

**Step 1 — Operator signs a firmware image**
- Create a mock firmware binary (any file will do for demo purposes)
- Sign it: `openssl dgst -sha256 -sign operator_private.pem -out firmware_v2.sig firmware_v2.bin`
- Distribute `firmware_v2.bin` and `firmware_v2.sig` together as the update package

**Step 2 — Upload the update to Azure IoT Hub Jobs**
- Use the Azure portal or CLI to create an IoT Hub Job that delivers the firmware package to target devices
- The job delivers the binary and signature file to the camera's Linux filesystem via a download URL in the Device Twin desired properties

**Step 3 — Write the Firmware Checker TA (Secure World)**
- Implement a `VERIFY_FIRMWARE` command: accepts the firmware binary and signature as input, verifies the signature using the operator's public key (stored inside the TA), returns ACCEPT or REJECT
- Use `TEE_AsymmetricVerify` from OP-TEE's crypto API

**Step 4 — Wire the Normal World update agent**
- When the camera receives a new firmware package, the Linux update agent calls the Firmware Checker TA before doing anything else
- If the TA returns REJECT, the agent discards the package and sends an alert message to IoT Hub
- If the TA returns ACCEPT, the agent applies the update

**Step 5 — Demonstrate the guarantee**
- Push the correctly signed firmware: camera accepts it
- Flip one byte in `firmware_v2.bin` (use a hex editor or `dd`), push the modified version: camera rejects it and the alert appears in the IoT Hub event log
- Show that the reject decision came from inside the Secure World, not from the Linux-side agent (the agent has no access to the operator public key — it only calls the TA and acts on the result)

---

### Use Case 4 — Detect a fake camera connecting to the fleet

**Goal:** A process that pretends to be a registered camera cannot produce a valid signed identity token because it has no access to a Secure World keypair.

**Step 1 — Write the Identity TA (Secure World)**
- Implement two commands:
  - `GENERATE_IDENTITY_KEY`: called once at first boot, generates an ECC keypair inside the Secure World, stores the private key in OP-TEE secure storage (never exported), returns the public key to the Normal World
  - `SIGN_MESSAGE`: accepts an arbitrary message (e.g. a challenge nonce), signs it with the stored private key inside the Secure World, returns the signature
- The private key is generated inside the Secure World and never appears in Normal World memory at any point

**Step 2 — Register the camera's public key with IoT Hub**
- At first boot, the Linux-side camera app calls `GENERATE_IDENTITY_KEY`, receives the public key, and registers it with Azure IoT Hub as the device's identity certificate
- From this point, every message the camera sends includes a signature produced by `SIGN_MESSAGE`

**Step 3 — Implement challenge-response authentication**
- When the operator client connects, it sends a random nonce to the camera
- The camera passes the nonce to `SIGN_MESSAGE` inside the Secure World and returns the signature
- The operator verifies the signature against the registered public key

**Step 4 — Build the fake camera**
- Write a plain Linux process with the same device ID but no access to QEMU's Secure World
- Attempt to connect to IoT Hub and respond to the operator's challenge
- It cannot call `SIGN_MESSAGE` (it has no TA), so it either fails to sign or produces an invalid signature

**Step 5 — Demonstrate the guarantee**
- Real camera: challenge-response succeeds, operator accepts it
- Fake process: challenge-response fails, operator rejects it with a clear error
- Show the fake process cannot extract the private key from the Secure World even with root access to the Linux side

---

### Use Case 5 — Protect sensitive metadata, not just footage

**Goal:** Event metadata (motion detected, camera offline, storage full) is encrypted inside the Secure World so the server stores only ciphertext it cannot read.

**Note:** This use case reuses the Telemetry TA from Use Case 1. The only difference is the data type being encrypted — instead of footage frames, you encrypt small structured event records. If Use Case 1 is implemented, Use Case 5 is mostly a demonstration exercise on top of existing code.

**Step 1 — Define the telemetry event schema**
- Create a simple C struct representing a camera event: `{ event_type, timestamp, camera_id, value }`
- This is the plaintext that must never reach the server in readable form

**Step 2 — Encrypt events in the Telemetry TA**
- Reuse the `ENCRYPT_TELEMETRY` TA command from Use Case 1
- Pass the serialised event struct as input; receive encrypted blob as output
- Send the blob to IoT Hub as the message payload

**Step 3 — Show the server-side database**
- Query the IoT Hub message storage (or a connected Azure Storage account)
- Show that all stored records are opaque blobs with no readable field values

**Step 4 — Operator decrypts and displays**
- The operator client receives the blob, decrypts it using their private key, deserialises the struct, and prints the event in human-readable form

**Step 5 — Demonstrate the guarantee**
- Side by side: the raw Azure Storage record (unreadable blob) vs the operator's terminal (plain event log)
- This is a strong visual demo — the contrast makes the guarantee immediately obvious to an audience

---

*Implementation steps appended for advisor review.*
