# Project Secure Chat: Build It, Capture It, Break It

Welcome to the **Secure Chat** project! This guide walks you step-by-step through setting up your environment and running every program in the project from scratch, even if you have never worked with Python networking or cryptography before.

## 1. Prerequisites & Installation

Before running any code, make sure you have the following installed on your computer:

1. **Python 3.10 or newer**
   * Check your version by opening a terminal (Command Prompt / PowerShell on Windows, Terminal on macOS/Linux) and running:

     ```bash
     python --version
     ```

2. **Wireshark** (used to inspect network traffic locally)
   * Download from [wireshark.org](https://www.wireshark.org/).
   * **Windows Users:** During installation, make sure **Npcap** is checked so Wireshark can capture loopback (`127.0.0.1`) traffic.

3. **Python Dependencies (`requirements.txt`)**
   * Navigate to your project folder in the terminal and install the required `cryptography` library:

     ```bash
     pip install -r requirements.txt
     ```

   * *(If `pip` is not recognized, try `python -m pip install -r requirements.txt`.)*

## 2. How to Capture Traffic in Wireshark (Used in All Stages)

All chat programs communicate locally on your own machine using the loopback address `127.0.0.1`.

1. Open **Wireshark**.
2. Double-click your **Loopback** interface on the home screen:
   * **Windows:** `Adapter for loopback traffic capture`
   * **macOS:** `Loopback: lo0`
   * **Linux:** `Loopback: lo`
3. In the top filter bar, type `tcp.port == 5000` (or `tcp.port == 8000` for Stage 0) and press **Enter**.
4. Run your Python scripts (always start the **server** before the **client**).
5. Right-click any data packet in Wireshark and choose **Follow > TCP Stream** to inspect the conversation in **ASCII** or **Hex Dump**.

## 3. Project File Overview

Keep all `.py` files inside the same folder so they can import the shared helper modules:

* **Shared Helpers:**
  * `framing.py` — Packs and unpacks framed TCP messages (`4-byte length` + `payload`).
  * `crypto_helpers.py` — Derives 32-byte AES keys via `PBKDF2-HMAC-SHA256` and encrypts/decrypts using `AES-256-GCM`.
  * `x25519_helpers.py` — Handles X25519 key exchange, HKDF derivation, and Ed25519 digital signatures (Stage 4).
* **Stage 1 (Plaintext):** `server_stage1.py`, `client_stage1.py`
* **Stage 2 (Encrypted):** `server_stage2.py`, `client_stage2.py`
* **Stage 3 (Attacks):** `task_a_ecb.py`, `task_b_nonce_reuse.py`, `task_c_no_tag.py`, `task_d_server.py`, `task_d_send_once.py`, `replay.py`
* **Stage 4 (Bonus):** `server_stage4.py`, `mitm_stage4.py`, `client_stage4.py`

## 4. Step-by-Step Run Instructions

> **Important Rule:** Whenever running a client and server, open **two separate terminals** in your project folder. Always start the **server first**, then run the **client**.

### Stage 0: Warm-Up (Unencrypted HTTP)

1. Start Wireshark on your loopback interface with filter `tcp.port == 8000`.
2. In a terminal, start Python's built-in web server:

   ```bash
   python -m http.server 8000 --bind 127.0.0.1
   ```

3. Open your browser and visit `http://127.0.0.1:8000`.
4. Inspect the `GET` request in Wireshark using **Follow > TCP Stream**.

### Stage 1: Plaintext Chat

1. Start Wireshark on your loopback interface with filter `tcp.port == 5000`.
2. **Terminal 1 (Server):**

   ```bash
   python server_stage1.py
   ```

3. **Terminal 2 (Client):**

   ```bash
   python client_stage1.py
   ```

4. Check Wireshark (**Follow > TCP Stream**) to verify messages are visible in cleartext.

### Stage 2: Encrypted Chat (AES-256-GCM + PBKDF2)

1. Start Wireshark on your loopback interface with filter `tcp.port == 5000`.
2. **Terminal 1 (Server):**

   ```bash
   python server_stage2.py
   ```

   * Press **Enter** to accept the default passphrase (`blue-penguin-42`), or type a test passphrase.

3. **Terminal 2 (Client):**

   ```bash
   python client_stage2.py
   ```

   * Enter the **exact same passphrase** as the server. Messages will encrypt and decrypt cleanly.

4. **Testing a Wrong Passphrase (Q2.7):**
   * Restart `server_stage2.py` with `blue-penguin-42`, then run `client_stage2.py` with a different passphrase (e.g., `wrong-pass`). The server will reject the message (`InvalidTag`) and close the connection safely.

### Stage 3: Breaking Weak Implementations

#### Task A: ECB Mode (Repeating Blocks)

1. Start Wireshark (`tcp.port == 5000`).
2. **Terminal 1:** Run `python task_a_ecb.py` and type `server`.
3. **Terminal 2:** Run `python task_a_ecb.py` and type `client`.
4. Inspect the Hex Dump in Wireshark to spot identical 16-byte ciphertext blocks.

#### Task B: Nonce Reuse (Keystream Recovery)

1. Start Wireshark (`tcp.port == 5000`).
2. **Terminal 1:** Run `python task_b_nonce_reuse.py` and type `server`.
3. **Terminal 2:** Run `python task_b_nonce_reuse.py` and type `client`.
4. In Wireshark, copy the two 21-byte ciphertexts (skip the first 16 bytes `[4 length + 12 nonce]` and drop the last 16 bytes `[tag]`).
5. Run `python task_b_nonce_reuse.py`, type `recover`, and paste both hex strings to recover the second message without the key.

#### Task C: Missing Authentication Tag (Bit-Flipping)

1. No server or Wireshark capture is needed for this task. Run:

   ```bash
   python task_c_no_tag.py
   ```

2. Observe how AES-CTR silently decrypts the altered amount (`RM100` → `RM900`), while AES-GCM rejects it with `InvalidTag`.

#### Task D: Replay Attack (Fixed vs. Fresh Salt)

1. Start Wireshark (`tcp.port == 5000`).
2. **Terminal 1 (Vulnerable Fixed-Salt Server):**

   ```bash
   python task_d_server.py --fixed-salt
   ```

3. **Terminal 2 (Legitimate Client):**

   ```bash
   python task_d_send_once.py
   ```

4. In Wireshark, right-click a packet → **Follow > TCP Stream**, select the **client-to-server** direction, change **Show data as** to **Raw**, and click **Save as** → save as `recorded_c2s.bin` in your project folder.
5. **Terminal 2 (Attacker Replay):**

   ```bash
   python replay.py
   ```

   * Notice the fixed-salt server accepts the replayed message.

6. Stop the server (`Ctrl+C`), restart it with a **fresh random salt per session**, and run `python replay.py` again:

   ```bash
   python task_d_server.py
   python replay.py
   ```

   * The server now rejects the replay with `InvalidTag`.

### Stage 4 (Bonus): X25519 Key Exchange, MITM & Ed25519 Signatures

#### 4(a): Direct X25519 Key Exchange

1. **Terminal 1:** `python server_stage4.py`
2. **Terminal 2:** `python client_stage4.py --port 5000`

#### 4(b): Man-in-the-Middle (MITM) Attack

1. **Terminal 1 (Server on 5000):** `python server_stage4.py`
2. **Terminal 2 (MITM Proxy on 5001):** `python mitm_stage4.py`
3. **Terminal 3 (Client connecting to 5001):** `python client_stage4.py --port 5001`
4. Watch the MITM terminal print the decrypted messages in plaintext.

#### 4(c): Stopping the MITM with Ed25519 Signatures

1. **Terminal 1 (Signed Server):**

   ```bash
   python server_stage4.py --sign
   ```

   *(This automatically creates `server_ed25519.pub` in your folder.)*

2. **Terminal 2 (MITM Proxy):**

   ```bash
   python mitm_stage4.py
   ```

3. **Terminal 3 (Client verifying signature):**

   ```bash
   python client_stage4.py --port 5001 --verify-file server_ed25519.pub
   ```

4. The client detects the invalid signature on the attacker's substitute key and aborts the connection.

## 5. Common Troubleshooting

| Error / Issue | Solution |
| :--- | :--- |
| `ConnectionRefusedError` | Start the server script first before running the client script. |
| `Address already in use` | Close any previous server terminal still running in the background. |
| `ModuleNotFoundError: No module named 'cryptography'` | Run `python -m pip install -r requirements.txt` using the same Python interpreter you use to run the scripts. |
| Wireshark shows no packets | Verify you selected the **Loopback** adapter and typed `tcp.port == 5000` (not `=`). |