
# Password Manager CLI

## Introduction

Password Manager CLI is a simple, secure, and extensible command-line application for managing your passwords. It allows you to safely store, retrieve, and manage account credentials using strong encryption. The project is designed with modular architecture for easy future expansion (e.g., UI, cloud sync).

## Prerequisites

- Linux operating system
- CMake ≥ 3.16
- C++ compiler with C++17 support (e.g., g++ ≥ 9)
- OpenSSL development libraries (for AES encryption)
- Git (to clone the repository)

## Functional Requirements

- **Master Password Authentication:**  
  - First run: create and store a master password hash (SHA256).
  - Subsequent runs: require correct master password to access the vault.
- **Account Storage:**  
  - Store service name, username, encrypted password, and notes for each account.
  - All data is encrypted with AES-256-CBC using a key derived from the master password.
- **Account Management:**  
  - Add, search, list, and delete accounts.
  - Copy username/password to clipboard (if supported).
  - Generate random passwords with customizable options.
- **CLI Interface:**  
  - Simple menu-driven interface for all operations.

## Non-Functional Requirements

- **Security:**  
  - No plaintext password storage or display.
  - Input masking for passwords.
  - Random salt and IV for encryption.
- **Extensibility:**  
  - Modular codebase for easy future enhancements.
- **Reliability:**  
  - Unit tests for core modules (encryption, storage, logic).
- **Portability:**  
  - Runs on any Linux system with required dependencies.

## How to Install

1. **Clone the repository:**
   ```bash
   git clone https://github.com/bngiahuy/PasswordManagerCPP.git
   cd PasswordManagerCPP
   ```

2. **Install dependencies (if not already installed):**
   ```bash
   sudo apt-get update
   sudo apt-get install build-essential cmake libssl-dev
   ```

## How to Build and Run on Linux using CMake

1. **Create a build directory and configure the project:**
   ```bash
   mkdir build
   cd build
   cmake ..
   ```

2. **Build the application:**
   ```bash
   make
   ```

3. **Run the Password Manager CLI:**
   ```bash
   ./PasswordManager
   ```

4. **(Optional) Run tests:**
   - If test executables are enabled in `CMakeLists.txt`, build and run them similarly.

---

**Note:**  
- All data is stored locally in the `stored_data/` directory.
- The application uses strong cryptography (AES-256-CBC, SHA256) via OpenSSL.
- For more details, see the source code and comments.
