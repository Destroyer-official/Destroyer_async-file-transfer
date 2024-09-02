
<div align="center">
  
# 🚀 Destroyer_async-file-transfer 🗂🌐
  
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/Python-3.6%2B-blue.svg)](https://www.python.org/downloads/)

</div>
`Destroyer_async-file-transfer` is an asynchronous file transfer application written in Python. It allows users to transfer files and folders between a server and clients using a graphical user interface (GUI) built with Tkinter and async IO operations for efficient performance.

## ✨ Features

- **🚀 Asynchronous Transfers**: Powered by `asyncio`, our application ensures non-blocking, fast, and efficient file transfers.
- **💼 Multi-threaded Operations**: A thread pool executor manages concurrent file operations, boosting performance.
- **🖥️ User-Friendly GUI**: A Tkinter-based interface simplifies file selection and transfer monitoring.
- **🔒 Secure Transfers**: MD5 checksum verification guarantees data integrity.
- **🔄 Resilient Transfers**: A retry mechanism with exponential backoff ensures reliable data delivery.
- **📊 Real-Time Progress**: Stay informed with real-time progress updates on file transfers.

## 📋 Requirements

- Python 3.6 or higher
- `aiofiles` library for asynchronous file operations
- `Tkinter` for GUI components



## ⚙️ Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/Destroyer-official/Destroyer_async-file-transfer.git
    cd Destroyer_async-file-transfer
    ```
2. Install the required dependencies:
    ```bash
    pip install aiofiles
    ```

## 🚀 Getting Started

### Running the Application

1. Navigate to the repository directory.
2. Execute the script:
    ```bash
    python file_transfer.py
    ```

### Using the Application

1. **Main Menu**:
    - Choose to either `Send` or `Receive` files.
2. **Send Mode**:
    - Enter the server IP address.
    - Select files or folders to send using the file dialog.
    - Monitor the transfer progress in the progress window.
3. **Receive Mode**:
    - The server starts listening for incoming connections.
    - Displays server IP and port information.
    - Monitor the transfer progress in the progress window once a client connects.

## 📂 File Structure

- `file_transfer.py`: Main script containing the `FileTransfer` class and the core functionality.
- `file_transfer.log`: Log file generated for error tracking and debugging.

## 📝 Logging

- The application logs errors and significant events to `file_transfer.log`.
- Check the log file for detailed information on any issues encountered during file transfers.

## 🔍 Code Overview

### `FileTransfer` Class

- **Initialization**:
    - Initializes server settings, thread pool executor, and logging.
- **Server Methods**:
    - `start_server`: Sets up and starts the server to listen for incoming connections.
    - `handle_client`: Handles communication with a connected client.
- **Client Methods**:
    - `start_client`: Connects to the server and sends files/folders.
- **File Operations**:
    - `send_files`: Prompts user to select files/folders and sends them to the server.
    - `send_file`: Sends a single file to the server.
    - `send_folder`: Sends a folder and its contents to the server.
    - `receive_files_or_folders`: Receives files or folders from the client.
    - `receive_file`: Receives a single file from the client.
    - `receive_folder`: Receives a folder from the client.
- **Utility Methods**:
    - `calculate_checksum`: Calculates MD5 checksum of a file.
    - `send_with_retry`: Sends data with retry mechanism.
    - `receive_with_retry`: Receives data with retry mechanism.
    - `get_unique_filename`: Generates a unique filename to avoid conflicts.
    - `get_unique_foldername`: Generates a unique folder name to avoid conflicts.
    - `create_progress_window`: Creates a progress window for file transfers.
    - `update_progress`: Updates progress bar and percentage label during transfer.
    - `update_gui_client_info`: Updates GUI with client information.
    - `show_server_info`: Displays server information in a GUI window.
    - `get_public_ip`: Gets the public IP address of the server.
    - `exit_program`: Exits the program and closes the GUI.

### Main Function

- **Main Menu**: Provides options to either start the server (receive mode) or connect to a server (send mode).
- **Tkinter GUI**: Handles user interactions and displays progress during file transfers.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

---
