import zipfile
import tempfile 
import socket
import os
import struct
import logging
import asyncio
import aiofiles
from concurrent.futures import ThreadPoolExecutor
import tkinter as tk
from tkinter import filedialog, simpledialog, ttk
import sys
import threading
import time
from asyncio import gather
import hashlib

class FileTransfer:
    def __init__(self, max_thread_workers=100, max_retries=3, timeout=5):
        # Initialize server and transfer settings
        self.server_ip = '0.0.0.0'
        self.server_port = 60000
        self.socket = None
        self.root = tk.Tk()
        self.root.withdraw()
        self.loop = asyncio.new_event_loop()  # Create a new event loop
        self.executor = ThreadPoolExecutor(max_workers=max_thread_workers)
        self.loop_thread = threading.Thread(target=self.start_event_loop, daemon=True)
        self.loop_thread.start()
        self.chunk_size = None
        self.server_info_label = None
        self.server_info_window = None
        self.client_connected = False
        self.server_info_var = tk.StringVar()
        self.max_retries = max_retries
        self.timeout = timeout
        self.failed_files = []  
        self.setup_logging()


    def setup_logging(self):
        logging.basicConfig(
            filename='file_transfer.log',
            # level=logging.DEBUG,  # Set to DEBUG for more detailed logs
            level=logging.ERROR,  # Log only errors to reduce file I/O overhead    
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
    def start_event_loop(self):
        asyncio.set_event_loop(self.loop)  # Set the loop for the current thread
        self.loop.run_forever()


    def stop_event_loop(self):
        self.loop.call_soon_threadsafe(self.loop.stop)  # Stop the loop safely

    async def exit_program(self, code=0):
        await asyncio.sleep(.5)

        try:
            # Attempt to close the socket if it exists
            if self.socket:
                self.socket.close()
        except Exception as e:
            print(f"Error closing socket: {e}")
            logging.error(f"Error closing socket: {e}")

        try:
            # Attempt to stop the asyncio event loop if it's running
            loop = asyncio.get_event_loop()
            if loop.is_running():
                self.loop.stop()
                await asyncio.sleep(0.1)  # Give the loop time to stop properly
        except Exception as e:
            print(f"Error stopping event loop: {e}")
            logging.error(f"Error stopping event loop: {e}")

        try:
            # Attempt to quit and destroy the Tkinter root window if it exists
            if self.root:
                self.root.quit()
                self.root.destroy()
        except Exception as e:
            print(f"Error closing GUI: {e}")
            logging.error(f"Error closing GUI: {e}")

        try:
            # Exit the program with the provided code
            sys.exit(code)
        except SystemExit as e:
            print(f"SystemExit raised: {e}")
            logging.error(f"SystemExit raised: {e}")
            raise
        except Exception as e:
            print(f"Error during program exit: {e}")
            logging.error(f"Error during program exit: {e}")
            sys.exit(1)  # Exit with error code if something unexpected happens

    async def start_server(self):
        # Set up and start the server
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.setblocking(False)
        self.socket.bind((self.server_ip, self.server_port))
        self.socket.listen(5)

        self.show_server_info()
        public_ip = self.get_public_ip()
        print(f"{public_ip}")
        logging.info(f"Server started on port {self.server_port}, public IP: {public_ip}")
        print(f"Server started on port {self.server_port}. Listening for connections...")

        loop = asyncio.get_event_loop()
        try:
            while True:
                client_socket, client_address = await loop.sock_accept(self.socket)
                print("Client connected:", client_address)
                logging.info(f"Client connected: {client_address}")
                self.client_connected = True
                self.update_gui_client_info(client_address)
                loop.call_soon_threadsafe(self.close_server_info_window)
                loop.create_task(self.handle_client(client_socket))
        except KeyboardInterrupt:
            print("Server stopping...")
            logging.info("Server stopping...")
        finally:
            await self.exit_program()


    def close_server_info_window(self):
        # Close server info window if it is open
        if self.server_info_window:
            self.server_info_window.quit()
            self.server_info_window.destroy()
            self.server_info_window = None

    async def handle_client(self, client_socket):
        # Handle communication with a connected client
        try:
            await self.receive_files_or_folders(client_socket)
        except Exception as e:
            print(f"Error handling client: {e}")
            logging.error(f"Error handling client: {e}")
        finally:
            client_socket.close()
            await self.exit_program()

    async def start_client(self, server_ip):
        # Connect to the server and send files/folders
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.socket.setblocking(False)
        await asyncio.get_event_loop().sock_connect(self.socket, (server_ip, self.server_port))
        print("Connected to the server.")
        logging.info("Connected to the server.")
        try:
            await self.send_files(self.socket)
            print("All transfers completed successfully.")  
            # Wait for 5 seconds to ensure receiver has successfully received the files
            await asyncio.sleep(1)
        except Exception as e:
            print(f"Error during communication: {e}")
            logging.error(f"Error during communication: {e}")
        finally:
            self.socket.close()
            print("Connection closed.")
            logging.info("Connection closed.")
            await self.exit_program()

    def adjust_chunk_size(self, file_size):
        if file_size < 1024 * 1024:  # For small files (< 1MB)
            return 16384  # Use 16KB chunks
        elif 1024 * 1024 <= file_size < 1024 * 1024 * 100:  # For medium files (1MB to 100MB)
            return 32768  # Use 32KB chunks (adjust as needed)
        elif 1024 * 1024 * 100 <= file_size < 1024 * 1024 * 1024 * 5:  # For large files (100MB to 5GB)
            return 65536  # Use 64KB chunks (adjust as needed)
        else:  # For extremely large files (> 5GB)
            return 131072  # Use 128KB chunks

   
    def calculate_checksum(self, file_path):
        def read_chunks(file, chunk_size):
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            with ThreadPoolExecutor() as executor:
                for chunk in executor.map(lambda x: x, read_chunks(f, self.chunk_size)):
                    hash_md5.update(chunk)
        return hash_md5.digest()

    

    async def send_files(self, sock):
        choice = await self.prompt_file_or_folder()
        if choice == 'files':
            paths = filedialog.askopenfilenames()
        else:
            paths = [filedialog.askdirectory()]

        if paths:
            for path in paths:
                if os.path.isfile(path):
                    await self.send_file(sock, path, os.path.dirname(path))
                elif os.path.isdir(path):
                    await self.send_folder(sock, path)
                await asyncio.sleep(.1)  # 100 ms delay between sending files/folders

    async def send_file(self, sock, file_path, root, checksum=None):
        try:
            file_size = os.path.getsize(file_path)  # Pre-calculate file size
            self.chunk_size = self.adjust_chunk_size(file_size)
            # Correctly generate the relative path
            relative_path = os.path.relpath(file_path, root).encode('UTF-8')

            if checksum is None:
                checksum = self.calculate_checksum(file_path)

            print(f"\nSending file: {file_path}, size: {file_size} bytes")
            print(f"MD5 checksum: {checksum.hex()}")
            logging.info(f"Sending file: {file_path}, size: {file_size} bytes, MD5 checksum: {checksum.hex()}")

            # Send file metadata
            await asyncio.get_event_loop().sock_sendall(sock, b'F')
            await asyncio.get_event_loop().sock_sendall(sock, struct.pack('>I', len(relative_path)))
            await asyncio.get_event_loop().sock_sendall(sock, relative_path)
            await asyncio.get_event_loop().sock_sendall(sock, struct.pack('>Q', file_size))
            await asyncio.get_event_loop().sock_sendall(sock, checksum)

            progress_bar, percentage_label, progress_window = self.create_progress_window(file_size, f"Sending {relative_path.decode('UTF-8')}")

            async with aiofiles.open(file_path, 'rb') as f:
                sent_size = 0
                last_update_time = 0
                update_interval = 0.3  # Update progress every 0.3 seconds
                while sent_size < file_size:
                    chunk = await f.read(self.chunk_size)
                    await self.send_with_retry(sock, chunk)
                    sent_size += len(chunk)
                    current_time = time.time()
                    if current_time - last_update_time > update_interval:
                        self.update_progress(progress_bar, percentage_label, sent_size, file_size)
                        last_update_time = current_time

            print(f"File {relative_path.decode('UTF-8')} sent successfully.\n")
            logging.info(f"File {relative_path.decode('UTF-8')} sent successfully.")
            progress_window.destroy()
        except Exception as e:
            print(f"\nError sending file {file_path}: {e}")
            logging.error(f"Error sending file {file_path}: {e}")

    

    async def send_with_retry(self, sock, data):
        retries = 0
        backoff = 1
        max_backoff = 8  # Maximum backoff time in seconds
        while retries < self.max_retries:
            try:
                await asyncio.get_event_loop().sock_sendall(sock, data)
                response = await asyncio.wait_for(asyncio.get_event_loop().sock_recv(sock, 1), timeout=self.timeout)
                if response == b'A':  # ACK received
                    return
                elif response == b'C':  # ACM (Acknowledgment Checksum Mismatch) received
                    print("Checksum mismatch detected. Will retry after completing initial transfer.")
                    logging.warning("Checksum mismatch detected. Will retry after completing initial transfer.")
                    self.failed_files.append(data)
                    return
                else:
                    print("Invalid response, retrying...")
                    logging.warning("Invalid response, retrying...")
            except asyncio.TimeoutError:
                print("Timeout, retrying...")
                logging.warning("Timeout, retrying...")
            retries += 1
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        print("Failed to send data after retries.")
        logging.error("Failed to send data after retries.")



    async def send_folder(self, sock, folder_path):
        try:
            # Create a temporary ZIP file that includes the root folder
            with tempfile.NamedTemporaryFile(delete=False) as temp_zip:
                zip_file_path = temp_zip.name
                with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root_dir, _, files in os.walk(folder_path):
                        for file in files:
                            file_path = os.path.join(root_dir, file)
                            arcname = os.path.relpath(file_path, os.path.dirname(folder_path))
                            zipf.write(file_path, arcname)

            # Compute checksum for the ZIP file
            checksum = self.calculate_checksum(zip_file_path)

            # Send the ZIP file with checksum
            await self.send_file(sock, zip_file_path, os.path.dirname(folder_path), checksum)
            os.remove(zip_file_path)  # Delete the temporary ZIP file after sending

            print(f"Folder {folder_path} sent successfully as ZIP.")
            logging.info(f"Folder {folder_path} sent successfully as ZIP.")
        except Exception as e:
            print(f"Error sending folder {folder_path}: {e}")
            logging.error(f"Error sending folder {folder_path}: {e}")



    async def receive_files_or_folders(self, sock):
        self.failed_files = []  # Initialize list to track failed files
        try:
            while True:
                data_type = await asyncio.get_event_loop().sock_recv(sock, 1)
                if not data_type:
                    break
                if data_type.decode() == 'F':
                    await self.receive_file(sock)
                elif data_type.decode() == 'D':
                    await self.receive_folder(sock)

            # After all files have been processed, request retransmission of failed files
            if self.failed_files:
                print("Requesting retransmission of corrupted files...")
                logging.info("Requesting retransmission of corrupted files...")
                await self.request_retransmission(sock, self.failed_files)
        except Exception as e:
            logging.error(f"Error receiving files or folders: {e}")
            exit()

    
    async def request_retransmission(self, sock, files):
        # Send the list of failed files to the client for retransmission
        await asyncio.get_event_loop().sock_sendall(sock, b'R')
        await asyncio.get_event_loop().sock_sendall(sock, struct.pack('>I', len(files)))
        for file in files:
            encoded_file = file.encode('UTF-8')
            await asyncio.get_event_loop().sock_sendall(sock, struct.pack('>I', len(encoded_file)))
            await asyncio.get_event_loop().sock_sendall(sock, encoded_file)

    async def handle_retransmissions(self, sock):
        if self.failed_files:
            print("Retransmitting failed files...")
            logging.info("Retransmitting failed files...")
            for file_data in self.failed_files:
                await self.send_with_retry(sock, file_data)
            print("Retransmission complete.")
            logging.info("Retransmission complete.")
    async def receive_file(self, sock):
        try:
            file_name_length = struct.unpack('>I', await asyncio.get_event_loop().sock_recv(sock, 4))[0]
            file_name = await asyncio.get_event_loop().sock_recv(sock, file_name_length)
            file_name = file_name.decode('UTF-8', errors='replace')
            file_size = struct.unpack('>Q', await asyncio.get_event_loop().sock_recv(sock, 8))[0]
            self.chunk_size = self.adjust_chunk_size(file_size)
            checksum = await asyncio.get_event_loop().sock_recv(sock, 16)
            print(f"\nReceiving file: {file_name}, size: {file_size} bytes")
            print(f"Expected MD5 checksum: {checksum.hex()}")
            logging.info(f"Receiving file: {file_name}, size: {file_size} bytes, expected MD5 checksum: {checksum.hex()}")

            # Define a fixed directory on the server for received files
            received_dir = 'received'
            os.makedirs(received_dir, exist_ok=True)

            # Sanitize the file name to avoid directory traversal
            base_file_name = os.path.basename(file_name)

            # Use get_unique_filename to handle duplicate files in the 'received' directory
            unique_file_name = self.get_unique_filename(os.path.join(received_dir, base_file_name))

            progress_bar, percentage_label, progress_window = self.create_progress_window(file_size, f"Receiving {base_file_name}")

            async with aiofiles.open(unique_file_name, 'wb') as f:
                received_size = 0
                last_update_time = 0
                update_interval = 0.3  # Update progress every 0.3 seconds
                while received_size < file_size:
                    chunk = await self.receive_with_retry(sock)
                    await f.write(chunk)
                    received_size += len(chunk)
                    current_time = time.time()
                    if current_time - last_update_time > update_interval:
                        self.update_progress(progress_bar, percentage_label, received_size, file_size)
                        last_update_time = current_time

            received_checksum = self.calculate_checksum(unique_file_name)
            if received_checksum == checksum:
                print(f"File received successfully and checksum verified.")
                logging.info(f"File {unique_file_name} received successfully and checksum matched.")
                await asyncio.get_event_loop().sock_sendall(sock, b'A')  # Send ACK

                # If the received file is a ZIP archive, extract it
                if zipfile.is_zipfile(unique_file_name):
                    with zipfile.ZipFile(unique_file_name, 'r') as zip_ref:
                        original_folder_name = zip_ref.namelist()[0].split('/')[0]  # Extract original folder name
                        parent_dir = "received"
                        unique_folder_name = self.get_unique_foldername(parent_dir, original_folder_name)
                        zip_ref.extractall(unique_folder_name)
                        print(f"Extracted ZIP file to {unique_folder_name}.")
                        logging.info(f"Extracted ZIP file to {unique_folder_name}.")
                    os.remove(unique_file_name)  # Delete the ZIP file after extraction

            else:
                print(f"File {unique_file_name} is corrupted. Checksum mismatch.")
                logging.error(f"File {unique_file_name} is corrupted. Checksum mismatch.")
                await asyncio.sleep(0.3)  # Give the loop time
                await asyncio.get_event_loop().sock_sendall(sock, b'C')  # Send NACK
                self.failed_files.append(unique_file_name)  # Track failed files
            print(f"Received MD5 checksum: {received_checksum.hex()}\n")
            progress_window.destroy()
        except Exception as e:
            print(f"Error receiving file: {file_name}, Error: {e}")
            logging.error(f"Error receiving file: {file_name}, Error: {e}")
            self.failed_files.append(file_name)
            await asyncio.get_event_loop().sock_sendall(sock, b'C')  # Send NACK in case of error



    def show_error_message(self, message):
        # Show an error message to the user
        error_window = tk.Tk()
        error_window.title("Error")
        tk.Label(error_window, text=message).pack(pady=10, padx=10)
        tk.Button(error_window, text="Close", command=error_window.destroy).pack(pady=5)
        error_window.mainloop()

    async def receive_with_retry(self, sock):
        retries = 0
        backoff = 1
        max_backoff = 8  # Maximum backoff time in seconds
        while retries < self.max_retries:
            try:
                chunk = await asyncio.wait_for(asyncio.get_event_loop().sock_recv(sock, self.chunk_size), timeout=self.timeout)
                await asyncio.get_event_loop().sock_sendall(sock, b'A')
                return chunk
            except asyncio.TimeoutError:
                print("Timeout, retrying...")
                logging.warning("Timeout, retrying...")
            retries += 1
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
        logging.error("Failed to receive data after retries.")
        raise Exception("Failed to receive data.")
    

    async def receive_folder(self, sock):
        try:
            # Receive the number of files in the folder
            num_files = struct.unpack('>I', await asyncio.get_event_loop().sock_recv(sock, 4))[0]

            for _ in range(num_files):
                await self.receive_file(sock)

            print("Folder received successfully.")
            logging.info("Folder received successfully.")
        except Exception as e:
            print(f"Error receiving folder: {e}")
            logging.error(f"Error receiving folder: {e}")


    def get_unique_filename(self, file_name):
        base_name = os.path.basename(file_name)
        base, ext = os.path.splitext(base_name)
        parent_dir = os.path.dirname(file_name)
        new_file_name = os.path.join(parent_dir, base + ext)
        counter = 1

        while os.path.exists(new_file_name):
            new_file_name = os.path.join(parent_dir, f"{base}({counter}){ext}")
            counter += 1

        return new_file_name



    def get_unique_foldername(self, parent_folder, folder_name):
        unique_folder_name = os.path.join(parent_folder, folder_name)
        counter = 1

        while os.path.exists(unique_folder_name):
            unique_folder_name = os.path.join(parent_folder, f"{folder_name}({counter})")
            counter += 1

        return unique_folder_name


    def create_progress_window(self, total_size, title):
        # Create a new progress window with the given title
        progress_window = tk.Tk()
        progress_window.title(title)

        # Progress bar to show the transfer progress
        progress_bar = ttk.Progressbar(progress_window, maximum=total_size, length=300, mode='determinate')
        progress_bar.pack(pady=10, padx=10, fill=tk.X)

        # Label to show the percentage of completion
        percentage_label = tk.Label(progress_window, text="0%")
        percentage_label.pack(pady=5, padx=10)

        # Close button for the progress window
        tk.Button(progress_window, text="Close", command=progress_window.destroy).pack(pady=5)

        # Start a separate thread for GUI updates
        threading.Thread(args=(progress_bar, percentage_label, progress_window)).start()

        return progress_bar, percentage_label, progress_window

    def update_progress(self, progress_bar, percentage_label, transferred_size, total_size):
        # Update the progress bar and percentage label during file transfer
        progress_bar['value'] = transferred_size
        percentage = (transferred_size / total_size) * 100
        percentage_label['text'] = f"{int(percentage)}%"
        progress_bar.update()
        percentage_label.update()
    def update_gui_client_info(self, client_address):
        # Update the GUI with client information
        if self.server_info_window:
            self.server_info_label.config(text=f"Client connected: {client_address}")
            self.server_info_window.after(1000, self.server_info_window.quit)

    def show_server_info(self):
        # Display server information in a GUI window
        if self.server_info_window is None:
            self.server_info_window = tk.Toplevel()
            self.server_info_window.title("Server Information")
            server_info = f"Server running at {self.get_public_ip()}:{self.server_port}"
            self.server_info_label = tk.Label(self.server_info_window, text=server_info)
            self.server_info_label.pack(pady=20, padx=20)
            tk.Button(self.server_info_window, text="Close", command=self.server_info_window.quit).pack(pady=5)
            self.server_info_window.protocol("WM_DELETE_WINDOW", self.server_info_window.quit)
            self.root.update()
            self.root.after(200, self.check_server_info_window)

    def check_server_info_window(self):
        # Continuously check if the server info window is open
        if self.server_info_window:
            self.root.after(200, self.check_server_info_window)

    def get_public_ip(self):
        # Get the public IP address of the server
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(('8.8.8.8', 80))
                return s.getsockname()[0]
        except Exception as e:
            logging.error(f"Error getting public IP: {e}")
            return '0.0.0.0'

    async def prompt_file_or_folder(self):
        choice = None

        # Functions to handle button clicks
        def select_files():
            nonlocal choice
            choice = 'files'
            root.quit()

        def select_folders():
            nonlocal choice
            choice = 'folders'
            root.quit()

        # Create a simple window to prompt user choice
        root = tk.Tk()
        root.title("Send Files or Folder")
        tk.Button(root, text="Send Files", command=select_files).pack(pady=5)
        tk.Button(root, text="Send Folder", command=select_folders).pack(pady=5)
        root.mainloop()
        return choice

    def run_server(self):
        asyncio.run_coroutine_threadsafe(self.start_server(), self.loop)  # Run the server coroutine

    @staticmethod
    def main():
        # Main function to start the file transfer program
        transfer = FileTransfer()

        def receiver():
            root.quit()
            root.destroy()
            asyncio.run(transfer.start_server())


        def sender():
            server_ip = simpledialog.askstring("Server IP", "Enter the server IP address:")
            root.quit()
            root.destroy()
            asyncio.run(transfer.start_client(server_ip))

        root = tk.Tk()

        tk.Label(root, text="Choose 'send' or 'receive'").pack(pady=10)
        tk.Button(root, text="Send", command=sender).pack(pady=5)
        tk.Button(root, text="Receive", command=receiver).pack(pady=5)
        root.mainloop()

if __name__ == "__main__":
    FileTransfer.main()
