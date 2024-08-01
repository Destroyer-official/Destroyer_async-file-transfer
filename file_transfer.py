

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
import time
import hashlib

class FileTransfer:
    def __init__(self, max_thread_workers=50, chunk_size=65536, max_retries=3, timeout=5):
        # Initialize server and transfer settings
        self.server_ip = '0.0.0.0'
        self.server_port = 60000
        self.socket = None
        self.executor = ThreadPoolExecutor(max_workers=max_thread_workers)
        self.server_info_label = None
        self.server_info_window = None
        self.client_connected = False
        self.root = tk.Tk()
        self.root.withdraw()
        self.server_info_var = tk.StringVar()
        self.chunk_size = chunk_size
        self.max_retries = max_retries
        self.timeout = timeout
        self.setup_logging()

    def setup_logging(self):
        # Set up logging for error tracking
        logging.basicConfig(filename='file_transfer.log', level=logging.ERROR)

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
            self.socket.close()
            print("Server stopped.")
            logging.info("Server stopped.")
            asyncio.get_event_loop().stop()
            sys.exit()

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
            self.exit_program()

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
        except Exception as e:
            print(f"Error during communication: {e}")
            logging.error(f"Error during communication: {e}")
        finally:
            self.socket.close()
            print("Connection closed.")
            logging.info("Connection closed.")
            self.exit_program()

    def calculate_checksum(self, file_path):
        hash_md5 = hashlib.md5()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(self.chunk_size), b""):
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
                await asyncio.sleep(0.01)  # Ensure smooth operation with a slight delay

    async def send_file(self, sock, file_path, root):
        try:
            file_size = os.path.getsize(file_path)  # Pre-calculate file size
            relative_path = os.path.relpath(file_path, root).encode('UTF-8')
            checksum = self.calculate_checksum(file_path)
            print(f"Sending file: {file_path}, size: {file_size} bytes")
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
                update_interval = 0.5  # Update progress every 0.5 seconds
                while sent_size < file_size:
                    chunk = await f.read(self.chunk_size)
                    await self.send_with_retry(sock, chunk)
                    sent_size += len(chunk)
                    current_time = time.time()
                    if current_time - last_update_time > update_interval:
                        self.update_progress(progress_bar, percentage_label, sent_size, file_size)
                        last_update_time = current_time
            print(f"\nFile {relative_path.decode('UTF-8')} sent successfully.")
            logging.info(f"File {relative_path.decode('UTF-8')} sent successfully.")
            progress_window.destroy()
        except Exception as e:
            print(f"\nError sending file {file_path}: {e}")
            logging.error(f"Error sending file {file_path}: {e}")


    async def send_with_retry(self, sock, data):
        # Send data with retry mechanism for reliability
        retries = 0
        backoff = 1
        while retries < self.max_retries:
            try:
                await asyncio.get_event_loop().sock_sendall(sock, data)
                ack = await asyncio.wait_for(asyncio.get_event_loop().sock_recv(sock, 1), timeout=self.timeout)
                if ack == b'A':
                    return
                else:
                    print("Acknowledgment failed, retrying...")
                    logging.warning("Acknowledgment failed, retrying...")
            except asyncio.TimeoutError:
                print("Timeout, retrying...")
                logging.warning("Timeout, retrying...")
            retries += 1
            await asyncio.sleep(backoff)
            backoff *= 2
        print("Failed to send data after retries.")
        logging.error("Failed to send data after retries.")


    async def send_folder(self, sock, folder_path):
        # Send a folder and its contents to the server
        try:
            folder_name = os.path.relpath(folder_path).encode('UTF-8')
            await asyncio.get_event_loop().sock_sendall(sock, b'D')
            await asyncio.get_event_loop().sock_sendall(sock, struct.pack('>I', len(folder_name)))
            await asyncio.get_event_loop().sock_sendall(sock, folder_name)
            for root_dir, _, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root_dir, file)
                    await self.send_file(sock, file_path, folder_path)
                    await asyncio.sleep(0.1)  # 100 ms delay between sending files
        except Exception as e:
            print(f"Error sending folder {folder_path}: {e}")
            logging.error(f"Error sending folder {folder_path}: {e}")

    async def receive_files_or_folders(self, sock):
        # Receive files or folders from the server
        try:
            while True:
                data_type = await asyncio.get_event_loop().sock_recv(sock, 1)
                if not data_type:
                    break
                if data_type.decode() == 'F':
                    await self.receive_file(sock)
                elif data_type.decode() == 'D':
                    await self.receive_folder(sock)
        except Exception as e:
            print(f"Error receiving files or folders: {e}")
            logging.error(f"Error receiving files or folders: {e}")

    async def receive_file(self, sock):
        try:
            file_name_length = struct.unpack('>I', await asyncio.get_event_loop().sock_recv(sock, 4))[0]
            file_name = await asyncio.get_event_loop().sock_recv(sock, file_name_length)
            file_name = file_name.decode('UTF-8', errors='replace')
            file_size = struct.unpack('>Q', await asyncio.get_event_loop().sock_recv(sock, 8))[0]
            checksum = await asyncio.get_event_loop().sock_recv(sock, 16)
            print(f"Receiving file: {file_name}, size: {file_size} bytes")
            print(f"Expected MD5 checksum: {checksum.hex()}")
            logging.info(f"Receiving file: {file_name}, size: {file_size} bytes, expected MD5 checksum: {checksum.hex()}")
            received_dir = 'received'
            os.makedirs(received_dir, exist_ok=True)
            file_name = os.path.join(received_dir, self.get_unique_filename(file_name))

            if os.path.dirname(file_name):
                os.makedirs(os.path.dirname(file_name), exist_ok=True)

            progress_bar, percentage_label, progress_window = self.create_progress_window(file_size, f"Receiving {file_name}")

            async with aiofiles.open(file_name, 'wb') as f:
                received_size = 0
                last_update_time = 0
                update_interval = 0.2  # Update progress every 0.2seconds
                while received_size < file_size:
                    chunk = await self.receive_with_retry(sock)
                    await f.write(chunk)
                    received_size += len(chunk)
                    current_time = time.time()
                    if current_time - last_update_time > update_interval:
                        self.update_progress(progress_bar, percentage_label, received_size, file_size)
                        last_update_time = current_time

            received_checksum = self.calculate_checksum(file_name)
            if received_checksum == checksum:
                print(f"File {file_name} received successfully and checksum verified.")
                logging.info(f"File {file_name} received successfully and checksum matched.")
            else:
                print(f"File {file_name} is corrupted. Checksum mismatch.")
                logging.error(f"File {file_name} is corrupted. Checksum mismatch.")
            print(f"Received MD5 checksum: {received_checksum.hex()}")
            logging.error(f"Checksum mismatch for file {file_name}.")
            progress_window.destroy()
        except Exception as e:
            print(f"Error receiving file: {e}")
            logging.error(f"Error receiving file: {e}")



    async def receive_with_retry(self, sock):
        # Receive data with retry mechanism for reliability
        retries = 0
        backoff = 1
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
            backoff *= 2
        logging.error("Failed to receive data after retries.")
        raise Exception("Failed to receive data.")


    async def receive_folder(self, sock):
        # Receive a folder from the client
        try:
            folder_name_length = struct.unpack('>I', await asyncio.get_event_loop().sock_recv(sock, 4))[0]
            folder_name = await asyncio.get_event_loop().sock_recv(sock, folder_name_length)
            folder_name = folder_name.decode('UTF-8', errors='replace')
            received_dir = 'received'
            os.makedirs(received_dir, exist_ok=True)
            folder_name = os.path.join(received_dir, self.get_unique_foldername(folder_name))

            os.makedirs(folder_name, exist_ok=True)
            print(f"Folder {folder_name} created successfully.")
            logging.info(f"Receiving folder: {folder_name}")
        except Exception as e:
            print(f"Error receiving folder: {e}")
            logging.error(f"Error receiving folder: {e}")

    def get_unique_filename(self, file_name):
        # Generate a unique filename to avoid conflicts
        base, ext = os.path.splitext(file_name)
        counter = 1
        while os.path.exists(file_name):
            file_name = f"{base}({counter}){ext}"
            counter += 1
        return file_name

    def get_unique_foldername(self, folder_name):
        # Generate a unique folder name to avoid conflicts
        counter = 1
        while os.path.exists(folder_name):
            folder_name = f"{folder_name}({counter})"
            counter += 1
        return folder_name

    def create_progress_window(self, total_size, title):
        # Create a new progress window with the given title
        progress_window = tk.Tk()
        progress_window.title( title)

        # Progress bar to show the transfer progress
        progress_bar = ttk.Progressbar(progress_window, maximum=total_size, length=300, mode='determinate')
        progress_bar.pack(pady=10, padx=10, fill=tk.X)

        # Label to show the percentage of completion
        percentage_label = tk.Label(progress_window, text="0%")
        percentage_label.pack(pady=5, padx=10)

        # Close button for the progress window
        tk.Button(progress_window, text="Close", command=progress_window.destroy).pack(pady=5)

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

    def exit_program(self):
        # Exit the program and close the GUI
        if self.root:
            self.root.quit()
            self.root.destroy()
        asyncio.get_event_loop().stop()
        sys.exit()

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
        root.title("File Transfer Options")
        tk.Label(root, text="Choose 'send' or 'receive'").pack(pady=10)
        tk.Button(root, text="Send", command=sender).pack(pady=5)
        tk.Button(root, text="Receive", command=receiver).pack(pady=5)
        root.mainloop()

if __name__ == "__main__":
    FileTransfer.main()
