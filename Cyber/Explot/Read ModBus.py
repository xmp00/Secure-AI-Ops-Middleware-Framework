#!/usr/bin/python3
import socket
import time
from umodbus import conf
from umodbus.client import tcp

# Adjust modbus configuration
conf.SIGNED_VALUES = True

# Define the IP address and port of the Modbus server
SERVER_IP = '83.136.254.139'
SERVER_PORT = 37988

# Define the number of retries and delay between retries
MAX_RETRIES = 3
RETRY_DELAY = 5

def connect_to_modbus(slave_id, server_ip=SERVER_IP, server_port=SERVER_PORT):
    # Create a socket connection
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Attempt to connect to the Modbus server
    try:
        print(f"Attempting to connect to the Modbus server at {server_ip}:{server_port} with Slave ID {slave_id}...")
        sock.connect((server_ip, server_port))
        print(f"Connection to the Modbus server successful with Slave ID {slave_id}.")
        return sock
    except ConnectionRefusedError:
        print(f"Connection to the Modbus server at {server_ip}:{server_port} with Slave ID {slave_id} refused.")
    except Exception as e:
        print(f"Connection to the Modbus server at {server_ip}:{server_port} with Slave ID {slave_id} failed. Error: {e}")
    return None

def read_modbus_value(sock, slave_id, address, quantity=1):
    # Define the Modbus command to read holding registers
    request = tcp.read_holding_registers(slave_id=slave_id, starting_address=address, quantity=quantity)

    retry_count = 0
    while retry_count < MAX_RETRIES:  # Retry up to MAX_RETRIES times
        print(f"Sending Modbus command to read value at address {address} for Slave ID {slave_id}...")
        try:
            response = tcp.send_message(request, sock)

            # Check if the response contains an error code
            if isinstance(response, int):
                if response == 72:  # Retry if server is busy
                    print(f"Server is busy, retrying after {RETRY_DELAY} seconds...")
                    time.sleep(RETRY_DELAY)
                    retry_count += 1
                    print(f"Retry attempt {retry_count}/{MAX_RETRIES}")
                    continue  # Retry the request
                else:
                    print(f"Error reading value for address {address} and Slave ID {slave_id}. Error code: {response}")
                    return None
            else:
                # Response contains a single or multiple registers
                if hasattr(response, 'registers'):
                    # Response contains multiple registers
                    values = [register.value for register in response.registers]
                    print(f"Values successfully read from address {address} (Slave ID {slave_id}): {values}")
                    return values
                elif hasattr(response, 'value'):
                    # Response contains a single register
                    value = response.value
                    print(f"Value successfully read from address {address} (Slave ID {slave_id}): {value}")
                    return value
                else:
                    # Try to handle other possible response formats
                    if isinstance(response, list):
                        if all(isinstance(register, int) for register in response):
                            print(f"Response is a list of integers, trying to use it as the value...")
                            print(f"Value successfully read from address {address} (Slave ID {slave_id}): {response}")
                            return response
                        elif all(hasattr(register, 'value') for register in response):
                            print(f"Response is a list of registers, extracting values...")
                            values = [register.value for register in response]
                            print(f"Values successfully read from address {address} (Slave ID {slave_id}): {values}")
                            return values
                    print(f"Unknown response format for address {address} and Slave ID {slave_id}. Response: {response}")
                    return None
        except Exception as e:
            print(f"Error reading value for address {address} and Slave ID {slave_id}. Error: {e}")
            return None

    print(f"Unable to read value for address {address} and Slave ID {slave_id} after {MAX_RETRIES} retries.")
    return None

def save_to_txt(slave_id, starting_addresses, file_name, sock):
    with open(file_name, 'w') as f:
        for address in starting_addresses:
            print(f"Checking address {address} for Slave ID {slave_id}...")
            values = read_modbus_value(sock, slave_id, address, quantity=100)
            if values is not None:
                f.write(f"Values at address {address} (Slave ID {slave_id}): {values}\n")
            time.sleep(3)

def main():
    slave_id = 52
    starting_addresses = range(300)
    file_name = f"output_slave_{slave_id}.txt"

    sock = connect_to_modbus(slave_id)

    if sock:
        print(f"Connection to Slave ID {slave_id} established.")
        print(f"Saving data for Slave ID {slave_id} to {file_name}...")
        save_to_txt(slave_id, starting_addresses, file_name, sock)
        sock.close()
        print(f"Data saved to {file_name}.")
    else:
        print("Connection failed. Exiting...")

if __name__ == "__main__":
    main()
