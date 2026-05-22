#!/usr/bin/env python3
import os
import sys
import re
import asyncio
import argparse

# Command rate limiter
RATE_LIMIT = 1.5  # seconds between commands for the same device
rate_limiters = {}

async def async_gnetch_command(cmd, target):
    """
    Asynchronously execute a gnetch command using asyncio subprocess.
    """
    gnetch_cmd = f"stubby --proto2 call blade:gnetch-frontend Gnetch2.Command 'command: \"{cmd}\" target: \"{target}\"'"
    process = await asyncio.create_subprocess_shell(
        gnetch_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, _ = await process.communicate()
    raw_out = stdout.decode()
    match = re.search(r'data:\s*"(.*)"', raw_out, re.DOTALL)
    if match:
        # Extract inner content and split by escaped newlines
        content = match.group(1)
        # Clean up escaped backslashes/quotes
        content = content.replace('\\"', '"')
        return content.split("\\n")
    return []

async def rate_limited_gnetch_command(cmd, target):
    """
    Execute gnetch_command with rate limiting for the target device.
    """
    if target not in rate_limiters:
        rate_limiters[target] = asyncio.Semaphore(1)

    async with rate_limiters[target]:
        output = await async_gnetch_command(cmd, target)
        await asyncio.sleep(RATE_LIMIT)  # Enforce the rate limit
        return output

def parse_isis_adjacencies(lines):
    adjacencies = []
    for line in lines:
        match = re.search(r"\b(\S+)\s+\S+\s+(Up)\s+\d+\s+(ae\d+)\b", line, re.IGNORECASE)
        if match:
            system_id = match.group(1)
            interface = match.group(3)
            adjacencies.append({
                "system_id": system_id,
                "interface": interface
            })
    return adjacencies

def parse_router_interface(lines, interface_name):
    for line in lines:
        match = re.search(rf"\b({interface_name})\b\s+\S+\s+\S+\s+\S+\s+(\S+)", line)
        if match:
            return match.group(2)
    return None

def parse_lag_ports(lines, lag_id):
    ports = []
    for line in lines:
        if "up" in line.lower() or "active" in line.lower():
            match = re.search(r"\b\d+/\d+/[a-zA-Z0-9]+(?:/[a-zA-Z0-9]+)*\b", line)
            if match:
                ports.append(match.group(0))
    return ports

def parse_port_speed(lines):
    for line in lines:
        if "Oper Speed" in line:
            parts = line.split(":")
            if len(parts) >= 3:
                speed_str = parts[2].strip()
                match = re.match(r"^(\d+)\s*(Gbps|Mbps|kbps|Gb|Mb|Kb)", speed_str, re.IGNORECASE)
                if match:
                    val = int(match.group(1))
                    unit = match.group(2).lower()
                    if "g" in unit:
                        return val * 1_000_000_000
                    elif "m" in unit:
                        return val * 1_000_000
                    elif "k" in unit:
                        return val * 1_000
                return 0
    return 0

def parse_monitor_lag_totals(lines):
    # Iterate backwards to find the last "Totals" block
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip().startswith("Totals"):
            # The next line contains the total bytes
            if i + 1 < len(lines):
                parts = lines[i+1].split()
                if len(parts) >= 2:
                    in_bytes = int(parts[0])
                    out_bytes = int(parts[1])
                    return in_bytes, out_bytes
    return 0, 0

async def audit_device(target):
    print(f"Starting BGP Interface Audit on target: {target}...")
    
    # 1) show router isis adjacency
    print("Executing show router isis adjacency...")
    isis_output = await rate_limited_gnetch_command("show router isis adjacency", target)
    adjacencies = parse_isis_adjacencies(isis_output)
    
    if not adjacencies:
        print("No active ISIS adjacencies on bundle interfaces found.")
        return
    
    print(f"Found {len(adjacencies)} active adjacencies.")
    
    for adj in adjacencies:
        intf = adj["interface"]
        system_id = adj["system_id"]
        print(f"\nAuditing Interface: {intf} (Neighbor: {system_id})")
        
        # 2) show router interface <intf>
        intf_output = await rate_limited_gnetch_command(f'show router interface {intf}', target)
        lag_id = parse_router_interface(intf_output, intf)
        
        if not lag_id:
            print(f"Could not find LAG associated with interface {intf}.")
            continue
            
        print(f"Associated LAG: {lag_id}")
        
        # 3) show lag <lag_id> port
        lag_output = await rate_limited_gnetch_command(f'show lag {lag_id} port', target)
        ports = parse_lag_ports(lag_output, lag_id)
        
        if not ports:
            print(f"No active ports found in LAG {lag_id}.")
            continue
            
        print(f"LAG Member Ports: {ports}")
        
        total_lag_speed = 0
        port_speeds = {}
        
        # 4) find out the speed of each port
        for port in ports:
            port_output = await rate_limited_gnetch_command(f"show port {port}", target)
            speed = parse_port_speed(port_output)
            port_speeds[port] = speed
            total_lag_speed += speed
            
        if total_lag_speed == 0:
            print(f"Total speed for LAG {lag_id} could not be determined.")
            continue
            
        print(f"Total LAG Capacity: {total_lag_speed / 1e9} Gbps")
        
        # 5) use monitor lag command to get total input and output bytes
        lag_num_match = re.search(r"\d+", lag_id)
        if not lag_num_match:
            print(f"Could not extract LAG number from {lag_id}.")
            continue
            
        lag_num = lag_num_match.group(0)
        print(f"Monitoring LAG ID {lag_num} over 3s interval...")
        
        monitor_output = await rate_limited_gnetch_command(f"monitor lag {lag_num} interval 3 repeat 3", target)
        in_bytes, out_bytes = parse_monitor_lag_totals(monitor_output)
        
        # Convert bytes into bits, divided by 3 seconds to get bps
        in_bps = (in_bytes * 8) / 3.0
        out_bps = (out_bytes * 8) / 3.0
        
        # Calculate utilization percents
        input_util = (in_bps / total_lag_speed) * 100
        output_util = (out_bps / total_lag_speed) * 100
        
        print(f"{intf}: input: {input_util:.0f}%, output: {output_util:.0f}%")

async def main():
    parser = argparse.ArgumentParser(description="Audit SROS BGP/ISIS interfaces utilization using monitor snapshots.")
    parser.add_argument("-t", "--target", required=True, help="Target SROS device hostname (e.g. bng01.atl101)")
    args = parser.parse_args()
    
    await audit_device(args.target)

if __name__ == "__main__":
    asyncio.run(main())
