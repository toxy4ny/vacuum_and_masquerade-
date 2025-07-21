#!/usr/bin/env python3
import requests
import json
import socket
import concurrent.futures
import random
import ipaddress
import argparse
from datetime import datetime
import sys
import time
import os

LOGO = r"""

{__         {__      {_           {__   {__     {__{__     {__{__       {__
 {__       {__      {_ __      {__   {__{__     {__{__     {__{_ {__   {___
  {__     {__      {_  {__    {__       {__     {__{__     {__{__ {__ { {__
   {__   {__      {__   {__   {__       {__     {__{__     {__{__  {__  {__
    {__ {__      {______ {__  {__       {__     {__{__     {__{__   {_  {__
     {____      {__       {__  {__   {__{__     {__{__     {__{__       {__
      {__      {__         {__   {____    {_____     {_____   {__       {__
                                                                           
BY KL3FT3Z https://github.com/toxy4ny
"""

def banner():

    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)
    print("DNS Amplification Vulnerable Scanner\n")



try:
    from scapy.all import *
    SCAPY_AVAILABLE = True
except ImportError:
    print("⚠️ Scapy is not installed. Installing it...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "scapy"])
    from scapy.all import *
    SCAPY_AVAILABLE = True

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    print("⚠️ dnspython is not installed. Installing it...")
    import subprocess  
    subprocess.check_call([sys.executable, "-m", "pip", "install", "dnspython"])
    import dns.resolver
    DNS_AVAILABLE = True

class DNSAmplificationScanner:
    def __init__(self):
        self.vulnerable_servers = []
        self.public_dns_lists = [
            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt"
        ]
        
    def is_valid_ip(self, ip_str):
        
        try:
            ipaddress.ip_address(ip_str)
            return True
        except:
            return False
            
    def collect_public_dns_servers(self):
        
        dns_servers = set()
        
        known_dns = [
            "8.8.8.8", "8.8.4.4",  
            "1.1.1.1", "1.0.0.1",  
            "208.67.222.222", "208.67.220.220", 
            "9.9.9.9", "149.112.112.112",  
            "77.88.8.8", "77.88.8.1",  
            "4.2.2.1", "4.2.2.2",  
            "156.154.70.1", "156.154.71.1",
        ]
        dns_servers.update(known_dns)
        print(f"✅ Added {len(known_dns)} known DNS servers")
        
        for url in self.public_dns_lists:
            try:
                print(f"📥 Downloading from {url}")
                response = requests.get(url, timeout=10)
                count = 0
                
                for line in response.text.strip().split('\n'):
                    ip = line.strip()
                    if self.is_valid_ip(ip):
                        dns_servers.add(ip)
                        count += 1
                        
                print(f"✅ {count} DNS servers received from the list")
                
            except Exception as e:
                print(f"❌ Download error {url}: {e}")
        
        return list(dns_servers)

    def scan_network_ranges(self, networks):
        
        dns_servers = []
        
        def scan_host(ip):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(1)
                
                query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
                sock.sendto(query, (str(ip), 53))
                
                response, addr = sock.recvfrom(512)
                if len(response) > 12: 
                    return str(ip)
                    
            except:
                pass
            finally:
                sock.close()
            return None
        
        for network in networks:
            print(f"🔍 Network scanning {network}")
            try:
                net = ipaddress.IPv4Network(network, strict=False)
                total_hosts = sum(1 for _ in net.hosts())
                
                if total_hosts > 1000:
                    print(f"⚠️ The {network} contains {total_hosts} hosts, it will take a long time")
                    response = input("Continue? (y/n): ")
                    if response.lower() != 'y':
                        continue
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                    futures = []
                    for ip in net.hosts():
                        futures.append(executor.submit(scan_host, ip))
                    
                    processed = 0
                    for future in concurrent.futures.as_completed(futures):
                        result = future.result()
                        processed += 1
                        
                        if result:
                            dns_servers.append(result)
                            print(f"✅ DNS server found: {result}")
                        
                        if processed % 50 == 0:
                            print(f"📊 Scan progress: {processed}/{total_hosts}")
                            
            except Exception as e:
                print(f"❌ Scan error {network}: {e}")
        
        return dns_servers

class AmplificationTester:
    def __init__(self):
        self.test_queries = [
            ('ANY', 'google.com'),
            ('ANY', 'facebook.com'),  
            ('TXT', 'google.com'),
            ('MX', 'google.com'),
            ('NS', 'google.com'),
        ]
    
    def test_amplification_simple(self, dns_server, timeout=3):
        
        results = []
        
        for qtype, domain in self.test_queries:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                
                transaction_id = random.randint(1, 65535)
                
                if qtype == 'ANY':
                    qtype_num = 255
                elif qtype == 'TXT':
                    qtype_num = 16
                elif qtype == 'MX':
                    qtype_num = 15
                elif qtype == 'NS':
                    qtype_num = 2
                else:
                    qtype_num = 1  
                
                query = struct.pack('>HHHHHH', transaction_id, 0x0100, 1, 0, 0, 0)
                
                for part in domain.split('.'):
                    query += struct.pack('B', len(part)) + part.encode()
                query += b'\x00'  
                
                query += struct.pack('>HH', qtype_num, 1) 
                
                query_size = len(query)
                
                sock.sendto(query, (dns_server, 53))
                response, _ = sock.recvfrom(4096)
                
                response_size = len(response)
                amplification_factor = response_size / query_size
                
                result = {
                    'server': dns_server,
                    'query_type': qtype,
                    'domain': domain,
                    'query_size': query_size,
                    'response_size': response_size,
                    'amplification': round(amplification_factor, 2),
                    'vulnerable': amplification_factor > 2.0
                }
                results.append(result)
                
                sock.close()
                
            except Exception as e:
                if sock:
                    sock.close()
                continue
        
        return results
    
    def test_multiple_servers(self, dns_servers):
        
        vulnerable_servers = []
        
        def test_server(server):
            try:
                results = self.test_amplification_simple(server)
                max_amplification = 0
                best_result = None
                
                for result in results:
                    if result['amplification'] > max_amplification:
                        max_amplification = result['amplification']
                        best_result = result
                
                if best_result and best_result['vulnerable']:
                    return best_result
                return None
            except Exception as e:
                return None
        
        print(f"🧪 Testing {len(dns_servers)} DNS servers for amplification...")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            futures = []
            for server in dns_servers:
                futures.append(executor.submit(test_server, server))
            
            processed = 0
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                processed += 1
                
                if result:
                    vulnerable_servers.append(result)
                    print(f"🎯 Vulnerable server: {result['server']:<15s} | "
                          f"x{result['amplification']:5.1f} | "
                          f"{result['query_type']:3s} | "
                          f"{result['response_size']:4d}B")
                
                if processed % 20 == 0:
                    print(f"📊 Progress: {processed}/{len(dns_servers)} "
                          f"| Vulnerable servers found: {len(vulnerable_servers)}")
        
        return vulnerable_servers

class DNSAnalytics:
    def generate_report(self, vulnerable_servers):
        
        if not vulnerable_servers:
            return {
                'total_vulnerable': 0,
                'top_amplifiers': [],
                'statistics': {
                    'avg_amplification': 0,
                    'max_amplification': 0,
                    'query_types': {}
                }
            }
            
        report = {
            'total_vulnerable': len(vulnerable_servers),
            'top_amplifiers': sorted(vulnerable_servers, 
                                   key=lambda x: x['amplification'], 
                                   reverse=True)[:10],
            'statistics': {
                'avg_amplification': round(sum(s['amplification'] for s in vulnerable_servers) / len(vulnerable_servers), 2),
                'max_amplification': max(s['amplification'] for s in vulnerable_servers),
                'query_types': {}
            }
        }
        
        
        for server_data in vulnerable_servers:
            qtype = server_data['query_type']
            if qtype not in report['statistics']['query_types']:
                report['statistics']['query_types'][qtype] = []
            report['statistics']['query_types'][qtype].append(server_data['amplification'])
        
        
        for qtype in report['statistics']['query_types']:
            amplifications = report['statistics']['query_types'][qtype]
            report['statistics']['query_types'][qtype] = {
                'count': len(amplifications),
                'avg_amplification': round(sum(amplifications) / len(amplifications), 2),
                'max_amplification': max(amplifications)
            }
        
        return report

def main():
    banner()
    print("🔍 VACUUM a DNS Amplification Vulnerability Scanner")
    print("=" * 50)
    print("⚠️ FOR EDUCATIONAL PURPOSES ONLY!")
    print("=" * 50)
    
    parser = argparse.ArgumentParser(description="DNS Amplification Vulnerability Scanner")
    parser.add_argument('--mode', choices=['public', 'scan', 'all'], default='public',
                       help='Operating mode: public, scan или all')
    parser.add_argument('--networks', nargs='+', 
                       help='Network ranges for scanning (for example: 8.8.8.0/24)')
    parser.add_argument('--output', default='dns_amplification_report.json',
                       help='File to save the report')
    parser.add_argument('--limit', type=int, default=1000,
                       help='Maximum number of servers for testing')
    
    args = parser.parse_args()
    
    scanner = DNSAmplificationScanner()
    tester = AmplificationTester()
    analytics = DNSAnalytics()
    
    all_dns_servers = set()
    
    if args.mode in ['public', 'all']:
        print("\n📡 Collection of public DNS servers...")
        public_servers = scanner.collect_public_dns_servers()
        all_dns_servers.update(public_servers)
        print(f"✅ Public DNS servers found: {len(public_servers)}")
    
    if args.mode in ['scan', 'all'] and args.networks:
        print("\n🌐 Scanning network ranges...")
        scanned_servers = scanner.scan_network_ranges(args.networks)
        all_dns_servers.update(scanned_servers)
        print(f"✅ DNS servers found during the scan: {len(scanned_servers)}")
    
    all_dns_servers = list(all_dns_servers)
    
    if len(all_dns_servers) > args.limit:
        print(f"⚠️ Limiting testing to {args.limit} servers")
        all_dns_servers = all_dns_servers[:args.limit]
    
    print(f"\n📊 Total DNS servers for testing: {len(all_dns_servers)}")
    
    if not all_dns_servers:
        print("❌ No DNS servers were found for testing!")
        return
    
    
    print("\n🧪 We are starting to test the amplification...")
    start_time = time.time()
    
    vulnerable_servers = tester.test_multiple_servers(all_dns_servers)
    
    end_time = time.time()
    test_duration = end_time - start_time
    
    print(f"\n" + "="*60)
    print(f"🎯SCAN RESULTS")
    print(f"="*60)
    print(f"📊 Total servers tested: {len(all_dns_servers)}")
    print(f"🎯 Vulnerable servers found: {len(vulnerable_servers)}")
    print(f"⏱️ Testing time: {test_duration:.1f} seconds")
    
    if vulnerable_servers:
        report = analytics.generate_report(vulnerable_servers)
        
        print(f"📈 Average amplification coefficient: {report['statistics']['avg_amplification']}")
        print(f"🚀 Maximum coefficient: {report['statistics']['max_amplification']}")
        
        final_report = {
            'timestamp': datetime.now().isoformat(),
            'scan_duration': test_duration,
            'total_servers_tested': len(all_dns_servers),
            'vulnerable_servers': vulnerable_servers,
            'statistics': report
        }
        
        with open(args.output, 'w') as f:
            json.dump(final_report, f, indent=2)
        
        print(f"\n📝 The detailed report is saved in {args.output}")
        
        
        print(f"\n🏆 TOP-{min(10, len(vulnerable_servers))} maximum vulnerable servers:")
        print("-" * 60)
        for i, server in enumerate(report['top_amplifiers'], 1):
            print(f"{i:2d}. {server['server']:15s} | "
                  f"x{server['amplification']:5.1f} | "
                  f"{server['query_type']:3s} | "
                  f"Query: {server['query_size']:3d}B -> Response: {server['response_size']:4d}B")
        
        
        if report['statistics']['query_types']:
            print(f"\n📊 Statistics on query types:")
            print("-" * 40)
            for qtype, stats in report['statistics']['query_types'].items():
                print(f"{qtype:3s}: {stats['count']:3d} servers | "
                      f"Average amplification: x{stats['avg_amplification']:5.1f} | "
                      f"Maximum: x{stats['max_amplification']:5.1f}")
    else:
        print("❌ Servers vulnerable to amplification were not found")
    
    print(f"\n" + "="*60)
    print("✅ Scan completed!")

if __name__ == "__main__":
    try:
        
        import os
        if os.geteuid() != 0:
            print("⚠️ It is recommended to run with root privileges for better performance.")
            print("  But you can continue without them...\n")
        
        main()
        
    except KeyboardInterrupt:
        print("\n\n❌ The scan was interrupted by the user")
    except Exception as e:
        print(f"\n❌ Critical error: {e}")
        import traceback
        traceback.print_exc()
