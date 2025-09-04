#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Padocca - Elite Pentesting Framework
Main CLI interface that orchestrates all tools
"""

import os
import sys
import json
import subprocess
import argparse
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional
import platform

# ASCII Art Banner
BANNER = """
\033[36m
    ██████╗  █████╗ ██████╗  ██████╗  ██████╗ ██████╗ █████╗ 
    ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
    ██████╔╝███████║██║  ██║██║   ██║██║     ██║     ███████║
    ██╔═══╝ ██╔══██║██║  ██║██║   ██║██║     ██║     ██╔══██║
    ██║     ██║  ██║██████╔╝╚██████╔╝╚██████╗╚██████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═════╝╚═╝  ╚═╝
\033[0m
    \033[33m🥖 Elite Pentesting Framework v2.0 🥖\033[0m
    \033[34mFast • Powerful • Stealthy\033[0m
"""

class Colors:
    """Terminal colors"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class Padocca:
    """Main Padocca orchestrator"""
    
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.build_dir = self.base_dir / "build"
        self.tools = {
            "scan": self.build_dir / "padocca-core",
            "crawl": self.build_dir / "padocca-crawler",
            "brute": self.build_dir / "padocca-brute",
        }
        self.check_installation()
    
    def check_installation(self):
        """Check if all tools are built and available"""
        missing = []
        for tool, path in self.tools.items():
            if not path.exists():
                missing.append(tool)
        
        if missing:
            print(f"{Colors.RED}❌ Missing tools: {', '.join(missing)}{Colors.RESET}")
            print(f"{Colors.YELLOW}Run 'make build' to compile all tools{Colors.RESET}")
            sys.exit(1)
    
    def run_tool(self, tool: str, args: List[str]) -> int:
        """Run a specific tool with arguments"""
        if tool not in self.tools:
            print(f"{Colors.RED}Unknown tool: {tool}{Colors.RESET}")
            return 1
        
        tool_path = self.tools[tool]
        cmd = [str(tool_path)] + args
        
        try:
            result = subprocess.run(cmd, check=False)
            return result.returncode
        except Exception as e:
            print(f"{Colors.RED}Error running {tool}: {e}{Colors.RESET}")
            return 1
    
    def master_scan(self, target: str, options: Dict):
        """Run comprehensive scan on target"""
        print(f"\n{Colors.CYAN}🎯 Starting Master Scan on {target}{Colors.RESET}")
        print(f"{Colors.YELLOW}{'='*60}{Colors.RESET}\n")
        
        results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scans": {}
        }
        
        # Phase 1: Network Discovery
        if options.get("discover", True):
            print(f"{Colors.GREEN}[1/5] Network Discovery...{Colors.RESET}")
            self.run_tool("scan", ["discover", "-n", target, "--method", "arp"])
        
        # Phase 2: Port Scanning
        if options.get("ports", True):
            print(f"\n{Colors.GREEN}[2/5] Port Scanning...{Colors.RESET}")
            scan_args = ["scan", "-t", target, "-p", "1-65535"]
            if options.get("stealth"):
                scan_args.append("--stealth")
            self.run_tool("scan", scan_args)
        
        # Phase 3: Web Crawling
        if options.get("web", True):
            print(f"\n{Colors.GREEN}[3/5] Web Crawling...{Colors.RESET}")
            self.run_tool("crawl", ["-u", f"https://{target}", "-d", "3", "-e"])
        
        # Phase 4: SSL Analysis
        if options.get("ssl", True):
            print(f"\n{Colors.GREEN}[4/5] SSL/TLS Analysis...{Colors.RESET}")
            self.run_tool("scan", ["ssl", "-t", f"{target}:443", "--vuln-check"])
        
        # Phase 5: Vulnerability Assessment
        if options.get("vuln", True):
            print(f"\n{Colors.GREEN}[5/5] Vulnerability Assessment...{Colors.RESET}")
            # Additional vulnerability checks can be added here
        
        print(f"\n{Colors.GREEN}✅ Master scan completed!{Colors.RESET}")
        
        # Save results
        if options.get("output"):
            self.save_results(results, options["output"])
    
    def save_results(self, results: Dict, filename: str):
        """Save scan results to file"""
        output_path = Path(filename)
        
        if output_path.suffix == ".json":
            with open(output_path, 'w') as f:
                json.dump(results, f, indent=2)
        else:
            # Default to text format
            with open(output_path, 'w') as f:
                f.write(f"Padocca Scan Report\n")
                f.write(f"{'='*60}\n")
                f.write(f"Target: {results['target']}\n")
                f.write(f"Timestamp: {results['timestamp']}\n")
                f.write(f"{'='*60}\n")
        
        print(f"{Colors.GREEN}Results saved to {filename}{Colors.RESET}")

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Padocca - Elite Pentesting Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  padocca scan -t 192.168.1.1 -p 1-1000        # Port scan
  padocca crawl -u example.com -d 3            # Web crawl
  padocca master -t example.com --stealth      # Full audit
  padocca exploit --generate reverse_shell     # Generate payload
        '''
    )
    
    # Global options
    parser.add_argument('--stealth', action='store_true', 
                       help='Enable stealth mode')
    parser.add_argument('--tor', action='store_true',
                       help='Route through Tor')
    parser.add_argument('--aggressive', action='store_true',
                       help='Aggressive mode (faster but noisier)')
    parser.add_argument('--threads', type=int, default=100,
                       help='Number of threads (default: 100)')
    parser.add_argument('-o', '--output', type=str,
                       help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    parser.add_argument('--version', action='version',
                       version='Padocca 2.0.0')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Port scanning')
    scan_parser.add_argument('-t', '--target', required=True, help='Target IP/host')
    scan_parser.add_argument('-p', '--ports', default='1-1000', help='Port range')
    scan_parser.add_argument('--scan-type', default='tcp', 
                           choices=['tcp', 'syn', 'udp'], help='Scan type')
    
    # Crawl command
    crawl_parser = subparsers.add_parser('crawl', help='Web crawling')
    crawl_parser.add_argument('-u', '--url', required=True, help='Target URL')
    crawl_parser.add_argument('-d', '--depth', type=int, default=3, 
                            help='Crawl depth')
    crawl_parser.add_argument('-e', '--extract', action='store_true',
                            help='Extract all information')
    
    # Discover command
    discover_parser = subparsers.add_parser('discover', help='Network discovery')
    discover_parser.add_argument('-n', '--network', required=True, 
                               help='Network CIDR')
    discover_parser.add_argument('--method', default='arp',
                               choices=['arp', 'icmp', 'tcp'])
    
    # Brute command
    brute_parser = subparsers.add_parser('brute', help='Brute force attacks')
    brute_parser.add_argument('-t', '--target', required=True, help='Target')
    brute_parser.add_argument('-u', '--userlist', help='Username list')
    brute_parser.add_argument('-p', '--passlist', help='Password list')
    brute_parser.add_argument('--protocol', default='http',
                            choices=['http', 'ssh', 'ftp', 'mysql'])
    
    # Master command
    master_parser = subparsers.add_parser('master', help='Run full audit')
    master_parser.add_argument('-t', '--target', required=True, help='Target')
    master_parser.add_argument('--skip-discovery', action='store_true')
    master_parser.add_argument('--skip-ports', action='store_true')
    master_parser.add_argument('--skip-web', action='store_true')
    
    # Exploit command
    exploit_parser = subparsers.add_parser('exploit', help='Generate exploits')
    exploit_parser.add_argument('--generate', required=True, help='Payload type')
    exploit_parser.add_argument('--os', default='linux', 
                              choices=['linux', 'windows', 'macos'])
    exploit_parser.add_argument('--encode', help='Encoding method')
    
    args = parser.parse_args()
    
    # Print banner
    if not args.command or args.verbose:
        print(BANNER)
    
    # Initialize Padocca
    padocca = Padocca()
    
    # Handle commands
    if not args.command:
        parser.print_help()
        return 0
    
    # Build command arguments
    cmd_args = []
    
    if args.command == 'scan':
        cmd_args = ['scan', '-t', args.target, '-p', args.ports, 
                   '--scan-type', args.scan_type]
        if args.stealth:
            cmd_args.append('--stealth')
        if args.verbose:
            cmd_args.append('--verbose')
        return padocca.run_tool('scan', cmd_args[1:])
    
    elif args.command == 'crawl':
        cmd_args = ['-u', args.url, '-d', str(args.depth)]
        if args.extract:
            cmd_args.append('-e')
        if args.output:
            cmd_args.extend(['-o', args.output])
        return padocca.run_tool('crawl', cmd_args)
    
    elif args.command == 'discover':
        cmd_args = ['discover', '-n', args.network, '--method', args.method]
        return padocca.run_tool('scan', cmd_args[1:])
    
    elif args.command == 'brute':
        print(f"{Colors.YELLOW}Brute force module not yet implemented{Colors.RESET}")
        return 0
    
    elif args.command == 'master':
        options = {
            'discover': not args.skip_discovery,
            'ports': not args.skip_ports,
            'web': not args.skip_web,
            'ssl': True,
            'vuln': True,
            'stealth': args.stealth,
            'output': args.output
        }
        padocca.master_scan(args.target, options)
        return 0
    
    elif args.command == 'exploit':
        cmd_args = ['exploit', '-p', args.generate, '--os', args.os]
        if args.encode:
            cmd_args.extend(['-e', args.encode])
        return padocca.run_tool('scan', cmd_args[1:])
    
    return 0

if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
        sys.exit(130)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {e}{Colors.RESET}")
        sys.exit(1)
