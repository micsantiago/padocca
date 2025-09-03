#!/usr/bin/env python3
"""
PADOCCA CLI - Main command-line interface
"""

import os
import sys
import click
import subprocess
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint
from . import __version__, print_banner

console = Console()

# Find binary directory
def get_bin_dir():
    """Get the binary directory path"""
    # Check multiple possible locations
    possible_paths = [
        Path(__file__).parent / "bin",
        Path("/opt/padocca/bin"),
        Path.home() / ".local/padocca/bin",
        Path("/usr/local/bin"),
        Path(__file__).parent.parent / "bin",
    ]
    
    for path in possible_paths:
        if path.exists():
            return str(path)
    
    # Fallback to local bin
    return str(Path(__file__).parent / "bin")

def run_binary(binary_name, args):
    """Run a compiled binary tool"""
    bin_dir = get_bin_dir()
    binary_path = Path(bin_dir) / binary_name
    
    if not binary_path.exists():
        console.print(f"[red][!] Binary not found: {binary_name}[/red]")
        console.print(f"[yellow]Please run: pip install --upgrade padocca[/yellow]")
        return False
    
    try:
        cmd = [str(binary_path)] + list(args)
        subprocess.run(cmd, check=False)
        return True
    except Exception as e:
        console.print(f"[red][!] Error running {binary_name}: {e}[/red]")
        return False

@click.group(invoke_without_command=True)
@click.pass_context
@click.version_option(version=__version__, prog_name="padocca")
def cli(ctx):
    """PADOCCA - Elite Pentesting Framework
    
    Professional security testing suite with WAF bypass,
    advanced OSINT, and exploit development capabilities.
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("\n[bold cyan]Available Commands:[/bold cyan]\n")
        
        # Create commands table
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Command", style="cyan", width=15)
        table.add_column("Description", style="white")
        table.add_column("Example", style="green")
        
        commands = [
            ("scan", "Full comprehensive scan", "padocca scan example.com"),
            ("xss", "XSS/SQLi scanner with WAF bypass", "padocca xss https://example.com"),
            ("osint", "Deep OSINT intelligence", "padocca osint example.com"),
            ("brute", "Intelligent stealth bruteforce", "padocca brute https://example.com/admin"),
            ("dns", "DNS enumeration", "padocca dns example.com"),
            ("ports", "Port scanning", "padocca ports 192.168.1.1"),
            ("crawl", "Web crawling", "padocca crawl https://example.com"),
            ("fuzz", "Directory fuzzing", "padocca fuzz https://example.com"),
            ("ssl", "SSL/TLS analysis", "padocca ssl example.com"),
            ("exploit", "Exploit framework", "padocca exploit --help"),
        ]
        
        for cmd, desc, example in commands:
            table.add_row(cmd, desc, example)
        
        console.print(table)
        console.print("\n[bold]Use:[/bold] padocca <command> --help for more information\n")

@cli.command()
@click.argument('domain')
@click.option('--deep', is_flag=True, help='Deep scan mode')
@click.option('--output', '-o', help='Output file')
def scan(domain, deep, output):
    """Perform comprehensive security scan"""
    print_banner()
    console.print(f"[cyan][*] Starting comprehensive scan on {domain}[/cyan]\n")
    
    # Run various scans
    tools = [
        ("dns_enum", [domain]),
        ("port_scanner", [domain]),
        ("web_crawler", [f"https://{domain}"]),
        ("xss_sqli_scanner", [f"https://{domain}"]),
        ("osint_intelligence", [domain]),
    ]
    
    for i, (tool, args) in enumerate(tools, 1):
        console.print(f"\n[yellow][{i}/5] Running {tool}...[/yellow]")
        run_binary(tool, args)
    
    console.print("\n[green][+] Scan complete![/green]")
    
    if output:
        console.print(f"[green]Results saved to: {output}[/green]")

@cli.command()
@click.argument('url')
@click.option('--waf-bypass', is_flag=True, default=True, help='Enable WAF bypass')
@click.option('--threads', '-t', default=10, help='Number of threads')
def xss(url, waf_bypass, threads):
    """Advanced XSS/SQLi scanner with WAF bypass"""
    print_banner()
    console.print(f"[cyan][*] XSS/SQLi Scanning: {url}[/cyan]")
    
    if waf_bypass:
        console.print("[yellow][*] WAF bypass enabled[/yellow]")
    
    run_binary("xss_sqli_scanner", [url])

@cli.command()
@click.argument('domain')
@click.option('--deep', is_flag=True, help='Deep OSINT analysis')
@click.option('--email', is_flag=True, help='Focus on email discovery')
@click.option('--social', is_flag=True, help='Include social media')
def osint(domain, deep, email, social):
    """Deep OSINT intelligence gathering"""
    print_banner()
    console.print(f"[cyan][*] OSINT Intelligence Gathering: {domain}[/cyan]")
    
    args = [domain]
    if deep:
        args.append("--deep")
    if email:
        args.append("--email")
    if social:
        args.append("--social")
    
    run_binary("osint_intelligence", args)

@cli.command()
@click.argument('url')
@click.option('--stealth', type=click.IntRange(1, 5), default=5, help='Stealth level (1-5)')
@click.option('--wordlist', '-w', help='Custom wordlist')
@click.confirmation_option(prompt='Are you authorized to test this target?')
def brute(url, stealth, wordlist):
    """Intelligent stealth bruteforce"""
    print_banner()
    console.print(f"[cyan][*] Intelligent Bruteforce: {url}[/cyan]")
    console.print(f"[yellow][*] Stealth level: {stealth}/5[/yellow]")
    
    args = [url, f"--stealth={stealth}"]
    if wordlist:
        args.extend(["-w", wordlist])
    
    run_binary("intelligent_bruteforce", args)

@cli.command()
@click.argument('domain')
@click.option('--recursive', '-r', is_flag=True, help='Recursive enumeration')
def dns(domain, recursive):
    """DNS enumeration"""
    console.print(f"[cyan][*] DNS Enumeration: {domain}[/cyan]")
    
    args = [domain]
    if recursive:
        args.append("--recursive")
    
    run_binary("dns_enum", args)

@cli.command()
@click.argument('target')
@click.option('--fast', is_flag=True, help='Fast scan (top 100 ports)')
@click.option('--all', 'scan_all', is_flag=True, help='Scan all ports')
def ports(target, fast, scan_all):
    """Port scanning"""
    console.print(f"[cyan][*] Port Scanning: {target}[/cyan]")
    
    args = [target]
    if fast:
        args.append("--fast")
    elif scan_all:
        args.append("--all")
    
    run_binary("port_scanner", args)

@cli.command()
@click.argument('url')
@click.option('--depth', '-d', default=3, help='Crawl depth')
@click.option('--timeout', '-t', default=10, help='Request timeout')
def crawl(url, depth, timeout):
    """Web crawling for URLs and emails"""
    console.print(f"[cyan][*] Web Crawling: {url}[/cyan]")
    
    args = [url, f"--depth={depth}", f"--timeout={timeout}"]
    run_binary("web_crawler", args)

@cli.command()
@click.argument('url')
@click.option('--wordlist', '-w', help='Custom wordlist')
@click.option('--extensions', '-x', default='php,html,txt', help='File extensions')
def fuzz(url, wordlist, extensions):
    """Directory and file fuzzing"""
    console.print(f"[cyan][*] Directory Fuzzing: {url}[/cyan]")
    
    args = [url]
    if wordlist:
        args.extend(["-w", wordlist])
    args.extend(["-x", extensions])
    
    run_binary("directory_fuzzer", args)

@cli.command()
@click.argument('domain')
@click.option('--port', '-p', default=443, help='Port to test')
def ssl(domain, port):
    """SSL/TLS security analysis"""
    console.print(f"[cyan][*] SSL/TLS Analysis: {domain}:{port}[/cyan]")
    
    # This could call a Python function or binary
    from padocca.modules import ssl_analyzer
    ssl_analyzer.analyze(domain, port)

@cli.group()
def exploit():
    """Exploit development framework"""
    pass

@exploit.command()
@click.argument('binary')
@click.option('--arch', default='x64', help='Architecture (x86/x64/arm)')
def rop(binary, arch):
    """Generate ROP chain"""
    console.print(f"[cyan][*] Generating ROP chain for: {binary}[/cyan]")
    run_binary("exploit-framework", ["rop-chain", "-b", binary, "-a", arch])

@exploit.command()
@click.argument('target')
@click.option('--technique', '-t', help='Bypass technique')
def bypass(target, technique):
    """Bypass security protections (ASLR/DEP)"""
    console.print(f"[cyan][*] Bypassing protections for: {target}[/cyan]")
    
    args = ["bypass", "-t", target]
    if technique:
        args.extend(["--technique", technique])
    
    run_binary("exploit-framework", args)

@exploit.command()
@click.argument('type', type=click.Choice(['reverse', 'bind', 'exec']))
@click.option('--params', '-p', help='Parameters (IP:PORT for shells)')
@click.option('--encode', '-e', help='Encoding type')
def shellcode(type, params, encode):
    """Generate advanced shellcode"""
    console.print(f"[cyan][*] Generating {type} shellcode[/cyan]")
    
    args = ["shellcode", "-p", type]
    if params:
        args.extend(["--params", params])
    if encode:
        args.extend(["--encode", encode])
    
    run_binary("exploit-framework", args)

@exploit.command()
@click.argument('binary')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(binary, verbose):
    """Analyze binary protections"""
    console.print(f"[cyan][*] Analyzing binary: {binary}[/cyan]")
    
    args = ["analyze", "-b", binary]
    if verbose:
        args.append("--verbose")
    
    run_binary("exploit-framework", args)

@cli.command()
def update():
    """Update Padocca to the latest version"""
    console.print("[cyan][*] Updating Padocca...[/cyan]")
    
    try:
        subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "padocca"], check=True)
        console.print("[green][+] Padocca updated successfully![/green]")
    except Exception as e:
        console.print(f"[red][!] Update failed: {e}[/red]")

@cli.command()
def doctor():
    """Check Padocca installation health"""
    print_banner()
    console.print("[cyan][*] Running health check...[/cyan]\n")
    
    # Check components
    checks = {
        "Python": sys.version.split()[0],
        "Padocca Version": __version__,
        "Binary Directory": get_bin_dir(),
    }
    
    # Check for binaries
    binaries = [
        "xss_sqli_scanner",
        "osint_intelligence",
        "intelligent_bruteforce",
        "dns_enum",
        "web_crawler",
        "port_scanner"
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")
    
    for component, detail in checks.items():
        table.add_row(component, "✅ OK", detail)
    
    bin_dir = Path(get_bin_dir())
    for binary in binaries:
        if (bin_dir / binary).exists():
            table.add_row(f"Binary: {binary}", "✅ OK", "Found")
        else:
            table.add_row(f"Binary: {binary}", "❌ Missing", "Not compiled")
    
    console.print(table)
    
    # Check for Go and Rust
    console.print("\n[cyan]Optional Dependencies:[/cyan]")
    
    for cmd, name in [("go", "Go"), ("cargo", "Rust")]:
        try:
            result = subprocess.run([cmd, "version"], capture_output=True, text=True)
            if result.returncode == 0:
                version = result.stdout.strip().split()[2] if cmd == "go" else result.stdout.strip().split()[1]
                console.print(f"  ✅ {name}: {version}")
        except:
            console.print(f"  ⚠️  {name}: Not installed (some features limited)")
    
    console.print("\n[green][+] Health check complete![/green]")

def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
