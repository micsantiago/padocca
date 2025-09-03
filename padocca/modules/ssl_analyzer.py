#!/usr/bin/env python3
"""
SSL/TLS Security Analyzer Module
"""

import ssl
import socket
import datetime
import subprocess
from typing import Dict, List, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import print as rprint

console = Console()

def get_certificate_info(domain: str, port: int = 443) -> Dict:
    """Get SSL certificate information"""
    try:
        context = ssl.create_default_context()
        
        with socket.create_connection((domain, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                return {
                    "cert": cert,
                    "cipher": cipher,
                    "version": version
                }
    except Exception as e:
        return {"error": str(e)}

def check_certificate_validity(cert: Dict) -> Dict:
    """Check certificate validity and expiration"""
    results = {}
    
    # Check expiration
    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
    not_before = datetime.datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
    now = datetime.datetime.utcnow()
    
    results['valid_from'] = not_before
    results['valid_until'] = not_after
    results['days_remaining'] = (not_after - now).days
    results['is_expired'] = now > not_after
    results['is_not_yet_valid'] = now < not_before
    
    # Check CN and SANs
    subject = dict(x[0] for x in cert['subject'])
    results['common_name'] = subject.get('commonName', 'N/A')
    
    sans = []
    for ext in cert.get('subjectAltName', []):
        sans.append(ext[1])
    results['san'] = sans
    
    # Issuer info
    issuer = dict(x[0] for x in cert['issuer'])
    results['issuer'] = issuer.get('organizationName', 'Unknown')
    
    return results

def check_vulnerabilities(domain: str, port: int = 443) -> List[Dict]:
    """Check for known SSL/TLS vulnerabilities"""
    vulnerabilities = []
    
    # Check for SSLv2/SSLv3
    for protocol in ['ssl2', 'ssl3']:
        try:
            cmd = f"timeout 5 openssl s_client -connect {domain}:{port} -{protocol} 2>/dev/null | grep -q 'CONNECTED'"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            if result.returncode == 0:
                vulnerabilities.append({
                    "name": f"{protocol.upper()} Enabled",
                    "severity": "HIGH",
                    "description": f"Deprecated {protocol.upper()} protocol is enabled"
                })
        except:
            pass
    
    # Check for weak ciphers
    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
    try:
        cmd = f"timeout 5 openssl s_client -connect {domain}:{port} -cipher 'ALL' 2>/dev/null"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        for cipher in weak_ciphers:
            if cipher in result.stdout:
                vulnerabilities.append({
                    "name": f"Weak Cipher: {cipher}",
                    "severity": "MEDIUM",
                    "description": f"Weak cipher {cipher} is supported"
                })
    except:
        pass
    
    # Check for Heartbleed
    try:
        cmd = f"timeout 5 openssl s_client -connect {domain}:{port} -tlsextdebug 2>&1 | grep -q 'heartbeat'"
        result = subprocess.run(cmd, shell=True, capture_output=True)
        
        if result.returncode == 0:
            vulnerabilities.append({
                "name": "Heartbleed",
                "severity": "CRITICAL",
                "description": "Server may be vulnerable to Heartbleed (CVE-2014-0160)"
            })
    except:
        pass
    
    return vulnerabilities

def test_tls_versions(domain: str, port: int = 443) -> Dict[str, bool]:
    """Test supported TLS versions"""
    versions = {}
    tls_versions = [
        ('tls1', 'TLS 1.0'),
        ('tls1_1', 'TLS 1.1'),
        ('tls1_2', 'TLS 1.2'),
        ('tls1_3', 'TLS 1.3')
    ]
    
    for flag, name in tls_versions:
        try:
            cmd = f"timeout 5 openssl s_client -connect {domain}:{port} -{flag} 2>/dev/null | grep -q 'CONNECTED'"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            versions[name] = result.returncode == 0
        except:
            versions[name] = False
    
    return versions

def analyze(domain: str, port: int = 443):
    """Main SSL/TLS analysis function"""
    console.print(Panel(f"[bold cyan]SSL/TLS Security Analysis[/bold cyan]\n[white]Target: {domain}:{port}[/white]", expand=False))
    
    # Get certificate info
    console.print("\n[cyan][*] Fetching certificate information...[/cyan]")
    cert_info = get_certificate_info(domain, port)
    
    if "error" in cert_info:
        console.print(f"[red][!] Error: {cert_info['error']}[/red]")
        return
    
    # Certificate details
    cert = cert_info['cert']
    validity = check_certificate_validity(cert)
    
    # Create certificate table
    cert_table = Table(title="Certificate Information", show_header=True, header_style="bold magenta")
    cert_table.add_column("Property", style="cyan")
    cert_table.add_column("Value", style="white")
    
    cert_table.add_row("Common Name", validity['common_name'])
    cert_table.add_row("Issuer", validity['issuer'])
    cert_table.add_row("Valid From", str(validity['valid_from']))
    cert_table.add_row("Valid Until", str(validity['valid_until']))
    
    # Days remaining status
    days = validity['days_remaining']
    if days < 0:
        days_str = f"[red]EXPIRED ({abs(days)} days ago)[/red]"
    elif days < 30:
        days_str = f"[yellow]{days} days[/yellow]"
    else:
        days_str = f"[green]{days} days[/green]"
    cert_table.add_row("Days Remaining", days_str)
    
    # SANs
    if validity['san']:
        cert_table.add_row("Alt Names", ", ".join(validity['san'][:3]) + ("..." if len(validity['san']) > 3 else ""))
    
    # Protocol and Cipher
    cert_table.add_row("Protocol", cert_info['version'])
    cert_table.add_row("Cipher Suite", f"{cert_info['cipher'][0]} ({cert_info['cipher'][2]} bits)")
    
    console.print("\n", cert_table)
    
    # Test TLS versions
    console.print("\n[cyan][*] Testing TLS version support...[/cyan]")
    tls_versions = test_tls_versions(domain, port)
    
    tls_table = Table(title="TLS Version Support", show_header=True, header_style="bold magenta")
    tls_table.add_column("Version", style="cyan")
    tls_table.add_column("Status", style="white")
    tls_table.add_column("Security", style="white")
    
    for version, supported in tls_versions.items():
        if supported:
            if version in ['TLS 1.0', 'TLS 1.1']:
                status = "✅ Supported"
                security = "[yellow]⚠ Deprecated[/yellow]"
            elif version == 'TLS 1.2':
                status = "✅ Supported"
                security = "[green]✅ Secure[/green]"
            else:  # TLS 1.3
                status = "✅ Supported"
                security = "[green]✅ Most Secure[/green]"
        else:
            status = "❌ Not Supported"
            security = "N/A"
        
        tls_table.add_row(version, status, security)
    
    console.print("\n", tls_table)
    
    # Check vulnerabilities
    console.print("\n[cyan][*] Checking for vulnerabilities...[/cyan]")
    vulnerabilities = check_vulnerabilities(domain, port)
    
    if vulnerabilities:
        vuln_table = Table(title="[red]Vulnerabilities Found[/red]", show_header=True, header_style="bold red")
        vuln_table.add_column("Vulnerability", style="red")
        vuln_table.add_column("Severity", style="yellow")
        vuln_table.add_column("Description", style="white")
        
        for vuln in vulnerabilities:
            severity_color = {
                "CRITICAL": "[red]CRITICAL[/red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[green]LOW[/green]"
            }
            vuln_table.add_row(
                vuln['name'],
                severity_color.get(vuln['severity'], vuln['severity']),
                vuln['description']
            )
        
        console.print("\n", vuln_table)
    else:
        console.print("[green][+] No major vulnerabilities detected[/green]")
    
    # Security recommendations
    console.print("\n[cyan][*] Security Recommendations:[/cyan]")
    recommendations = []
    
    if validity['days_remaining'] < 30:
        recommendations.append("• Renew certificate soon (expires in less than 30 days)")
    
    if tls_versions.get('TLS 1.0') or tls_versions.get('TLS 1.1'):
        recommendations.append("• Disable deprecated TLS 1.0 and TLS 1.1 protocols")
    
    if not tls_versions.get('TLS 1.3'):
        recommendations.append("• Enable TLS 1.3 for improved security")
    
    if vulnerabilities:
        recommendations.append("• Address identified vulnerabilities immediately")
    
    if recommendations:
        for rec in recommendations:
            console.print(f"  {rec}")
    else:
        console.print("  [green]✅ Configuration appears secure[/green]")
    
    # Overall grade
    console.print("\n[bold cyan]Overall Security Grade:[/bold cyan]", end=" ")
    
    score = 100
    if validity['is_expired']:
        score -= 50
    elif validity['days_remaining'] < 30:
        score -= 10
    
    if tls_versions.get('TLS 1.0'):
        score -= 15
    if tls_versions.get('TLS 1.1'):
        score -= 10
    if not tls_versions.get('TLS 1.3'):
        score -= 5
    
    for vuln in vulnerabilities:
        if vuln['severity'] == 'CRITICAL':
            score -= 30
        elif vuln['severity'] == 'HIGH':
            score -= 20
        elif vuln['severity'] == 'MEDIUM':
            score -= 10
    
    if score >= 90:
        grade = "[green]A[/green]"
    elif score >= 80:
        grade = "[green]B[/green]"
    elif score >= 70:
        grade = "[yellow]C[/yellow]"
    elif score >= 60:
        grade = "[yellow]D[/yellow]"
    else:
        grade = "[red]F[/red]"
    
    console.print(f"{grade} ({max(0, score)}/100)")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        console.print("[red]Usage: python ssl_analyzer.py <domain> [port][/red]")
        sys.exit(1)
    
    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    
    analyze(domain, port)
