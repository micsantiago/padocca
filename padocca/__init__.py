"""
PADOCCA - Elite Pentesting Framework
Author: Donato Reis
Version: 2.0.0
"""

__version__ = "2.0.0"
__author__ = "Donato Reis"
__email__ = "contact@donatoreis.com"
__url__ = "https://github.com/DonatoReis/padocca"

# ASCII Banner
BANNER = """
╔════════════════════════════════════════════════════╗
║       🥖 PADOCCA SECURITY FRAMEWORK v2.0 🥖       ║
║         Elite • Stealth • Undetectable            ║
╚════════════════════════════════════════════════════╝
"""

def get_version():
    """Return the current version"""
    return __version__

def print_banner():
    """Print the Padocca banner"""
    from colorama import Fore, Style
    print(Fore.CYAN + BANNER + Style.RESET_ALL)
