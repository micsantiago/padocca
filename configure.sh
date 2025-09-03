#!/bin/bash

# PADOCCA - Script de Configuração Rápida
# Configura alias ou link simbólico para usar 'padocca' globalmente

# Cores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
echo "╔════════════════════════════════════════════════════╗"
echo "║    🥖 CONFIGURAÇÃO RÁPIDA DO PADOCCA 🥖          ║"
echo "║      Configurar comando 'padocca' global           ║"
echo "╚════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detectar OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS="linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS="windows"
        echo -e "${RED}[!] Windows detectado. Use WSL2 para o Padocca.${NC}"
        exit 1
    else
        OS="unknown"
    fi
}

# Detectar shell ativo
detect_shell() {
    CURRENT_SHELL=$(basename "$SHELL")
    echo -e "${GREEN}[✓] Shell detectado: $CURRENT_SHELL${NC}"
    
    # Determinar arquivo de configuração do shell
    if [[ "$CURRENT_SHELL" == "zsh" ]]; then
        SHELL_CONFIG="$HOME/.zshrc"
    elif [[ "$CURRENT_SHELL" == "bash" ]]; then
        if [[ "$OS" == "macos" ]]; then
            SHELL_CONFIG="$HOME/.bash_profile"
        else
            SHELL_CONFIG="$HOME/.bashrc"
        fi
    else
        SHELL_CONFIG="$HOME/.bashrc"
    fi
}

# Configurar Padocca
configure_padocca() {
    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    PADOCCA_SCRIPT="$SCRIPT_DIR/padocca.sh"
    
    # Verificar se padocca.sh existe
    if [[ ! -f "$PADOCCA_SCRIPT" ]]; then
        echo -e "${RED}[!] Erro: padocca.sh não encontrado em $SCRIPT_DIR${NC}"
        exit 1
    fi
    
    echo -e "${CYAN}[?] Escolha o método de instalação:${NC}"
    echo "  1) Link simbólico em /usr/local/bin (recomendado, requer sudo)"
    echo "  2) Alias no shell (não requer sudo)"
    read -p "Escolha [1-2]: " -n 1 -r
    echo
    
    if [[ $REPLY == "1" ]]; then
        # Criar link simbólico
        echo -e "${YELLOW}[*] Criando link simbólico...${NC}"
        
        # Criar diretório se não existir
        if [[ ! -d /usr/local/bin ]]; then
            echo -e "${YELLOW}[*] Criando /usr/local/bin...${NC}"
            sudo mkdir -p /usr/local/bin
        fi
        
        # Remover link antigo se existir
        if [[ -L /usr/local/bin/padocca ]]; then
            sudo rm /usr/local/bin/padocca
        fi
        
        if sudo ln -sf "$PADOCCA_SCRIPT" /usr/local/bin/padocca; then
            echo -e "${GREEN}[✓] Link simbólico criado com sucesso!${NC}"
            echo -e "${GREEN}    Você já pode usar: ${CYAN}padocca --help${NC}"
            
            # Verificar se /usr/local/bin está no PATH
            if ! echo "$PATH" | grep -q "/usr/local/bin"; then
                echo -e "${YELLOW}[!] Atenção: /usr/local/bin não está no seu PATH${NC}"
                echo -e "    Adicione ao seu $SHELL_CONFIG:"
                echo -e "    ${CYAN}export PATH=\"/usr/local/bin:\$PATH\"${NC}"
            fi
        else
            echo -e "${RED}[!] Falha ao criar link simbólico${NC}"
            echo -e "${YELLOW}    Configurando alias como alternativa...${NC}"
            REPLY="2"
        fi
    fi
    
    if [[ $REPLY == "2" ]]; then
        # Adicionar alias ao shell
        echo -e "${YELLOW}[*] Configurando alias no shell...${NC}"
        
        PADOCCA_ALIAS="alias padocca='$PADOCCA_SCRIPT'"
        PADOCCA_PATH="export PATH=\"\$PATH:$SCRIPT_DIR/bin\""
        
        # Verificar se já existe
        if grep -q "alias padocca=" "$SHELL_CONFIG" 2>/dev/null; then
            echo -e "${YELLOW}[!] Alias já existe em $SHELL_CONFIG${NC}"
            echo -e "    Atualizando..."
            # Remover alias antigo
            sed -i.bak '/alias padocca=/d' "$SHELL_CONFIG"
            sed -i.bak '/# Padocca Security Framework/d' "$SHELL_CONFIG"
        fi
        
        # Adicionar novo alias
        echo "" >> "$SHELL_CONFIG"
        echo "# Padocca Security Framework" >> "$SHELL_CONFIG"
        echo "$PADOCCA_PATH" >> "$SHELL_CONFIG"
        echo "$PADOCCA_ALIAS" >> "$SHELL_CONFIG"
        
        echo -e "${GREEN}[✓] Alias configurado em $SHELL_CONFIG${NC}"
        echo -e "${YELLOW}[!] Para ativar o alias, execute:${NC}"
        echo -e "    ${CYAN}source $SHELL_CONFIG${NC}"
        echo -e "${GREEN}    Depois você poderá usar: ${CYAN}padocca --help${NC}"
    fi
}

# Main
main() {
    detect_os
    echo -e "${GREEN}[✓] Sistema detectado: $OS${NC}"
    
    detect_shell
    
    configure_padocca
    
    echo
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}Configuração completa!${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════${NC}"
}

# Executar
main
