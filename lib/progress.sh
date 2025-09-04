#!/bin/bash

# PADOCCA Advanced Progress Bar System
# Visual feedback with animated progress bars and status indicators

# Colors and Styles
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# Unicode Characters
CHECK_MARK="✅"
WARNING_SIGN="⚠️"
ERROR_MARK="❌"
SPINNER_CHARS=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
PROGRESS_CHAR="▓"
EMPTY_CHAR="░"

# Global Variables
PROGRESS_PID=""
PROGRESS_START_TIME=""

# Function to show spinner
show_spinner() {
    local pid=$1
    local message=$2
    local spinner_index=0
    
    while kill -0 $pid 2>/dev/null; do
        echo -ne "\r${CYAN}${SPINNER_CHARS[$spinner_index]}${NC} $message"
        spinner_index=$(( (spinner_index + 1) % ${#SPINNER_CHARS[@]} ))
        sleep 0.1
    done
    echo -ne "\r"
}

# Function to draw progress bar
draw_progress_bar() {
    local current=$1
    local total=$2
    local width=$3
    local label=$4
    
    # Calculate percentage
    local percent=$(( current * 100 / total ))
    local filled=$(( percent * width / 100 ))
    local empty=$(( width - filled ))
    
    # Build the bar
    local bar=""
    for ((i=0; i<filled; i++)); do
        bar="${bar}${PROGRESS_CHAR}"
    done
    for ((i=0; i<empty; i++)); do
        bar="${bar}${EMPTY_CHAR}"
    done
    
    # Color based on percentage
    local color=$CYAN
    if [ $percent -ge 75 ]; then
        color=$GREEN
    elif [ $percent -ge 50 ]; then
        color=$YELLOW
    fi
    
    # Print the progress bar
    printf "\r%-30s [${color}%s${NC}] %3d%% " "$label" "$bar" "$percent"
}

# Function to show animated progress
animated_progress() {
    local task_name=$1
    local total_steps=$2
    local current_step=0
    
    while [ $current_step -le $total_steps ]; do
        draw_progress_bar $current_step $total_steps 30 "$task_name"
        current_step=$((current_step + 1))
        sleep 0.03
    done
    # Ensure we always end at 100%
    draw_progress_bar $total_steps $total_steps 30 "$task_name"
    echo ""
}

# Function to show task status
show_task_status() {
    local task=$1
    local status=$2
    local duration=$3
    local details=$4
    
    case $status in
        "success")
            echo -e "${GREEN}${CHECK_MARK}${NC} $task ${DIM}(${duration}s)${NC}"
            [ -n "$details" ] && echo -e "   ${DIM}$details${NC}"
            ;;
        "warning")
            echo -e "${YELLOW}${WARNING_SIGN}${NC} $task ${DIM}(${duration}s)${NC}"
            [ -n "$details" ] && echo -e "   ${YELLOW}$details${NC}"
            ;;
        "error")
            echo -e "${RED}${ERROR_MARK}${NC} $task ${DIM}(${duration}s)${NC}"
            [ -n "$details" ] && echo -e "   ${RED}$details${NC}"
            ;;
        "running")
            echo -e "${CYAN}⏳${NC} $task ${DIM}...${NC}"
            ;;
    esac
}

# Function to show module progress with details
show_module_progress() {
    local module_num=$1
    local total_modules=$2
    local module_name=$3
    local status=$4
    
    # Header
    echo -e "\n${BOLD}${CYAN}[$module_num/$total_modules]${NC} ${BOLD}$module_name${NC}"
    echo -e "${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Function to show live statistics
show_live_stats() {
    local label=$1
    local value=$2
    local icon=$3
    
    echo -e "   ${icon} ${BOLD}${label}:${NC} ${GREEN}${value}${NC}"
}

# Function to calculate elapsed time
calculate_elapsed_time() {
    local start_time=$1
    local end_time=$(date +%s)
    local elapsed=$((end_time - start_time))
    
    if [ $elapsed -lt 60 ]; then
        echo "${elapsed}s"
    else
        local minutes=$((elapsed / 60))
        local seconds=$((elapsed % 60))
        echo "${minutes}m ${seconds}s"
    fi
}

# Function to show dashboard
show_dashboard() {
    local target=$1
    local mode=$2
    local start_time=$3
    
    clear
    echo -e "${CYAN}╭──────────────────────────────────────────────────────────╮${NC}"
    echo -e "${CYAN}│${NC}   ${BOLD}🥖 PADOCCA SECURITY FRAMEWORK v2.0${NC}                 ${CYAN}│${NC}"
    echo -e "${CYAN}│${NC}   ${YELLOW}Target:${NC} ${GREEN}$target${NC}"
    printf "${CYAN}│${NC}   ${YELLOW}Mode:${NC} %-47s ${CYAN}│${NC}\n" "$mode"
    echo -e "${CYAN}│${NC}   ${YELLOW}Time:${NC} $(date '+%Y-%m-%d %H:%M:%S')                          ${CYAN}│${NC}"
    echo -e "${CYAN}╰──────────────────────────────────────────────────────────╯${NC}"
    echo ""
}

# Function to show phase header
show_phase_header() {
    local phase_num=$1
    local phase_name=$2
    local total_phases=4
    
    echo ""
    echo -e "${BOLD}${PURPLE}═══ PHASE $phase_num/$total_phases: $phase_name ═══${NC}"
    echo ""
}

# Function to show final summary panel
show_summary_panel() {
    local target=$1
    local subdomains=$2
    local urls=$3
    local ports=$4
    local vulnerabilities=$5
    local waf_status=$6
    local ssl_status=$7
    local emails=$8
    local duration=$9
    local report_path=${10}
    
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${WHITE}🔎 SCAN SUMMARY: $target${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    
    # Services and Ports
    if [ -n "$ports" ] && [ "$ports" != "0" ]; then
        echo -e "📡 ${BOLD}Services${NC}        : ${GREEN}$ports${NC}"
    else
        echo -e "📡 ${BOLD}Services${NC}        : ${DIM}No open ports found${NC}"
    fi
    
    # Security Status
    if [ "$waf_status" = "DETECTED" ]; then
        echo -e "🛡️  ${BOLD}Security${NC}        : ${YELLOW}WAF Detected${NC}"
    else
        echo -e "🛡️  ${BOLD}Security${NC}        : ${GREEN}No WAF detected${NC}"
    fi
    
    # SSL/TLS Status
    if [ "$ssl_status" = "valid" ]; then
        echo -e "🔐 ${BOLD}SSL/TLS${NC}         : ${GREEN}Valid, Strong Ciphers${NC}"
    else
        echo -e "🔐 ${BOLD}SSL/TLS${NC}         : ${YELLOW}Check Required${NC}"
    fi
    
    # Subdomains
    if [ -n "$subdomains" ] && [ "$subdomains" != "0" ]; then
        echo -e "🌐 ${BOLD}Subdomains${NC}      : ${GREEN}$subdomains discovered${NC}"
    else
        echo -e "🌐 ${BOLD}Subdomains${NC}      : ${DIM}None found${NC}"
    fi
    
    # Historical URLs
    if [ -n "$urls" ] && [ "$urls" != "0" ]; then
        echo -e "🕰️  ${BOLD}Historical URLs${NC} : ${GREEN}$urls found${NC}"
    else
        echo -e "🕰️  ${BOLD}Historical URLs${NC} : ${DIM}None found${NC}"
    fi
    
    # Vulnerabilities
    if [ -n "$vulnerabilities" ] && [ "$vulnerabilities" != "0" ]; then
        echo -e "⚠️  ${BOLD}Vulnerabilities${NC} : ${YELLOW}$vulnerabilities potential issues${NC}"
    else
        echo -e "✅ ${BOLD}Vulnerabilities${NC} : ${GREEN}No issues found${NC}"
    fi
    
    # OSINT
    if [ -n "$emails" ] && [ "$emails" != "0" ]; then
        echo -e "📧 ${BOLD}OSINT${NC}           : ${GREEN}$emails emails found${NC}"
    else
        echo -e "📧 ${BOLD}OSINT${NC}           : ${DIM}No emails found${NC}"
    fi
    
    # Duration
    echo -e "⏱️  ${BOLD}Duration${NC}        : ${CYAN}$duration${NC}"
    
    echo ""
    echo -e "${GREEN}Report saved to: $report_path${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
}

# Export functions for use in main script
export -f show_spinner
export -f draw_progress_bar
export -f animated_progress
export -f show_task_status
export -f show_module_progress
export -f show_live_stats
export -f calculate_elapsed_time
export -f show_dashboard
export -f show_phase_header
export -f show_summary_panel
