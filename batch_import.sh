#!/bin/bash

# Azure DNS Batch Import Script
# 
# This script imports split DNS zone files to Azure DNS in the correct order.
# Use this after running the Azure DNS evaluator with the --split option.
#
# Usage:
#   ./batch_import.sh <resource-group> <zone-name> <split-directory> [validate]
#
# Examples:
#   ./batch_import.sh myResourceGroup example.com ./zone_split
#   ./batch_import.sh myResourceGroup example.com ./zone_split validate

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "$1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to validate parameters
validate_params() {
    if [ $# -lt 3 ]; then
        echo "Usage: $0 <resource-group> <zone-name> <split-directory> [validate]"
        echo ""
        echo "Examples:"
        echo "  $0 myResourceGroup example.com ./zone_split"
        echo "  $0 myResourceGroup example.com ./zone_split validate"
        exit 1
    fi

    RESOURCE_GROUP="$1"
    ZONE_NAME="$2"
    SPLIT_DIR="$3"
    VALIDATE_FIRST="${4:-}"

    if [ ! -d "$SPLIT_DIR" ]; then
        print_error "Split directory not found: $SPLIT_DIR"
        exit 1
    fi
}

# Function to check Azure CLI
check_azure_cli() {
    print_info "Checking Azure CLI..."
    
    if ! command_exists az; then
        print_error "Azure CLI not found. Please install Azure CLI first."
        print_info "Download from: https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
        exit 1
    fi
    
    # Check if logged in
    if ! az account show >/dev/null 2>&1; then
        print_error "Not logged into Azure. Please run 'az login' first."
        exit 1
    fi
    
    ACCOUNT_NAME=$(az account show --query "user.name" -o tsv 2>/dev/null || echo "Unknown")
    SUBSCRIPTION_NAME=$(az account show --query "name" -o tsv 2>/dev/null || echo "Unknown")
    
    print_success "Logged in as: $ACCOUNT_NAME"
    print_success "Subscription: $SUBSCRIPTION_NAME"
}

# Function to validate split files
validate_split_files() {
    print_info "Validating split files..."
    
    if [ ! -f "azure_dns_evaluator.py" ]; then
        print_warning "azure_dns_evaluator.py not found. Skipping validation."
        return 0
    fi
    
    local all_valid=true
    for file in "$SPLIT_DIR"/*_part_*.txt; do
        if [ -f "$file" ]; then
            local filename=$(basename "$file")
            print_info "  Validating $filename..."
            
            if python azure_dns_evaluator.py "$file" >/dev/null 2>&1; then
                print_success "  Validation passed for $filename"
            else
                print_error "  Validation failed for $filename"
                all_valid=false
            fi
        fi
    done
    
    if [ "$all_valid" = false ]; then
        print_error "Validation failed. Fix errors before importing."
        exit 1
    fi
}

# Function to create DNS zone
create_dns_zone() {
    print_info "Checking/creating DNS zone $ZONE_NAME..."
    
    if az network dns zone show --resource-group "$RESOURCE_GROUP" --name "$ZONE_NAME" >/dev/null 2>&1; then
        print_success "DNS zone $ZONE_NAME already exists"
    else
        print_info "Creating DNS zone $ZONE_NAME..."
        if az network dns zone create --resource-group "$RESOURCE_GROUP" --name "$ZONE_NAME" >/dev/null 2>&1; then
            print_success "Created DNS zone $ZONE_NAME"
        else
            print_error "Failed to create DNS zone $ZONE_NAME"
            exit 1
        fi
    fi
}

# Function to import a zone file
import_zone_file() {
    local file_path="$1"
    local filename=$(basename "$file_path")
    
    print_info "  Importing $filename..."
    
    if az network dns zone import \
        --resource-group "$RESOURCE_GROUP" \
        --name "$ZONE_NAME" \
        --file-name "$file_path" >/dev/null 2>&1; then
        print_success "  Successfully imported $filename"
        return 0
    else
        print_error "  Failed to import $filename"
        return 1
    fi
}

# Function to import all zone files
import_zone_files() {
    local split_files=("$SPLIT_DIR"/*_part_*.txt)
    local total_files=${#split_files[@]}
    local success_count=0
    local failed_files=()
    
    if [ ${#split_files[@]} -eq 1 ] && [ ! -f "${split_files[0]}" ]; then
        print_error "No split files found in $SPLIT_DIR"
        exit 1
    fi
    
    print_info "Found $total_files split files to import"
    
    # Sort files to ensure correct order
    IFS=$'\n' split_files=($(sort <<<"${split_files[*]}")); unset IFS
    
    local i=1
    for file_path in "${split_files[@]}"; do
        if [ -f "$file_path" ]; then
            local filename=$(basename "$file_path")
            local part_number=$(echo "$filename" | sed 's/.*_part_\([0-9]*\)\.txt/\1/')
            
            print_info ""
            print_info "Importing part $part_number ($i/$total_files): $filename"
            
            if import_zone_file "$file_path"; then
                ((success_count++))
            else
                failed_files+=("$filename")
            fi
            
            # Rate limiting delay
            if [ $i -lt $total_files ]; then
                print_info "  Waiting 3 seconds before next import..."
                sleep 3
            fi
            
            ((i++))
        fi
    done
    
    # Summary
    print_info ""
    print_info "=================================================="
    print_info "Batch import completed!"
    print_info "Success: $success_count/$total_files files imported"
    
    if [ ${#failed_files[@]} -gt 0 ]; then
        print_warning "Failed files: ${failed_files[*]}"
        print_info "Check the errors above and manually retry failed imports if needed."
        return 1
    else
        print_success "All files imported successfully!"
        return 0
    fi
}

# Main function
main() {
    echo "Azure DNS Batch Import Tool"
    echo "========================================"
    
    # Validate parameters
    validate_params "$@"
    
    # Check prerequisites
    check_azure_cli
    
    # Validate files if requested
    if [ "$VALIDATE_FIRST" = "validate" ]; then
        validate_split_files
    fi
    
    # Create DNS zone
    create_dns_zone
    
    # Import files
    print_info ""
    print_info "Starting batch import..."
    print_info "Resource Group: $RESOURCE_GROUP"
    print_info "Zone Name: $ZONE_NAME"
    print_info "Split Directory: $SPLIT_DIR"
    print_info "Validate First: ${VALIDATE_FIRST:-no}"
    
    if import_zone_files; then
        print_info ""
        print_success "Batch import completed successfully!"
        print_info "Your DNS zone '$ZONE_NAME' is now configured in Azure DNS."
        print_info "You can view it in the Azure portal under Resource Groups > $RESOURCE_GROUP > DNS zones"
        exit 0
    else
        print_info ""
        print_error "Batch import completed with errors."
        print_info "Check the error messages above and retry failed imports manually if needed."
        exit 1
    fi
}

# Run main function with all arguments
main "$@"
