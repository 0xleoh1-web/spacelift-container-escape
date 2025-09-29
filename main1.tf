# Local Unix Container Escape Testing Framework
# Enhanced with Kernel Privilege Escalation Techniques
# For Docker testing on Unix systems (Linux/macOS with Docker Desktop)
# WARNING: For educational/research purposes only

terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.1"
    }
  }
}

# Stage 1: Local Environment Setup and Container Baseline
resource "null_resource" "local_container_baseline" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== LOCAL UNIX CONTAINER ESCAPE TESTING FRAMEWORK ==="
      echo "Timestamp: $(date)"
      echo "Testing Host: $(uname -a)"
      echo "Docker Version: $(docker --version 2>/dev/null || echo 'Docker not found')"
      echo "Current User: $(whoami)"
      echo "Current UID/GID: $(id)"
      echo ""
      
      echo "=== HOST SYSTEM BASELINE ==="
      echo "Host Kernel: $(uname -r)"
      echo "Host OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME || echo 'Unknown OS')"
      echo "Host CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 || echo 'Unknown CPU')"
      echo "Host Memory: $(free -h 2>/dev/null | grep Mem || echo 'Unknown Memory')"
      echo ""
      
      echo "=== CONTAINER RUNTIME DETECTION ==="
      if [ -f /.dockerenv ]; then
        echo "RUNNING INSIDE CONTAINER"
        echo "Container hostname: $(hostname)"
        echo "Container IP: $(hostname -i 2>/dev/null || echo 'Unknown')"
        echo "Container ID: $(cat /proc/self/cgroup | grep docker | head -1 | sed 's/.*\///' | cut -c1-12 2>/dev/null || echo 'Unknown')"
      else
        echo "RUNNING ON HOST SYSTEM"
        echo "Host hostname: $(hostname)"
        echo "Host IP: $(hostname -I | awk '{print $1}' 2>/dev/null || echo 'Unknown')"
      fi
      echo ""
    EOT
  }
}

# Stage 2: Kernel Version Analysis and CVE Detection
resource "null_resource" "kernel_vulnerability_analysis" {
  depends_on = [null_resource.local_container_baseline]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== KERNEL VULNERABILITY ANALYSIS ==="
      echo "Analyzing kernel version for known exploits..."
      echo ""
      
      KERNEL_VERSION=$(uname -r)
      echo "Kernel Version: $KERNEL_VERSION"
      echo ""
      
      echo "=== KNOWN KERNEL EXPLOIT CHECKS ==="
      
      # CVE-2022-0847 - Dirty Pipe
      echo "CVE-2022-0847 (Dirty Pipe) - Affects kernels 5.8-5.16.11, 5.15.25, 5.10.102:"
      KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
      KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
      if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 16 ]; then
        echo "  ⚠️  POTENTIALLY VULNERABLE to Dirty Pipe!"
      else
        echo "  ✅ Likely not vulnerable to Dirty Pipe"
      fi
      echo ""
      
      # CVE-2021-4034 - PwnKit (polkit)
      echo "CVE-2021-4034 (PwnKit) - Check for vulnerable polkit:"
      if command -v pkexec >/dev/null 2>&1; then
        echo "  ⚠️  pkexec found - potentially vulnerable to PwnKit"
        ls -la $(which pkexec) 2>/dev/null || echo "  Cannot check pkexec permissions"
      else
        echo "  ✅ pkexec not found"
      fi
      echo ""
      
      # CVE-2022-32250 - netfilter use-after-free
      echo "CVE-2022-32250 (netfilter UAF) - Affects kernels before 5.18.1:"
      if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 18 ]; then
        echo "  ⚠️  POTENTIALLY VULNERABLE to netfilter exploit!"
      else
        echo "  ✅ Likely not vulnerable to netfilter UAF"
      fi
      echo ""
      
      # CVE-2021-3490 - eBPF privilege escalation
      echo "CVE-2021-3490 (eBPF privesc) - Affects kernels 5.8-5.12.9:"
      if [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ] && [ "$KERNEL_MINOR" -le 12 ]; then
        echo "  ⚠️  POTENTIALLY VULNERABLE to eBPF exploit!"
      else
        echo "  ✅ Likely not vulnerable to eBPF privesc"
      fi
      echo ""
      
      # CVE-2019-13272 - ptrace_link privilege escalation
      echo "CVE-2019-13272 (ptrace_link) - Affects kernels before 5.1.17:"
      if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 2 ]); then
        echo "  ⚠️  POTENTIALLY VULNERABLE to ptrace_link exploit!"
      else
        echo "  ✅ Likely not vulnerable to ptrace_link"
      fi
      echo ""
      
      echo "=== SYSTEM EXPLOIT SURFACE ANALYSIS ==="
      echo "Checking for additional attack vectors..."
      
      # Check for SUID binaries
      echo "High-risk SUID binaries:"
      find /usr/bin /bin /usr/sbin /sbin -perm -4000 -type f 2>/dev/null | grep -E "(sudo|su|passwd|gpasswd|newgrp|chsh|chfn)" | head -10 || echo "None found"
      echo ""
      
      # Check capabilities
      echo "Checking current process capabilities:"
      cat /proc/self/status | grep -i cap || echo "Cannot read capabilities"
      echo ""
      
      # Check for Docker socket
      echo "Docker socket access:"
      ls -la /var/run/docker.sock 2>/dev/null && echo "  ⚠️  Docker socket accessible!" || echo "  ✅ Docker socket not accessible"
      echo ""
    EOT
  }
}

# Stage 3: Container Escape Techniques - Traditional Methods
resource "null_resource" "traditional_escape_methods" {
  depends_on = [null_resource.kernel_vulnerability_analysis]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== TRADITIONAL CONTAINER ESCAPE METHODS ==="
      echo "Testing classic container breakout techniques..."
      echo ""
      
      echo "Method 1: /proc/1/root filesystem escape"
      if ls -la /proc/1/root/ 2>/dev/null >/dev/null; then
        echo "  🚨 SUCCESS: Host filesystem accessible via /proc/1/root!"
        echo "  Host root contents:"
        ls -la /proc/1/root/ 2>/dev/null | head -5
        
        echo "  Host /etc/passwd test:"
        if cat /proc/1/root/etc/passwd 2>/dev/null >/dev/null; then
          echo "    🚨 CRITICAL: Host /etc/passwd readable!"
          echo "    Host users: $(cat /proc/1/root/etc/passwd 2>/dev/null | wc -l) accounts"
        else
          echo "    ✅ Host /etc/passwd blocked"
        fi
        
        echo "  Host /etc/shadow test:"
        if cat /proc/1/root/etc/shadow 2>/dev/null >/dev/null; then
          echo "    🚨 CRITICAL: Host /etc/shadow readable!"
        else
          echo "    ✅ Host /etc/shadow blocked"
        fi
      else
        echo "  ✅ /proc/1/root access blocked"
      fi
      echo ""
      
      echo "Method 2: Docker socket escape"
      if [ -S /var/run/docker.sock ]; then
        echo "  🚨 Docker socket found!"
        ls -la /var/run/docker.sock
        
        if command -v docker >/dev/null 2>&1; then
          echo "  Testing Docker API access..."
          docker ps 2>/dev/null && echo "    🚨 CRITICAL: Docker API accessible!" || echo "    ✅ Docker API blocked"
        else
          echo "  Docker client not available for testing"
        fi
      else
        echo "  ✅ Docker socket not accessible"
      fi
      echo ""
      
      echo "Method 3: Privileged container detection"
      echo "  Container capabilities:"
      cat /proc/self/status | grep CapEff | awk '{print "    Effective: " $2}'
      cat /proc/self/status | grep CapBnd | awk '{print "    Bounding: " $2}'
      
      # Check for dangerous capabilities
      CAP_EFF=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
      if [ "$CAP_EFF" != "0000000000000000" ]; then
        echo "    ⚠️  Container has elevated capabilities!"
      else
        echo "    ✅ Container has minimal capabilities"
      fi
      echo ""
      
      echo "Method 4: Host PID namespace sharing"
      HOST_PID_NS=$(readlink /proc/1/ns/pid 2>/dev/null)
      CONTAINER_PID_NS=$(readlink /proc/self/ns/pid 2>/dev/null)
      
      if [ "$HOST_PID_NS" = "$CONTAINER_PID_NS" ] && [ -n "$HOST_PID_NS" ]; then
        echo "  🚨 CRITICAL: Sharing PID namespace with host!"
        echo "    Host processes visible: $(ps aux | wc -l)"
      else
        echo "  ✅ Isolated PID namespace"
        echo "    Visible processes: $(ps aux | wc -l)"
      fi
      echo ""
      
      echo "Method 5: Filesystem mount escape"
      echo "  Checking for host filesystem mounts:"
      mount | grep -E "(host|proc|sys)" | head -5 || echo "    No obvious host mounts"
      echo ""
      
      echo "  Checking for writable host paths:"
      for path in /host /hostfs /rootfs /mnt/host; do
        if [ -d "$path" ] && [ -w "$path" ]; then
          echo "    🚨 Writable host path: $path"
        fi
      done
      echo ""
    EOT
  }
}

# Stage 4: Advanced Kernel Exploitation Techniques
resource "null_resource" "kernel_exploitation_techniques" {
  depends_on = [null_resource.traditional_escape_methods]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== ADVANCED KERNEL EXPLOITATION TECHNIQUES ==="
      echo "Testing kernel-level privilege escalation methods..."
      echo ""
      
      echo "Technique 1: Dirty Pipe Exploit (CVE-2022-0847)"
      echo "  Checking for vulnerable kernel version and conditions..."
      KERNEL_VERSION=$(uname -r)
      
      # Create a simple dirty pipe test (safe version)
      cat > /tmp/dirty_pipe_test.c << 'EOFCPP'
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int main() {
    printf("Testing Dirty Pipe conditions...\n");
    
    // Check if we can create pipes
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        printf("  ❌ Cannot create pipes\n");
        return 1;
    }
    close(pipefd[0]);
    close(pipefd[1]);
    
    // Check if we can access /proc/version
    int fd = open("/proc/version", O_RDONLY);
    if (fd == -1) {
        printf("  ❌ Cannot access /proc/version\n");
        return 1;
    }
    close(fd);
    
    printf("  ✅ Basic conditions met for pipe operations\n");
    printf("  ⚠️  Manual exploit development required\n");
    return 0;
}
EOFCPP
      
      if command -v gcc >/dev/null 2>&1; then
        gcc -o /tmp/dirty_pipe_test /tmp/dirty_pipe_test.c 2>/dev/null
        if [ -x /tmp/dirty_pipe_test ]; then
          /tmp/dirty_pipe_test
          rm -f /tmp/dirty_pipe_test /tmp/dirty_pipe_test.c
        else
          echo "  ❌ Compilation failed"
        fi
      else
        echo "  ❌ GCC not available for testing"
        rm -f /tmp/dirty_pipe_test.c
      fi
      echo ""
      
      echo "Technique 2: eBPF Privilege Escalation"
      echo "  Checking eBPF availability and permissions..."
      
      if [ -f /proc/sys/kernel/unprivileged_bpf_disabled ]; then
        UNPRIVILEGED_BPF=$(cat /proc/sys/kernel/unprivileged_bpf_disabled)
        if [ "$UNPRIVILEGED_BPF" = "0" ]; then
          echo "    🚨 Unprivileged eBPF enabled - potential attack vector!"
        else
          echo "    ✅ Unprivileged eBPF disabled"
        fi
      else
        echo "    ❓ eBPF configuration unknown"
      fi
      
      # Check for BPF capabilities
      if command -v bpftool >/dev/null 2>&1; then
        echo "    ⚠️  bpftool available"
      fi
      echo ""
      
      echo "Technique 3: SUID Binary Exploitation"
      echo "  Scanning for exploitable SUID binaries..."
      
      # Check for common vulnerable SUID binaries
      for binary in find vim nano less more; do
        BINARY_PATH=$(which $binary 2>/dev/null)
        if [ -n "$BINARY_PATH" ] && [ -u "$BINARY_PATH" ]; then
          echo "    🚨 SUID binary found: $BINARY_PATH"
        fi
      done
      
      # Look for custom SUID binaries
      echo "    Custom SUID binaries:"
      find /usr/local -perm -4000 -type f 2>/dev/null | head -5 || echo "    None found"
      echo ""
      
      echo "Technique 4: Capability-based Exploitation"
      echo "  Analyzing dangerous capabilities..."
      
      # Check for CAP_SYS_ADMIN
      if capsh --print 2>/dev/null | grep -q "cap_sys_admin"; then
        echo "    🚨 CAP_SYS_ADMIN detected - can mount filesystems!"
      fi
      
      # Check for CAP_SYS_PTRACE
      if capsh --print 2>/dev/null | grep -q "cap_sys_ptrace"; then
        echo "    🚨 CAP_SYS_PTRACE detected - can trace processes!"
      fi
      
      # Check for CAP_DAC_OVERRIDE
      if capsh --print 2>/dev/null | grep -q "cap_dac_override"; then
        echo "    🚨 CAP_DAC_OVERRIDE detected - can bypass file permissions!"
      fi
      echo ""
      
      echo "Technique 5: Namespace Manipulation"
      echo "  Testing namespace escape possibilities..."
      
      # Check current namespaces
      echo "    Current namespaces:"
      ls -la /proc/self/ns/ 2>/dev/null | grep -v "^total" | awk '{print "      " $9 " -> " $11}' || echo "    Cannot read namespaces"
      
      # Test unshare capability
      if command -v unshare >/dev/null 2>&1; then
        echo "    ⚠️  unshare command available"
        # Test if we can create new namespaces
        if unshare -r echo "test" 2>/dev/null >/dev/null; then
          echo "    🚨 Can create new user namespaces!"
        fi
      fi
      echo ""
      
      echo "Technique 6: /proc/sys Exploitation"
      echo "  Checking for writable kernel parameters..."
      
      # Check for writable /proc/sys entries
      echo "    Writable kernel parameters:"
      find /proc/sys -type f -writable 2>/dev/null | head -10 | while read file; do
        echo "      $file"
      done || echo "    None found"
      echo ""
    EOT
  }
}

# Stage 5: Memory and System Exploitation
resource "null_resource" "memory_system_exploitation" {
  depends_on = [null_resource.kernel_exploitation_techniques]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== MEMORY AND SYSTEM EXPLOITATION ==="
      echo "Testing advanced system-level attacks..."
      echo ""
      
      echo "Attack 1: Shared Memory Exploitation"
      echo "  Checking shared memory configuration..."
      
      # Check /dev/shm permissions
      if [ -d /dev/shm ]; then
        echo "    /dev/shm permissions: $(ls -ld /dev/shm | awk '{print $1, $3, $4}')"
        echo "    /dev/shm size: $(df -h /dev/shm 2>/dev/null | tail -1 | awk '{print $2}' || echo 'Unknown')"
        
        # Test if we can create files in /dev/shm
        if touch /dev/shm/test_file 2>/dev/null; then
          echo "    ✅ Can write to /dev/shm"
          rm -f /dev/shm/test_file
        else
          echo "    ❌ Cannot write to /dev/shm"
        fi
      else
        echo "    /dev/shm not available"
      fi
      echo ""
      
      echo "Attack 2: /proc Memory Exploitation"
      echo "  Checking /proc filesystem access..."
      
      # Check if we can read other process memory
      echo "    Process memory access test:"
      for pid in 1 $(pidof init 2>/dev/null) $(pidof systemd 2>/dev/null); do
        if [ -n "$pid" ] && [ -r "/proc/$pid/mem" ]; then
          echo "      🚨 Can read /proc/$pid/mem"
        fi
      done
      
      # Check /proc/kcore access
      if [ -r /proc/kcore ]; then
        echo "    🚨 CRITICAL: /proc/kcore readable - kernel memory exposed!"
      else
        echo "    ✅ /proc/kcore not readable"
      fi
      echo ""
      
      echo "Attack 3: Cgroup Exploitation"
      echo "  Analyzing cgroup configuration..."
      
      # Check cgroup version
      if [ -f /proc/cgroups ]; then
        echo "    Cgroup subsystems:"
        cat /proc/cgroups | head -5
        
        # Check if we can modify cgroup settings
        CGROUP_PATH="/sys/fs/cgroup"
        if [ -d "$CGROUP_PATH" ]; then
          echo "    Cgroup mount: $(mount | grep cgroup | head -1 | awk '{print $1, $3}')"
          
          # Look for writable cgroup files
          find $CGROUP_PATH -name "*.max" -writable 2>/dev/null | head -3 | while read file; do
            echo "      🚨 Writable cgroup file: $file"
          done
        fi
      else
        echo "    Cgroups not available"
      fi
      echo ""
      
      echo "Attack 4: Device File Exploitation" 
      echo "  Checking dangerous device files..."
      
      # Check for accessible device files
      for device in /dev/mem /dev/kmem /dev/port; do
        if [ -r "$device" ]; then
          echo "    🚨 CRITICAL: $device is readable!"
        elif [ -e "$device" ]; then
          echo "    ⚠️  $device exists but not readable"
        fi
      done
      
      # Check for other interesting devices
      echo "    Other device files:"
      ls -la /dev/ | grep -E "(loop|dm-|mapper)" | head -3 || echo "    None found"
      echo ""
      
      echo "Attack 5: Kernel Module Interface"
      echo "  Checking kernel module capabilities..."
      
      # Check if we can load kernel modules
      if [ -w /sys/module ]; then
        echo "    🚨 /sys/module is writable!"
      fi
      
      # Check for module loading capabilities
      if command -v modprobe >/dev/null 2>&1; then
        echo "    ⚠️  modprobe available"
      fi
      
      if command -v insmod >/dev/null 2>&1; then
        echo "    ⚠️  insmod available"
      fi
      
      # Check loaded modules
      echo "    Currently loaded modules: $(lsmod 2>/dev/null | wc -l || echo 'Unknown')"
      echo ""
      
      echo "Attack 6: Timing Attack Surfaces"
      echo "  Checking for timing-based vulnerabilities..."
      
      # Check for high-resolution timers
      if [ -r /proc/timer_list ]; then
        echo "    ⚠️  Timer information accessible"
      fi
      
      # Check CPU frequency scaling
      if [ -d /sys/devices/system/cpu/cpu0/cpufreq ]; then
        echo "    ⚠️  CPU frequency control accessible"
      fi
      
      # Check for performance counters
      if [ -r /proc/sys/kernel/perf_event_paranoid ]; then
        PERF_PARANOID=$(cat /proc/sys/kernel/perf_event_paranoid)
        echo "    Performance counters paranoid level: $PERF_PARANOID"
        if [ "$PERF_PARANOID" -lt 2 ]; then
          echo "      🚨 Performance counters may be accessible!"
        fi
      fi
      echo ""
    EOT
  }
}

# Stage 6: Exploitation Results and Recommendations
resource "null_resource" "exploitation_summary" {
  depends_on = [null_resource.memory_system_exploitation]
  
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== EXPLOITATION SUMMARY AND RECOMMENDATIONS ==="
      echo "Container escape testing completed on $(date)"
      echo ""
      
      echo "=== VULNERABILITY ASSESSMENT ==="
      VULN_COUNT=0
      
      # Count vulnerabilities found
      echo "Critical findings summary:"
      
      # Check /proc/1/root access
      if ls -la /proc/1/root/ 2>/dev/null >/dev/null; then
        echo "  🚨 Host filesystem escape possible via /proc/1/root"
        VULN_COUNT=$((VULN_COUNT + 1))
      fi
      
      # Check Docker socket
      if [ -S /var/run/docker.sock ] && [ -r /var/run/docker.sock ]; then
        echo "  🚨 Docker socket accessible for container escape"
        VULN_COUNT=$((VULN_COUNT + 1))
      fi
      
      # Check PID namespace sharing
      HOST_PID_NS=$(readlink /proc/1/ns/pid 2>/dev/null)
      CONTAINER_PID_NS=$(readlink /proc/self/ns/pid 2>/dev/null)
      if [ "$HOST_PID_NS" = "$CONTAINER_PID_NS" ] && [ -n "$HOST_PID_NS" ]; then
        echo "  🚨 PID namespace sharing with host detected"
        VULN_COUNT=$((VULN_COUNT + 1))
      fi
      
      # Check capabilities
      CAP_EFF=$(cat /proc/self/status | grep CapEff | awk '{print $2}')
      if [ "$CAP_EFF" != "0000000000000000" ]; then
        echo "  ⚠️  Elevated capabilities detected"
        VULN_COUNT=$((VULN_COUNT + 1))
      fi
      
      # Check for kernel memory access
      if [ -r /proc/kcore ]; then
        echo "  🚨 Kernel memory accessible via /proc/kcore"
        VULN_COUNT=$((VULN_COUNT + 1))
      fi
      
      echo ""
      echo "Total vulnerabilities found: $VULN_COUNT"
      echo ""
      
      echo "=== RECOMMENDED EXPLOITATION PATHS ==="
      
      if [ $VULN_COUNT -eq 0 ]; then
        echo "✅ Container appears well-isolated"
        echo "Focus on:"
        echo "  - Application-level vulnerabilities"
        echo "  - Credential extraction"
        echo "  - Network-based attacks"
      else
        echo "⚠️  Multiple escape vectors available"
        echo "Recommended attack sequence:"
        echo "  1. Attempt traditional escape methods first"
        echo "  2. Exploit kernel vulnerabilities if present"
        echo "  3. Use capability-based attacks"
        echo "  4. Leverage namespace manipulation"
        echo "  5. Try memory-based exploitation"
      fi
      echo ""
      
      echo "=== NEXT STEPS FOR TESTING ==="
      echo "1. Run this test in different container configurations:"
      echo "   - Privileged containers: docker run --privileged"
      echo "   - PID namespace sharing: docker run --pid=host" 
      echo "   - Volume mounts: docker run -v /:/host"
      echo "   - Capability additions: docker run --cap-add=SYS_ADMIN"
      echo ""
      echo "2. Test with different base images:"
      echo "   - Alpine Linux (minimal)"
      echo "   - Ubuntu (full system)"
      echo "   - Debian (security-focused)"
      echo ""
      echo "3. Kernel exploit development:"
      echo "   - Research specific CVEs for your kernel version"
      echo "   - Develop proof-of-concept exploits"
      echo "   - Test in isolated environments first"
      echo ""
      echo "4. Advanced techniques:"
      echo "   - Container runtime exploitation (runc, containerd)"
      echo "   - Kubernetes pod escape techniques"
      echo "   - OCI runtime vulnerabilities"
      echo ""
      
      echo "=== LEGAL AND ETHICAL NOTICE ==="
      echo "⚠️  WARNING: This framework is for:"
      echo "  - Educational purposes only"
      echo "  - Authorized security testing"
      echo "  - Research environments"
      echo ""
      echo "  DO NOT use on systems you don't own or lack permission to test"
      echo "  Ensure compliance with local laws and regulations"
      echo ""
      echo "Container escape testing completed successfully!"
      echo "Framework ready for local Unix testing environments."
    EOT
  }
}

# Output results
output "local_escape_test_results" {
  value = "Local Unix container escape testing framework executed. Check output for vulnerability assessment and exploitation recommendations."
  depends_on = [
    null_resource.local_container_baseline,
    null_resource.kernel_vulnerability_analysis,
    null_resource.traditional_escape_methods,
    null_resource.kernel_exploitation_techniques,
    null_resource.memory_system_exploitation,
    null_resource.exploitation_summary
  ]
}

output "testing_summary" {
  value = {
    baseline = "Local system baseline and container detection completed"
    kernel_analysis = "Kernel vulnerability analysis and CVE detection performed"
    traditional_escapes = "Classic container escape methods tested"
    kernel_exploits = "Advanced kernel exploitation techniques analyzed"
    memory_attacks = "Memory and system-level attack vectors examined"
    summary = "Comprehensive vulnerability assessment and exploitation recommendations provided"
  }
}
