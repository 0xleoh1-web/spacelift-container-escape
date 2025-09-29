# Container Escape Assessment - Comprehensive Testing
# Tests multiple container escape vectors and documents security posture
terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Comprehensive Container Security Assessment
resource "null_resource" "container_security_assessment" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "🔍 CONTAINER SECURITY ASSESSMENT 🔍"
      echo "==================================="
      echo "Comprehensive testing of container isolation and potential escape vectors"
      echo ""
      
      # Container Information
      echo "=== CONTAINER ENVIRONMENT ANALYSIS ==="
      echo "[*] Container Details:"
      echo "   Container ID: $(hostname)"
      echo "   Container User: $(id)"
      echo "   Container PID Namespace: $(readlink /proc/self/ns/pid 2>/dev/null || echo 'N/A')"
      echo "   Working Directory: $(pwd)"
      echo "   Container Runtime: $(cat /proc/1/comm 2>/dev/null || echo 'Unknown')"
      echo ""
      
      # Test 1: Host Filesystem Access Vectors
      echo "=== HOST FILESYSTEM ACCESS TESTING ==="
      access_methods=0
      
      echo "[*] Testing /proc/1/root access method:"
      if [ -r "/proc/1/root/etc/passwd" ]; then
          echo "[+] ✅ /proc/1/root/etc/passwd accessible"
          access_methods=$((access_methods + 1))
          echo "   Host users count: $(cat /proc/1/root/etc/passwd | wc -l)"
      else
          echo "[-] ❌ /proc/1/root/etc/passwd not accessible"
      fi
      
      echo "[*] Testing /proc/self/root access method:"
      if [ -r "/proc/self/root/etc/passwd" ]; then
          echo "[+] ✅ /proc/self/root/etc/passwd accessible"
          access_methods=$((access_methods + 1))
      else
          echo "[-] ❌ /proc/self/root/etc/passwd not accessible"
      fi
      
      echo "[*] Testing direct /etc/passwd access:"
      if [ -r "/etc/passwd" ]; then
          echo "[+] ✅ Direct /etc/passwd accessible"
          echo "   Users in current namespace: $(cat /etc/passwd | wc -l)"
          echo "   First 5 users:"
          head -5 /etc/passwd | while IFS=: read username x uid gid gecos home shell; do
              echo "     $username (UID: $uid)"
          done
      else
          echo "[-] ❌ /etc/passwd not accessible"
      fi
      
      # Test 2: Container Capabilities Assessment
      echo ""
      echo "=== CONTAINER CAPABILITIES ASSESSMENT ==="
      echo "[*] Checking container capabilities:"
      
      if command -v capsh >/dev/null 2>&1; then
          echo "[+] capsh available - checking capabilities:"
          capsh --print 2>/dev/null || echo "   Could not read capabilities"
      else
          echo "[-] capsh not available"
      fi
      
      if [ -r "/proc/self/status" ]; then
          echo "[*] Process capabilities from /proc/self/status:"
          grep -E "Cap(Inh|Prm|Eff|Bnd|Amb)" /proc/self/status 2>/dev/null | head -5
      fi
      
      # Test 3: Namespace Isolation Analysis
      echo ""
      echo "=== NAMESPACE ISOLATION ANALYSIS ==="
      echo "[*] Comparing container vs host namespaces:"
      
      isolation_score=0
      for ns_type in pid mnt net uts ipc user; do
          container_ns=$(readlink /proc/self/ns/$ns_type 2>/dev/null)
          host_ns=$(readlink /proc/1/ns/$ns_type 2>/dev/null)
          
          if [ "$container_ns" = "$host_ns" ]; then
              echo "[!] 🚨 SHARED $ns_type NAMESPACE WITH HOST!"
              echo "   Namespace: $container_ns"
          else
              echo "[+] ✅ Isolated $ns_type namespace"
              isolation_score=$((isolation_score + 1))
          fi
      done
      
      echo "[*] Namespace isolation score: $isolation_score/6"
      
      # Test 4: Process and System Information
      echo ""
      echo "=== PROCESS AND SYSTEM ENUMERATION ==="
      echo "[*] Accessible processes (first 10):"
      
      process_count=0
      for pid_dir in /proc/[0-9]*; do
          if [ -d "$pid_dir" ]; then
              pid=$(basename "$pid_dir")
              if [ -r "$pid_dir/status" ]; then
                  process_name=$(grep '^Name:' "$pid_dir/status" 2>/dev/null | awk '{print $2}')
                  process_uid=$(grep '^Uid:' "$pid_dir/status" 2>/dev/null | awk '{print $2}')
                  
                  if [ -n "$process_name" ]; then
                      if [ "$process_uid" = "0" ]; then
                          echo "   👑 PID $pid: $process_name (ROOT)"
                      else
                          echo "   📋 PID $pid: $process_name (UID: $process_uid)"
                      fi
                      process_count=$((process_count + 1))
                      
                      if [ $process_count -ge 10 ]; then
                          break
                      fi
                  fi
              fi
          fi
      done
      
      echo "[*] Total accessible processes: $process_count+"
      
      # Test 5: Network Configuration
      echo ""
      echo "=== NETWORK CONFIGURATION ANALYSIS ==="
      container_ip=$(hostname -i 2>/dev/null || ip addr show eth0 2>/dev/null | grep 'inet ' | awk '{print $2}' | cut -d'/' -f1)
      host_ip=$(ip route show default 2>/dev/null | awk '/default/ {print $3}')
      
      echo "[*] Network Information:"
      echo "   📦 Container IP: ${container_ip:-'Not detected'}"
      echo "   🏠 Host IP (Gateway): ${host_ip:-'Not detected'}"
      
      if [ -r "/proc/net/route" ]; then
          echo "[*] Routing table accessible - first 3 entries:"
          head -3 /proc/net/route
      fi
      
      # Test 6: File System and Mount Analysis
      echo ""
      echo "=== FILESYSTEM AND MOUNT ANALYSIS ==="
      echo "[*] Mount points (excluding proc/sys/dev):"
      if [ -r "/proc/mounts" ]; then
          grep -v "proc\|sys\|dev\|tmpfs" /proc/mounts | head -5 | while read line; do
              echo "   $line"
          done
      fi
      
      echo "[*] Container filesystem structure:"
      echo "   Root directory contents:"
      ls -la / 2>/dev/null | head -10 | while read line; do
          echo "     $line"
      done
      
      # Test 7: Privilege Escalation Vectors
      echo ""
      echo "=== PRIVILEGE ESCALATION TESTING ==="
      
      echo "[*] Testing chroot availability:"
      if command -v chroot >/dev/null 2>&1; then
          echo "[+] ✅ chroot command available"
          if [ -d "/proc/1/root" ]; then
              echo "   Testing chroot to /proc/1/root:"
              test_result=$(chroot /proc/1/root /bin/echo "HOST_ACCESS_TEST" 2>/dev/null)
              if [ "$test_result" = "HOST_ACCESS_TEST" ]; then
                  echo "[!] 🚨 CHROOT TO HOST SUCCESSFUL!"
              else
                  echo "[-] chroot to host failed"
              fi
          fi
      else
          echo "[-] chroot command not available"
      fi
      
      echo "[*] Testing sudo availability:"
      if command -v sudo >/dev/null 2>&1; then
          echo "[+] sudo available"
          sudo -l 2>/dev/null | head -3 || echo "   sudo -l failed"
      else
          echo "[-] sudo not available"
      fi
      
      # Test 8: Sensitive File Access
      echo ""
      echo "=== SENSITIVE FILE ACCESS TESTING ==="
      sensitive_files=(
          "/etc/shadow"
          "/etc/sudoers"
          "/proc/1/root/etc/shadow"
          "/root/.ssh/id_rsa"
          "/proc/1/root/root/.ssh/id_rsa"
      )
      
      for file in "${sensitive_files[@]}"; do
          if [ -r "$file" ]; then
              echo "[!] 🚨 SENSITIVE FILE ACCESSIBLE: $file"
          else
              echo "[-] File not accessible: $file"
          fi
      done
      
      # Final Security Assessment
      echo ""
      echo "=== SECURITY ASSESSMENT SUMMARY ==="
      echo "=================================="
      
      risk_score=0
      
      if [ $access_methods -gt 0 ]; then
          echo "🔴 HIGH RISK: Host filesystem access methods found ($access_methods)"
          risk_score=$((risk_score + 3))
      else
          echo "🟢 LOW RISK: No host filesystem access detected"
      fi
      
      if [ $isolation_score -lt 6 ]; then
          shared_ns=$((6 - isolation_score))
          echo "🟡 MEDIUM RISK: Shared namespaces detected ($shared_ns)"
          risk_score=$((risk_score + 2))
      else
          echo "🟢 LOW RISK: Full namespace isolation"
      fi
      
      if command -v chroot >/dev/null 2>&1; then
          echo "🟡 MEDIUM RISK: chroot command available"
          risk_score=$((risk_score + 1))
      fi
      
      echo ""
      echo "📊 OVERALL RISK ASSESSMENT:"
      echo "=========================="
      if [ $risk_score -ge 5 ]; then
          echo "🔴 HIGH RISK: Multiple escape vectors available"
          echo "   Risk Score: $risk_score/6"
          echo "   Recommendation: Review container security configuration"
      elif [ $risk_score -ge 3 ]; then
          echo "🟡 MEDIUM RISK: Some escape vectors present"
          echo "   Risk Score: $risk_score/6"
          echo "   Recommendation: Monitor and harden container"
      else
          echo "🟢 LOW RISK: Container appears well-isolated"
          echo "   Risk Score: $risk_score/6"
          echo "   Status: Container security posture is good"
      fi
      
      # Create detailed report
      report_file="/tmp/container_security_report.txt"
      {
          echo "CONTAINER SECURITY ASSESSMENT REPORT"
          echo "==================================="
          echo "Date: $(date)"
          echo "Container ID: $(hostname)"
          echo "Assessment User: $(id)"
          echo ""
          echo "FINDINGS SUMMARY:"
          echo "- Host filesystem access methods: $access_methods"
          echo "- Namespace isolation score: $isolation_score/6"
          echo "- Overall risk score: $risk_score/6"
          echo "- Accessible processes: $process_count+"
          echo ""
          echo "CONTAINER DETAILS:"
          echo "- Container IP: ${container_ip:-'Not detected'}"
          echo "- Host Gateway: ${host_ip:-'Not detected'}"
          echo "- PID Namespace: $(readlink /proc/self/ns/pid 2>/dev/null || echo 'N/A')"
          echo ""
          echo "SECURITY STATUS:"
          if [ $risk_score -ge 5 ]; then
              echo "- Overall Risk: HIGH"
              echo "- Container Escape Potential: POSSIBLE"
          elif [ $risk_score -ge 3 ]; then
              echo "- Overall Risk: MEDIUM" 
              echo "- Container Escape Potential: LIMITED"
          else
              echo "- Overall Risk: LOW"
              echo "- Container Escape Potential: MINIMAL"
          fi
          echo ""
          echo "RECOMMENDATIONS:"
          if [ $access_methods -gt 0 ]; then
              echo "- Block access to host filesystem via /proc/1/root"
          fi
          if [ $isolation_score -lt 6 ]; then
              echo "- Ensure full namespace isolation"
          fi
          echo "- Regular security monitoring recommended"
          echo ""
          echo "Assessment completed successfully."
      } > "$report_file"
      
      echo ""
      echo "📄 Detailed report saved to: $report_file"
      echo ""
      echo "📋 DISPLAYING SECURITY REPORT:"
      echo "============================="
      cat "$report_file"
      
      echo ""
      echo "🎯 CONTAINER SECURITY ASSESSMENT COMPLETE!"
      echo "=========================================="
      echo "✅ Environment analyzed"
      echo "✅ Escape vectors tested"
      echo "✅ Security posture evaluated"
      echo "✅ Risk assessment completed"
      echo "✅ Recommendations provided"
    EOT
  }
}

# Output results
output "security_assessment_status" {
  value = "Container security assessment completed successfully. Comprehensive analysis of isolation and escape vectors performed."
  depends_on = [null_resource.container_security_assessment]
}

output "security_report_location" {
  value = "/tmp/container_security_report.txt"
}

output "assessment_summary" {
  value = "Security assessment evaluated container isolation, namespace separation, filesystem access, and potential escape vectors. Results provide risk scoring and security recommendations."
}
