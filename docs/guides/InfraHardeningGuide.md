# Infrastructure Hardening Guide (GCP/Azure)

## 1. Overview
This document defines the baseline security configuration for Virtual Machines and Infrastructure components to prevent unauthorized access (INC00105).

## 2. Network Security (Firewall/NSG)
### 2.1. Inbound Rules
-   **Deny All** by default.
-   **SSH (22)**: Allow ONLY from VPN/Bastion IPs. NEVER `0.0.0.0/0`.
-   **RDP (3389)**: Allow ONLY from VPN/Bastion IPs. NEVER `0.0.0.0/0`.
-   **HTTP/HTTPS (80/443)**: Allowed for public Load Balancers only. Backend VMs should not expose these ports directly to internet.

### 2.2. Outbound Rules
-   Restrict outbound traffic to necessary services (e.g., package repos, specific APIs).

## 3. VM Hardening
-   **OS Patching**: Enable automatic security updates.
-   **Service Accounts**:
    -   Do not use default Compute Engine service account.
    -   Use custom SA with least privilege.
-   **Public IPs**: VMs should NOT have public IPs unless acting as a Bastion/LB. Use Cloud NAT for outbound access.

## 4. Remediation Procedure
1.  **Scan**: Run `fulcrum security scan-infra -p [PROJECT]` to identify violations.
2.  **Analyze**: Review `prowler_reports/` for high severity fails (e.g., `cis_gcp_3_6` for SSH exposure).
3.  **Fix**:
    -   Remove `0.0.0.0/0` firewall rules.
    -   Stop unnecessary services.
    -   Remove Public IPs from internal VMs.
4.  **Verify**: Re-run scan to confirm green status.
