# KubeSec User Guide: Accessing the Dashboard

This guide explains how to generate a secure access token and log into the KubeSec Dashboard using your existing Kubernetes credentials.

## 1. How to Login

KubeSec uses your Kubernetes identity to log you in. You don't need a separate username or password; you simply need a **Bearer Token** from your cluster.

1. Ensure your port-forwarding is active: `kubectl port-forward svc/kubesec-service 8080:80`.
2. Open the dashboard in your browser.
3. Paste your token into the login box and click **Identify & Enter**.

---

## 2. Generating an Access Token

You can generate a temporary token for your current workspace using a single command.

### Standard Login (1 hour)
```bash
kubectl create token default -n <your-namespace>
```

### Shift-Long Login (8 hours)
If you want to stay logged in for your entire shift, use the `--duration` flag:
```bash
kubectl create token default -n <your-namespace> --duration=8h
```

---

## 3. Understanding Your Permissions

What you see in the KubeSec dashboard depends entirely on your Kubernetes RBAC permissions:

- **Namespace Scope**: If you are a Developer for the `demo` namespace, you will only see workloads and security policies belonging to `demo`. 
- **Read-Only vs Manage**: If your account has `view` rights, you can see policies and audit logs. If you have `edit` or `admin` rights, you can also approve/revoke syscalls and change workload security modes.

### Verify your identity
Once logged in, your Kubernetes identity (e.g., `system:serviceaccount:demo:default`) will be displayed in the top navigation bar.

---

## 4. Troubleshooting

### "Invalid or Expired Token"
Kubernetes tokens are temporary. If your session expires:
1. Generate a new token using the command in Section 2.
2. Refresh the KubeSec login page.
3. Paste the new token.

### "No Workloads Found"
If the dashboard is empty, either:
- Your ServiceAccount does not have permission to `list pods` in that namespace.
- No workloads in your namespace have the `icu.systems/secure: "true"` label.
