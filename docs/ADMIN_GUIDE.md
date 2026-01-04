# KubeSec Administrator Guide: Authentication & Access Control

This guide explains how to secure and manage access to the KubeSec Dashboard using Kubernetes-native Role-Based Access Control (RBAC).

## Authentication Overview

KubeSec leverages the Kubernetes `TokenReview` API. When a user logs in with a Bearer Token, the KubeSec backend verifies that token directly with the Kubernetes API server. This ensures:
1. **No Password Database**: User identities are managed by Kubernetes (OIDC, ServiceAccounts, etc.).
2. **Inherited Permissions**: The dashboard automatically respects the user's existing Kubernetes permissions.

---

## 1. Setting Up Persistent Access (Recommended)

By default, the `kubectl create token` command generates a short-lived token (usually 1 hour). For a persistent connection to the dashboard, administrators should create a ServiceAccount with a linked Secret.

### Create a Dedicated Admin ServiceAccount
```bash
# Create the service account
kubectl create serviceaccount kubesec-admin -n demo

# Grant cluster-admin rights (for global visibility)
kubectl create clusterrolebinding kubesec-admin-global \
  --clusterrole=cluster-admin \
  --serviceaccount=demo:kubesec-admin

# Create a permanent Token Secret
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: kubesec-admin-token
  namespace: demo
  annotations:
    kubernetes.io/service-account.name: kubesec-admin
type: kubernetes.io/service-account-token
EOF
```

### Retrieve the Permanent Token
```bash
kubectl get secret kubesec-admin-token -n demo -o jsonpath='{.data.token}' | base64 --decode
```

---

## 2. Setting Up Individual User Roles

If you want to grant access to specific users or teams without giving them cluster-wide admin rights, use standard Namespace-level Roles.

### Delegate Access to a Namespace Admin
If a user is responsible for the `frontend` namespace, give their ServiceAccount `edit` or `view` rights in that namespace:

```bash
kubectl create rolebinding dashboard-manager \
  --clusterrole=edit \
  --serviceaccount=frontend:default \
  -n frontend
```

Now, any token generated for the `default` account in the `frontend` namespace will allow the user to manage security policies for that namespace.

---

## 3. Best Practices

- **Zero Network Exposure**: The KubeSec dashboard is intended to be accessed via `kubectl port-forward`. Do not expose the internal API port to the public internet unless you have an Ingress with additional OIDC protection.
- **Session Security**: KubeSec stores tokens in `sessionStorage`. They are automatically wiped when the browser tab is closed.
- **Audit Logs**: Actions performed in the dashboard are logged in the KubeSec Audit Log with the `user_id` mapped to the Kubernetes ServiceAccount name.
