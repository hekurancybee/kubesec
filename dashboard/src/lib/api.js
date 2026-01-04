const API_BASE = '/api'

function getAuthHeader() {
    const token = sessionStorage.getItem('kubesec_token')
    return token ? { 'Authorization': `Bearer ${token}` } : {}
}

async function fetchWithAuth(url, options = {}) {
    const headers = {
        ...options.headers,
        ...getAuthHeader()
    }
    const res = await fetch(url, { ...options, headers })
    if (res.status === 401) {
        sessionStorage.removeItem('kubesec_token')
        window.location.href = '/login'
        throw new Error('Unauthorized')
    }
    return res
}

export async function login(token) {
    const res = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
    })
    if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Login failed')
    }
    const data = await res.json()
    sessionStorage.setItem('kubesec_token', token)
    sessionStorage.setItem('kubesec_user', data.username)
    return data
}

export async function logout() {
    sessionStorage.removeItem('kubesec_token')
    sessionStorage.removeItem('kubesec_user')
    window.location.href = '/login'
}

export async function fetchWorkloads() {
    const res = await fetchWithAuth(`${API_BASE}/workloads`)
    if (!res.ok) throw new Error('Failed to fetch workloads')
    return res.json()
}

export async function fetchStatsSummary(windowMinutes = 1440) {
    const res = await fetchWithAuth(`${API_BASE}/stats/summary?window=${windowMinutes}`)
    if (!res.ok) throw new Error('Failed to fetch stats summary')
    return res.json()
}

export async function fetchTimeseries(windowMinutes = 1440) {
    const res = await fetchWithAuth(`${API_BASE}/stats/timeseries?window=${windowMinutes}`)
    if (!res.ok) throw new Error('Failed to fetch timeseries')
    return res.json()
}

export async function fetchTopNamespaces(windowMinutes = 1440) {
    const res = await fetchWithAuth(`${API_BASE}/stats/top-namespaces?window=${windowMinutes}`)
    if (!res.ok) throw new Error('Failed to fetch top namespaces')
    return res.json()
}

export async function fetchDetections(windowMinutes = 15, page = 1, limit = 100, search = "", grouped = false) {
    const res = await fetchWithAuth(`${API_BASE}/detections?window=${windowMinutes}&page=${page}&limit=${limit}&search=${encodeURIComponent(search)}&grouped=${grouped}`)
    if (!res.ok) throw new Error('Failed to fetch detections')
    return res.json()
}

export async function fetchPolicyBaseline() {
    const res = await fetchWithAuth(`${API_BASE}/policies/baseline`)
    if (!res.ok) throw new Error('Failed to fetch policy baseline')
    return res.json()
}

export async function approveSyscall(workloadKey, syscallName, argument, isPrefix = false, cleanupMatched = false) {
    const res = await fetchWithAuth(`${API_BASE}/policies/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workloadKey, syscallName, argument, isPrefix, cleanupMatched })
    })
    if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Failed to approve syscall')
    }
    return res.json()
}

export async function revokeSyscall(workloadKey, syscallName, argument, isPrefix = false) {
    const res = await fetchWithAuth(`${API_BASE}/policies/revoke`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workloadKey, syscallName, argument, isPrefix })
    })
    if (!res.ok) throw new Error('Failed to revoke policy')
    return res.json()
}

export async function setWorkloadMode(workloadKey, mode) {
    const res = await fetchWithAuth(`${API_BASE}/workloads/mode`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workloadKey, mode })
    })
    if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Failed to update workload mode')
    }
    return res.json()
}

export async function bulkApproveSyscalls(requests) {
    const res = await fetchWithAuth(`${API_BASE}/policies/bulk-approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ requests })
    })
    if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Failed to bulk approve syscalls')
    }
    return res.json()
}

export async function clearBaseline(workloadKey) {
    const res = await fetchWithAuth(`${API_BASE}/policies/baseline/all?workloadKey=${encodeURIComponent(workloadKey)}`, {
        method: 'DELETE'
    })
    if (!res.ok) throw new Error('Failed to clear baseline')
    return res.json()
}

export async function fetchPolicyAudit(workloadKey) {
    const res = await fetchWithAuth(`${API_BASE}/policies/audit?workloadKey=${encodeURIComponent(workloadKey)}`)
    if (!res.ok) throw new Error('Failed to fetch policy audit')
    return res.json()
}

export async function fetchGlobalAudit(limit = 100) {
    const res = await fetchWithAuth(`${API_BASE}/audit/global?limit=${limit}`)
    if (!res.ok) throw new Error('Failed to fetch global audit')
    return res.json()
}

export async function fetchWorkloadBaseline(workloadKey) {
    const res = await fetchWithAuth(`${API_BASE}/policies/baseline/export?workloadKey=${encodeURIComponent(workloadKey)}`)
    if (!res.ok) throw new Error('Failed to fetch workload baseline')
    return res.json()
}
