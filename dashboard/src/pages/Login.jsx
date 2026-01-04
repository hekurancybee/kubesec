import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { login } from '../lib/api'
import { Button } from '../components/ui/Button'
import { Shield, Key, AlertCircle, Loader2, Lock, ChevronRight } from 'lucide-react'

export default function Login() {
    const [token, setToken] = useState('')
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const navigate = useNavigate()

    useEffect(() => {
        setError(null)
    }, [])

    async function handleSubmit(e) {
        e.preventDefault()
        if (!token.trim()) return

        setLoading(true)
        setError(null)
        try {
            await login(token.trim())
            navigate('/')
        } catch (err) {
            setError(err.message)
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="stack items-center justify-center min-h-screen" style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            minHeight: '100vh',
            width: '100vw',
            padding: '2rem',
            backgroundAttachment: 'fixed',
            position: 'relative',
            overflow: 'hidden'
        }}>
            {/* Background decorative elements */}
            <div style={{
                position: 'fixed',
                top: '50%',
                left: '50%',
                transform: 'translate(-50%, -50%)',
                width: '60vw',
                height: '60vw',
                background: 'radial-gradient(circle, rgba(183, 255, 42, 0.03) 0%, transparent 70%)',
                filter: 'blur(120px)',
                zIndex: -1,
                pointerEvents: 'none'
            }} />

            <div className="stack items-center justify-center" style={{ width: '100%', maxWidth: '440px', gap: '2rem' }}>
                <div className="card anim-fade-in" style={{
                    width: '100%',
                    background: 'rgba(15, 20, 30, 0.4)',
                    backdropFilter: 'blur(20px)',
                    border: '1px solid rgba(255, 255, 255, 0.08)',
                    boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
                    overflow: 'hidden'
                }}>
                    <div style={{
                        height: '2px',
                        width: '100%',
                        background: 'linear-gradient(90deg, transparent, var(--accent), transparent)',
                        opacity: 0.5
                    }} />

                    <div style={{ padding: '2.5rem' }}>
                        <div className="stack items-center mb-8" style={{ gap: '0.5rem' }}>
                            <Shield size={32} color="var(--accent)" />
                            <h2 style={{ fontSize: '1.5rem', fontWeight: 900, margin: 0 }}>Cluster Access</h2>
                            <p className="dim x-small">Authentication Required</p>
                        </div>

                        <form onSubmit={handleSubmit} className="stack" style={{ gap: '1.75rem' }}>
                            <div className="stack" style={{ gap: '0.75rem' }}>
                                <div className="row between items-center">
                                    <label className="bold small dim ml-1" style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                                        Identity Token
                                    </label>
                                    <Lock size={12} className="subtle" />
                                </div>

                                <div className="row items-center relative" style={{
                                    background: 'rgba(0,0,0,0.3)',
                                    border: '1px solid var(--border)',
                                    borderRadius: '14px',
                                    padding: '0 1rem',
                                    transition: 'all 0.2s',
                                    boxShadow: 'inset 0 2px 4px rgba(0,0,0,0.2)'
                                }}>
                                    <Key size={20} className="subtle" strokeWidth={1.5} />
                                    <input
                                        type="password"
                                        value={token}
                                        onChange={(e) => setToken(e.target.value)}
                                        placeholder="Paste bearer token..."
                                        className="mono"
                                        style={{
                                            background: 'transparent',
                                            border: 'none',
                                            color: 'var(--text-1)',
                                            padding: '1.15rem 0.75rem',
                                            width: '100%',
                                            outline: 'none',
                                            fontSize: '0.9rem',
                                            letterSpacing: token ? '0.2em' : 'normal'
                                        }}
                                    />
                                </div>
                            </div>

                            {error && (
                                <div className="row items-center p-4 anim-filter-flash" style={{
                                    background: 'rgba(255, 59, 59, 0.08)',
                                    border: '1px solid rgba(255, 59, 59, 0.2)',
                                    borderRadius: '12px',
                                    gap: '0.75rem',
                                    color: '#ff7b7b'
                                }}>
                                    <AlertCircle size={20} />
                                    <span className="small bold">{error}</span>
                                </div>
                            )}

                            <Button
                                type="submit"
                                variant="primary"
                                style={{
                                    height: '56px',
                                    borderRadius: '14px',
                                    fontSize: '1rem',
                                    fontWeight: 800,
                                    boxShadow: '0 10px 20px -5px rgba(183, 255, 42, 0.2)'
                                }}
                                disabled={loading || !token.trim()}
                            >
                                {loading ? (
                                    <div className="row items-center" style={{ gap: '0.75rem' }}>
                                        <Loader2 className="anim-spin" size={20} />
                                        <span>Verifying...</span>
                                    </div>
                                ) : (
                                    <div className="row items-center" style={{ gap: '0.5rem' }}>
                                        <span>Enter Dashboard</span>
                                        <ChevronRight size={18} />
                                    </div>
                                )}
                            </Button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    )
}
