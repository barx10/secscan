import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Shield,
  LayoutDashboard,
  Scan,
  Settings,
  Activity,
  AlertTriangle,
  FileCheck,
  RefreshCw,
  ArrowRight,
  Globe,
  Download,
  DownloadCloud,
  CheckCircle,
  XCircle,
  Minus,
  HelpCircle,
  Trash2
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { LanguageProvider, useLanguage } from './i18n';

// API Helpers
const api = {
  getScans: async () => {
    const res = await fetch('/api/scans');
    return res.json();
  },
  createScan: async (target, scanTypes = ['full'], targetType = 'repo') => {
    const res = await fetch('/api/scans', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, target_type: targetType, scan_types: scanTypes })
    });
    return res.json();
  },
  getTools: async () => {
    const res = await fetch('/api/tools');
    return res.json();
  },
  installTool: async (name) => {
    const res = await fetch(`/api/tools/${name}/install`, { method: 'POST' });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || 'Installation failed');
    }
    return res.json();
  },
  deleteScan: async (scanId) => {
    const res = await fetch(`/api/scans/${scanId}`, { method: 'DELETE' });
    return res.json();
  }
};

// Components
const SidebarItem = ({ icon: Icon, label, to }) => {
  const location = useLocation();
  const isActive = location.pathname === to;

  return (
    <Link to={to} style={{ textDecoration: 'none' }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        padding: '12px 16px',
        margin: '4px 0',
        borderRadius: '8px',
        color: isActive ? 'var(--text-main)' : 'var(--text-muted)',
        background: isActive ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
        borderLeft: isActive ? '3px solid var(--color-primary)' : '3px solid transparent',
        transition: 'all 0.2s ease',
        cursor: 'pointer'
      }}>
        <Icon size={20} style={{ marginRight: '12px', color: isActive ? 'var(--color-primary)' : 'inherit' }} />
        <span style={{ fontWeight: isActive ? 600 : 400 }}>{label}</span>
      </div>
    </Link>
  );
};

const Header = () => {
  const { t, language, toggleLanguage } = useLanguage();

  return (
    <header style={{
      height: '70px',
      borderBottom: '1px solid var(--border-color)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '0 32px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 600 }}>{t('commandCenter')}</h2>
      </div>
      <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
        <button
          onClick={toggleLanguage}
          style={{
            background: 'transparent',
            color: 'var(--text-muted)',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            padding: '8px 12px',
            borderRadius: '6px',
            border: '1px solid var(--border-color)',
            cursor: 'pointer'
          }}
        >
          <Globe size={16} />
          <span style={{ textTransform: 'uppercase', fontSize: '0.875rem' }}>{language}</span>
        </button>
        <div className="glass-panel" style={{ padding: '8px 16px', fontSize: '0.875rem' }}>
          {t('systemStatus')}: <span style={{ color: 'var(--color-success)' }}>{t('operational')}</span>
        </div>
      </div>
    </header>
  );
};

const StatCard = ({ label, value, color }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className="glass-panel"
    style={{ padding: '24px', flex: 1 }}
  >
    <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '8px' }}>{label}</div>
    <div style={{ fontSize: '2.5rem', fontWeight: 700, color: color }}>{value}</div>
  </motion.div>
);

const ScansTable = ({ scans, showActions = true, onDelete = null }) => {
  const { t, language } = useLanguage();

  if (scans.length === 0) {
    return (
      <div style={{ padding: '32px', textAlign: 'center', color: 'var(--text-muted)' }}>
        {t('noScans')}
      </div>
    );
  }

  return (
    <table style={{ width: '100%', borderCollapse: 'collapse' }}>
      <thead>
        <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
          <th style={{ padding: '16px' }}>{t('scanId')}</th>
          <th style={{ padding: '16px' }}>{t('status')}</th>
          <th style={{ padding: '16px' }}>{t('findings')}</th>
          {showActions && <th style={{ padding: '16px' }}>{t('actions')}</th>}
        </tr>
      </thead>
      <tbody>
        {scans.map((scan) => (
          <tr key={scan.scan_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <td style={{ padding: '16px', fontFamily: 'monospace' }}>{scan.scan_id.slice(0, 8)}...</td>
            <td style={{ padding: '16px' }}>
              <span style={{
                padding: '4px 8px',
                borderRadius: '4px',
                fontSize: '0.75rem',
                background: scan.status === 'completed' ? 'rgba(0, 255, 157, 0.1)' :
                  scan.status === 'failed' ? 'rgba(255, 0, 85, 0.1)' : 'rgba(255, 184, 0, 0.1)',
                color: scan.status === 'completed' ? 'var(--color-success)' :
                  scan.status === 'failed' ? 'var(--color-danger)' : 'var(--color-warning)'
              }}>
                {scan.status.toUpperCase()}
              </span>
            </td>
            <td style={{ padding: '16px' }}>{scan.findings_count !== null ? scan.findings_count : '-'}</td>
            {showActions && (
              <td style={{ padding: '16px', display: 'flex', gap: '12px', alignItems: 'center' }}>
                {scan.status === 'completed' && (
                  <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                    <a href={`/api/scans/${scan.scan_id}/report.html?lang=${language}`} target="_blank" style={{ color: 'var(--color-primary)', fontSize: '0.875rem' }}>{t('viewReport')}</a>
                  </div>
                )}
                {onDelete && (
                  <button
                    onClick={() => onDelete(scan.scan_id)}
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 0 }}
                    title={t('delete')}
                  >
                    <Trash2 size={16} color="var(--color-danger)" />
                  </button>
                )}
              </td>
            )}
          </tr>
        ))}
      </tbody>
    </table>
  );
};

const Dashboard = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const { t } = useLanguage();

  const fetchData = async () => {
    try {
      const data = await api.getScans();
      setScans(data);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const pendingCount = scans.filter(s => s.status === 'pending').length;
  const completedCount = scans.filter(s => s.status === 'completed').length;
  const failedCount = scans.filter(s => s.status === 'failed').length;

  return (
    <div style={{ padding: '32px' }}>
      <div style={{ display: 'flex', gap: '24px', marginBottom: '40px' }}>
        <StatCard label={t('activeScans')} value={pendingCount} color="var(--color-warning)" />
        <StatCard label={t('completed')} value={completedCount} color="var(--color-success)" />
        <StatCard label={t('failed')} value={failedCount} color="var(--color-danger)" />
      </div>

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '20px' }}>
        <h3 style={{ fontSize: '1.25rem' }}>{t('recentActivity')}</h3>
        <button
          onClick={fetchData}
          style={{ background: 'transparent', color: 'var(--color-primary)', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}
        >
          <RefreshCw size={16} className={loading ? 'spin' : ''} /> {t('refresh')}
        </button>
      </div>

      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <ScansTable scans={scans.slice(0, 5)} />
      </div>
    </div>
  );
};

const ActivityLog = () => {
  const [scans, setScans] = useState([]);
  const { t } = useLanguage();

  const loadScans = () => {
    api.getScans().then(setScans).catch(console.error);
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleDelete = async (scanId) => {
    if (!confirm(t('delete') + '?')) return;
    await api.deleteScan(scanId);
    loadScans();
  };

  return (
    <div style={{ padding: '32px' }}>
      <h2 style={{ marginBottom: '24px' }}>{t('activityLog')}</h2>
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <ScansTable scans={scans} onDelete={handleDelete} />
      </div>
    </div>
  );
};

const FindingsPage = () => {
  const [scans, setScans] = useState([]);
  const { t, language } = useLanguage();

  useEffect(() => {
    api.getScans().then(data => {
      // Filter for completed scans only
      setScans(data.filter(s => s.status === 'completed'));
    }).catch(console.error);
  }, []);

  return (
    <div style={{ padding: '32px' }}>
      <h2 style={{ marginBottom: '24px' }}>{t('findingsOverview')}</h2>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '24px' }}>
        {scans.length === 0 ? (
          <div style={{ color: 'var(--text-muted)' }}>{t('noFindings')}</div>
        ) : (
          scans.map(scan => (
            <div key={scan.scan_id} className="glass-panel" style={{ padding: '24px' }}>
              <div style={{ marginBottom: '16px', display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ fontFamily: 'monospace', color: 'var(--text-muted)' }}>{scan.scan_id.slice(0, 8)}</span>
                <span style={{ color: 'var(--color-success)', fontSize: '0.875rem' }}>{t('completed')}</span>
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 700, marginBottom: '8px' }}>
                {scan.findings_count}
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '16px' }}>
                {t('findings')}
              </div>
              <a
                href={`/api/scans/${scan.scan_id}/report.html?lang=${language}`}
                target="_blank"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '8px',
                  color: 'var(--color-primary)',
                  fontSize: '0.875rem',
                  fontWeight: 600
                }}
              >
                {t('viewReport')} <ArrowRight size={16} />
              </a>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

const ReportsPage = () => {
  const [scans, setScans] = useState([]);
  const { t, language } = useLanguage();

  useEffect(() => {
    api.getScans().then(data => {
      setScans(data.filter(s => s.status === 'completed'));
    }).catch(console.error);
  }, []);

  return (
    <div style={{ padding: '32px' }}>
      <h2 style={{ marginBottom: '24px' }}>{t('availableReports')}</h2>

      <div className="glass-panel">
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '16px' }}>{t('scanId')}</th>
              <th style={{ padding: '16px' }}>{t('findings')}</th>
              <th style={{ padding: '16px' }}>{t('format')}</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <tr key={scan.scan_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '16px', fontFamily: 'monospace' }}>{scan.scan_id.slice(0, 8)}...</td>
                <td style={{ padding: '16px' }}>{scan.findings_count}</td>
                <td style={{ padding: '16px', display: 'flex', gap: '12px' }}>
                  <a
                    href={`/api/scans/${scan.scan_id}/report.json?lang=${language}`}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      color: 'var(--text-main)',
                      fontSize: '0.875rem',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      border: '1px solid var(--border-color)'
                    }}
                  >
                    <Download size={14} /> JSON
                  </a>
                  <a
                    href={`/api/scans/${scan.scan_id}/report.html?lang=${language}`}
                    target="_blank"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      color: 'var(--color-primary)',
                      fontSize: '0.875rem',
                      padding: '4px 8px',
                      borderRadius: '4px',
                      border: '1px solid var(--color-primary)',
                      background: 'rgba(0, 240, 255, 0.1)'
                    }}
                  >
                    <FileCheck size={14} /> HTML
                  </a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

const SettingsPage = () => {
  const [tools, setTools] = useState([]);
  const [installing, setInstalling] = useState(null);
  const { t } = useLanguage();

  useEffect(() => {
    loadTools();
  }, []);

  const loadTools = () => {
    api.getTools().then(setTools).catch(console.error);
  };

  const handleInstall = async (toolName) => {
    setInstalling(toolName);
    try {
      await api.installTool(toolName);
      loadTools();
      // Optional: show toast/success message
    } catch (e) {
      alert(e.message);
    } finally {
      setInstalling(null);
    }
  };

  return (
    <div style={{ padding: '32px' }}>
      <h2 style={{ marginBottom: '24px' }}>{t('settingsTitle')}</h2>

      <div className="glass-panel" style={{ padding: '24px', marginBottom: '32px' }}>
        <h3 style={{ marginBottom: '16px' }}>{t('toolsStatus')}</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ textAlign: 'left', borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
              <th style={{ padding: '12px' }}>{t('toolName')}</th>
              <th style={{ padding: '12px' }}>{t('status')}</th>
              <th style={{ padding: '12px' }}>{t('version')}</th>
              <th style={{ padding: '12px' }}>{t('actions')}</th>
            </tr>
          </thead>
          <tbody>
            {tools.map((tool, i) => (
              <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
                <td style={{ padding: '12px', fontWeight: 500 }}>{tool.name}</td>
                <td style={{ padding: '12px' }}>
                  {tool.available ? (
                    <span style={{ color: 'var(--color-success)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <CheckCircle size={14} /> {t('installed')}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--color-danger)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <XCircle size={14} /> {t('missing')}
                    </span>
                  )}
                </td>
                <td style={{ padding: '12px', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                  {tool.version || '-'}
                </td>
                <td style={{ padding: '12px' }}>
                  {!tool.available && (
                    <div style={{ width: '100%', maxWidth: '140px' }}>
                      {installing === tool.name ? (
                        <div style={{ width: '100%' }}>
                          <div style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            fontSize: '0.75rem',
                            color: 'var(--color-primary)',
                            marginBottom: '4px'
                          }}>
                            <RefreshCw size={12} className="spin" /> {t('installing')}
                          </div>
                          <div style={{
                            width: '100%',
                            height: '4px',
                            background: 'rgba(255,255,255,0.1)',
                            borderRadius: '2px',
                            overflow: 'hidden'
                          }}>
                            <motion.div
                              initial={{ width: '0%' }}
                              animate={{ width: '100%' }}
                              transition={{ duration: 15, ease: "linear" }}
                              style={{
                                height: '100%',
                                background: 'var(--color-primary)'
                              }}
                            />
                          </div>
                        </div>
                      ) : (
                        <button
                          onClick={() => handleInstall(tool.name)}
                          style={{
                            background: 'rgba(0, 240, 255, 0.1)',
                            border: '1px solid var(--color-primary)',
                            color: 'var(--color-primary)',
                            padding: '6px 12px',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '0.75rem',
                            display: 'flex',
                            alignItems: 'center',
                            gap: '6px',
                            width: '100%',
                            justifyContent: 'center'
                          }}
                        >
                          <DownloadCloud size={14} /> {t('install')}
                        </button>
                      )}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>


    </div>
  );
};

const NewScanParams = () => {
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('repo'); // 'repo' or 'url'
  const [selectedTools, setSelectedTools] = useState({
    secrets: true,
    deps: true,
    sast: true,
    config: true,
    zap: true
  });
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();
  const { t } = useLanguage();

  const handleScan = async () => {
    if (!target) return;
    setLoading(true);

    // Convert selection to list
    const scanTypes = [];

    if (targetType === 'url') {
      // Web scan mostly implies ZAP + maybe others if applicable
      if (selectedTools.zap) scanTypes.push('web');
    } else {
      if (selectedTools.secrets && selectedTools.deps && selectedTools.sast && selectedTools.config) {
        scanTypes.push('full');
      } else {
        if (selectedTools.secrets) scanTypes.push('secrets');
        if (selectedTools.deps) scanTypes.push('deps');
        if (selectedTools.sast) scanTypes.push('sast');
        if (selectedTools.config) scanTypes.push('config');
      }
    }

    try {
      await api.createScan(target, scanTypes, targetType);
      navigate('/');
    } catch (e) {
      alert(t('failedStart'));
    } finally {
      setLoading(false);
    }
  };

  const toggleTool = (key) => {
    setSelectedTools(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div style={{ padding: '32px' }}>
      <h2 style={{ marginBottom: '24px' }}>{t('newScan')}</h2>
      <div className="glass-panel" style={{ padding: '32px', maxWidth: '600px' }}>

        {/* Source Type Selector */}
        <div style={{ marginBottom: '24px' }}>
          <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.875rem' }}>{t('sourceType')}</label>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              onClick={() => setTargetType('repo')}
              style={{
                flex: 1,
                padding: '10px',
                background: targetType === 'repo' ? 'var(--color-primary)' : 'rgba(255,255,255,0.05)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'white',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px'
              }}
            >
              <FileCheck size={16} />
              {t('repository')}
            </button>
            <button
              onClick={() => setTargetType('url')}
              style={{
                flex: 1,
                padding: '10px',
                background: targetType === 'url' ? 'var(--color-primary)' : 'rgba(255,255,255,0.05)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'white',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px'
              }}
            >
              <Globe size={16} />
              {t('website')}
            </button>
          </div>
        </div>

        <p style={{ color: 'var(--text-muted)', marginBottom: '24px' }}>
          {t('enterRepoUrl')}
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.875rem' }}>{t('targetUrl')}</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={targetType === 'repo' ? "https://github.com/user/repo" : "https://example.com"}
              style={{
                width: '100%',
                padding: '12px',
                background: 'rgba(0,0,0,0.2)',
                border: '1px solid var(--border-color)',
                color: 'white',
                borderRadius: '6px',
                outline: 'none'
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '12px', fontSize: '0.875rem' }}>{t('selectTools')}</label>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>

              {targetType === 'repo' ? (
                <>
                  <div
                    onClick={() => toggleTool('secrets')}
                    style={{
                      padding: '12px',
                      borderRadius: '6px',
                      border: selectedTools.secrets ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                      background: selectedTools.secrets ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    <Shield size={18} />
                    <span>{t('scanSecrets')}</span>
                  </div>
                  <div
                    onClick={() => toggleTool('deps')}
                    style={{
                      padding: '12px',
                      borderRadius: '6px',
                      border: selectedTools.deps ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                      background: selectedTools.deps ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    <AlertTriangle size={18} />
                    <span>{t('scanDeps')}</span>
                  </div>
                  <div
                    onClick={() => toggleTool('sast')}
                    style={{
                      padding: '12px',
                      borderRadius: '6px',
                      border: selectedTools.sast ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                      background: selectedTools.sast ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    <FileCheck size={18} />
                    <span>{t('scanSast')}</span>
                  </div>
                  <div
                    onClick={() => toggleTool('config')}
                    style={{
                      padding: '12px',
                      borderRadius: '6px',
                      border: selectedTools.config ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                      background: selectedTools.config ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px'
                    }}
                  >
                    <Settings size={18} />
                    <span>{t('scanConfig')}</span>
                  </div>
                </>
              ) : (
                <div
                  onClick={() => toggleTool('zap')}
                  style={{
                    gridColumn: 'span 2',
                    padding: '12px',
                    borderRadius: '6px',
                    border: selectedTools.zap ? '1px solid var(--color-primary)' : '1px solid var(--border-color)',
                    background: selectedTools.zap ? 'rgba(0, 240, 255, 0.1)' : 'transparent',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px'
                  }}
                >
                  <Globe size={18} />
                  <span>{t('scanWeb')}</span>
                </div>
              )}

            </div>
          </div>
        </div>

        <button
          onClick={handleScan}
          disabled={loading}
          style={{
            background: loading ? 'var(--text-muted)' : 'var(--color-primary)',
            color: 'black',
            fontWeight: 600,
            padding: '12px',
            borderRadius: '6px',
            marginTop: '16px',
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '8px',
            cursor: loading ? 'not-allowed' : 'pointer'
          }}>
          {loading ? t('initializing') : <><Scan size={18} /> {t('initiateScan')}</>}
        </button>
      </div>
    </div>
  );
}

const HelpPage = () => {
  const { t } = useLanguage();

  const steps = [
    { title: t('step1Title'), desc: t('step1Desc'), icon: Settings },
    { title: t('step2Title'), desc: t('step2Desc'), icon: Scan },
    { title: t('step3Title'), desc: t('step3Desc'), icon: AlertTriangle },
    { title: t('step4Title'), desc: t('step4Desc'), icon: FileCheck },
  ];

  return (
    <div style={{ padding: '32px', maxWidth: '1000px', margin: '0 auto' }}>
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
      >
        <div style={{ textAlign: 'center', marginBottom: '48px' }}>
          <Shield size={64} color="var(--color-primary)" style={{ marginBottom: '16px' }} />
          <h1 style={{ fontSize: '2.5rem', fontWeight: 700, marginBottom: '12px' }}>{t('onboardingTitle')}</h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '1.25rem' }}>{t('onboardingSubtitle')}</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '24px', marginBottom: '48px' }}>
          {steps.map((step, i) => (
            <div key={i} className="glass-panel" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
              <div style={{
                position: 'absolute',
                top: '0',
                right: '0',
                fontSize: '4rem',
                opacity: '0.05',
                fontWeight: '900',
                lineHeight: '1',
                paddingRight: '16px'
              }}>
                {i + 1}
              </div>
              <step.icon size={32} color="var(--color-primary)" style={{ marginBottom: '16px' }} />
              <h3 style={{ fontSize: '1.25rem', marginBottom: '12px' }}>{step.title}</h3>
              <p style={{ color: 'var(--text-muted)', lineHeight: '1.5' }}>{step.desc}</p>
            </div>
          ))}
        </div>

        <div className="glass-panel" style={{ padding: '32px', marginBottom: '32px', background: 'rgba(0, 240, 255, 0.03)', border: '1px solid rgba(0, 240, 255, 0.1)' }}>
          <h2 style={{ marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Settings size={24} /> {t('toolsInstallTitle')}
          </h2>
          <p style={{ color: 'var(--text-muted)', lineHeight: '1.6' }}>
            {t('toolsInstallDesc')}
          </p>
        </div>

        <div className="glass-panel" style={{ padding: '32px' }}>
          <h2 style={{ marginBottom: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <HelpCircle size={24} /> {t('faqTitle')}
          </h2>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '32px' }}>
            {[1, 2, 3, 4, 5, 6].map(num => (
              <div key={num}>
                <h4 style={{ fontSize: '1.1rem', marginBottom: '8px', color: 'var(--text-main)' }}>{t(`faq${num}Q`)}</h4>
                <p style={{ color: 'var(--text-muted)', lineHeight: '1.5' }}>{t(`faq${num}A`)}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '48px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', marginTop: '32px' }}>
          <a href="https://www.laererliv.no/" target="_blank" rel="noopener noreferrer" style={{ marginBottom: '24px', display: 'inline-block', transition: 'transform 0.2s' }}>
            <img
              src="/logo.png"
              alt="Lærerliv Logo"
              style={{
                height: '100px',
                width: 'auto',
                borderRadius: '24px',
                boxShadow: '0 0 30px rgba(0, 240, 255, 0.15)',
                border: '1px solid rgba(255,255,255,0.1)'
              }}
            />
          </a>

          <h4 style={{ fontSize: '1.75rem', fontWeight: 700, marginBottom: '8px' }}>Lærerliv &copy; 2025</h4>

          <a href="mailto:kenneth@laererliv.no" style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            color: 'var(--color-primary)',
            textDecoration: 'none',
            padding: '10px 20px',
            background: 'rgba(0, 240, 255, 0.05)',
            borderRadius: '8px',
            border: '1px solid rgba(0, 240, 255, 0.2)',
            fontWeight: 500,
            transition: 'all 0.2s ease'
          }}>
            kenneth@laererliv.no
          </a>
        </div>
      </motion.div>
    </div>
  );
};

const AppContent = () => {
  const { t } = useLanguage();

  return (
    <Router>
      <div style={{ display: 'flex', height: '100vh', width: '100vw' }}>
        {/* Sidebar */}
        <aside style={{
          width: '260px',
          background: 'var(--bg-panel)',
          borderRight: '1px solid var(--border-color)',
          display: 'flex',
          flexDirection: 'column'
        }}>
          <div style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Shield size={32} color="var(--color-primary)" />
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, letterSpacing: '-0.5px' }}>
              Sec<span style={{ color: 'var(--color-primary)' }}>Scan</span>
            </h1>
          </div>

          <nav style={{ flex: 1, padding: '0 12px' }}>
            <SidebarItem to="/" label={t('dashboard')} icon={LayoutDashboard} />
            <SidebarItem to="/scan" label={t('newScan')} icon={Scan} />
            <SidebarItem to="/activity" label={t('activity')} icon={Activity} />
            <SidebarItem to="/findings" label={t('findings')} icon={AlertTriangle} />
            <SidebarItem to="/reports" label={t('reports')} icon={FileCheck} />
          </nav>

          <div style={{ padding: '12px' }}>
            <SidebarItem to="/settings" label={t('settings')} icon={Settings} />
            <SidebarItem to="/help" label={t('help')} icon={HelpCircle} />
          </div>
        </aside>

        {/* Main Content */}
        <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg-app)' }}>
          <Header />
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan" element={<NewScanParams />} />
            <Route path="/activity" element={<ActivityLog />} />
            <Route path="/findings" element={<FindingsPage />} />
            <Route path="/reports" element={<ReportsPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/help" element={<HelpPage />} />
            <Route path="*" element={<div style={{ padding: '32px' }}>{t('pageUnderConstruction')}</div>} />
          </Routes>
        </main>
      </div>
    </Router>
  );
};

// Main Layout
function App() {
  return (
    <LanguageProvider>
      <AppContent />
    </LanguageProvider>
  );
}

export default App;
