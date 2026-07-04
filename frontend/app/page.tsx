'use client'

import { DragEvent, useCallback, useEffect, useMemo, useRef, useState } from 'react'

type RuleInventory = {
  yara: number
  sigma: number
  suricata: number
  cs_beacon: number
  available_detectors: string[]
  refreshed_at: string
}

type ScanSummary = {
  id: string
  status: ScanJob['status']
  stage: string
  verdict: ScanJob['verdict']
  created_at: string
  finished_at?: string
  file: ScanJob['file']
  detectors: string[]
  match_count: number
  cs_match_count: number
}

type ScanHistory = { items: ScanSummary[]; count: number }

type RuleFile = {
  rule: string
  source: string
  content: string
  size: number
  line: number
  truncated: boolean
}

type ManagedYARARule = {
  name: string
  enabled: boolean
  size: number
  modified_at: string
  rule_count: number
}

type ManagedYARADocument = ManagedYARARule & { content: string }
type ManagedYARAList = { items: ManagedYARARule[]; count: number }

type DetectionMatch = {
  detector: string
  rule: string
  source?: string
  severity?: string
  category?: string
  tags?: string[]
  detail?: string
  timestamp?: string
}

type DetectorResult = {
  name: string
  status: string
  rule_files: number
  duration_ms: number
  matches: DetectionMatch[]
  warnings?: string[]
}

type ScanJob = {
  id: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  stage: string
  verdict: 'pending' | 'clean' | 'matched' | 'inconclusive'
  created_at: string
  finished_at?: string
  file: {
    name: string
    size: number
    sha256: string
    kind: string
    media_type: string
    executable: boolean
  }
  detectors: DetectorResult[]
  matches: DetectionMatch[]
  error?: string
}

const EMPTY_RULES: RuleInventory = { yara: 0, sigma: 0, suricata: 0, cs_beacon: 0, available_detectors: [], refreshed_at: '' }
const MAX_CLIENT_BYTES = 100 * 1024 * 1024
const YARA_TEMPLATE = `rule custom_detection
{
    meta:
        description = "Custom local detection"
        author = "C2 / SIGNAL"
        severity = "medium"

    strings:
        $indicator = "replace_me" ascii wide

    condition:
        $indicator
}
`

export default function ScannerPage() {
  const [rules, setRules] = useState<RuleInventory>(EMPTY_RULES)
  const [file, setFile] = useState<File | null>(null)
  const [dragging, setDragging] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [job, setJob] = useState<ScanJob | null>(null)
  const [history, setHistory] = useState<ScanSummary[]>([])
  const [deletingID, setDeletingID] = useState('')
  const [ruleFile, setRuleFile] = useState<RuleFile | null>(null)
  const [ruleLoading, setRuleLoading] = useState('')
  const [ruleError, setRuleError] = useState('')
  const [yaraManagerOpen, setYaraManagerOpen] = useState(false)
  const [error, setError] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)
  const pollingRef = useRef<AbortController | null>(null)
  const ruleRequestRef = useRef<AbortController | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([
      fetchJSON<RuleInventory>('/api/v1/rules', controller.signal),
      fetchJSON<ScanHistory>('/api/v1/scans?limit=30', controller.signal),
    ])
      .then(([inventory, scans]) => { setRules(inventory); setHistory(scans.items ?? []) })
      .catch((reason) => { if (reason.name !== 'AbortError') setError('无法读取规则清单，请检查扫描服务。') })
    return () => controller.abort()
  }, [])

  useEffect(() => () => { pollingRef.current?.abort(); ruleRequestRef.current?.abort() }, [])

  const totalRules = rules.yara + rules.sigma + rules.suricata
  const busy = job?.status === 'queued' || job?.status === 'running'
  const ruleViewerOpen = Boolean(ruleFile || ruleLoading || ruleError)

  useEffect(() => {
    if (!ruleViewerOpen) return
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        ruleRequestRef.current?.abort()
        setRuleFile(null)
        setRuleLoading('')
        setRuleError('')
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [ruleViewerOpen])
  const groupedMatches = useMemo(() => {
    const groups = new Map<string, DetectionMatch[]>()
    for (const match of job?.matches ?? []) {
      const current = groups.get(match.detector) ?? []
      current.push(match)
      groups.set(match.detector, current)
    }
    return Array.from(groups.entries())
  }, [job?.matches])

  const chooseFile = useCallback((candidate?: File) => {
    if (!candidate) return
    if (candidate.size > MAX_CLIENT_BYTES) {
      setError('文件超过前端 100 MB 限制。可通过服务端配置调整上限。')
      return
    }
    pollingRef.current?.abort()
    setFile(candidate)
    setJob(null)
    setUploadProgress(0)
    setError('')
  }, [])

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragging(false)
    chooseFile(event.dataTransfer.files[0])
  }

  async function startScan() {
    if (!file || busy) return
    setError('')
    setJob(null)
    setUploadProgress(1)
    try {
      const created = await uploadArtifact(file, setUploadProgress)
      setJob(created)
      const controller = new AbortController()
      pollingRef.current = controller
      await pollJob(created.id, controller.signal, setJob)
      const scans = await fetchJSON<ScanHistory>('/api/v1/scans?limit=30', controller.signal)
      setHistory(scans.items ?? [])
    } catch (reason) {
      if ((reason as Error).name !== 'AbortError') setError((reason as Error).message || '扫描失败')
    }
  }

  async function openHistory(id: string) {
    pollingRef.current?.abort()
    setError('')
    try {
      const selected = normalizeJob(await fetchJSON<ScanJob>(`/api/v1/scans/${id}`))
      setJob(selected)
    } catch (reason) {
      setError((reason as Error).message || '无法读取历史任务')
    }
  }

  async function deleteHistory(scan: ScanSummary) {
    if (!window.confirm(`确认删除扫描记录“${scan.file.name}”？此操作不可撤销。`)) return
    setDeletingID(scan.id)
    setError('')
    try {
      await fetchJSON<{ deleted: string }>(`/api/v1/scans/${scan.id}`, undefined, { method: 'DELETE' })
      setHistory((current) => current.filter((item) => item.id !== scan.id))
      setJob((current) => current?.id === scan.id ? null : current)
      if (job?.id === scan.id) closeRuleFile()
    } catch (reason) {
      setError((reason as Error).message || '删除扫描记录失败')
    } finally {
      setDeletingID('')
    }
  }

  async function openRuleFile(match: DetectionMatch) {
    if (!job || !match.source) return
    ruleRequestRef.current?.abort()
    const controller = new AbortController()
    ruleRequestRef.current = controller
    setRuleFile(null)
    setRuleError('')
    setRuleLoading(match.rule)
    try {
      const rule = await fetchJSON<RuleFile>(`/api/v1/scans/${job.id}/rule?name=${encodeURIComponent(match.rule)}`, controller.signal)
      setRuleFile(rule)
    } catch (reason) {
      if ((reason as Error).name !== 'AbortError') setRuleError((reason as Error).message || '读取规则文件失败')
    } finally {
      if (!controller.signal.aborted) setRuleLoading('')
    }
  }

  function closeRuleFile() {
    ruleRequestRef.current?.abort()
    setRuleFile(null)
    setRuleLoading('')
    setRuleError('')
  }

  return (
    <main>
      <header className="masthead">
        <div className="brand-lockup">
          <span className="brand-mark">⌁</span>
          <div><strong>C2 / SIGNAL</strong><small>ARTIFACT DETECTION CONSOLE</small></div>
        </div>
        <div className="system-state"><i /> DETECTION GRID ONLINE</div>
        <div className="revision">RELEASE <span>v0.1.0</span></div>
      </header>

      <section className="hero-panel">
        <div className="hero-copy">
          <span className="overline">MULTI-ENGINE / STATIC TRIAGE</span>
          <h1>上传制品<br /><em>自动触发规则</em></h1>
          <p>文件制品使用 YARA，Windows EVTX 使用 Sigma，PCAP 使用 Suricata。规则按数据类型严格路由，上传内容不会被执行。</p>
        </div>
        <div className="engine-strip" aria-label="规则引擎状态">
          <EngineStat code="YR" label="YARA" value={rules.yara} active={rules.available_detectors.includes('YARA')} />
          <EngineStat code="Σ" label="SIGMA" value={rules.sigma} active={rules.available_detectors.includes('Sigma / Chainsaw')} />
          <EngineStat code="S:" label="SURICATA" value={rules.suricata} active={rules.available_detectors.includes('Suricata')} />
          <EngineStat code="CS" label="BEACON" value={rules.cs_beacon} active={rules.available_detectors.includes('YARA')} />
        </div>
      </section>

      <section className="workspace">
        <div className="upload-column">
          <div className="panel-label"><span>01</span> ARTIFACT INTAKE <i>{busy ? 'LOCKED' : 'READY'}</i></div>
          <div
            className={`dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDragEnter={() => setDragging(true)}
            onDragLeave={() => setDragging(false)}
            onDragOver={(event) => event.preventDefault()}
            onDrop={handleDrop}
            onClick={() => !busy && inputRef.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(event) => { if ((event.key === 'Enter' || event.key === ' ') && !busy) inputRef.current?.click() }}
            aria-label="选择待扫描文件"
          >
            <input ref={inputRef} type="file" hidden disabled={busy} onChange={(event) => chooseFile(event.target.files?.[0])} />
            <div className="target-glyph"><span /><span /><b>{file ? fileKind(file.name) : '+'}</b></div>
            {file ? (
              <div className="selected-file"><small>SELECTED ARTIFACT</small><strong>{file.name}</strong><p>{formatBytes(file.size)} · {file.type || '未知媒体类型'}</p></div>
            ) : (
              <div className="drop-copy"><strong>拖放制品到检测区</strong><p>或点击选择文件 · 最大 100 MB</p><small>PE / ELF / MACH-O / EVTX / PCAP / ARCHIVE / DOCUMENT</small></div>
            )}
          </div>

          <div className="scan-controls">
            <button className="scan-button" onClick={startScan} disabled={!file || busy}>
              <span>{busy ? '检测运行中' : '开始自动检测'}</span><b>{busy ? `${Math.max(uploadProgress, 1)}%` : '→'}</b>
            </button>
            <div className="progress-rail"><span style={{ width: `${busy ? stageProgress(job, uploadProgress) : 0}%` }} /></div>
          </div>
          {error ? <div className="error-banner"><b>!</b><span>{error}</span></div> : null}
        </div>

        <aside className="status-column">
          <div className="panel-label"><span>02</span> DETECTION ROUTER <i>AUTO</i></div>
          <div className="route-map">
            <RouteItem code="BIN" title="文件制品" engine="YARA" active={Boolean(file && !file.name.toLowerCase().endsWith('.evtx') && !isNetworkCapture(file.name))} />
            <RouteItem code="LOG" title="Windows EVTX" engine="CHAINSAW + SIGMA" active={file?.name.toLowerCase().endsWith('.evtx') ?? false} />
            <RouteItem code="NET" title="PCAP / PCAPNG" engine="SURICATA" active={isNetworkCapture(file?.name)} />
            <RouteItem code="CS" title="CS Beacon 制品" engine="YARA / CONFIG / BOF" active={Boolean(file && !file.name.toLowerCase().endsWith('.evtx') && !isNetworkCapture(file.name))} />
          </div>
          <div className="inventory-card">
            <span>LOADED RULE FILES</span>
            <strong>{totalRules.toLocaleString('zh-CN')}</strong>
            <p>{rules.available_detectors.length} / 3 个检测器可用</p>
            <button className="manage-yara-button" onClick={() => setYaraManagerOpen(true)}>管理本地 YARA <b>→</b></button>
          </div>
          <div className="safety-note"><b>安全边界</b><p>服务不会执行上传制品。解析器运行在受限容器中；生产部署仍应放在独立主机并关闭容器外网。</p></div>
        </aside>
      </section>

      <section className="history-panel">
        <div className="panel-label"><span>03</span> SCAN HISTORY <i>{history.length} RECORDS</i></div>
        <div className="history-head"><span>时间 / 文件</span><span>路由</span><span>结果</span><span>命中</span><span>CS</span><span>操作</span></div>
        <div className="history-list">
          {history.length ? history.map((scan) => (
            <div className={`history-item ${job?.id === scan.id ? 'selected' : ''}`} key={scan.id}>
              <button className="history-open" onClick={() => openHistory(scan.id)} aria-label={`查看 ${scan.file.name} 的扫描结果`}>
                <span className="history-file"><small>{formatDate(scan.created_at)}</small><strong title={scan.file.name}>{scan.file.name}</strong></span>
                <span>{scan.detectors.join(' + ') || scan.stage}</span>
                <span className={`history-verdict ${scan.verdict}`}>{scan.status === 'completed' ? scan.verdict : scan.status}</span>
                <b>{scan.match_count}</b>
                <b className={scan.cs_match_count ? 'cs-hit' : ''}>{scan.cs_match_count}</b>
              </button>
              <button className="history-delete" onClick={() => deleteHistory(scan)} disabled={deletingID === scan.id} aria-label={`删除 ${scan.file.name} 的扫描记录`}>
                {deletingID === scan.id ? '…' : '删除'}
              </button>
            </div>
          )) : <div className="history-empty">尚无扫描记录。完成一次扫描后，结果会持久保存在 Docker 数据卷中。</div>}
        </div>
      </section>

      {job ? (
        <section className={`results ${job.verdict}`} aria-live="polite">
          <div className="result-head">
            <div><span>04 / DETECTION OUTPUT</span><h2>{resultTitle(job)}</h2></div>
            <div className="verdict-seal"><small>VERDICT</small><strong>{job.status === 'completed' ? job.verdict.toUpperCase() : 'SCANNING'}</strong><span>{job.matches.length} MATCHES</span></div>
          </div>

          <div className="artifact-meta">
            <Meta label="FILE" value={job.file.name} />
            <Meta label="TYPE" value={job.file.kind.toUpperCase()} />
            <Meta label="SIZE" value={formatBytes(job.file.size)} />
            <Meta label="SHA-256" value={job.file.sha256} mono />
          </div>

          <div className="detector-ledger">
            {job.detectors.map((detector) => (
              <article key={detector.name}>
                <div><i className={detector.status} /><strong>{detector.name}</strong><span>{detector.status.toUpperCase()}</span></div>
                <p>{detector.rule_files.toLocaleString('zh-CN')} 个规则文件</p>
                <b>{detector.matches.length} 命中</b>
                <small>{formatDuration(detector.duration_ms)}</small>
              </article>
            ))}
          </div>

          {groupedMatches.length ? (
            <div className="match-groups">
              {groupedMatches.map(([detector, matches]) => (
                <div className="match-group" key={detector}>
                  <div className="match-group-head"><span>{detector}</span><b>{matches.length}</b></div>
                  {matches.map((match, index) => <MatchRow key={`${match.rule}-${index}`} match={match} onOpenRule={openRuleFile} />)}
                </div>
              ))}
            </div>
          ) : job.status === 'completed' ? <div className="empty-result"><b>NO RULE MATCH</b><p>“无命中”不等于文件安全，仅表示当前已加载规则没有匹配。</p></div> : null}
        </section>
      ) : null}

      {ruleViewerOpen ? (
        <div className="rule-viewer-backdrop" role="presentation" onClick={closeRuleFile}>
          <aside className="rule-viewer" role="dialog" aria-modal="true" aria-label="YARA 规则文件" onClick={(event) => event.stopPropagation()}>
            <header>
              <div><small>YARA / SOURCE FILE</small><strong>{ruleFile?.rule || ruleLoading || '读取失败'}</strong></div>
              <button onClick={closeRuleFile} aria-label="关闭规则文件">×</button>
            </header>
            {ruleFile ? (
              <>
                <div className="rule-file-meta"><span title={ruleFile.source}>{ruleFile.source}</span><b>{formatBytes(ruleFile.size)}</b></div>
                <RuleSource file={ruleFile} />
              </>
            ) : ruleError ? <div className="rule-viewer-state error">{ruleError}</div> : <div className="rule-viewer-state">正在读取规则文件…</div>}
          </aside>
        </div>
      ) : null}

      <YaraManager open={yaraManagerOpen} onClose={() => setYaraManagerOpen(false)} onInventoryChange={setRules} />

      <footer><span>DEFENSIVE ANALYSIS ONLY</span><p>不执行上传文件 · 命中结果需要分析员复核 · 无命中不代表安全</p><span>LOCAL / DOCKER</span></footer>
    </main>
  )
}

function YaraManager({ open, onClose, onInventoryChange }: { open: boolean; onClose: () => void; onInventoryChange: (rules: RuleInventory) => void }) {
  const [items, setItems] = useState<ManagedYARARule[]>([])
  const [document, setDocument] = useState<ManagedYARADocument | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState('')
  const [messageError, setMessageError] = useState(false)
  const requestRef = useRef<AbortController | null>(null)

  useEffect(() => {
    if (!open) return
    const controller = new AbortController()
    requestRef.current = controller
    setLoading(true)
    setMessage('')
    fetchJSON<ManagedYARAList>('/api/v1/yara/rules', controller.signal)
      .then(async (list) => {
        setItems(list.items ?? [])
        if (list.items?.length) {
          const first = await fetchJSON<ManagedYARADocument>(`/api/v1/yara/rules/${encodeURIComponent(list.items[0].name)}`, controller.signal)
          setDocument(first)
          setIsNew(false)
        } else {
          setDocument({ name: 'custom_detection.yar', enabled: true, size: 0, modified_at: '', rule_count: 1, content: YARA_TEMPLATE })
          setIsNew(true)
          showMessage('已生成基础模板；保存时会自动校验并启用。')
        }
      })
      .catch((reason) => { if (reason.name !== 'AbortError') showMessage((reason as Error).message || '读取 YARA 规则失败', true) })
      .finally(() => { if (!controller.signal.aborted) setLoading(false) })
    return () => controller.abort()
  }, [open])

  useEffect(() => {
    if (!open) return
    const closeOnEscape = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', closeOnEscape)
    return () => window.removeEventListener('keydown', closeOnEscape)
  }, [open, onClose])

  function showMessage(value: string, error = false) {
    setMessage(value)
    setMessageError(error)
  }

  function createRule() {
    requestRef.current?.abort()
    setDocument({ name: 'custom_detection.yar', enabled: true, size: 0, modified_at: '', rule_count: 1, content: YARA_TEMPLATE })
    setIsNew(true)
    showMessage('已生成基础模板；保存时会自动校验并启用。')
  }

  async function selectRule(name: string) {
    requestRef.current?.abort()
    const controller = new AbortController()
    requestRef.current = controller
    setLoading(true)
    showMessage('')
    try {
      const selected = await fetchJSON<ManagedYARADocument>(`/api/v1/yara/rules/${encodeURIComponent(name)}`, controller.signal)
      setDocument(selected)
      setIsNew(false)
    } catch (reason) {
      if ((reason as Error).name !== 'AbortError') showMessage((reason as Error).message || '读取规则失败', true)
    } finally {
      if (!controller.signal.aborted) setLoading(false)
    }
  }

  async function refreshAfterChange(selected: ManagedYARADocument) {
    const [list, inventory] = await Promise.all([
      fetchJSON<ManagedYARAList>('/api/v1/yara/rules'),
      fetchJSON<RuleInventory>('/api/v1/rules'),
    ])
    setItems(list.items ?? [])
    setDocument(selected)
    onInventoryChange(inventory)
  }

  async function saveRule() {
    if (!document || saving) return
    setSaving(true)
    showMessage('正在编译校验并保存…')
    try {
      const saved = await fetchJSON<ManagedYARADocument>(`/api/v1/yara/rules/${encodeURIComponent(document.name.trim())}`, undefined, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ content: document.content }),
      })
      await refreshAfterChange(saved)
      setIsNew(false)
      showMessage(`已保存并自动加载：${saved.rule_count} 条规则。`)
    } catch (reason) {
      showMessage((reason as Error).message || '保存规则失败', true)
    } finally {
      setSaving(false)
    }
  }

  async function toggleRule() {
    if (!document || isNew || saving) return
    setSaving(true)
    const enabled = !document.enabled
    showMessage(enabled ? '正在校验并启用…' : '正在停用规则…')
    try {
      const updated = await fetchJSON<ManagedYARADocument>(`/api/v1/yara/rules/${encodeURIComponent(document.name)}/enabled`, undefined, {
        method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled }),
      })
      await refreshAfterChange(updated)
      showMessage(enabled ? '规则已启用并加入扫描。' : '规则已停用并从扫描库存移除。')
    } catch (reason) {
      showMessage((reason as Error).message || '更新规则状态失败', true)
    } finally {
      setSaving(false)
    }
  }

  if (!open) return null
  return <div className="yara-manager-backdrop" onClick={onClose}>
    <section className="yara-manager" role="dialog" aria-modal="true" aria-label="本地 YARA 规则管理" onClick={(event) => event.stopPropagation()}>
      <header><div><small>LOCAL RULE CONTROL</small><strong>YARA 配置中心</strong></div><button onClick={onClose} aria-label="关闭 YARA 配置中心">×</button></header>
      <div className="yara-manager-body">
        <aside>
          <div className="yara-list-head"><span>本地规则</span><b>{items.length}</b></div>
          <button className="new-yara-rule" onClick={createRule}>＋ 新建规则</button>
          <div className="managed-yara-list">
            {items.map((rule) => <button className={document?.name === rule.name && !isNew ? 'selected' : ''} key={rule.name} onClick={() => selectRule(rule.name)}>
              <i className={rule.enabled ? 'enabled' : ''} /><span><strong>{rule.name}</strong><small>{rule.rule_count} RULES · {formatBytes(rule.size)}</small></span><b>{rule.enabled ? 'ON' : 'OFF'}</b>
            </button>)}
          </div>
        </aside>
        <div className="yara-editor">
          {document ? <>
            <div className="yara-editor-toolbar">
              <label><span>FILE NAME</span><input value={document.name} disabled={!isNew} onChange={(event) => setDocument({ ...document, name: event.target.value })} spellCheck={false} /></label>
              <button className={document.enabled ? 'enabled' : ''} onClick={toggleRule} disabled={isNew || saving}>{isNew ? '保存后启用' : document.enabled ? '已启用' : '已停用'}</button>
            </div>
            <textarea value={document.content} onChange={(event) => setDocument({ ...document, content: event.target.value })} spellCheck={false} aria-label="YARA 规则内容" />
            <div className="yara-editor-footer"><span className={messageError ? 'error' : ''}>{loading ? '正在读取…' : message || '保存前自动执行 YARA 语法校验。'}</span><button onClick={saveRule} disabled={saving || loading}>{saving ? '处理中…' : '校验并保存'}</button></div>
          </> : <div className="yara-editor-empty">{loading ? '正在读取本地规则…' : '选择或新建一条 YARA 规则。'}</div>}
        </div>
      </div>
    </section>
  </div>
}

function EngineStat({ code, label, value, active }: { code: string; label: string; value: number; active: boolean }) {
  return <div className={active ? 'active' : ''}><span>{code}</span><p>{label}<small>{active ? 'ONLINE' : 'OFFLINE'}</small></p><strong>{value.toLocaleString('zh-CN')}</strong></div>
}

function RouteItem({ code, title, engine, active }: { code: string; title: string; engine: string; active: boolean }) {
  return <div className={active ? 'active' : ''}><span>{code}</span><p><strong>{title}</strong><small>{engine}</small></p><b>{active ? '●' : '○'}</b></div>
}

function Meta({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><span>{label}</span><strong className={mono ? 'mono' : ''} title={value}>{value}</strong></div>
}

function MatchRow({ match, onOpenRule }: { match: DetectionMatch; onOpenRule: (match: DetectionMatch) => void }) {
  const source = match.source?.split('/').slice(-3).join('/')
  const canOpen = Boolean(match.source && match.detector.toLowerCase().includes('yara'))
  return <article className="match-row">
    <span className={`severity ${normalizeSeverity(match.severity)}`}>{match.severity || 'review'}</span>
    <div>{canOpen ? <button className="rule-link" onClick={() => onOpenRule(match)}>{match.rule}<i>查看文件 ↗</i></button> : <strong>{match.rule}</strong>}<p>{match.category || '未分类'}{match.detail ? ` · ${match.detail}` : ''}</p></div>
    <code title={match.source}>{source || match.detector}</code>
  </article>
}

function RuleSource({ file }: { file: RuleFile }) {
  const lines = useMemo(() => file.content.split('\n'), [file.content])
  const preRef = useRef<HTMLPreElement>(null)
  const matchedRef = useRef<HTMLSpanElement>(null)
  const renderLineElements = lines.length <= 8000 && file.line > 0

  useEffect(() => {
    if (matchedRef.current) {
      matchedRef.current.scrollIntoView({ block: 'center' })
    } else if (preRef.current && file.line > 0) {
      preRef.current.scrollTop = Math.max(0, (file.line - 1) * 24 - preRef.current.clientHeight / 2)
    }
  }, [file.line, renderLineElements])

  return <div className="rule-source">
    <div className="rule-location"><span>MATCHED RULE</span><strong>{file.rule}</strong><b>{file.line ? `LINE ${file.line}` : 'LINE N/A'}</b></div>
    {file.truncated ? <div className="rule-truncated">文件超过 1 MB，仅展示前 1 MB。</div> : null}
    <pre ref={preRef}><code>{renderLineElements ? lines.map((line, index) => {
      const matched = index + 1 === file.line
      return <span className={`source-line ${matched ? 'matched' : ''}`} ref={matched ? matchedRef : undefined} key={index}><i>{index + 1}</i><b>{line || ' '}</b></span>
    }) : file.content}</code></pre>
  </div>
}

function uploadArtifact(file: File, onProgress: (value: number) => void): Promise<ScanJob> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest()
    request.open('POST', '/api/v1/scans')
    request.responseType = 'json'
    request.upload.onprogress = (event) => { if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100)) }
    request.onerror = () => reject(new Error('无法连接扫描服务'))
    request.onload = () => {
      if (request.status >= 200 && request.status < 300) resolve(normalizeJob(request.response as ScanJob))
      else reject(new Error(request.response?.error || `上传失败 (${request.status})`))
    }
    const body = new FormData()
    body.append('file', file)
    request.send(body)
  })
}

async function pollJob(id: string, signal: AbortSignal, update: (job: ScanJob) => void) {
  for (;;) {
    await delay(850, signal)
    const response = await fetch(`/api/v1/scans/${id}`, { signal, cache: 'no-store' })
    if (!response.ok) throw new Error('无法读取扫描状态')
    const job = normalizeJob(await response.json() as ScanJob)
    update(job)
    if (job.status === 'completed' || job.status === 'failed') return
  }
}

async function fetchJSON<T>(url: string, signal?: AbortSignal, options: RequestInit = {}): Promise<T> {
  const response = await fetch(url, { ...options, signal, cache: 'no-store' })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.error || `请求失败 (${response.status})`)
  }
  return response.json() as Promise<T>
}

function normalizeJob(job: ScanJob): ScanJob {
  return {
    ...job,
    detectors: (job.detectors ?? []).map((detector) => ({
      ...detector,
      matches: detector.matches ?? [],
      warnings: detector.warnings ?? [],
    })),
    matches: job.matches ?? [],
  }
}

function delay(milliseconds: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    const timer = window.setTimeout(resolve, milliseconds)
    signal.addEventListener('abort', () => { window.clearTimeout(timer); reject(new DOMException('Aborted', 'AbortError')) }, { once: true })
  })
}

function stageProgress(job: ScanJob | null, upload: number) {
  if (!job) return Math.min(upload * 0.25, 25)
  if (job.status === 'completed') return 100
  if (job.stage.includes('YARA')) return 48
  if (job.stage.includes('Sigma')) return 72
  if (job.stage.includes('Suricata')) return 72
  return 32
}

function resultTitle(job: ScanJob) {
  if (job.status !== 'completed') return job.stage
  if (job.verdict === 'matched') return '规则已触发'
  if (job.verdict === 'inconclusive') return '检测未完整执行'
  return '未发现规则命中'
}

function fileKind(name: string) { const extension = name.split('.').pop()?.slice(0, 5).toUpperCase(); return extension || 'FILE' }
function isNetworkCapture(name?: string) { return Boolean(name && /\.(pcap|pcapng)$/i.test(name)) }
function formatBytes(bytes: number) { if (bytes < 1024) return `${bytes} B`; if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`; return `${(bytes / 1024 ** 2).toFixed(1)} MB` }
function formatDuration(milliseconds: number) { return milliseconds < 1000 ? `${milliseconds} ms` : `${(milliseconds / 1000).toFixed(1)} s` }
function formatDate(value: string) { return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(value)) }
function normalizeSeverity(value?: string) { const normalized = value?.toLowerCase() || ''; if (['critical', 'high', '1'].includes(normalized)) return 'high'; if (['medium', 'moderate', '2'].includes(normalized)) return 'medium'; return 'low' }
