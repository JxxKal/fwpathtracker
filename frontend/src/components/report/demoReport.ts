import type { ReportData, ReportList, ReportListItem } from '../../api';

// Ein ausgedachter, aber plausibler Bericht für den Demo-Modus.

const DAYS = ['Fr 16.10.', 'Sa 17.10.', 'So 18.10.', 'Mo 19.10.', 'Di 20.10.', 'Mi 21.10.',
  'Do 22.10.', 'Fr 23.10.'].map((label, i) => ({ date: `2026-10-${16 + i}`, label }));

const DATA: ReportData = {
  version: 1, title: 'Stephan fragt, A38 antwortet',
  period: { start: '2026-10-16T04:30:00+00:00', end: '2026-10-23T04:30:00+00:00',
    kw: 'KW 43/2026', kw_key: '2026-W43', from: '16.10.2026 06:30', to: '23.10.2026 06:30' },
  days: DAYS,
  sources: [
    { id: 'firewall', question: '', source: 'FortiAnalyzer', status: 'ok', note: null },
    { id: 'hosts', question: '', source: 'ARP-Historie, DNS, iTop, Zabbix', status: 'ok', note: null },
    { id: 'librenms', question: '', source: 'LibreNMS', status: 'ok', note: null },
    { id: 'zabbix', question: '', source: 'Zabbix', status: 'ok', note: null },
    { id: 'ad', question: '', source: 'Graylog (Winlogbeat, Domain Controller)', status: 'ok', note: null },
    { id: 'ifix', question: '', source: 'Graylog (Winlogbeat, iFIX-Knoten)', status: 'ok', note: null },
    { id: 'webdrive', question: '', source: 'Webdrive (Graylog)', status: 'partial',
      note: 'Webdrive bewahrt nur 7 Tage auf — der Anfang des Zeitraums kann fehlen.' },
  ],
  summary: {
    status: 'partial', attention: 6,
    kpis: [
      { key: 'fw_changes', label: 'Firewall-Änderungen', value: 37, prev: 22 },
      { key: 'fw_off_hours', label: 'davon außerhalb der Arbeitszeit', value: 3, prev: 0 },
      { key: 'zbx_problems', label: 'Zabbix-Probleme', value: 58, prev: 71 },
      { key: 'zbx_high', label: 'davon Hoch und schwerer', value: 4, prev: 6 },
      { key: 'hosts_new', label: 'Neue MACs', value: 12, prev: 9 },
      { key: 'hosts_unmanaged', label: 'Neu, ohne iTop/Zabbix', value: 5, prev: 4 },
      { key: 'ad_changes', label: 'AD-Änderungen', value: 41, prev: 35 },
      { key: 'ad_lockouts', label: 'Kontosperrungen', value: 17, prev: 23 },
      { key: 'ifix_msgs', label: 'iFIX-Meldungen', value: 384, prev: 402 },
      { key: 'ifix_reboots', label: 'Unerwartete Neustarts (iFIX)', value: 1, prev: 0 },
      { key: 'lnms_port_down', label: 'Port-Ausfälle', value: 26, prev: 31 },
      { key: 'wd_errors', label: 'Webdrive-Fehler', value: 7, prev: 12 },
    ],
  },
  heatmap: [
    { id: 'firewall', label: 'Firewall-Änderungen', values: [4, 0, 2, 11, 8, 6, 5, 1] },
    { id: 'hosts', label: 'Neue Hosts', values: [1, 0, 0, 4, 3, 2, 2, 0] },
    { id: 'librenms', label: 'LibreNMS', values: [3, 1, 0, 9, 6, 4, 5, 0] },
    { id: 'zabbix', label: 'Zabbix', values: [7, 3, 2, 14, 11, 9, 10, 2] },
    { id: 'ad', label: 'Active Directory', values: [5, 0, 0, 12, 9, 8, 7, 0] },
    { id: 'ifix', label: 'iFIX', values: [48, 47, 49, 51, 46, 48, 50, 45] },
    { id: 'webdrive', label: 'Webdrive', values: [22, 2, 1, 41, 38, 35, 33, 4] },
  ],
  attention: [
    { title: 'Privilegierte Gruppe Domain Admins: Mitglied zu globaler Gruppe hinzugefügt',
      why: 'Mo 19.10. 09:14 · Max Muster · durch admin.jk auf SVO3005-OT.op-tech.com',
      source: 'Active Directory', level: 'high' },
    { title: 'iFIX-Knoten STAFFS2.op-tech.com: Unerwarteter Neustart', why: 'Mi 21.10. 22:07',
      source: 'iFIX', level: 'high' },
    { title: 'Offenes Problem (Hoch): srv-backup01', why: 'Disk /backup over 95% — seit Do 22.10. 03:12, 1 h 18 min, nicht quittiert',
      source: 'Zabbix', level: 'high' },
    { title: 'Firewall-Änderung Wochenende: fw-svo-01 durch admin.jk',
      why: 'So 18.10. 21:40 · Edit firewall.policy 118', source: 'FortiAnalyzer', level: 'medium' },
    { title: 'Zabbix-Problem kurz nach Firewall-Änderung: srv-mes02',
      why: 'Service unreachable um Di 20.10. 14:22; davor geändert: fw-svo-01. Zeitliche Nähe — ein Hinweis, kein Beweis.',
      source: 'Zabbix × FortiAnalyzer', level: 'medium' },
    { title: 'Neuer Host ohne Pflege: 10.180.22.47 (cam-halle3-07)',
      why: 'erstmals Mo 19.10. 10:02, MAC 00408c11a2b3 — weder im iTop noch in Zabbix',
      source: 'ARP-Historie', level: 'medium' },
  ],
  chapters: [
    {
      id: 'firewall', question: 'Was wurde an den Firewalls geändert?', source: 'FortiAnalyzer',
      status: 'ok', note: null,
      answer: '37 Konfigurationsänderungen auf 4 Firewalls durch 3 Admins, davon 3 außerhalb der Arbeitszeit.',
      kpis: [], daily: [4, 0, 2, 11, 8, 6, 5, 1],
      charts: [
        { type: 'daily', title: 'Änderungen je Tag', series: [{ label: 'Änderungen', color: '#3d6ea8', values: [4, 0, 2, 11, 8, 6, 5, 1] }] },
        { type: 'top', title: 'Nach Admin', items: [{ label: 'admin.jk', value: 21 }, { label: 'admin.ms', value: 12 }, { label: 'fmg-install', value: 4 }] },
        { type: 'top', title: 'Nach Firewall', items: [{ label: 'fw-svo-01', value: 19 }, { label: 'fw-seh-01', value: 10 }, { label: 'fw-emd-01', value: 6 }, { label: 'fw-dmz-02', value: 2 }] },
      ],
      tables: [{ title: 'Änderungen', columns: ['Zeit', 'Firewall', 'VDOM', 'Admin', 'Zugang', 'Aktion', 'Pfad', 'Objekt'], total: 37, rows: [
        ['Mo 19.10. 08:41', 'fw-svo-01', 'OT-Prod', 'admin.jk', 'GUI(10.1.1.20)', 'Add', 'firewall.address', 'H_cam-halle3-07'],
        ['Mo 19.10. 08:43', 'fw-svo-01', 'OT-Prod', 'admin.jk', 'GUI(10.1.1.20)', 'Edit', 'firewall.policy', '118'],
        ['Di 20.10. 14:05', 'fw-svo-01', 'OT-Prod', 'admin.ms', 'jsconsole', 'Edit', 'firewall.policy', '204'],
        ['So 18.10. 21:40', 'fw-svo-01', 'root', 'admin.jk', 'ssh(10.1.1.20)', 'Edit', 'firewall.policy', '118'],
      ] }],
      attention: [],
    },
    {
      id: 'zabbix', question: 'Wie stabil lief der Betrieb?', source: 'Zabbix', status: 'ok', note: null,
      answer: '58 Probleme begannen im Zeitraum, 4 davon „Hoch“ oder schwerer; 2 sind noch offen.',
      kpis: [], daily: [7, 3, 2, 14, 11, 9, 10, 2],
      charts: [
        { type: 'daily', title: 'Probleme je Tag nach Schwere', stacked: true, series: [
          { label: 'Hoch', color: '#E97659', values: [0, 0, 0, 2, 1, 0, 1, 0] },
          { label: 'Durchschnitt', color: '#FFA059', values: [2, 1, 0, 4, 3, 3, 2, 1] },
          { label: 'Warnung', color: '#FFC859', values: [5, 2, 2, 8, 7, 6, 7, 1] },
        ] },
        { type: 'top', title: 'Hosts mit den meisten Problemen', items: [{ label: 'srv-mes02', value: 9 }, { label: 'srv-backup01', value: 6 }, { label: 'sw-halle3-01', value: 5 }] },
      ],
      tables: [{ title: 'Längste Probleme', columns: ['Beginn', 'Host', 'Problem', 'Schwere', 'Dauer', 'Status'], total: 58, rows: [
        ['Mo 19.10. 06:10', 'srv-mes02', 'Service unreachable', 'Hoch', '3 h 12 min', 'behoben, quittiert'],
        ['Do 22.10. 03:12', 'srv-backup01', 'Disk /backup over 95%', 'Hoch', '1 h 18 min', 'offen'],
      ] }],
      attention: [],
    },
    {
      id: 'ad', question: 'Was ist im Active Directory passiert?', source: 'Graylog (Winlogbeat, Domain Controller)',
      status: 'ok', note: null,
      answer: '41 Änderungen an Konten und Gruppen: 3 Konten angelegt, 1 gelöscht, 14 Gruppenmitgliedschaften geändert; 17 Sperrungen, 1.204 Fehlanmeldungen.',
      kpis: [], daily: [5, 0, 0, 12, 9, 8, 7, 0],
      charts: [
        { type: 'daily', title: 'Änderungen an Konten und Gruppen je Tag', series: [{ label: 'Änderungen', color: '#7A5CC4', values: [5, 0, 0, 12, 9, 8, 7, 0] }] },
        { type: 'top', title: 'Am häufigsten gesperrte Konten', items: [{ label: 'svc-scan', value: 6 }, { label: 'm.meier', value: 3 }] },
      ],
      tables: [{ title: 'Änderungen an Konten und Gruppen', columns: ['Zeit', 'Ereignis', 'Konto / Mitglied', 'Gruppe', 'durch', 'DC'], total: 41, rows: [
        ['Mo 19.10. 09:14', 'Mitglied zu globaler Gruppe hinzugefügt', 'Max Muster', 'Domain Admins', 'admin.jk', 'SVO3005-OT.op-tech.com'],
        ['Mo 19.10. 09:20', 'Konto angelegt', 'p.neumann', '', 'admin.jk', 'SVO3005-OT.op-tech.com'],
      ] }],
      attention: [],
    },
    {
      id: 'ifix', question: 'Was meldet iFIX?', source: 'Graylog (Winlogbeat, iFIX-Knoten)', status: 'ok', note: null,
      answer: '384 iFIX-Meldungen auf 4 Knoten; 1 unerwarteter Neustart und 0 Dienst- oder Anwendungsabstürze.',
      kpis: [], daily: [48, 47, 49, 51, 46, 48, 50, 45],
      charts: [
        { type: 'daily', title: 'iFIX-Meldungen je Tag', series: [{ label: 'Meldungen', color: '#d4762c', values: [48, 47, 49, 51, 46, 48, 50, 45] }] },
        { type: 'top', title: 'Nach Stichwort', items: [{ label: 'File service Message time out', value: 336 }, { label: 'NODE', value: 31 }, { label: 'SCADA Sync', value: 17 }] },
      ],
      tables: [{ title: 'Jüngste iFIX-Meldungen', columns: ['Zeit', 'Knoten', 'Code', 'Meldung'], total: 384, rows: [
        ['Mi 21.10. 22:45', 'STAFFS2.op-tech.com', '1', '[10/21/2026 22:40:36] File service Message time out D:\\DYNAMICS\\STAFFS\\PDB\\STAFFS.^DB'],
        ['Mi 21.10. 22:10', 'SVO3230-OT.op-tech.com', '2', 'Connection NOT established with node STAFFS2'],
      ] }],
      attention: [],
    },
  ],
};

const ITEM: ReportListItem = {
  id: 1, period_start: DATA.period.start, period_end: DATA.period.end,
  created_at: '2026-10-23T04:31:12+00:00', trigger: 'schedule', status: 'partial',
  created_by: null, summary: DATA.summary,
};

export function demoList(): ReportList {
  return { reports: [ITEM], schedule: { enabled: true, next: '2026-10-30T05:30:00+00:00' },
    default: { start: '2026-10-23T04:30:00+00:00', end: new Date().toISOString() } };
}

export function demoReport(id: number): ReportListItem & { data: ReportData } {
  return { ...ITEM, id, data: DATA };
}
