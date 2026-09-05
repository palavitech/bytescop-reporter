import { Injectable, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';
import { marked } from 'marked';
import DOMPurify from 'dompurify';
import { wrapImageCaptions } from '../engagement-findings-view/markdown-utils';

import { Engagement, EngagementType } from '../models/engagement.model';
import { Finding, FindingSeverity, FindingStatus, FINDING_SEVERITY_LABELS, FINDING_STATUS_LABELS } from '../models/finding.model';
import { Asset, ASSET_TYPE_LABELS } from '../../assets/models/asset.model';
import { EngagementStakeholder, EngagementSettingDef, STAKEHOLDER_ROLE_LABELS } from '../models/stakeholder.model';
import { SettingsService } from '../../admin/settings/services/settings.service';
import { EngagementsService } from './engagements.service';
import { DateFormatService } from '../../../services/core/date-format.service';

const SEV_ORDER: FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Role hierarchy — higher priority first */
const ROLE_ORDER: string[] = [
  'client_poc',
  'account_manager',
  'project_manager',
  'technical_lead',
  'lead_tester',
  'security_engineer',
  'qa_reviewer',
  'observer',
];

const STATUS_COLORS: Record<string, string> = {
  open: '#ef4444', triage: '#f97316', accepted: '#3b82f6', fixed: '#22c55e', false_positive: '#94a3b8',
};

const REPORT_TITLES: Partial<Record<EngagementType, string>> = {
  malware_analysis: 'Malware Analysis<br>Report',
  digital_forensics: 'Digital Forensics<br>Report',
  wifi: 'WiFi Assessment<br>Report',
  linux_audit: 'Linux Server Audit<br>Report',
  windows_audit: 'Windows Audit<br>Report',
  active_directory: 'Active Directory<br>Report',
};
const DEFAULT_REPORT_TITLE = 'Penetration Test<br>Report';

@Injectable({ providedIn: 'root' })
export class ReportService {
  private readonly settingsService = inject(SettingsService);
  private readonly engagementsService = inject(EngagementsService);
  private readonly dateFormatService = inject(DateFormatService);

  async generate(
    engagement: Engagement,
    findings: Finding[],
    scopeAssets: Asset[],
  ): Promise<void> {
    const sorted = [...findings].sort(
      (a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity),
    );

    let companyName = 'BytesCop-Reporter';
    try {
      const settings = await firstValueFrom(this.settingsService.list());
      const cn = settings.find(s => s.key === 'company_name');
      if (cn?.value?.trim()) companyName = cn.value.trim();
    } catch (err) {
      console.warn('[report] failed to load company name, using default', err);
    }

    let logoDataUrl: string | null = null;
    try {
      const { has_logo } = await firstValueFrom(this.settingsService.hasLogo());
      if (has_logo) {
        const blob = await firstValueFrom(this.settingsService.getLogoBlob());
        logoDataUrl = await this.blobToDataUrl(blob);
      }
    } catch (err) {
      console.warn('[report] failed to load logo', err);
    }

    let stakeholders: EngagementStakeholder[] = [];
    let showContactInfo = true;
    try {
      stakeholders = await firstValueFrom(this.engagementsService.listStakeholders(engagement.id));
      stakeholders.sort((a, b) => {
        const ai = ROLE_ORDER.indexOf(a.role);
        const bi = ROLE_ORDER.indexOf(b.role);
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi);
      });
    } catch (err) {
      console.warn('[report] failed to load stakeholders', err);
    }
    try {
      const engSettings = await firstValueFrom(this.engagementsService.listSettings(engagement.id));
      const contactSetting = engSettings.find(s => s.key === 'show_contact_info_on_report');
      if (contactSetting) showContactInfo = contactSetting.value === 'true';
    } catch (err) {
      console.warn('[report] failed to load engagement settings, using defaults', err);
    }

    const descriptions = await Promise.all(sorted.map(f => this.renderMarkdown(f.description_md)));
    const recommendations = await Promise.all(sorted.map(f => this.renderMarkdown(f.recommendation_md)));
    const html = this.buildHtml(engagement, sorted, scopeAssets, descriptions, recommendations, companyName, logoDataUrl, stakeholders, showContactInfo);

    const win = window.open('', '_blank');
    if (!win) {
      alert('Pop-up blocked. Please allow pop-ups for this site and try again.');
      return;
    }
    win.document.open();
    win.document.write(html);
    win.document.close();
  }

  private async renderMarkdown(md: string | undefined | null): Promise<string> {
    if (!md?.trim()) return '';
    const raw = marked.parse(md, { async: false }) as string;
    const withCaptions = wrapImageCaptions(raw);
    return DOMPurify.sanitize(withCaptions, {
      USE_PROFILES: { html: true },
      ADD_TAGS: ['figure', 'figcaption'],
    });
  }

  private buildHtml(
    eng: Engagement,
    sorted: Finding[],
    scopeAssets: Asset[],
    descriptions: string[],
    recommendations: string[],
    companyName: string,
    logoDataUrl: string | null,
    stakeholders: EngagementStakeholder[],
    showContactInfo: boolean,
  ): string {
    const reportDate = this.dateFormatService.formatDate(new Date().toISOString());
    const fmt = (d: string | null | undefined) => this.dateFormatService.formatDate(d);

    const startDate = fmt(eng.start_date);
    const endDate = fmt(eng.end_date);

    const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of sorted) sevCounts[f.severity] = (sevCounts[f.severity] || 0) + 1;

    const statusCounts: Record<string, number> = { open: 0, triage: 0, accepted: 0, fixed: 0, false_positive: 0 };
    for (const f of sorted) {
      const s = (f.status || '').toLowerCase();
      statusCounts[s] = (statusCounts[s] || 0) + 1;
    }

    const total = sorted.length || 1;
    const pieDeg = (k: string) => ((statusCounts[k] || 0) / total * 360).toFixed(1) + 'deg';

    const scopeSummary = scopeAssets.length ? this.buildScopeSummary(scopeAssets) : '—';
    const barRowsHtml = this.buildBarRows(sorted);
    const pieLegendHtml = this.buildPieLegend(statusCounts);

    const scopeListHtml = scopeAssets.length
      ? scopeAssets.map(a =>
          `<li><span class="bc-mono">${this.esc(a.target || a.name)}</span> &nbsp;·&nbsp; ${this.esc(ASSET_TYPE_LABELS[a.asset_type] || a.asset_type)} &nbsp;·&nbsp; ${this.esc(a.environment)} &nbsp;·&nbsp; ${this.esc(a.criticality)}</li>`
        ).join('\n')
      : '<li>No assets in scope.</li>';

    const findingsHtml = sorted.length
      ? sorted.map((f, i) => this.buildFinding(f, i, descriptions[i], recommendations[i])).join('\n')
      : '<p style="color:var(--muted);font-style:italic;padding:20px 0;">No findings recorded for this engagement.</p>';

    // Brand block — uses tenant logo if available, otherwise BytesCop-Reporter SVG mark
    const brandHtml = logoDataUrl
      ? `<img src="${logoDataUrl}" class="bc-markLogo" alt="${this.esc(companyName)}" />`
      : `<div class="bc-mark"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z"/><path d="M9 12l2 2 4-4"/></svg></div>`;

    return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>${this.esc(companyName)} — ${this.esc(eng.name)} Report</title>
<style>
${this.getStyles()}
</style>
</head>
<body>

<button class="print-btn" onclick="window.print()">&#8659; Export / Print</button>

<!-- COVER -->
<section class="bc-page" id="page-cover">
  <div class="bc-cover">
    <div class="bc-coverTop">
      <div class="bc-brand">
        ${brandHtml}
        <div>
          <div class="bc-brandName">${this.esc(companyName)}</div>
          <div class="bc-brandTag">Security Assessment</div>
        </div>
      </div>
      <div class="bc-classification">Confidential</div>
    </div>

    <div class="bc-coverCenter">
      <div class="bc-accentRule"></div>
      <h1 class="bc-coverTitle">${REPORT_TITLES[eng.engagement_type] ?? DEFAULT_REPORT_TITLE}</h1>
      <p class="bc-coverClient">${this.esc(eng.client_name || '—')}</p>
      <p class="bc-coverEngagement">${this.esc(eng.name)}</p>
    </div>

    <div class="bc-coverBottom">
      <div class="bc-coverMeta">
        <div class="bc-coverMetaLabel">Report Date</div>
        <div class="bc-coverMetaValue">${this.esc(reportDate)}</div>
      </div>
      <div class="bc-coverMeta">
        <div class="bc-coverMetaLabel">Version</div>
        <div class="bc-coverMetaValue"><strong>1.0</strong></div>
      </div>
      <div class="bc-coverMeta">
        <div class="bc-coverMetaLabel">Testing Window</div>
        <div class="bc-coverMetaValue">${this.esc(startDate)} &rarr; ${this.esc(endDate)}</div>
      </div>
      <div class="bc-coverMeta">
        <div class="bc-coverMetaLabel">Classification</div>
        <div class="bc-coverMetaValue">Confidential</div>
      </div>
    </div>
  </div>
</section>

${this.buildStakeholdersSection(stakeholders, showContactInfo)}

<!-- 02 — SCOPE & CONTEXT -->
<section class="bc-page bc-pageBreak" id="page-scope">
  <div class="bc-sectionHead">
    <div class="bc-sectionNum">02 &mdash; Scope &amp; Context</div>
    <h2 class="bc-sectionTitle">Engagement Details</h2>
    <p class="bc-sectionSub">Testing window, asset scope, methodology, and disclaimers.</p>
    <hr class="bc-sectionRule">
  </div>

  <div class="bc-card">
    <div class="bc-kv">
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Client</div>
        <p class="bc-kvValue">${this.esc(eng.client_name || '—')}</p>
      </div>
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Engagement</div>
        <p class="bc-kvValue">${this.esc(eng.name)}</p>
      </div>
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Testing Window</div>
        <p class="bc-kvValue">${this.esc(startDate)} &ndash; ${this.esc(endDate)}</p>
      </div>
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Scope Summary</div>
        <p class="bc-kvValue">${this.esc(scopeSummary)}</p>
      </div>
    </div>

    <div class="bc-divider"></div>

    <div class="bc-kv">
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Targets In Scope (SoW Assets)</div>
        <ul class="bc-list" style="margin-top:6px;">${scopeListHtml}</ul>
      </div>
      <div class="bc-kvItem">
        <div class="bc-kvLabel">Methodology (High-Level)</div>
        <ul class="bc-list" style="margin-top:6px;">
          <li>Reconnaissance and attack surface mapping</li>
          <li>Authentication and authorization testing</li>
          <li>Input validation and business logic testing</li>
          <li>Configuration and security headers review</li>
          <li>Evidence capture and validation</li>
        </ul>
      </div>
    </div>

    <div class="bc-divider"></div>

    <div class="bc-kvItem">
      <div class="bc-kvLabel">Disclaimers and Limitations</div>
      <p class="bc-text" style="margin-top:6px;">
        This report documents the results of a penetration test performed for the client listed above,
        limited strictly to the agreed scope and testing window. Penetration testing is a time-bound
        effort and cannot guarantee the identification of all security weaknesses. Findings reflect the
        state of the environment at the time of testing.
      </p>
      <p class="bc-text" style="margin-top:10px;">
        The assessment used a combination of manual testing and tool-assisted techniques. Any exploitation
        was limited to what was necessary to validate impact. This report is confidential and intended
        solely for authorized stakeholders.
      </p>
    </div>

    <p class="bc-small" style="margin-top:14px;">
      Classification: Confidential &nbsp;&middot;&nbsp; Distribution: Authorized recipients only
    </p>
  </div>
</section>

<!-- 03 — EXECUTIVE SUMMARY -->
<section class="bc-page bc-pageBreak" id="page-exec">
  <div class="bc-sectionHead">
    <div class="bc-sectionNum">03 &mdash; Executive Summary</div>
    <h2 class="bc-sectionTitle">Risk Posture Overview</h2>
    <p class="bc-sectionSub">${this.esc(eng.client_name || '—')} &nbsp;&middot;&nbsp; Total findings: <strong>${sorted.length}</strong></p>
    <hr class="bc-sectionRule">
  </div>

  <div class="bc-card">
    <div class="bc-scoreRow">
      <div class="bc-scoreCard sev-critical">
        <div class="bc-scoreLabel">Critical</div>
        <p class="bc-scoreValue">${sevCounts['critical']}</p>
      </div>
      <div class="bc-scoreCard sev-high">
        <div class="bc-scoreLabel">High</div>
        <p class="bc-scoreValue">${sevCounts['high']}</p>
      </div>
      <div class="bc-scoreCard sev-medium">
        <div class="bc-scoreLabel">Medium</div>
        <p class="bc-scoreValue">${sevCounts['medium']}</p>
      </div>
      <div class="bc-scoreCard sev-low">
        <div class="bc-scoreLabel">Low</div>
        <p class="bc-scoreValue">${sevCounts['low']}</p>
      </div>
      <div class="bc-scoreCard sev-info">
        <div class="bc-scoreLabel">Info</div>
        <p class="bc-scoreValue">${sevCounts['info']}</p>
      </div>
    </div>

    <div class="bc-divider"></div>

    <div class="bc-grid2">
      <div class="bc-chartCard">
        <div class="bc-chartTitle">Findings by Asset &amp; Severity</div>
        <div class="bc-barLegend">
          <div class="bc-legendItem"><span class="bc-swatch" style="background:#f43f5e;"></span> Critical</div>
          <div class="bc-legendItem"><span class="bc-swatch" style="background:#fb923c;"></span> High</div>
          <div class="bc-legendItem"><span class="bc-swatch" style="background:#fbbf24;"></span> Medium</div>
          <div class="bc-legendItem"><span class="bc-swatch" style="background:#60a5fa;"></span> Low</div>
          <div class="bc-legendItem"><span class="bc-swatch" style="background:#22d3ee;"></span> Info</div>
        </div>
        <div class="bc-bars">${barRowsHtml}</div>
      </div>

      <div class="bc-chartCard" style="--p-open:${pieDeg('open')}; --p-triage:${pieDeg('triage')}; --p-accepted:${pieDeg('accepted')}; --p-fixed:${pieDeg('fixed')};">
        <div class="bc-chartTitle">Findings by Status</div>
        <div class="bc-pieWrap">
          <div class="bc-pie" aria-label="Status distribution"></div>
          <div class="bc-pieLegend">${pieLegendHtml}</div>
        </div>
      </div>
    </div>

    <div class="bc-divider"></div>

    <div class="bc-kvItem">
      <div class="bc-kvLabel">Summary Narrative</div>
      <p class="bc-text" style="margin-top:6px;">
        The assessment of <strong>${this.esc(eng.client_name || 'the client')}</strong>&rsquo;s environment
        identified <strong>${sorted.length} finding${sorted.length !== 1 ? 's' : ''}</strong> across
        the assets in scope for engagement <em>${this.esc(eng.name)}</em>
        (${this.esc(startDate)}&ndash;${this.esc(endDate)}).
        ${sevCounts['critical'] > 0 || sevCounts['high'] > 0
          ? 'Critical and high severity findings should be prioritized due to their potential for significant business impact.'
          : 'No critical or high severity findings were identified during this assessment.'}
      </p>
      <p class="bc-text" style="margin-top:10px;">
        Recommendations are intended to reduce exploitability and attack surface.
        Remediation should be validated via retesting, especially for externally exposed systems.
      </p>
    </div>
  </div>
</section>

<!-- 04 — FINDINGS -->
<section class="bc-page bc-pageBreak" id="page-findings">
  <div class="bc-sectionHead">
    <div class="bc-sectionNum">04 &mdash; Findings</div>
    <h2 class="bc-sectionTitle">Detailed Findings</h2>
    <p class="bc-sectionSub">Sorted by severity, highest first &nbsp;&middot;&nbsp; Total: <strong>${sorted.length}</strong></p>
    <hr class="bc-sectionRule">
  </div>

  <div class="bc-findingsList">${findingsHtml}</div>
</section>

<!-- FOOTER -->
<footer class="bc-footer">
  <div class="bc-footerInner">
    <span>${this.esc(companyName)} &nbsp;&middot;&nbsp; ${this.esc(eng.name)} &nbsp;&middot;&nbsp; ${this.esc(reportDate)}</span>
    <span>Confidential</span>
  </div>
</footer>

</body>
</html>`;
  }

  // ── Stakeholders section ──

  private buildStakeholdersSection(stakeholders: EngagementStakeholder[], showContactInfo: boolean): string {
    if (!stakeholders.length) return '';

    // Group by role, preserving hierarchy order
    const grouped = new Map<string, EngagementStakeholder[]>();
    for (const sh of stakeholders) {
      const list = grouped.get(sh.role) ?? [];
      list.push(sh);
      grouped.set(sh.role, list);
    }

    const rows = stakeholders.map(sh => {
      const name = `${this.esc(sh.user.first_name)} ${this.esc(sh.user.last_name)}`;
      const role = this.esc(STAKEHOLDER_ROLE_LABELS[sh.role] || sh.role);

      if (showContactInfo) {
        const email = sh.user.email ? `<a href="mailto:${this.esc(sh.user.email)}">${this.esc(sh.user.email)}</a>` : '—';
        const phone = sh.user.phone ? this.esc(sh.user.phone) : '—';
        return `
          <tr>
            <td class="bc-stakeName">${name}</td>
            <td class="bc-stakeRole">${role}</td>
            <td class="bc-stakeContact">${email}</td>
            <td class="bc-stakeContact">${phone}</td>
          </tr>`;
      }
      return `
        <tr>
          <td class="bc-stakeName">${name}</td>
          <td class="bc-stakeRole">${role}</td>
        </tr>`;
    }).join('\n');

    const contactHeaders = showContactInfo
      ? '<th class="bc-stakeTh">Email</th><th class="bc-stakeTh">Phone</th>'
      : '';

    return `
<!-- 01 — POINT OF CONTACT -->
<section class="bc-page bc-pageBreak" id="page-contacts">
  <div class="bc-sectionHead">
    <div class="bc-sectionNum">01 &mdash; Points of Contact</div>
    <h2 class="bc-sectionTitle">Engagement Team</h2>
    <p class="bc-sectionSub">Team members, stakeholders, and their roles in this assessment.</p>
    <hr class="bc-sectionRule">
  </div>

  <div class="bc-card">
    <table class="bc-stakeTable">
      <thead>
        <tr>
          <th class="bc-stakeTh">Name</th>
          <th class="bc-stakeTh">Role</th>
          ${contactHeaders}
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </div>
</section>`;
  }

  // ── Chart helpers ──

  private buildBarRows(findings: Finding[]): string {
    const assetMap = new Map<string, Map<string, number>>();
    for (const f of findings) {
      const asset = f.asset_name || 'Unlinked';
      const sev = (f.severity || '').toLowerCase();
      if (!assetMap.has(asset)) assetMap.set(asset, new Map());
      const m = assetMap.get(asset)!;
      m.set(sev, (m.get(sev) || 0) + 1);
    }
    if (!assetMap.size) return '<p class="bc-small">No findings to display.</p>';

    const sorted = [...assetMap.entries()]
      .map(([name, m]) => ({ name, total: [...m.values()].reduce((a, b) => a + b, 0), m }))
      .sort((a, b) => b.total - a.total);

    return sorted.map(({ name, total, m }) => {
      const pct = (k: string) => ((m.get(k) || 0) / total * 100).toFixed(1) + '%';
      return `
        <div class="bc-barRow" style="--w-critical:${pct('critical')};--w-high:${pct('high')};--w-medium:${pct('medium')};--w-low:${pct('low')};--w-info:${pct('info')};">
          <div class="bc-barLabel" title="${this.esc(name)}">${this.esc(name)}</div>
          <div class="bc-barTrack">
            <div class="bc-barSeg critical"></div>
            <div class="bc-barSeg high"></div>
            <div class="bc-barSeg medium"></div>
            <div class="bc-barSeg low"></div>
            <div class="bc-barSeg info"></div>
          </div>
        </div>`;
    }).join('\n');
  }

  private buildPieLegend(statusCounts: Record<string, number>): string {
    const items = [
      { key: 'open',           label: 'Open',           color: '#ef4444' },
      { key: 'triage',         label: 'Triage',         color: '#f97316' },
      { key: 'accepted',       label: 'Accepted',       color: '#3b82f6' },
      { key: 'fixed',          label: 'Fixed',          color: '#22c55e' },
      { key: 'false_positive', label: 'False Positive',  color: '#94a3b8' },
    ];
    return items.map(({ key, label, color }) =>
      `<div class="bc-legendItem"><span class="bc-swatch" style="background:${color};border-radius:50%;"></span> ${label}: ${statusCounts[key] || 0}</div>`
    ).join('\n');
  }

  // ── Finding ──

  private buildFinding(f: Finding, idx: number, descHtml: string, recHtml: string): string {
    const findingNum = `F-${String(idx + 1).padStart(3, '0')}`;
    const dotColor = STATUS_COLORS[(f.status || '').toLowerCase()] ?? '#64748b';
    const statusLabel = FINDING_STATUS_LABELS[f.status] ?? f.status;
    const sevLabel = FINDING_SEVERITY_LABELS[f.severity] ?? f.severity;

    const observationHtml = descHtml || '<p class="bc-placeholder">No description provided.</p>';
    const recommendationHtml = recHtml || '<p class="bc-placeholder">No recommendation provided.</p>';

    return `
    <article class="bc-finding sev-${f.severity}">
      <div class="bc-findingTop">
        <div>
          <h3 class="bc-findingTitle">${this.esc(f.title)}</h3>
          <div class="bc-findingId">${this.esc(findingNum)} &nbsp;&middot;&nbsp; ${this.esc(f.asset_name || 'No asset linked')}${f.assessment_area ? ` &nbsp;&middot;&nbsp; ${this.esc(f.assessment_area)}` : ''}</div>
        </div>
        <div class="bc-badges">
          <span class="bc-pill sev-${f.severity}"><span class="bc-dot"></span>${this.esc(sevLabel)}</span>
          <span class="bc-pill"><span class="bc-dot" style="background:${dotColor};"></span>${this.esc(statusLabel)}</span>
        </div>
      </div>

      <div class="bc-sectionLabel">Observation</div>
      <div class="bc-text">${observationHtml}</div>

      <div class="bc-sectionLabel">Recommendation</div>
      <div class="bc-text">${recommendationHtml}</div>
    </article>`;
  }

  // ── Utilities ──

  private buildScopeSummary(assets: Asset[]): string {
    const typeCount = new Map<string, number>();
    for (const a of assets) {
      const label = ASSET_TYPE_LABELS[a.asset_type] || a.asset_type;
      typeCount.set(label, (typeCount.get(label) || 0) + 1);
    }
    const parts = [...typeCount.entries()].map(([type, count]) => `${count} ${type}`);
    return `${assets.length} asset${assets.length !== 1 ? 's' : ''} — ${parts.join(', ')}`;
  }

  private esc(str: string | null | undefined): string {
    return (str ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  private blobToDataUrl(blob: Blob): Promise<string> {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result as string);
      reader.onerror = reject;
      reader.readAsDataURL(blob);
    });
  }

  // ── Styles ──

  private getStyles(): string {
    return `
/* ─── Screen: dark ─── */
:root{
  --bg:#07101f;
  --bg2:#0c1728;
  --card:#101e33;
  --card2:#142240;
  --accent:#00e5a0;
  --accent-dim:rgba(0,229,160,.15);
  --border:#1d3455;
  --border2:#0f2240;
  --text:#dce8f8;
  --muted:#5a7898;
  --sev-critical:#f43f5e;
  --sev-high:#fb923c;
  --sev-medium:#fbbf24;
  --sev-low:#60a5fa;
  --sev-info:#22d3ee;
  --radius:14px;
  --page-max:960px;
}

/* ─── Print: light ─── */
@media print{
  :root{
    --bg:#fff; --bg2:#f8fafc; --card:#fff; --card2:#f1f5f9;
    --accent:#059669; --accent-dim:rgba(5,150,105,.08);
    --border:#cbd5e1; --border2:#e2e8f0;
    --text:#0f172a; --muted:#475569;
    --sev-critical:#be123c; --sev-high:#c2410c;
    --sev-medium:#92400e; --sev-low:#1d4ed8; --sev-info:#0e7490;
  }
  html,body{ background:#fff !important; color:#0f172a !important; }
  *{ -webkit-print-color-adjust:exact !important; print-color-adjust:exact !important; }
  .bc-cover{
    background:#fff !important;
    border:1px solid #e2e8f0 !important;
  }
  .bc-cover::before,.bc-cover::after{ display:none !important; }
  .bc-mark{ border-color:#059669 !important; background:#f0fdf4 !important; color:#059669 !important; }
  .bc-coverTitle{ color:#0f172a !important; font-size:36px !important; }
  .bc-coverClient{ color:#059669 !important; }
  .bc-coverEngagement{ color:#475569 !important; }
  .bc-classification{ background:#fee2e2 !important; color:#991b1b !important; border-color:#fca5a5 !important; }
  .bc-accentRule{ background:#059669 !important; }
  .bc-coverBottom{ background:rgba(0,0,0,.03) !important; border-color:#e2e8f0 !important; }
  .bc-coverMeta{ background:#f8fafc !important; border-right-color:#e2e8f0 !important; }
  .bc-sectionNum{ color:#059669 !important; }
  .bc-sectionRule{ background:linear-gradient(to right,#059669,transparent) !important; }
  .bc-sectionLabel{ color:#059669 !important; }
  .bc-sectionLabel::before{ background:#059669 !important; }
  .bc-card,.bc-chartCard,.bc-kvItem,.bc-scoreCard,.bc-finding{ background:#fff !important; border-color:#e2e8f0 !important; }
  .bc-card2,.bc-kvItem,.bc-scoreCard,.bc-chartCard{ background:#f8fafc !important; }
  .bc-barTrack{ background:#e2e8f0 !important; }
  .bc-pie{ box-shadow:none !important; }
  .bc-pie::after{ background:#f8fafc !important; border-color:#e2e8f0 !important; }
  .bc-scoreCard.sev-critical{ background:rgba(244,63,94,.05) !important; border-color:rgba(244,63,94,.4) !important; }
  .bc-scoreCard.sev-high{ background:rgba(251,146,60,.05) !important; border-color:rgba(251,146,60,.4) !important; }
  .bc-scoreCard.sev-medium{ background:rgba(251,191,36,.05) !important; border-color:rgba(251,191,36,.4) !important; }
  .bc-scoreCard.sev-low{ background:rgba(96,165,250,.05) !important; border-color:rgba(96,165,250,.4) !important; }
  .bc-scoreCard.sev-info{ background:rgba(34,211,238,.05) !important; border-color:rgba(34,211,238,.4) !important; }
  .bc-scoreCard.sev-critical .bc-scoreValue{ color:#be123c !important; }
  .bc-scoreCard.sev-high .bc-scoreValue{ color:#c2410c !important; }
  .bc-scoreCard.sev-medium .bc-scoreValue{ color:#92400e !important; }
  .bc-scoreCard.sev-low .bc-scoreValue{ color:#1d4ed8 !important; }
  .bc-scoreCard.sev-info .bc-scoreValue{ color:#0e7490 !important; }
  .bc-pageBreak{ page-break-before:always; break-before:page; }
  .print-btn{ display:none !important; }
  a{ color:#0f172a !important; text-decoration:none !important; }
  .bc-sectionHead{ break-after:avoid; page-break-after:avoid; }
  .bc-scoreRow{ break-inside:avoid; page-break-inside:avoid; }
  .bc-grid2{ break-inside:avoid; page-break-inside:avoid; }
  .bc-kvItem{ break-inside:avoid; page-break-inside:avoid; }
  .bc-chartCard{ break-inside:avoid; page-break-inside:avoid; }
  .bc-finding{ break-inside:avoid; page-break-inside:avoid; }
  .bc-stakeTable{ break-inside:avoid; page-break-inside:avoid; }
  .bc-stakeTh{ background:#f8fafc !important; }
  .bc-stakeRole{ color:#059669 !important; }
  .bc-stakeContact a{ color:#059669 !important; }
  .bc-sectionLabel{ break-after:avoid; page-break-after:avoid; }
  p, li{ orphans:3; widows:3; }
  .bc-footer{ position:fixed; bottom:0; left:0; right:0; }
}

/* ─── Base ─── */
*{ box-sizing:border-box; margin:0; padding:0; }
html,body{
  background:var(--bg); color:var(--text);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  font-size:14px; line-height:1.65;
}
a{ color:var(--accent); }
strong{ font-weight:800; }
.bc-mono{
  font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Courier New",monospace;
  font-size:12px;
}

/* ─── Pages ─── */
.bc-page{ max-width:var(--page-max); margin:0 auto; padding:48px 28px; }
.bc-pageBreak{ page-break-before:always; break-before:page; }

/* ─── Cover ─── */
.bc-cover{
  display:flex; flex-direction:column; gap:28px;
  background:linear-gradient(140deg,#040d1c 0%,#091d3d 50%,#050e1e 100%);
  padding:36px 40px 40px;
  border-radius:var(--radius);
  position:relative; overflow:hidden;
}
.bc-cover::before{
  content:""; position:absolute; inset:0; pointer-events:none; z-index:0;
  background:
    radial-gradient(ellipse at 72% 22%, rgba(0,229,160,.10) 0%, transparent 52%),
    radial-gradient(ellipse at 12% 78%, rgba(14,165,233,.06) 0%, transparent 48%);
}
.bc-cover::after{
  content:""; position:absolute; inset:0; pointer-events:none; z-index:0;
  background-image:
    linear-gradient(rgba(255,255,255,.016) 1px, transparent 1px),
    linear-gradient(90deg, rgba(255,255,255,.016) 1px, transparent 1px);
  background-size:52px 52px;
}

.bc-coverTop{
  display:flex; align-items:flex-start; justify-content:space-between; gap:16px;
  position:relative; z-index:1;
}
.bc-brand{ display:flex; align-items:center; gap:14px; }
.bc-mark{
  width:50px; height:50px; border-radius:13px;
  border:1.5px solid var(--accent); background:rgba(0,229,160,.09);
  display:grid; place-items:center;
  font-size:13px; font-weight:900; letter-spacing:.1em; color:var(--accent);
}
.bc-brandName{ font-size:14px; font-weight:900; letter-spacing:.1em; text-transform:uppercase; color:var(--text); }
.bc-brandTag{ font-size:11px; color:var(--muted); letter-spacing:.04em; margin-top:3px; }
.bc-markLogo{
  height:56px; width:auto; max-width:160px; border-radius:10px;
  background:rgba(255,255,255,.05);
  object-fit:contain; padding:4px; flex-shrink:0;
}
.bc-classification{
  padding:6px 16px; border-radius:6px;
  font-size:10px; font-weight:800; letter-spacing:.16em; text-transform:uppercase;
  background:rgba(239,68,68,.12); border:1px solid rgba(239,68,68,.35); color:#f87171;
}

.bc-coverCenter{ display:flex; flex-direction:column; position:relative; z-index:1; }
.bc-accentRule{ width:48px; height:3px; background:var(--accent); border-radius:2px; margin-bottom:16px; }
.bc-coverTitle{
  font-size:clamp(32px,4.2vw,48px); font-weight:950; line-height:1.08;
  letter-spacing:-.025em; color:#eaf3ff; margin-bottom:14px;
}
.bc-coverClient{
  font-size:clamp(16px,2vw,20px); font-weight:700;
  color:var(--accent); letter-spacing:.01em;
}
.bc-coverEngagement{ font-size:13px; color:var(--muted); margin-top:5px; letter-spacing:.02em; }

.bc-coverBottom{
  display:grid; grid-template-columns:repeat(4,1fr);
  border:1px solid rgba(255,255,255,.1); border-radius:13px; overflow:hidden;
  background:rgba(255,255,255,.03);
  position:relative; z-index:1;
}
.bc-coverMeta{ padding:14px 20px; border-right:1px solid rgba(255,255,255,.08); }
.bc-coverMeta:last-child{ border-right:none; }
.bc-coverMetaLabel{ font-size:10px; color:var(--muted); letter-spacing:.14em; text-transform:uppercase; font-weight:700; margin-bottom:6px; }
.bc-coverMetaValue{ font-size:13px; font-weight:700; color:var(--text); }

/* ─── Sections ─── */
.bc-sectionHead{ margin-bottom:32px; }
.bc-sectionNum{
  font-size:11px; font-weight:900; letter-spacing:.2em; text-transform:uppercase;
  color:var(--accent); margin-bottom:8px;
}
.bc-sectionTitle{ font-size:26px; font-weight:950; letter-spacing:-.02em; color:var(--text); margin-bottom:6px; }
.bc-sectionSub{ font-size:13px; color:var(--muted); }
.bc-sectionRule{
  height:1px; border:none; margin:14px 0 32px; opacity:.55;
  background:linear-gradient(to right, var(--accent) 0%, transparent 70%);
}

/* ─── Cards ─── */
.bc-card{ background:var(--card); border:1px solid var(--border); border-radius:var(--radius); padding:24px; }
.bc-divider{ height:1px; background:var(--border2); margin:22px 0; }

/* ─── KV grid ─── */
.bc-kv{ display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.bc-kvItem{ border:1px solid var(--border2); border-radius:11px; padding:16px; background:var(--card2); }
.bc-kvLabel{
  font-size:10px; color:var(--muted); letter-spacing:.14em; text-transform:uppercase;
  margin-bottom:8px; font-weight:800;
}
.bc-kvValue{ font-size:14px; font-weight:800; color:var(--text); }

/* ─── Typography ─── */
.bc-small{ font-size:12px; color:var(--muted); }
.bc-text{ color:var(--text); font-size:13px; line-height:1.75; }
.bc-text img{ max-width:100%; height:auto; border-radius:8px; margin:8px 0; }
.bc-list{ padding-left:18px; color:var(--text); font-size:13px; line-height:1.75; }
.bc-list li{ margin:5px 0; }

/* ─── Image captions ─── */
.bc-mdFigure{ display:block; margin:14px auto; text-align:center; }
.bc-mdFigure img{ max-width:100%; height:auto; display:block; margin:0 auto; border-radius:8px; }
.bc-mdFigcaption{ display:block; margin-top:6px; font-size:.88em; color:var(--muted); text-align:center; }

/* ─── Severity pills ─── */
.bc-badges{ display:flex; gap:8px; flex-wrap:wrap; }
.bc-pill{
  display:inline-flex; align-items:center; gap:7px; padding:5px 12px;
  border-radius:999px; font-size:11px; font-weight:800; letter-spacing:.03em;
  border:1px solid var(--border2); background:var(--card2); color:var(--text); white-space:nowrap;
}
.bc-dot{ width:8px; height:8px; border-radius:50%; flex-shrink:0; }
.sev-critical .bc-dot{ background:#f43f5e; }
.sev-high .bc-dot{ background:#fb923c; }
.sev-medium .bc-dot{ background:#fbbf24; }
.sev-low .bc-dot{ background:#60a5fa; }
.sev-info .bc-dot{ background:#22d3ee; }
.sev-critical.bc-pill{ border-color:rgba(244,63,94,.4); background:rgba(244,63,94,.12); color:#fb7185; }
.sev-high.bc-pill{ border-color:rgba(251,146,60,.4); background:rgba(251,146,60,.12); color:#fdba74; }
.sev-medium.bc-pill{ border-color:rgba(251,191,36,.4); background:rgba(251,191,36,.12); color:#fde68a; }
.sev-low.bc-pill{ border-color:rgba(96,165,250,.4); background:rgba(96,165,250,.12); color:#93c5fd; }
.sev-info.bc-pill{ border-color:rgba(34,211,238,.4); background:rgba(34,211,238,.12); color:#67e8f9; }

/* ─── Scorecard ─── */
.bc-scoreRow{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; }
.bc-scoreCard{
  border-radius:12px; padding:20px 16px 16px; background:var(--card2);
  border:1px solid var(--border2); position:relative; overflow:hidden;
}
.bc-scoreCard::before{
  content:""; position:absolute; top:0; left:0; right:0; height:3px; background:var(--border2);
}
.bc-scoreLabel{ font-size:10px; color:var(--muted); letter-spacing:.14em; text-transform:uppercase; margin-bottom:10px; font-weight:800; }
.bc-scoreValue{ font-size:34px; font-weight:950; line-height:1; letter-spacing:-.03em; }
.bc-scoreCard.sev-critical{ background:rgba(244,63,94,.10); border-color:rgba(244,63,94,.3); }
.bc-scoreCard.sev-critical::before{ background:#f43f5e; }
.bc-scoreCard.sev-critical .bc-scoreValue{ color:#f43f5e; }
.bc-scoreCard.sev-high{ background:rgba(251,146,60,.10); border-color:rgba(251,146,60,.3); }
.bc-scoreCard.sev-high::before{ background:#fb923c; }
.bc-scoreCard.sev-high .bc-scoreValue{ color:#fb923c; }
.bc-scoreCard.sev-medium{ background:rgba(251,191,36,.10); border-color:rgba(251,191,36,.3); }
.bc-scoreCard.sev-medium::before{ background:#fbbf24; }
.bc-scoreCard.sev-medium .bc-scoreValue{ color:#fbbf24; }
.bc-scoreCard.sev-low{ background:rgba(96,165,250,.10); border-color:rgba(96,165,250,.3); }
.bc-scoreCard.sev-low::before{ background:#60a5fa; }
.bc-scoreCard.sev-low .bc-scoreValue{ color:#60a5fa; }
.bc-scoreCard.sev-info{ background:rgba(34,211,238,.10); border-color:rgba(34,211,238,.3); }
.bc-scoreCard.sev-info::before{ background:#22d3ee; }
.bc-scoreCard.sev-info .bc-scoreValue{ color:#22d3ee; }

/* ─── Charts ─── */
.bc-grid2{ display:grid; grid-template-columns:1.2fr .8fr; gap:12px; align-items:stretch; }
.bc-chartCard{ border:1px solid var(--border2); border-radius:12px; padding:18px; background:var(--card2); }
.bc-chartTitle{
  font-size:10px; font-weight:900; letter-spacing:.16em; text-transform:uppercase;
  color:var(--muted); margin-bottom:18px;
}
.bc-barLegend{ display:flex; gap:12px; flex-wrap:wrap; margin-bottom:16px; }
.bc-legendItem{ display:flex; align-items:center; gap:7px; font-size:11px; color:var(--muted); font-weight:700; }
.bc-swatch{ width:10px; height:10px; border-radius:3px; flex-shrink:0; }
.bc-bars{ display:flex; flex-direction:column; gap:12px; }
.bc-barRow{ display:grid; grid-template-columns:160px 1fr; gap:10px; align-items:center; }
.bc-barLabel{ font-size:11px; color:var(--text); font-weight:700; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.bc-barTrack{ height:11px; border-radius:999px; background:var(--border2); overflow:hidden; display:flex; }
.bc-barSeg{ height:100%; }
.bc-barSeg.critical{ background:#f43f5e; width:var(--w-critical); }
.bc-barSeg.high{ background:#fb923c; width:var(--w-high); }
.bc-barSeg.medium{ background:#fbbf24; width:var(--w-medium); }
.bc-barSeg.low{ background:#60a5fa; width:var(--w-low); }
.bc-barSeg.info{ background:#22d3ee; width:var(--w-info); }

.bc-pieWrap{ display:flex; flex-direction:column; align-items:center; gap:20px; margin-top:6px; }
.bc-pie{
  width:140px; height:140px; border-radius:50%; flex-shrink:0;
  background:conic-gradient(
    #ef4444 0 var(--p-open),
    #f97316 var(--p-open) calc(var(--p-open) + var(--p-triage)),
    #3b82f6 calc(var(--p-open) + var(--p-triage)) calc(var(--p-open) + var(--p-triage) + var(--p-accepted)),
    #22c55e calc(var(--p-open) + var(--p-triage) + var(--p-accepted)) calc(var(--p-open) + var(--p-triage) + var(--p-accepted) + var(--p-fixed)),
    #94a3b8 calc(var(--p-open) + var(--p-triage) + var(--p-accepted) + var(--p-fixed)) 360deg
  );
  position:relative;
  box-shadow:0 0 40px rgba(0,229,160,.08), 0 0 0 1px var(--border2);
}
.bc-pie::after{
  content:""; position:absolute; inset:34px; border-radius:50%;
  background:var(--card2); border:1px solid var(--border2);
}
.bc-pieLegend{ display:flex; flex-direction:column; gap:8px; width:100%; }
.bc-pieLegend .bc-legendItem{ font-weight:700; font-size:12px; }

/* ─── Stakeholder table ─── */
.bc-stakeTable{
  width:100%; border-collapse:collapse; font-size:13px;
}
.bc-stakeTable th,.bc-stakeTable td{
  padding:12px 16px; text-align:left; border-bottom:1px solid var(--border2);
}
.bc-stakeTh{
  font-size:10px; font-weight:900; letter-spacing:.14em; text-transform:uppercase;
  color:var(--muted); background:var(--card2);
}
.bc-stakeName{ font-weight:800; color:var(--text); }
.bc-stakeRole{
  font-size:12px; font-weight:700; color:var(--accent);
  letter-spacing:.02em;
}
.bc-stakeContact{ font-size:12px; color:var(--muted); }
.bc-stakeContact a{ color:var(--accent); text-decoration:none; }
.bc-stakeTable tbody tr:last-child td{ border-bottom:none; }

/* ─── Findings ─── */
.bc-findingsList{ display:grid; gap:16px; }
.bc-finding{
  border:1px solid var(--border); border-radius:var(--radius);
  padding:22px 24px 20px 28px; background:var(--card);
  position:relative;
}
.bc-finding::before{
  content:""; position:absolute; top:0; left:0; bottom:0; width:4px;
  border-radius:4px 0 0 4px; background:var(--sev-color, var(--border));
}
.bc-finding.sev-critical{ --sev-color:#f43f5e; }
.bc-finding.sev-high{ --sev-color:#fb923c; }
.bc-finding.sev-medium{ --sev-color:#fbbf24; }
.bc-finding.sev-low{ --sev-color:#60a5fa; }
.bc-finding.sev-info{ --sev-color:#22d3ee; }

.bc-findingTop{
  display:flex; align-items:flex-start; justify-content:space-between;
  gap:14px; flex-wrap:wrap; margin-bottom:16px;
}
.bc-findingTitle{ font-size:15px; font-weight:900; letter-spacing:-.01em; color:var(--text); }
.bc-findingId{ font-size:10px; color:var(--muted); letter-spacing:.1em; text-transform:uppercase; margin-top:5px; }

.bc-sectionLabel{
  font-size:10px; color:var(--accent); letter-spacing:.16em; text-transform:uppercase;
  margin:18px 0 7px; font-weight:900; display:flex; align-items:center; gap:8px;
}
.bc-sectionLabel::before{
  content:""; display:inline-block; width:16px; height:1.5px;
  background:var(--accent); flex-shrink:0;
}
.bc-placeholder{ font-style:italic; color:var(--muted); font-size:13px; }

/* ─── Footer ─── */
.bc-footer{
  max-width:var(--page-max); margin:0 auto; padding:24px 28px;
  border-top:1px solid var(--border2);
}
.bc-footerInner{
  display:flex; justify-content:space-between; align-items:center;
  font-size:11px; color:var(--muted); letter-spacing:.04em;
}

/* ─── Print button ─── */
.print-btn{
  position:fixed; bottom:24px; right:24px;
  background:var(--accent); color:#07101f;
  border:none; padding:11px 24px; border-radius:8px; font-size:12px;
  font-weight:900; cursor:pointer; letter-spacing:.06em; z-index:999;
  box-shadow:0 4px 24px rgba(0,229,160,.4);
}

/* ─── Responsive ─── */
@media(max-width:820px){
  .bc-cover{ padding:32px 24px; }
  .bc-coverBottom{ grid-template-columns:1fr 1fr; }
  .bc-kv{ grid-template-columns:1fr; }
  .bc-scoreRow{ grid-template-columns:1fr 1fr; }
  .bc-grid2{ grid-template-columns:1fr; }
  .bc-barRow{ grid-template-columns:1fr; }
}
`;
  }
}
