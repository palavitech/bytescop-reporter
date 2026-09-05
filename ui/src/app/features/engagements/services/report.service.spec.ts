import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { ReportService } from './report.service';
import { SettingsService } from '../../admin/settings/services/settings.service';
import { EngagementsService } from './engagements.service';
import { DateFormatService } from '../../../services/core/date-format.service';
import { Engagement } from '../models/engagement.model';
import { Finding } from '../models/finding.model';
import { Asset } from '../../assets/models/asset.model';
import { of, throwError } from 'rxjs';

const MOCK_ENGAGEMENT: Engagement = {
  id: 'eng-1',
  name: 'Q1 Pentest',
  client_id: 'c-1',
  client_name: 'ACME Corp',
  status: 'active',
  description: '',
  notes: '',
  start_date: '2026-01-15',
  end_date: '2026-02-15',
  findings_summary: null,
  engagement_type: 'general',
  project_id: null,
  project_name: null,
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

const MOCK_FINDING_CRITICAL: Finding = {
  id: 'f-1',
  engagement_id: 'eng-1',
  asset_id: 'a-1',
  asset_name: 'WebApp',
  title: 'SQL Injection',
  severity: 'critical',
  assessment_area: 'application_security',
  owasp_category: 'A03:2021',
  cwe_id: 'CWE-89',
  status: 'open',
  description_md: '**Critical** SQL injection found',
  recommendation_md: 'Use parameterized queries',
  is_draft: false,
  sample_id: null,
  sample_name: '',
  analysis_type: '',
  analysis_check_key: '',
  execution_status: '',
  created_at: '2026-01-10T00:00:00Z',
  updated_at: '2026-01-10T00:00:00Z',
};

const MOCK_FINDING_LOW: Finding = {
  id: 'f-2',
  engagement_id: 'eng-1',
  asset_id: 'a-1',
  asset_name: 'WebApp',
  title: 'Missing Header',
  severity: 'low',
  assessment_area: 'configuration_and_deployment',
  owasp_category: 'A05:2021',
  cwe_id: 'CWE-693',
  status: 'fixed',
  description_md: 'X-Frame-Options missing',
  recommendation_md: 'Add header',
  is_draft: false,
  sample_id: null,
  sample_name: '',
  analysis_type: '',
  analysis_check_key: '',
  execution_status: '',
  created_at: '2026-01-11T00:00:00Z',
  updated_at: '2026-01-11T00:00:00Z',
};

const MOCK_ASSET: Asset = {
  id: 'a-1',
  name: 'WebApp',
  client_id: 'c-1',
  client_name: 'ACME Corp',
  asset_type: 'webapp',
  environment: 'prod',
  criticality: 'high',
  target: 'https://app.acme.com',
  notes: '',
  attributes: {},
  created_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
};

describe('ReportService', () => {
  let service: ReportService;
  let settingsService: jasmine.SpyObj<SettingsService>;
  let engagementsService: jasmine.SpyObj<EngagementsService>;
  let dateFormatService: jasmine.SpyObj<DateFormatService>;

  beforeEach(() => {
    settingsService = jasmine.createSpyObj('SettingsService', ['list', 'hasLogo', 'getLogoBlob']);
    engagementsService = jasmine.createSpyObj('EngagementsService', ['listStakeholders', 'listSettings']);
    dateFormatService = jasmine.createSpyObj('DateFormatService', ['formatDate']);

    settingsService.list.and.returnValue(of([
      { key: 'company_name', value: 'TestCo', label: '', description: '', setting_type: 'text' as const, choices: [], default: '', group: '', order: 0, has_value: true, updated_at: null, updated_by: null },
    ]));
    settingsService.hasLogo.and.returnValue(of({ has_logo: false }));
    engagementsService.listStakeholders.and.returnValue(of([]));
    engagementsService.listSettings.and.returnValue(of([]));
    dateFormatService.formatDate.and.callFake((d: string | null | undefined) => d ?? '—');

    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        ReportService,
        { provide: SettingsService, useValue: settingsService },
        { provide: EngagementsService, useValue: engagementsService },
        { provide: DateFormatService, useValue: dateFormatService },
      ],
    });
    service = TestBed.inject(ReportService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // --- generate ---

  it('generate() opens a new window and writes HTML', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    const mockWin = { document: mockDoc } as unknown as Window;
    spyOn(window, 'open').and.returnValue(mockWin);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_CRITICAL, MOCK_FINDING_LOW], [MOCK_ASSET]);

    expect(window.open).toHaveBeenCalledWith('', '_blank');
    expect(mockDoc.open).toHaveBeenCalled();
    expect(mockDoc.write).toHaveBeenCalledTimes(1);
    expect(mockDoc.close).toHaveBeenCalled();

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('TestCo');
    expect(html).toContain('Q1 Pentest');
    expect(html).toContain('ACME Corp');
    expect(html).toContain('SQL Injection');
    expect(html).toContain('Missing Header');
  });

  it('generate() sorts findings by severity (critical first)', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    const mockWin = { document: mockDoc } as unknown as Window;
    spyOn(window, 'open').and.returnValue(mockWin);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_LOW, MOCK_FINDING_CRITICAL], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    const criticalIdx = html.indexOf('SQL Injection');
    const lowIdx = html.indexOf('Missing Header');
    expect(criticalIdx).toBeLessThan(lowIdx);
  });

  it('generate() alerts when pop-up is blocked', async () => {
    spyOn(window, 'open').and.returnValue(null);
    spyOn(window, 'alert');

    await service.generate(MOCK_ENGAGEMENT, [], []);

    expect(window.alert).toHaveBeenCalledWith('Pop-up blocked. Please allow pop-ups for this site and try again.');
  });

  it('generate() falls back to default company name on settings error', async () => {
    settingsService.list.and.returnValue(throwError(() => new Error('fail')));
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('BytesCop-Reporter');
  });

  it('generate() falls back when company_name setting has empty value', async () => {
    settingsService.list.and.returnValue(of([
      { key: 'company_name', value: '  ', label: '', description: '', setting_type: 'text' as const, choices: [], default: '', group: '', order: 0, has_value: false, updated_at: null, updated_by: null },
    ]));
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('BytesCop-Reporter');
  });

  it('generate() includes logo when available', async () => {
    settingsService.hasLogo.and.returnValue(of({ has_logo: true }));
    settingsService.getLogoBlob.and.returnValue(of(new Blob(['png'], { type: 'image/png' })));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('bc-markLogo');
    expect(html).toContain('data:');
  });

  it('generate() uses SVG mark when logo errors', async () => {
    settingsService.hasLogo.and.returnValue(throwError(() => new Error('fail')));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('bc-mark');
    expect(html).toContain('<svg');
  });

  it('generate() includes stakeholders section when stakeholders exist', async () => {
    engagementsService.listStakeholders.and.returnValue(of([
      {
        id: 'sh-1',
        member_id: 'm-1',
        role: 'lead_tester',
        user: { id: 'u-1', first_name: 'Jane', last_name: 'Doe', email: 'jane@test.com', phone: '+1111', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('Jane');
    expect(html).toContain('Doe');
    expect(html).toContain('Lead Tester');
    expect(html).toContain('jane@test.com');
  });

  it('generate() hides contact info when show_contact_info_on_report is false', async () => {
    engagementsService.listStakeholders.and.returnValue(of([
      {
        id: 'sh-1',
        member_id: 'm-1',
        role: 'lead_tester',
        user: { id: 'u-1', first_name: 'Jane', last_name: 'Doe', email: 'jane@test.com', phone: '+1111', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]));
    engagementsService.listSettings.and.returnValue(of([
      { key: 'show_contact_info_on_report', value: 'false', label: '', description: '', setting_type: 'boolean', default: 'true', group: '', order: 0, has_value: true, updated_at: null, updated_by: null },
    ]));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('Jane');
    // Should not contain email/phone columns
    expect(html).not.toContain('jane@test.com');
  });

  it('generate() handles empty findings list', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('No findings recorded');
  });

  it('generate() handles empty scope assets', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('No assets in scope');
  });

  it('generate() handles stakeholders error gracefully', async () => {
    engagementsService.listStakeholders.and.returnValue(throwError(() => new Error('fail')));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    expect(mockDoc.write).toHaveBeenCalled();
  });

  it('generate() handles engagement settings error gracefully', async () => {
    engagementsService.listSettings.and.returnValue(throwError(() => new Error('fail')));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    expect(mockDoc.write).toHaveBeenCalled();
  });

  it('generate() includes scope summary for assets', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('1 asset');
    expect(html).toContain('WebApp');
  });

  it('generate() renders markdown in descriptions', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_CRITICAL], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    // marked should convert **Critical** to <strong>Critical</strong>
    expect(html).toContain('<strong>Critical</strong>');
  });

  it('generate() escapes HTML in engagement name', async () => {
    const xssEngagement = { ...MOCK_ENGAGEMENT, name: '<script>alert("xss")</script>' };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(xssEngagement, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('generate() shows narrative for critical/high findings', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_CRITICAL], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('Critical and high severity findings should be prioritized');
  });

  it('generate() shows no-critical narrative when only low findings', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_LOW], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('No critical or high severity findings');
  });

  it('generate() falls back to BytesCop-Reporter when company_name key not found', async () => {
    settingsService.list.and.returnValue(of([
      { key: 'other_setting', value: 'foo', label: '', description: '', setting_type: 'text' as const, choices: [], default: '', group: '', order: 0, has_value: true, updated_at: null, updated_by: null },
    ]));
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('BytesCop-Reporter');
  });

  it('generate() handles finding with no assessment_area', async () => {
    const noAssessmentArea: Finding = { ...MOCK_FINDING_CRITICAL, assessment_area: '' };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [noAssessmentArea], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('SQL Injection');
    // Should not contain the assessment_area separator for empty assessment_area
    expect(html).not.toContain('&middot;&nbsp; &nbsp;');
  });

  it('generate() handles finding with empty asset_name (Unlinked)', async () => {
    const noAsset: Finding = { ...MOCK_FINDING_CRITICAL, asset_name: '', asset_id: null };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [noAsset], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('No asset linked');
  });

  it('generate() renders scope summary with plural assets and type counts', async () => {
    const assets: Asset[] = [
      MOCK_ASSET,
      { ...MOCK_ASSET, id: 'a-2', name: 'API', asset_type: 'api', target: 'https://api.acme.com' },
      { ...MOCK_ASSET, id: 'a-3', name: 'WebApp2', target: 'https://app2.acme.com' },
    ];
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], assets);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('3 assets');
  });

  it('generate() handles stakeholder without email and phone', async () => {
    engagementsService.listStakeholders.and.returnValue(of([
      {
        id: 'sh-1',
        member_id: 'm-1',
        role: 'observer',
        user: { id: 'u-1', first_name: 'Bob', last_name: 'Anon', email: '', phone: '', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('Bob');
    expect(html).toContain('Anon');
    // Empty email/phone should show dashes
    expect(html).toContain('\u2014');
  });

  it('generate() sorts stakeholders by role hierarchy', async () => {
    engagementsService.listStakeholders.and.returnValue(of([
      {
        id: 'sh-2',
        member_id: 'm-2',
        role: 'observer',
        user: { id: 'u-2', first_name: 'Observer', last_name: 'User', email: 'obs@test.com', phone: '', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
      {
        id: 'sh-1',
        member_id: 'm-1',
        role: 'client_poc',
        user: { id: 'u-1', first_name: 'Client', last_name: 'POC', email: 'poc@test.com', phone: '', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    const pocIdx = html.indexOf('Client');
    const obsIdx = html.indexOf('Observer');
    expect(pocIdx).toBeLessThan(obsIdx);
  });

  it('generate() handles stakeholder with unknown role', async () => {
    engagementsService.listStakeholders.and.returnValue(of([
      {
        id: 'sh-1',
        member_id: 'm-1',
        role: 'unknown_role' as any,
        user: { id: 'u-1', first_name: 'Unknown', last_name: 'Role', email: 'u@test.com', phone: '', timezone: 'UTC', avatar_url: null },
        created_at: '2026-01-01T00:00:00Z',
        updated_at: '2026-01-01T00:00:00Z',
      },
    ]));

    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], []);

    const html = mockDoc.write.calls.first().args[0] as string;
    // Unknown role sorts to end (index 99) and uses raw role name
    expect(html).toContain('unknown_role');
  });

  it('generate() handles finding with unknown status', async () => {
    const unknownStatus: Finding = { ...MOCK_FINDING_CRITICAL, status: 'unknown_status' as any };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [unknownStatus], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('unknown_status');
  });

  it('generate() handles finding with unknown severity', async () => {
    const unknownSev: Finding = { ...MOCK_FINDING_CRITICAL, severity: 'unknown_sev' as any };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [unknownSev], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('unknown_sev');
  });

  it('generate() shows singular "finding" when only 1 finding', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_CRITICAL], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    // singular "finding" (not "findings")
    expect(html).toContain('1 finding<');
  });

  it('generate() shows plural "findings" when multiple findings', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [MOCK_FINDING_CRITICAL, MOCK_FINDING_LOW], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('2 findings');
  });

  it('generate() uses single asset text for scope summary', async () => {
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    // singular "asset" not "assets"
    expect(html).toContain('1 asset ');
  });

  it('generate() escapes null values in esc helper', async () => {
    const engNoClient = { ...MOCK_ENGAGEMENT, client_name: null as any };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(engNoClient, [], []);

    // Should not throw and should render empty string for null
    expect(mockDoc.write).toHaveBeenCalled();
  });

  it('generate() handles null description_md gracefully', async () => {
    const findingNoDesc = { ...MOCK_FINDING_CRITICAL, description_md: '' as string, recommendation_md: '' as string };
    const mockDoc = { open: jasmine.createSpy('open'), write: jasmine.createSpy('write'), close: jasmine.createSpy('close') };
    spyOn(window, 'open').and.returnValue({ document: mockDoc } as unknown as Window);

    await service.generate(MOCK_ENGAGEMENT, [findingNoDesc], [MOCK_ASSET]);

    const html = mockDoc.write.calls.first().args[0] as string;
    expect(html).toContain('No description provided');
    expect(html).toContain('No recommendation provided');
  });
});
