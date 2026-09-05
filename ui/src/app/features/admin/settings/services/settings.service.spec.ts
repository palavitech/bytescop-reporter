import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { SettingsService } from './settings.service';
import { SettingDefinition } from '../models/setting.model';

const MOCK_SETTING: SettingDefinition = {
  key: 'company_name',
  label: 'Company Name',
  description: 'Your company name',
  setting_type: 'text',
  choices: [],
  default: 'BytesCop-Reporter',
  group: 'general',
  order: 1,
  value: 'ACME',
  has_value: true,
  updated_at: '2026-01-01T00:00:00Z',
  updated_by: 'admin@test.com',
};

describe('SettingsService', () => {
  let service: SettingsService;
  let httpTesting: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    service = TestBed.inject(SettingsService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => httpTesting.verify());

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  // --- list ---

  it('list() sends GET to /api/settings/', () => {
    service.list().subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/'));
    expect(req.request.method).toBe('GET');
    req.flush([MOCK_SETTING]);
  });

  it('list() returns the settings array', () => {
    let result: SettingDefinition[] | undefined;
    service.list().subscribe(r => (result = r));
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/')).flush([MOCK_SETTING]);
    expect(result).toEqual([MOCK_SETTING]);
  });

  // --- upsert ---

  it('upsert() sends PUT to /api/settings/:key/', () => {
    service.upsert('company_name', 'NewCo').subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/company_name/'));
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual({ value: 'NewCo' });
    req.flush(MOCK_SETTING);
  });

  it('upsert() returns the setting', () => {
    let result: SettingDefinition | undefined;
    service.upsert('company_name', 'X').subscribe(r => (result = r));
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/company_name/')).flush(MOCK_SETTING);
    expect(result).toEqual(MOCK_SETTING);
  });

  // --- reset ---

  it('reset() sends DELETE to /api/settings/:key/', () => {
    service.reset('company_name').subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/company_name/'));
    expect(req.request.method).toBe('DELETE');
    req.flush(MOCK_SETTING);
  });

  it('reset() returns the setting', () => {
    let result: SettingDefinition | undefined;
    service.reset('company_name').subscribe(r => (result = r));
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/company_name/')).flush(MOCK_SETTING);
    expect(result).toEqual(MOCK_SETTING);
  });

  // --- hasLogo ---

  it('hasLogo() sends GET to /api/settings/logo/', () => {
    service.hasLogo().subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo/'));
    expect(req.request.method).toBe('GET');
    req.flush({ has_logo: true });
  });

  it('hasLogo() returns the response', () => {
    let result: { has_logo: boolean } | undefined;
    service.hasLogo().subscribe(r => (result = r));
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo/')).flush({ has_logo: false });
    expect(result).toEqual({ has_logo: false });
  });

  // --- uploadLogo ---

  it('uploadLogo() sends multipart POST to /api/settings/logo/', () => {
    const file = new File(['img'], 'logo.png', { type: 'image/png' });
    let result: { has_logo: boolean } | undefined;
    service.uploadLogo(file).subscribe(r => (result = r));

    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo/') && r.method === 'POST');
    expect(req.request.body instanceof FormData).toBe(true);
    expect((req.request.body as FormData).get('logo')).toBeTruthy();
    req.flush({ has_logo: true });

    expect(result).toEqual({ has_logo: true });
  });

  // --- deleteLogo ---

  it('deleteLogo() sends DELETE to /api/settings/logo/', () => {
    service.deleteLogo().subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo/') && r.method === 'DELETE');
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });

  // --- getLogoBlob ---

  it('getLogoBlob() sends GET to /api/settings/logo-content/', () => {
    service.getLogoBlob().subscribe();
    const req = httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo-content/'));
    expect(req.request.method).toBe('GET');
    expect(req.request.responseType).toBe('blob');
    req.flush(new Blob(['img']));
  });

  // --- deleteLogo return value ---

  it('deleteLogo() completes with void', () => {
    let completed = false;
    service.deleteLogo().subscribe({ complete: () => (completed = true) });
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo/') && r.method === 'DELETE').flush(null);
    expect(completed).toBe(true);
  });

  // --- getLogoBlob return value ---

  it('getLogoBlob() returns the blob', () => {
    const blob = new Blob(['logo-data'], { type: 'image/png' });
    let result: Blob | undefined;
    service.getLogoBlob().subscribe(r => (result = r));
    httpTesting.expectOne(r => r.url.endsWith('/api/settings/logo-content/')).flush(blob);
    expect(result).toBeTruthy();
  });

});
