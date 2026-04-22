from django.conf import settings
from django.db import models

from core.models import TimeStampedModel


class ClassificationEntry(TimeStampedModel):
    """Global reference data for finding classification fields.

    Stores assessment areas, OWASP Top 10 categories, and CWE entries.
    These are seeded via data migration — no tenant scoping.
    """

    ENTRY_TYPES = [
        ('assessment_area', 'Assessment Area'),
        ('owasp', 'OWASP Top 10'),
        ('cwe', 'CWE'),
    ]

    entry_type = models.CharField(max_length=20, choices=ENTRY_TYPES)
    code = models.CharField(max_length=60)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default='')

    class Meta:
        ordering = ['entry_type', 'code']
        constraints = [
            models.UniqueConstraint(
                fields=['entry_type', 'code'],
                name='unique_classification_entry',
            ),
        ]
        indexes = [
            models.Index(fields=['entry_type']),
        ]

    def __str__(self):
        return f'{self.code} — {self.name}'


class Finding(TimeStampedModel):
    SEVERITIES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
        ('info', 'Info'),
    ]

    STATUSES = [
        ('open', 'Open'),
        ('triage', 'Triage'),
        ('accepted', 'Accepted'),
        ('fixed', 'Fixed'),
        ('false_positive', 'False Positive'),
    ]

    # Kept for backward compatibility / reference — no longer used as
    # field-level choices.  Validation is now DB-backed via
    # ClassificationEntry.
    ASSESSMENT_AREAS = [
        ('application_security', 'Application Security'),
        ('network_security', 'Network Security'),
        ('api_security', 'API Security'),
        ('cloud_security', 'Cloud Security'),
        ('infrastructure_security', 'Infrastructure Security'),
        ('cryptography', 'Cryptography'),
        ('auth_and_access_control', 'Authentication & Access Control'),
        ('configuration_and_deployment', 'Configuration & Deployment'),
        ('mobile_security', 'Mobile Security'),
        ('social_engineering', 'Social Engineering'),
        ('physical_security', 'Physical Security'),
        ('compliance', 'Compliance'),
    ]

    OWASP_CATEGORIES = [
        ('A01:2021', 'A01:2021 Broken Access Control'),
        ('A02:2021', 'A02:2021 Cryptographic Failures'),
        ('A03:2021', 'A03:2021 Injection'),
        ('A04:2021', 'A04:2021 Insecure Design'),
        ('A05:2021', 'A05:2021 Security Misconfiguration'),
        ('A06:2021', 'A06:2021 Vulnerable and Outdated Components'),
        ('A07:2021', 'A07:2021 Identification and Authentication Failures'),
        ('A08:2021', 'A08:2021 Software and Data Integrity Failures'),
        ('A09:2021', 'A09:2021 Security Logging and Monitoring Failures'),
        ('A10:2021', 'A10:2021 Server-Side Request Forgery'),
    ]

    tenant = models.ForeignKey(
        'tenancy.Tenant', on_delete=models.CASCADE, related_name='findings',
    )
    engagement = models.ForeignKey(
        'engagements.Engagement', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='findings',
    )
    asset = models.ForeignKey(
        'assets.Asset', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='findings',
    )
    sample = models.ForeignKey(
        'evidence.MalwareSample', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='findings',
    )
    evidence_source = models.ForeignKey(
        'evidence.EvidenceSource', null=True, blank=True,
        on_delete=models.SET_NULL, related_name='findings',
    )

    ANALYSIS_TYPES = [
        ('static', 'Static Analysis'),
        ('dynamic', 'Dynamic Analysis'),
        ('manual', 'Manual'),
    ]

    title = models.CharField(max_length=240)
    analysis_type = models.CharField(
        max_length=16, choices=ANALYSIS_TYPES, blank=True, default='',
    )
    severity = models.CharField(max_length=16, choices=SEVERITIES, default='medium')
    assessment_area = models.CharField(max_length=60, blank=True, default='')
    owasp_category = models.CharField(max_length=20, blank=True, default='')
    cwe_id = models.CharField(max_length=20, blank=True, default='')
    status = models.CharField(max_length=24, choices=STATUSES, default='open')
    description_md = models.TextField(blank=True, default='')
    recommendation_md = models.TextField(blank=True, default='')
    is_draft = models.BooleanField(default=False)

    # Forensics fields
    mitre_tactic = models.CharField(max_length=60, blank=True, default='')
    mitre_technique = models.CharField(max_length=20, blank=True, default='')
    ioc_type = models.CharField(max_length=30, blank=True, default='')
    ioc_value = models.CharField(max_length=500, blank=True, default='')
    occurrence_date = models.DateField(null=True, blank=True)
    confidence = models.CharField(max_length=20, blank=True, default='')

    analysis_check_key = models.CharField(
        max_length=60, blank=True, default='',
        help_text='Links to an analysis check definition. Empty for manual findings.',
    )

    EXECUTION_STATUSES = [
        ('', 'N/A'),
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    execution_status = models.CharField(
        max_length=16, choices=EXECUTION_STATUSES, blank=True, default='',
        help_text='Execution lifecycle for analysis check findings. Empty for manual findings.',
    )

    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True,
        on_delete=models.SET_NULL, related_name='findings_created',
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['tenant', 'severity']),
            models.Index(fields=['tenant', 'status']),
            models.Index(fields=['tenant', '-created_at']),
            models.Index(fields=['tenant', 'assessment_area']),
            models.Index(fields=['tenant', 'engagement', 'analysis_check_key']),
        ]

    def __str__(self) -> str:
        return self.title
