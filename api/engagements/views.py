import logging

from django.db.models import Count, Q
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from audit.base import AuditedModelViewSet
from audit.decorators import audited
from audit.models import AuditAction
from audit.service import log_audit
from authorization.permissions import TenantPermission
from subscriptions.guard import SubscriptionGuard, SubscriptionLimitExceeded
from subscriptions.services import check_image_limit
from assets.models import Asset
from assets.serializers import AssetSerializer
from evidence.services.attachment_upload import AttachmentUploadService
from evidence.services.sample_upload import MalwareSampleUploadService
from evidence.models import Attachment, EvidenceSource, MalwareSample
from evidence.serializers import EvidenceSourceSerializer, MalwareSampleSerializer
from evidence.signing import sign_attachment_url, sign_sample_url
from findings.models import Finding
from findings.serializers import FindingSerializer
from findings.services.attachment_reconcile import AttachmentReconcileService
from accounts.avatar_service import get_avatar_url
from tenancy.models import TenantMember
from .models import Engagement, EngagementSetting, EngagementStakeholder, Sow, SowAsset, StakeholderRole
from .serializers import EngagementSerializer, SowSerializer

logger = logging.getLogger("bytescop.engagements")


def _check_scope_for_approval(engagement, sow, tenant):
    """Return (has_scope, error_message) based on engagement type.

    Each engagement type defines what constitutes a valid scope.
    Default types use SowAsset; specialized types check their own entities.
    """
    _SCOPE_CHECKS = {
        'malware_analysis': (
            lambda eng, sow, t: MalwareSample.objects.filter(
                tenant=t, engagement=eng,
            ).exists(),
            'Cannot approve SoW with no malware samples uploaded.',
        ),
        'digital_forensics': (
            lambda eng, sow, t: EvidenceSource.objects.filter(
                tenant=t, engagement=eng,
            ).exists(),
            'Cannot approve SoW with no evidence sources added.',
        ),
    }

    check = _SCOPE_CHECKS.get(engagement.engagement_type)
    if check:
        checker, error_msg = check
        return checker(engagement, sow, tenant), error_msg

    # Default: check SowAsset scope
    has_scope = SowAsset.objects.filter(sow=sow, in_scope=True).exists()
    return has_scope, 'Cannot approve SoW with no assets in scope.'



def seed_analysis_findings(engagement, tenant, user):
    """Create placeholder findings for every sample x analysis-check combination
    that doesn't already exist.

    Checks with a non-empty ``file_types`` list are only seeded when the
    sample's detected file-type tags intersect that list.

    Returns the number of newly created findings.
    """
    from findings.analysis_checks import ANALYSIS_CHECKS, detect_sample_tags
    from evidence.storage.factory import get_attachment_storage

    samples = list(
        MalwareSample.objects.filter(
            tenant=tenant, engagement=engagement,
        ).order_by('created_at')
    )

    if not samples:
        return 0

    # Set of (sample_id, analysis_check_key) pairs that already have findings.
    existing_pairs = set(
        Finding.objects.filter(
            engagement=engagement,
            tenant=tenant,
            sample__in=samples,
        ).exclude(analysis_check_key='').values_list('sample_id', 'analysis_check_key')
    )

    storage = get_attachment_storage()
    created = 0
    for sample in samples:
        tags = detect_sample_tags(storage, sample)
        for check in ANALYSIS_CHECKS:
            if (sample.pk, check['key']) in existing_pairs:
                continue
            required = check.get('file_types', [])
            if required and not tags.intersection(required):
                continue
            Finding.objects.create(
                tenant=tenant,
                engagement=engagement,
                sample=sample,
                title=check['title'],
                analysis_type=check['analysis_type'],
                description_md=check['description_placeholder'],
                analysis_check_key=check['key'],
                execution_status='' if check['analysis_type'] == 'manual' else 'pending',
                created_by=user,
            )
            created += 1

    if created:
        logger.info(
            'Seeded %d analysis findings: engagement=%s tenant=%s',
            created, engagement.pk, tenant.slug,
        )
    return created


class EngagementViewSet(AuditedModelViewSet):
    permission_classes = [IsAuthenticated, TenantPermission, SubscriptionGuard]
    serializer_class = EngagementSerializer
    audit_resource_type = "engagement"

    # Subscription limit declarations — the guard reads these to enforce limits.
    # context lambdas resolve the objects needed by each rule.
    subscription_limits = {
        'create': {
            'rule': 'engagements_per_tenant',
            'context': lambda view, request: {},
        },
        'findings_create': {
            'rule': 'findings_per_engagement',
            'context': lambda view, request: {
                'engagement': view.get_object(),
            },
        },
    }

    required_permissions = {
        'list': ['engagement.view'],
        'retrieve': ['engagement.view'],
        'create': ['engagement.create'],
        'update': ['engagement.update'],
        'partial_update': ['engagement.update'],
        'destroy': ['engagement.delete'],
        'sow': ['sow.view'],              # gateway — handlers re-check
        'sow_retrieve': ['sow.view'],
        'sow_create': ['sow.create'],
        'sow_update': ['sow.update'],
        'sow_destroy': ['sow.delete'],
        'scope': ['scope.view'],             # gateway — handlers re-check
        'scope_list': ['scope.view'],
        'scope_add': ['scope.manage'],
        'scope_remove': ['scope.manage'],
        'findings': ['finding.view'],        # gateway — handlers re-check
        'findings_list': ['finding.view'],
        'findings_create': ['finding.create'],
        'finding_detail': ['finding.view'],  # gateway — handlers re-check
        'finding_retrieve': ['finding.view'],
        'finding_update': ['finding.update'],
        'finding_destroy': ['finding.delete'],
        'upload_image': ['finding.create'],
        'samples_list': ['engagement.view'],
        'upload_sample': ['engagement.update'],
        'delete_sample': ['engagement.update'],
        'evidence_sources_list': ['engagement.view'],
        'evidence_sources_create': ['engagement.update'],
        'evidence_sources_delete': ['engagement.update'],
        'initialize_analysis': ['engagement.update'],
        'execute_finding': ['engagement.update'],
        'send_to_report_finding': ['engagement.update'],
        'stakeholders': ['engagement.view'],
        'stakeholders_list': ['engagement.view'],
        'stakeholders_create': ['engagement.update'],
        'stakeholders_remove': ['engagement.update'],
        'eng_settings': ['engagement_settings.view'],
        'eng_settings_list': ['engagement_settings.view'],
        'eng_settings_upsert': ['engagement.update'],
    }

    def get_queryset(self):
        from authorization.scoping import scope_engagements
        qs = Engagement.objects.filter(
            tenant=self.request.tenant,
        ).select_related('client', 'project').order_by('-created_at')

        qs = scope_engagements(qs, self.request)

        if self.action == 'list':
            qs = qs.annotate(
                findings_critical=Count('findings', filter=Q(findings__severity='critical', findings__is_draft=False)),
                findings_high=Count('findings', filter=Q(findings__severity='high', findings__is_draft=False)),
                findings_medium=Count('findings', filter=Q(findings__severity='medium', findings__is_draft=False)),
                findings_low=Count('findings', filter=Q(findings__severity='low', findings__is_draft=False)),
                findings_info=Count('findings', filter=Q(findings__severity='info', findings__is_draft=False)),
            )

        # Only apply engagement-level filters on the list action.
        # Nested actions (findings, scope, sow) pass their own query
        # params (e.g. ?status=open for finding status) which must not
        # collide with the engagement queryset.
        if self.action == 'list':
            client_id = self.request.query_params.get('client')
            if client_id:
                qs = qs.filter(client_id=client_id)

            status_filter = self.request.query_params.get('status')
            if status_filter:
                qs = qs.filter(status=status_filter)

        return qs

    def perform_create(self, serializer):
        client = serializer.validated_data.get('client')
        engagement = serializer.save(
            tenant=self.request.tenant,
            created_by=self.request.user,
            client_name=client.name if client else '',
        )
        Sow.objects.create(
            engagement=engagement,
            title=f'{engagement.name} - Statement of Work',
        )
        # Seed default engagement setting
        EngagementSetting.objects.create(
            engagement=engagement,
            key='show_contact_info_on_report',
            value='true',
            updated_by=self.request.user,
        )
        logger.info("Engagement created id=%s user=%s tenant=%s", engagement.pk, self.request.user.pk, self.request.tenant.slug)

    def perform_update(self, serializer):
        old_status = serializer.instance.status
        engagement = serializer.save()
        logger.info("Engagement updated id=%s user=%s tenant=%s", engagement.pk, self.request.user.pk, self.request.tenant.slug)

        # Seed analysis placeholder findings when a malware_analysis engagement is activated.
        if (
            engagement.engagement_type == 'malware_analysis'
            and old_status != 'active'
            and engagement.status == 'active'
        ):
            seed_analysis_findings(engagement, self.request.tenant, self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        findings_count = Finding.objects.filter(engagement=instance).count()
        if findings_count > 0:
            return Response(
                {'detail': f'This engagement has {findings_count} finding{"s" if findings_count != 1 else ""} and cannot be deleted. Remove all findings first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)

    def perform_destroy(self, instance):
        eid = instance.pk
        reconciler = AttachmentReconcileService()

        # Clean up attachments linked to each finding
        for finding in Finding.objects.filter(engagement=instance):
            reconciler.cleanup_for_finding(tenant=self.request.tenant, finding=finding)

        # Clean up orphan drafts (uploaded to engagement but never linked to a finding)
        orphan_drafts = Attachment.objects.filter(
            engagement=instance, finding__isnull=True,
        )
        orphan_drafts.delete()  # post_delete signal handles file cleanup

        instance.delete()
        logger.info("Engagement deleted id=%s user=%s tenant=%s", eid, self.request.user.pk, self.request.tenant.slug)

    # ------------------------------------------------------------------
    # SoW nested endpoints: /api/engagements/<pk>/sow/
    # ------------------------------------------------------------------

    @action(detail=True, url_path='sow', url_name='sow', methods=['get', 'post', 'patch', 'delete'])
    def sow(self, request, pk=None):
        handler = getattr(self, f'_sow_{request.method.lower()}', None)
        if handler is None:
            return Response(status=status.HTTP_405_METHOD_NOT_ALLOWED)
        return handler(request, pk)

    def _sow_get(self, request, pk):
        self.action = 'sow_retrieve'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(SowSerializer(sow).data)

    @audited("sow", repr_fmt="SoW: {title}")
    def _sow_post(self, request, pk):
        self.action = 'sow_create'
        self.check_permissions(request)
        engagement = self.get_object()
        if Sow.objects.filter(engagement=engagement).exists():
            return Response(
                {'detail': 'Statement of work already exists for this engagement.'},
                status=status.HTTP_409_CONFLICT,
            )
        serializer = SowSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(engagement=engagement)
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    @audited("sow", repr_fmt="SoW: {title}")
    def _sow_patch(self, request, pk):
        self.action = 'sow_update'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Block approval if scope is empty (type-specific check)
        new_status = request.data.get('status')
        if new_status == 'approved' and sow.status != 'approved':
            has_scope, scope_error = _check_scope_for_approval(
                engagement, sow, request.tenant,
            )
            if not has_scope:
                return Response(
                    {'detail': scope_error},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        request._audit_before = SowSerializer(sow).data
        serializer = SowSerializer(sow, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

    @audited("sow")
    def _sow_delete(self, request, pk):
        self.action = 'sow_destroy'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        request._audit_before = SowSerializer(sow).data
        request._audit_resource_id = sow.pk
        request._audit_repr = f"SoW: {sow.title}"
        sow.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Scope nested endpoints: /api/engagements/<pk>/scope/
    # ------------------------------------------------------------------

    @action(detail=True, url_path='scope', url_name='scope', methods=['get', 'post'])
    def scope(self, request, pk=None):
        if request.method == 'GET':
            return self._scope_list(request, pk)
        return self._scope_add(request, pk)

    def _scope_list(self, request, pk):
        self.action = 'scope_list'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        asset_ids = SowAsset.objects.filter(
            sow=sow, in_scope=True,
        ).values_list('asset_id', flat=True)
        assets = Asset.objects.filter(
            tenant=request.tenant, id__in=asset_ids,
        ).select_related('client').order_by('-created_at')
        return Response(AssetSerializer(assets, many=True).data)

    @audited("scope", repr_fmt="Scope add: {name}")
    def _scope_add(self, request, pk):
        self.action = 'scope_add'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if sow.status == 'approved':
            return Response(
                {'detail': 'Scope cannot be modified while SoW is approved. Change status to Draft first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        asset_id = request.data.get('asset_id')
        if not asset_id:
            return Response(
                {'detail': 'asset_id is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            asset = Asset.objects.get(tenant=request.tenant, id=asset_id)
        except Asset.DoesNotExist:
            return Response(
                {'detail': 'Asset not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if engagement.client_id and asset.client_id != engagement.client_id:
            return Response(
                {'detail': 'Asset does not belong to this engagement\'s organization.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if SowAsset.objects.filter(sow=sow, asset=asset).exists():
            return Response(
                {'detail': 'Asset is already in scope.'},
                status=status.HTTP_409_CONFLICT,
            )
        SowAsset.objects.create(sow=sow, asset=asset, in_scope=True)
        logger.info("Scope add engagement=%s asset=%s user=%s tenant=%s", pk, asset_id, request.user.pk, request.tenant.slug)
        return Response(AssetSerializer(asset).data, status=status.HTTP_201_CREATED)

    @action(
        detail=True,
        url_path=r'scope/(?P<asset_id>[^/.]+)',
        url_name='scope-remove',
        methods=['delete'],
    )
    @audited("scope", id_kwarg="asset_id")
    def scope_remove(self, request, pk=None, asset_id=None):
        self.action = 'scope_remove'
        self.check_permissions(request)
        engagement = self.get_object()
        try:
            sow = engagement.sow
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Statement of work not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        if sow.status == 'approved':
            return Response(
                {'detail': 'Scope cannot be modified while SoW is approved. Change status to Draft first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        asset_name = Asset.objects.filter(tenant=request.tenant, id=asset_id).values_list('name', flat=True).first() or asset_id
        SowAsset.objects.filter(sow=sow, asset_id=asset_id).delete()
        request._audit_repr = f"Scope remove: {asset_name} from engagement {engagement.name}"
        logger.info("Scope remove engagement=%s asset=%s user=%s tenant=%s", pk, asset_id, request.user.pk, request.tenant.slug)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Findings nested endpoints: /api/engagements/<pk>/findings/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['get', 'post'], url_path='findings')
    def findings(self, request, pk=None):
        if request.method == 'GET':
            return self._findings_list(request, pk)
        return self._findings_create(request, pk)

    def _findings_list(self, request, pk):
        self.action = 'findings_list'
        self.check_permissions(request)
        engagement = self.get_object()
        qs = Finding.objects.filter(
            tenant=request.tenant, engagement=engagement,
        ).select_related('asset').order_by('-updated_at', '-created_at')

        # By default exclude drafts; include with ?include_drafts=true
        include_drafts = request.query_params.get('include_drafts', '').lower() == 'true'
        if not include_drafts:
            qs = qs.filter(is_draft=False)

        asset_filter = request.query_params.get('asset_id')
        if asset_filter:
            qs = qs.filter(asset_id=asset_filter)
        sample_filter = request.query_params.get('sample_id')
        if sample_filter:
            qs = qs.filter(sample_id=sample_filter)
        evidence_filter = request.query_params.get('evidence_source_id')
        if evidence_filter:
            qs = qs.filter(evidence_source_id=evidence_filter)
        severity_filter = request.query_params.get('severity')
        if severity_filter:
            qs = qs.filter(severity=severity_filter)
        status_filter = request.query_params.get('status')
        if status_filter:
            qs = qs.filter(status=status_filter)

        serializer = FindingSerializer(qs, many=True)
        return Response(serializer.data)

    @audited("finding", repr_fmt="Finding: {title}")
    def _findings_create(self, request, pk):
        self.action = 'findings_create'
        self.check_permissions(request)
        engagement = self.get_object()
        tenant = request.tenant

        # Block finding creation unless SoW is approved
        try:
            sow = engagement.sow
            if sow.status != 'approved':
                return Response(
                    {'detail': 'Cannot create findings until the Statement of Work is approved.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        except Sow.DoesNotExist:
            return Response(
                {'detail': 'Cannot create findings without a Statement of Work.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = FindingSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        # Subscription limit: images per finding
        desc_md = serializer.validated_data.get('description_md', '')
        rec_md = serializer.validated_data.get('recommendation_md', '')
        img_result = check_image_limit(tenant, desc_md, rec_md)
        if not img_result.allowed:
            raise SubscriptionLimitExceeded(detail=img_result.message)

        is_draft = serializer.validated_data.get('is_draft', False)
        asset = serializer.validated_data.get('asset')
        if asset and not is_draft:
            if engagement.client_id and asset.client_id != engagement.client_id:
                return Response(
                    {'detail': 'Asset does not belong to this engagement\'s organization.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                sow = engagement.sow
                if not SowAsset.objects.filter(sow=sow, asset=asset, in_scope=True).exists():
                    return Response(
                        {'detail': 'Asset is not in scope for this engagement.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Sow.DoesNotExist:
                pass

        finding = serializer.save(
            tenant=tenant,
            engagement=engagement,
            created_by=request.user,
        )

        description_md = finding.description_md or ''
        recommendation_md = finding.recommendation_md or ''
        if description_md or recommendation_md:
            AttachmentReconcileService().reconcile_for_finding(
                tenant=tenant,
                engagement=engagement,
                finding=finding,
                description_md=description_md,
                recommendation_md=recommendation_md,
            )

        logger.info("Finding created id=%s engagement=%s user=%s tenant=%s", finding.pk, pk, request.user.pk, tenant.slug)
        return Response(
            FindingSerializer(finding).data,
            status=status.HTTP_201_CREATED,
        )

    @action(
        detail=True,
        methods=['get', 'patch', 'delete'],
        url_path=r'findings/(?P<finding_id>[^/.]+)',
    )
    def finding_detail(self, request, pk=None, finding_id=None):
        if request.method == 'GET':
            return self._finding_retrieve(request, pk, finding_id)
        if request.method == 'PATCH':
            return self._finding_update(request, pk, finding_id)
        return self._finding_destroy(request, pk, finding_id)

    def _get_finding(self, request, pk, finding_id):
        engagement = self.get_object()
        try:
            return Finding.objects.select_related('asset').get(
                tenant=request.tenant,
                engagement=engagement,
                id=finding_id,
            )
        except Finding.DoesNotExist:
            logger.debug("Finding not found: id=%s engagement=%s", finding_id, pk)
            return None

    def _finding_retrieve(self, request, pk, finding_id):
        self.action = 'finding_retrieve'
        self.check_permissions(request)
        obj = self._get_finding(request, pk, finding_id)
        if not obj:
            return Response(
                {'detail': 'Finding not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        log_audit(
            request=request, action=AuditAction.READ,
            resource_type="finding", resource_id=obj.pk,
            resource_repr=f"Finding: {obj.title}",
        )
        return Response(FindingSerializer(obj).data)

    @audited("finding", repr_fmt="Finding: {title}")
    def _finding_update(self, request, pk, finding_id):
        self.action = 'finding_update'
        self.check_permissions(request)
        obj = self._get_finding(request, pk, finding_id)
        if not obj:
            return Response(
                {'detail': 'Finding not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        request._audit_before = FindingSerializer(obj).data
        engagement = self.get_object()
        tenant = request.tenant

        serializer = FindingSerializer(
            obj, data=request.data, partial=True, context={'request': request},
        )
        serializer.is_valid(raise_exception=True)

        # Subscription limit: images per finding (use updated markdown or existing)
        desc_md = serializer.validated_data.get('description_md', obj.description_md or '')
        rec_md = serializer.validated_data.get('recommendation_md', obj.recommendation_md or '')
        if 'description_md' in request.data or 'recommendation_md' in request.data:
            img_result = check_image_limit(tenant, desc_md, rec_md)
            if not img_result.allowed:
                raise SubscriptionLimitExceeded(detail=img_result.message)

        # Determine if finding will remain a draft after this update
        will_be_draft = serializer.validated_data.get('is_draft', obj.is_draft)

        asset = serializer.validated_data.get('asset')
        if asset and not will_be_draft:
            if engagement.client_id and asset.client_id != engagement.client_id:
                return Response(
                    {'detail': 'Asset does not belong to this engagement\'s organization.'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            try:
                sow = engagement.sow
                if not SowAsset.objects.filter(sow=sow, asset=asset, in_scope=True).exists():
                    return Response(
                        {'detail': 'Asset is not in scope for this engagement.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            except Sow.DoesNotExist:
                pass

        finding = serializer.save()

        if 'description_md' in request.data or 'recommendation_md' in request.data:
            AttachmentReconcileService().reconcile_for_finding(
                tenant=tenant,
                engagement=engagement,
                finding=finding,
                description_md=finding.description_md or '',
                recommendation_md=finding.recommendation_md or '',
            )

        logger.info("Finding updated id=%s engagement=%s user=%s tenant=%s", finding.pk, pk, request.user.pk, tenant.slug)
        return Response(FindingSerializer(finding).data)

    @audited("finding")
    def _finding_destroy(self, request, pk, finding_id):
        self.action = 'finding_destroy'
        self.check_permissions(request)
        obj = self._get_finding(request, pk, finding_id)
        if not obj:
            return Response(
                {'detail': 'Finding not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )
        request._audit_before = FindingSerializer(obj).data
        request._audit_resource_id = finding_id
        request._audit_repr = f"Finding: {obj.title}"
        AttachmentReconcileService().cleanup_for_finding(tenant=request.tenant, finding=obj)
        obj.delete()
        logger.info("Finding deleted id=%s engagement=%s user=%s tenant=%s", finding_id, pk, request.user.pk, request.tenant.slug)
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Image upload: POST /api/engagements/<pk>/attachments/images/
    # ------------------------------------------------------------------

    @action(
        detail=True, methods=['post'],
        url_path='attachments-images',
        parser_classes=[MultiPartParser],
    )
    def upload_image(self, request, pk=None):
        self.action = 'upload_image'
        self.check_permissions(request)
        engagement = self.get_object()
        tenant = request.tenant
        tenant_id = str(tenant.id)
        file_obj = request.FILES.get('file')

        if not file_obj:
            return Response(
                {'error': "Missing multipart file field 'file'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        service = AttachmentUploadService()
        att = service.upload_image(
            tenant=tenant,
            tenant_id=tenant_id,
            engagement=engagement,
            user=request.user,
            file_obj=file_obj,
        )

        log_audit(
            request=request, action=AuditAction.CREATE,
            resource_type="attachment", resource_id=att.id,
            resource_repr=f"Image: {att.filename}",
        )
        logger.info("Image uploaded attachment=%s engagement=%s user=%s tenant=%s", att.id, pk, request.user.pk, tenant_id)
        return Response(
            {
                'token': str(att.id),
                'url': sign_attachment_url(att.id, tenant_id=str(request.tenant.pk)),
            },
            status=status.HTTP_201_CREATED,
        )

    # ------------------------------------------------------------------
    # Malware samples: /api/engagements/<pk>/samples/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['get'], url_path='samples')
    def samples_list(self, request, pk=None):
        self.action = 'samples_list'
        self.check_permissions(request)
        engagement = self.get_object()
        samples = MalwareSample.objects.filter(
            tenant=request.tenant, engagement=engagement,
        ).order_by('-created_at')
        data = MalwareSampleSerializer(samples, many=True).data
        # Add signed download URL to each sample
        tid = str(request.tenant.pk)
        for item in data:
            item['download_url'] = sign_sample_url(item['id'], tenant_id=tid)
        return Response(data)

    @action(
        detail=True, methods=['post'],
        url_path='samples/upload',
        parser_classes=[MultiPartParser],
    )
    def upload_sample(self, request, pk=None):
        self.action = 'upload_sample'
        self.check_permissions(request)
        engagement = self.get_object()
        tenant = request.tenant
        tenant_id = str(tenant.id)
        file_obj = request.FILES.get('file')
        notes = request.data.get('notes', '')

        if not file_obj:
            return Response(
                {'error': "Missing multipart file field 'file'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        service = MalwareSampleUploadService()
        sample = service.upload_sample(
            tenant=tenant,
            tenant_id=tenant_id,
            engagement=engagement,
            user=request.user,
            file_obj=file_obj,
            notes=notes,
        )

        log_audit(
            request=request, action=AuditAction.CREATE,
            resource_type="malware_sample", resource_id=sample.id,
            resource_repr=f"Sample: {sample.original_filename}",
        )
        logger.info(
            "Sample uploaded id=%s engagement=%s user=%s tenant=%s",
            sample.id, pk, request.user.pk, tenant_id,
        )

        data = MalwareSampleSerializer(sample).data
        data['download_url'] = sign_sample_url(sample.id, tenant_id=tenant_id)
        return Response(data, status=status.HTTP_201_CREATED)

    @action(
        detail=True, methods=['delete'],
        url_path=r'samples/(?P<sample_id>[0-9a-f-]+)',
    )
    def delete_sample(self, request, pk=None, sample_id=None):
        self.action = 'delete_sample'
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            sample = MalwareSample.objects.get(
                pk=sample_id, tenant=request.tenant, engagement=engagement,
            )
        except MalwareSample.DoesNotExist:
            logger.warning("Sample not found: id=%s engagement=%s", sample_id, pk)
            return Response(
                {'detail': 'Sample not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        # Delete file from storage
        if sample.storage_uri:
            try:
                get_attachment_storage().delete(sample.storage_uri)
            except Exception:
                logger.warning("Failed to delete sample file uri=%s", sample.storage_uri)

        log_audit(
            request=request, action=AuditAction.DELETE,
            resource_type="malware_sample", resource_id=sample.id,
            resource_repr=f"Sample: {sample.original_filename}",
        )
        sample.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Evidence Sources: /api/engagements/<pk>/evidence-sources/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['get', 'post'], url_path='evidence-sources')
    def evidence_sources(self, request, pk=None):
        if request.method == 'GET':
            return self._evidence_sources_list(request, pk)
        return self._evidence_sources_create(request, pk)

    def _evidence_sources_list(self, request, pk):
        self.action = 'evidence_sources_list'
        self.check_permissions(request)
        engagement = self.get_object()
        sources = EvidenceSource.objects.filter(
            tenant=request.tenant, engagement=engagement,
        ).order_by('-created_at')
        data = EvidenceSourceSerializer(sources, many=True).data
        return Response(data)

    def _evidence_sources_create(self, request, pk):
        self.action = 'evidence_sources_create'
        self.check_permissions(request)
        engagement = self.get_object()

        serializer = EvidenceSourceSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        source = serializer.save(
            tenant=request.tenant,
            engagement=engagement,
            created_by=request.user,
        )

        log_audit(
            request=request, action=AuditAction.CREATE,
            resource_type="evidence_source", resource_id=source.id,
            resource_repr=f"Evidence: {source.name}",
        )
        logger.info(
            "Evidence source created id=%s engagement=%s user=%s",
            source.id, pk, request.user.pk,
        )
        return Response(
            EvidenceSourceSerializer(source).data,
            status=status.HTTP_201_CREATED,
        )

    @action(
        detail=True, methods=['delete'],
        url_path=r'evidence-sources/(?P<evidence_id>[0-9a-f-]+)',
    )
    def evidence_sources_delete(self, request, pk=None, evidence_id=None):
        self.action = 'evidence_sources_delete'
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            source = EvidenceSource.objects.get(
                pk=evidence_id, tenant=request.tenant, engagement=engagement,
            )
        except EvidenceSource.DoesNotExist:
            return Response(
                {'detail': 'Evidence source not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        log_audit(
            request=request, action=AuditAction.DELETE,
            resource_type="evidence_source", resource_id=source.id,
            resource_repr=f"Evidence: {source.name}",
        )
        source.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Initialize Analysis: POST /api/engagements/<pk>/initialize-analysis/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['post'], url_path='initialize-analysis')
    def initialize_analysis(self, request, pk=None):
        self.action = 'initialize_analysis'
        self.check_permissions(request)
        engagement = self.get_object()

        if engagement.engagement_type != 'malware_analysis':
            return Response(
                {'detail': 'Only malware_analysis engagements support analysis checks.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        created = seed_analysis_findings(engagement, request.tenant, request.user)
        return Response({'created': created}, status=status.HTTP_200_OK)

    # ------------------------------------------------------------------
    # Execute Finding: POST /api/engagements/<pk>/findings/<fid>/execute/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['post'], url_path=r'findings/(?P<finding_id>[^/.]+)/execute')
    def execute_finding(self, request, pk=None, finding_id=None):
        self.action = 'execute_finding'
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            finding = Finding.objects.get(
                id=finding_id,
                engagement=engagement,
                tenant=request.tenant,
            )
        except Finding.DoesNotExist:
            logger.warning("Finding not found for execute: id=%s engagement=%s", finding_id, pk)
            return Response({'detail': 'Finding not found.'}, status=status.HTTP_404_NOT_FOUND)

        if not finding.analysis_check_key:
            return Response(
                {'detail': 'This finding is not an analysis check.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if finding.execution_status == 'running':
            return Response(
                {'detail': 'Execution already in progress.'},
                status=status.HTTP_409_CONFLICT,
            )

        from findings.analysis_executors import EXECUTORS
        executor = EXECUTORS.get(finding.analysis_check_key)
        if not executor:
            return Response(
                {'detail': f'No executor for check: {finding.analysis_check_key}.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Need a sample to execute against
        sample = finding.sample
        if not sample:
            return Response(
                {'detail': 'No sample linked to this finding. Assign a sample first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Mark running and launch background thread
        Finding.objects.filter(id=finding.id).update(execution_status='running')

        import threading
        from evidence.storage.factory import get_attachment_storage

        def _run_executor():
            from django.db import connection
            try:
                storage = get_attachment_storage()
                description_md = executor(storage, sample, finding)
                Finding.objects.filter(id=finding.id).update(
                    execution_status='completed',
                    description_md=description_md,
                )
            except Exception:
                logger.exception('Executor failed: check=%s finding=%s', finding.analysis_check_key, finding.id)
                Finding.objects.filter(id=finding.id).update(execution_status='failed')
            finally:
                connection.close()

        threading.Thread(target=_run_executor, daemon=True).start()

        log_audit(
            request=request, action=AuditAction.CREATE,
            resource_type='analysis_execution', resource_id=str(finding.id),
            resource_repr=f'Execute {finding.analysis_check_key} on finding {finding.id}',
        )

        return Response({'status': 'started'}, status=status.HTTP_202_ACCEPTED)

    # ------------------------------------------------------------------
    # Send to Report: POST /api/engagements/<pk>/findings/<fid>/send-to-report/
    # ------------------------------------------------------------------

    @action(detail=True, methods=['post'], url_path=r'findings/(?P<finding_id>[^/.]+)/send-to-report')
    def send_to_report_finding(self, request, pk=None, finding_id=None):
        self.action = 'send_to_report_finding'
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            source = Finding.objects.get(
                id=finding_id,
                engagement=engagement,
                tenant=request.tenant,
            )
        except Finding.DoesNotExist:
            return Response({'detail': 'Finding not found.'}, status=status.HTTP_404_NOT_FOUND)

        if source.analysis_check_key == 'report':
            return Response(
                {'detail': 'Cannot send the Report finding to itself.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not source.sample_id:
            return Response(
                {'detail': 'Source finding has no associated sample.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if source.analysis_check_key and source.execution_status != 'completed':
            return Response(
                {'detail': 'Source finding has not been executed yet.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            report = Finding.objects.get(
                engagement=engagement,
                tenant=request.tenant,
                sample_id=source.sample_id,
                analysis_check_key='report',
            )
        except Finding.DoesNotExist:
            return Response(
                {'detail': 'No Report finding exists for this sample. Run Initialize Analysis first.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.utils import timezone
        timestamp = timezone.now().strftime('%Y-%m-%d %H:%M UTC')
        append_block = (
            f'\n\n---\n\n'
            f'### From: {source.title}  ·  {timestamp}\n\n'
            f'{source.description_md}\n'
        )
        report.description_md = (report.description_md or '') + append_block
        report.save(update_fields=['description_md', 'updated_at'])

        log_audit(
            request=request, action=AuditAction.UPDATE,
            resource_type='finding', resource_id=str(report.id),
            resource_repr=f'Send to Report: {source.title} -> {report.id}',
        )

        return Response(
            {'report_id': str(report.id), 'updated_at': report.updated_at.isoformat()},
            status=status.HTTP_200_OK,
        )

    # ------------------------------------------------------------------
    # Stakeholders: /api/engagements/<pk>/stakeholders/
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_stakeholder(sh):
        user = sh.member.user
        return {
            'id': str(sh.pk),
            'member_id': str(sh.member.pk),
            'role': sh.role,
            'user': {
                'id': str(user.pk),
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'phone': user.phone,
                'timezone': user.timezone,
                'avatar_url': get_avatar_url(user),
            },
            'created_at': sh.created_at.isoformat(),
            'updated_at': sh.updated_at.isoformat(),
        }

    @action(detail=True, url_path='stakeholders', url_name='stakeholders', methods=['get', 'post'])
    def stakeholders(self, request, pk=None):
        if request.method == 'GET':
            return self._stakeholders_list(request, pk)
        return self._stakeholders_create(request, pk)

    def _stakeholders_list(self, request, pk):
        self.action = 'stakeholders_list'
        self.check_permissions(request)
        engagement = self.get_object()
        qs = EngagementStakeholder.objects.filter(
            engagement=engagement,
        ).select_related('member__user').order_by('created_at')
        return Response([self._serialize_stakeholder(s) for s in qs])

    def _stakeholders_create(self, request, pk):
        self.action = 'stakeholders_create'
        self.check_permissions(request)
        engagement = self.get_object()

        member_id = request.data.get('member_id')
        role = request.data.get('role', StakeholderRole.ACCOUNT_MANAGER)

        if not member_id:
            return Response(
                {'detail': "Field 'member_id' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate role
        valid_roles = [c[0] for c in StakeholderRole.choices]
        if role not in valid_roles:
            return Response(
                {'detail': f"Invalid role. Must be one of: {', '.join(valid_roles)}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Validate member belongs to same tenant
        try:
            member = TenantMember.objects.select_related('user').get(
                pk=member_id,
                tenant=request.tenant,
                is_active=True,
            )
        except (TenantMember.DoesNotExist, ValueError):
            logger.warning("Stakeholder create failed: member not found id=%s tenant=%s", member_id, request.tenant.slug)
            return Response(
                {'detail': 'Member not found or not active in this tenant.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if EngagementStakeholder.objects.filter(engagement=engagement, member=member).exists():
            return Response(
                {'detail': 'This member is already assigned to this engagement.'},
                status=status.HTTP_409_CONFLICT,
            )

        sh = EngagementStakeholder.objects.create(
            engagement=engagement,
            member=member,
            role=role,
            created_by=request.user,
        )

        log_audit(
            request=request, action=AuditAction.CREATE,
            resource_type='engagement_stakeholder', resource_id=str(sh.pk),
            resource_repr=f'Stakeholder: {member.user.email} ({sh.get_role_display()})',
            after={'member_id': str(member.pk), 'role': role, 'email': member.user.email},
        )
        logger.info("Stakeholder created id=%s engagement=%s user=%s tenant=%s", sh.pk, pk, request.user.pk, request.tenant.slug)

        sh = EngagementStakeholder.objects.select_related('member__user').get(pk=sh.pk)
        return Response(self._serialize_stakeholder(sh), status=status.HTTP_201_CREATED)

    @action(
        detail=True,
        url_path=r'stakeholders/(?P<stakeholder_id>[^/.]+)',
        url_name='stakeholder-detail',
        methods=['patch', 'delete'],
    )
    def stakeholder_detail(self, request, pk=None, stakeholder_id=None):
        if request.method == 'PATCH':
            return self._stakeholder_update(request, pk, stakeholder_id)
        return self._stakeholder_remove(request, pk, stakeholder_id)

    def _stakeholder_update(self, request, pk, stakeholder_id):
        self.action = 'stakeholders_create'  # reuse engagement.update permission
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            sh = EngagementStakeholder.objects.select_related('member__user').get(
                pk=stakeholder_id, engagement=engagement,
            )
        except (EngagementStakeholder.DoesNotExist, ValueError):
            return Response({'detail': 'Stakeholder not found.'}, status=status.HTTP_404_NOT_FOUND)

        role = request.data.get('role')
        if not role:
            return Response({'detail': "Field 'role' is required."}, status=status.HTTP_400_BAD_REQUEST)

        valid_roles = [c[0] for c in StakeholderRole.choices]
        if role not in valid_roles:
            return Response(
                {'detail': f"Invalid role. Must be one of: {', '.join(valid_roles)}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        before_role = sh.role
        sh.role = role
        sh.save(update_fields=['role', 'updated_at'])

        log_audit(
            request=request, action=AuditAction.UPDATE,
            resource_type='engagement_stakeholder', resource_id=str(sh.pk),
            resource_repr=f'Stakeholder: {sh.member.user.email}',
            before={'role': before_role}, after={'role': role},
        )
        logger.info("Stakeholder updated id=%s engagement=%s user=%s tenant=%s", sh.pk, pk, request.user.pk, request.tenant.slug)

        return Response(self._serialize_stakeholder(sh))

    def _stakeholder_remove(self, request, pk, stakeholder_id):
        self.action = 'stakeholders_remove'
        self.check_permissions(request)
        engagement = self.get_object()

        try:
            sh = EngagementStakeholder.objects.select_related('member__user').get(
                pk=stakeholder_id, engagement=engagement,
            )
        except (EngagementStakeholder.DoesNotExist, ValueError):
            return Response({'detail': 'Stakeholder not found.'}, status=status.HTTP_404_NOT_FOUND)

        log_audit(
            request=request, action=AuditAction.DELETE,
            resource_type='engagement_stakeholder', resource_id=str(sh.pk),
            resource_repr=f'Stakeholder: {sh.member.user.email}',
            before={'member_id': str(sh.member.pk), 'role': sh.role, 'email': sh.member.user.email},
        )
        logger.info("Stakeholder deleted id=%s engagement=%s user=%s tenant=%s", sh.pk, pk, request.user.pk, request.tenant.slug)
        sh.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    # ------------------------------------------------------------------
    # Engagement Settings: /api/engagements/<pk>/settings/
    # ------------------------------------------------------------------

    # Engagement-level setting definitions (key → default)
    ENGAGEMENT_SETTING_DEFS = {
        'show_contact_info_on_report': {
            'label': 'Include Team Contact Info in Report',
            'description': 'Display team member and stakeholder contact details in generated reports.',
            'setting_type': 'boolean',
            'default': 'true',
            'group': 'Report',
            'order': 1,
        },
        'default_severity_threshold': {
            'label': 'Default Severity Threshold',
            'description': 'Minimum severity for findings to appear in reports.',
            'setting_type': 'choice',
            'choices': ('info', 'low', 'medium', 'high', 'critical'),
            'default': 'low',
            'group': 'Report',
            'order': 2,
        },
        'report_footer_text': {
            'label': 'Report Footer Text',
            'description': 'Custom text displayed in the footer of generated reports.',
            'setting_type': 'text',
            'default': '',
            'group': 'Report',
            'order': 3,
        },
    }

    @action(detail=True, url_path='settings', url_name='eng-settings', methods=['get', 'put'])
    def eng_settings(self, request, pk=None):
        if request.method == 'GET':
            return self._eng_settings_list(request, pk)
        return self._eng_settings_upsert(request, pk)

    def _eng_settings_list(self, request, pk):
        self.action = 'eng_settings_list'
        self.check_permissions(request)
        engagement = self.get_object()

        stored = {
            s.key: s
            for s in EngagementSetting.objects.filter(engagement=engagement)
        }
        result = []
        for key, defn in sorted(self.ENGAGEMENT_SETTING_DEFS.items(), key=lambda kv: kv[1]['order']):
            obj = stored.get(key)
            item = {
                'key': key,
                'label': defn['label'],
                'description': defn['description'],
                'setting_type': defn['setting_type'],
                'default': defn['default'],
                'group': defn['group'],
                'order': defn['order'],
                'value': obj.value if obj else defn['default'],
                'has_value': obj is not None,
                'updated_at': obj.updated_at.isoformat() if obj else None,
                'updated_by': obj.updated_by.email if obj and obj.updated_by else None,
            }
            if 'choices' in defn:
                item['choices'] = defn['choices']
            result.append(item)
        return Response(result)

    def _eng_settings_upsert(self, request, pk):
        self.action = 'eng_settings_upsert'
        self.check_permissions(request)
        engagement = self.get_object()

        key = request.data.get('key')
        value = request.data.get('value')

        if not key or key not in self.ENGAGEMENT_SETTING_DEFS:
            return Response(
                {'detail': f'Unknown setting key: {key}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if value is None:
            return Response(
                {'detail': "Field 'value' is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        value = str(value)
        defn = self.ENGAGEMENT_SETTING_DEFS[key]

        if defn['setting_type'] == 'boolean' and value not in ('true', 'false'):
            return Response(
                {'detail': "Boolean setting must be 'true' or 'false'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if defn['setting_type'] == 'choice' and value not in defn.get('choices', ()):
            return Response(
                {'detail': f"Invalid choice. Must be one of: {', '.join(defn['choices'])}."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        obj, created = EngagementSetting.objects.get_or_create(
            engagement=engagement, key=key,
            defaults={'value': value, 'updated_by': request.user},
        )

        if created:
            log_audit(
                request=request, action=AuditAction.CREATE,
                resource_type='engagement_setting', resource_id=key,
                resource_repr=f"Engagement Setting: {defn['label']}",
                after={'key': key, 'value': value},
            )
        else:
            before = {'key': key, 'value': obj.value}
            obj.value = value
            obj.updated_by = request.user
            obj.save(update_fields=['value', 'updated_by', 'updated_at'])
            log_audit(
                request=request, action=AuditAction.UPDATE,
                resource_type='engagement_setting', resource_id=key,
                resource_repr=f"Engagement Setting: {defn['label']}",
                before=before, after={'key': key, 'value': value},
            )

        logger.info(
            "Engagement setting %s key=%s engagement=%s user=%s tenant=%s",
            'created' if created else 'updated', key, pk, request.user.pk, request.tenant.slug,
        )

        resp = {
            'key': key,
            'label': defn['label'],
            'description': defn['description'],
            'setting_type': defn['setting_type'],
            'default': defn['default'],
            'group': defn['group'],
            'order': defn['order'],
            'value': value,
            'has_value': True,
            'updated_at': obj.updated_at.isoformat(),
            'updated_by': request.user.email,
        }
        if 'choices' in defn:
            resp['choices'] = defn['choices']
        return Response(resp)
