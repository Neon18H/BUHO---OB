import hashlib
import json
import os
from datetime import timedelta
from urllib import error, request
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import HashReputationCache, SecurityFinding


def build_fingerprint(agent_id, category, title, details):
    raw = f"{agent_id}:{category}:{title}:{details.get('rule', '')}:{details.get('sha256', '')}:{details.get('path', '')}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


def upsert_finding(*, organization, agent, category, severity, title, details=None, evidence=None):
    details = details or {}
    evidence = evidence or {}
    fingerprint = build_fingerprint(agent.id, category, title, details)
    now = timezone.now()
    finding, created = SecurityFinding.objects.get_or_create(
        organization=organization,
        agent=agent,
        fingerprint=fingerprint,
        defaults={
            'category': category,
            'severity': severity,
            'title': title[:255],
            'details_json': details,
            'evidence_json': evidence,
            'first_seen': now,
            'last_seen': now,
        },
    )
    if not created:
        finding.last_seen = now
        finding.severity = severity
        finding.details_json = details
        finding.evidence_json = evidence
        finding.save(update_fields=['last_seen', 'severity', 'details_json', 'evidence_json'])
    return finding


def vt_enabled():
    return bool(os.getenv('VT_API_KEY') or getattr(settings, 'VT_API_KEY', ''))


def vt_lookup_hash(sha256):
    now = timezone.now()
    cached = HashReputationCache.objects.filter(sha256=sha256).first()
    if cached and cached.expires_at > now:
        return cached.vt_json, True

    api_key = os.getenv('VT_API_KEY') or getattr(settings, 'VT_API_KEY', '')
    if not api_key:
        return None, False

    req = request.Request(f'https://www.virustotal.com/api/v3/files/{sha256}', headers={'x-apikey': api_key})
    try:
        with request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode('utf-8'))
    except error.HTTPError as exc:
        if exc.code == 429:
            return None, False
        body = {}
        data = {'error': exc.code}
    else:
        stats = (body.get('data') or {}).get('attributes', {}).get('last_analysis_stats', {})
        data = {
            'sha256': sha256,
            'malicious': int(stats.get('malicious', 0) or 0),
            'suspicious': int(stats.get('suspicious', 0) or 0),
            'harmless': int(stats.get('harmless', 0) or 0),
            'undetected': int(stats.get('undetected', 0) or 0),
            'reputation': (body.get('data') or {}).get('attributes', {}).get('reputation'),
            'last_analysis_date': (body.get('data') or {}).get('attributes', {}).get('last_analysis_date'),
        }
    expires = now + timedelta(hours=24)
    HashReputationCache.objects.update_or_create(
        sha256=sha256,
        defaults={'vt_json': data, 'last_checked': now, 'expires_at': expires},
    )
    return data, False


def ingest_findings(*, organization, agent, findings):
    stored = 0
    for item in findings:
        upsert_finding(
            organization=organization,
            agent=agent,
            category=item.get('category', SecurityFinding.Category.SUSPICIOUS_FILE),
            severity=item.get('severity', SecurityFinding.Severity.MED),
            title=item.get('title', 'Security Finding'),
            details=item.get('details') or {},
            evidence=item.get('evidence') or {},
        )
        stored += 1
    return stored


def ingest_artifacts(*, organization, agent, artifacts, threshold=3):
    checked = 0
    hits = 0
    for artifact in artifacts:
        sha256 = (artifact.get('sha256') or '').lower().strip()
        if len(sha256) != 64:
            continue
        checked += 1
        vt_data, _ = vt_lookup_hash(sha256)
        if not vt_data:
            continue
        if int(vt_data.get('malicious', 0)) >= threshold:
            hits += 1
            upsert_finding(
                organization=organization,
                agent=agent,
                category=SecurityFinding.Category.VT_HASH_MATCH,
                severity=SecurityFinding.Severity.HIGH if vt_data.get('malicious', 0) < 10 else SecurityFinding.Severity.CRITICAL,
                title='VirusTotal flagged hash as malicious',
                details={'sha256': sha256, 'path': artifact.get('path', ''), 'vt': vt_data},
                evidence={'artifact': artifact},
            )
    return checked, hits
