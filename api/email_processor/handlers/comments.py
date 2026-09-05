"""Handlers for comments area events (mention + reply notifications)."""

import os

from email_processor.handlers.base import BaseEventHandler

APP_URL = os.environ.get('APP_URL', 'https://bytescop.com')

# Map target_type to URL path segment for deep links
TARGET_URL_MAP = {
    'engagement': 'engagements',
    'finding': 'findings',
}


def _build_comment_url(payload: dict) -> str:
    """Build a deep link to the comment on the target page."""
    target_type = payload.get('target_type', '')
    target_id = payload.get('target_id', '')
    comment_id = payload.get('comment_id', '')
    path_segment = TARGET_URL_MAP.get(target_type, target_type + 's')
    return f'{APP_URL}/{path_segment}/{target_id}/view#comment-{comment_id}'


class CommentMentionHandler(BaseEventHandler):
    """Handles comments/mention — notifies a user they were @mentioned."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        author = payload.get('mentioned_by_name', 'Someone')
        return f'{author} mentioned you in a comment — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'mentioned_by_name': payload.get('mentioned_by_name', 'Someone'),
            'target_label': payload.get('target_label', ''),
            'comment_preview': payload.get('comment_preview', ''),
            'comment_url': _build_comment_url(payload),
        }


class CommentReplyHandler(BaseEventHandler):
    """Handles comments/reply — notifies thread participants of a new reply."""

    def get_recipient(self, payload: dict) -> str:
        return payload['email']

    def get_subject(self, payload: dict) -> str:
        author = payload.get('reply_by_name', 'Someone')
        return f'{author} replied to a comment — BytesCop-Reporter'

    def get_template_data(self, payload: dict) -> dict:
        return {
            'name': payload.get('name', ''),
            'tenant_name': payload.get('tenant_name', ''),
            'reply_by_name': payload.get('reply_by_name', 'Someone'),
            'target_label': payload.get('target_label', ''),
            'comment_preview': payload.get('comment_preview', ''),
            'comment_url': _build_comment_url(payload),
        }
