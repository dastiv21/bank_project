import hmac
import hashlib
import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings


class GitHubWebhookView(APIView):
    """
    Webhook endpoint to handle GitHub push events for file updates and
    pull_request events for logging PR metadata.
    """

    def post(self, request, *args, **kwargs):
        payload = json.loads(
            request.body)  # Use json.loads to parse the payload
        audit_logs = []

        # Secret token for validation
        secret_token = settings.GITHUB_WEBHOOK_SECRET.encode()

        # Validate secret token
        signature = request.headers.get('X-Hub-Signature')
        if not signature or not self.is_valid_signature(request.body,
                                                        signature,
                                                        secret_token):
            return Response({"error": "Invalid secret token"},
                            status=status.HTTP_403_FORBIDDEN)

        # Parse the JSON payload
        event_type = request.headers.get('X-GitHub-Event')

        if event_type == 'push':
            commits = payload.get("commits", [])

            for commit in commits:
                for file_name in commit.get("modified", []):
                    # Use the commit timestamp as the update time
                    audit_logs.append({
                        "type": "commit",
                        "file_name": file_name,
                        "update_time": commit.get("timestamp"),
                        "author": commit.get("author", {}).get("name", ""),
                        "message": commit.get("message", ""),
                    })

            # save audit log for file updates
            audit_response = save_audit_log(audit_logs)
            return Response(audit_response, status=status.HTTP_200_OK)

        elif event_type == 'pull_request':
            pr_info = payload.get("pull_request", {})

            # Log PR metadata
            audit_logs.append({
                "type": "pull_request",
                "author": pr_info.get("user", {}).get("login", ""),
                "state": pr_info.get("state", ""),
                "branch": pr_info.get("base", {}).get("ref", ""),
            })

            # save audit log for PRs
            audit_response = save_audit_log(audit_logs)
            return Response(audit_response, status=status.HTTP_200_OK)

        # If the event is not supported, return 400
        return Response({"error": "Unsupported event type"},
                        status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def is_valid_signature(payload, signature, secret):
        # Compute HMAC hex digest
        hash_hex = hmac.new(secret, payload, hashlib.sha1).hexdigest()
        # Compare with the GitHub signature
        return hmac.compare_digest(f'sha1={hash_hex}', signature)


def save_audit_log(audit_logs):
    # Logic to save the audit log to your storage or database
    # For example, you might save to a file or a database table
    return {"message": "Audit logs saved successfully",
            "audit_logs": audit_logs}
