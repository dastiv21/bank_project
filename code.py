import hmac
import hashlib
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.conf import settings

class GitHubWebhookView(APIView):
    """
    Webhook endpoint to handle GitHub push and pull_request events.
    """

    def post(self, request, *args, **kwargs):
        payload = request.body  # Use request.body to get raw payload
        event_type = request.headers.get('X-GitHub-Event')

        # Secret token for validation
        secret_token = settings.GITHUB_WEBHOOK_SECRET.encode()

        # Validate secret token
        signature = request.headers.get('X-Hub-Signature')
        if not signature or not self.is_valid_signature(payload, signature, secret_token):
            return Response({"error": "Invalid secret token"}, status=status.HTTP_403_FORBIDDEN)

        # Parse the JSON payload
        payload_data = request.json

        if event_type == 'push':
            # Process push events as before
            # ...
        pass

        elif event_type == 'pull_request':
            # Process pull_request events
            pull_requests = payload_data.get("pull_request", {})
            pr_metadata = {
                "author": pull_requests.get("user", {}).get("login", ""),
                "state": pull_requests.get("state", ""),
                "branch": pull_requests.get("base", {}).get("ref", "")
            }
            # Save pull_request metadata to the audit log
            audit_response = save_audit_log([pr_metadata], event_type)
            return Response(audit_response, status=status.HTTP_200_OK)

        else:
            # If the event is not supported, return 400
            return Response({"error": "Unsupported event type"}, status=status.HTTP_400_BAD_REQUEST)

    @staticmethod
    def is_valid_signature(payload, signature, secret):
        # Compute HMAC hex digest
        hash_hex = hmac.new(secret, payload, hashlib.sha1).hexdigest()
        # Compare with the GitHub signature
        return hmac.compare_digest(f'sha1={hash_hex}', signature)

def save_audit_log(data, event_type="push"):
    # Modify the save_audit_log function to accept event_type
    # and distinguish between commits and PRs in the audit logs
    # Save the data to the database or log file with the event_type
    # ...
    pass