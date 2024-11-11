import hashlib
import uuid


def generate_backup_codes(count=5):
    codes = []
    for _ in range(count):
        code = str(uuid.uuid4())
        hashed_code = hashlib.sha256(code.encode()).hexdigest()
        codes.append(hashed_code)
    return codes