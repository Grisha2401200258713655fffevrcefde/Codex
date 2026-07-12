import hmac


def token_valid(expected: str, supplied: str) -> bool:
    return bool(expected) and hmac.compare_digest(expected, supplied)
