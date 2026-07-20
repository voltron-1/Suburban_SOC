import time
import logging
from functools import wraps
import requests

logger = logging.getLogger(__name__)

def retry(max_attempts=3, base_backoff=1):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            attempts = 0
            while attempts < max_attempts:
                try:
                    return func(*args, **kwargs)
                except requests.exceptions.HTTPError as e:
                    # Do not retry on 4xx client errors
                    if 400 <= e.response.status_code < 500:
                        logger.error(f"Non-transient 4xx error in {func.__name__}: {e}")
                        raise
                    attempts += 1
                    if attempts == max_attempts:
                        raise
                except Exception as e:
                    attempts += 1
                    if attempts == max_attempts:
                        raise
                time.sleep(base_backoff * (2 ** (attempts - 1)))
        return wrapper
    return decorator
