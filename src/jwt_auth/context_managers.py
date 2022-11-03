import redis

from contextlib import contextmanager


@contextmanager
def redis_connection(host, port, password):
    try:
        redis_client = redis.Redis(
            host=host, port=port, password=password, db=0)
        yield redis_client
    finally:
        redis_client.close()
