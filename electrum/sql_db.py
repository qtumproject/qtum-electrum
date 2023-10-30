import os
import concurrent
import queue
import threading
import asyncio
import sqlite3

from .logging import Logger
from .util import test_read_write_permissions


def sql(func):
    """wrapper for sql methods"""
    def wrapper(self: 'SqlDB', *args, **kwargs):
        assert threading.current_thread() != self.sql_thread
        f = asyncio.Future()
        self.db_requests.put((f, func, args, kwargs))
        return f
    return wrapper


class SqlDB(Logger):

    def __init__(self, asyncio_loop: asyncio.BaseEventLoop, path, commit_interval=None):
        Logger.__init__(self)
        self.asyncio_loop = asyncio_loop
        self.path = path
        test_read_write_permissions(path)
        self.commit_interval = commit_interval
        self.db_requests = queue.Queue()
        self.sql_thread = threading.Thread(target=self.run_sql)
        self.sql_thread.start()

    def filesize(self):
        return os.stat(self.path).st_size

    def run_sql(self):
        self.logger.info("SQL thread started")
        self.conn = sqlite3.connect(self.path)
        self.logger.info("Creating database")
        self.create_database()
        i = 0
        while self.asyncio_loop.is_running():
            try:
                future, func, args, kwargs = self.db_requests.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                result = func(self, *args, **kwargs)
            except BaseException as e:
                self.asyncio_loop.call_soon_threadsafe(future.set_exception, e)
                continue
            if not future.cancelled():
                self.asyncio_loop.call_soon_threadsafe(future.set_result, result)
            # note: in sweepstore session.commit() is called inside
            # the sql-decorated methods, so commiting to disk is awaited
            if self.commit_interval:
                i = (i + 1) % self.commit_interval
                if i == 0:
                    self.conn.commit()
        # write
        self.conn.commit()
        self.conn.close()
        self.logger.info("SQL thread terminated")

    def create_database(self):
        raise NotImplementedError()
