from concurrent.futures import ThreadPoolExecutor
from main import *
from main.plugins.log import *
from main.fb import *

class thread:
    def __init__(self, thread_amt, func, cookies=[], args=[], boost=False, delay=0):
        self.maxworkers = int(thread_amt)
        self.func = func
        self.cookies = cookies
        self.args = list(args)
        self.boost = boost
        self.delay = 0
        self.futures = []
        self.work()

    def execute(self, cookie, exe: ThreadPoolExecutor):
        threads_per_cookie = 2 if self.boost else 1
        current_args = [cookie] + self.args

        for _ in range(threads_per_cookie):
            try:
                future = exe.submit(self.func, *current_args)
                self.futures.append(future)
            except Exception as e:
                log.error('Threads [main]', e)

    def work(self):
        if not self.cookies:
            log.warn('Threads [main]', 'Vui Lòng Nhập Cookies Vào input/cookies.txt Trước Khi Chạy')
            return

        total_threads = len(self.cookies) * (2 if self.boost else 1)
        adjusted_workers = min(self.maxworkers, total_threads)

        with ThreadPoolExecutor(max_workers=adjusted_workers) as exe:
            for cookie in self.cookies:
                self.execute(cookie, exe)
                #facebook(cookie).delay(self.delay)

            for future in self.futures:
                try:
                    future.result()
                except requests.RequestException as e:
                    log.error('Threads [result]', f'Request exception >> {e}')
                except Exception as e:
                    log.error('Threads [result]', e)
