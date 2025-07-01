from main import *
from main.fb import *
from main.plugins.log import *

class files:
    def getcookies(self):
        try:
            with open('input/cookies.txt', 'r') as f:
                cookies = f.read().splitlines()
            
            random.shuffle(cookies)
            return cookies
        except Exception as e:
            print(f"Lỗi Khi Đọc Files: {e}")
            return []