import json
import time
import ssl
import threading
import os
import sys
import random
import string
from urllib.parse import urlparse
import requests
import paho.mqtt.client as mqtt
import hashlib
from bs4 import BeautifulSoup
from main.fb import *
import gc
import psutil
import threading
from collections import defaultdict

cookie_attempts = defaultdict(lambda: {'count': 0, 'last_reset': time.time(), 'banned_until': 0, 'permanent_ban': False})
cookie_delays = {}
active_threads = {}
cleanup_lock = threading.Lock()

def clr():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def handle_failed_connection(cookie_hash):
    global cookie_attempts
    
    current_time = time.time()
    
    if current_time - cookie_attempts[cookie_hash]['banned_until'] > 43200:
        cookie_attempts[cookie_hash]['count'] = 0
        cookie_attempts[cookie_hash]['last_reset'] = current_time
        cookie_attempts[cookie_hash]['banned_until'] = 0
    
    if cookie_attempts[cookie_hash]['banned_until'] > 0:
        ban_count = getattr(cookie_attempts[cookie_hash], 'ban_count', 0) + 1
        cookie_attempts[cookie_hash]['ban_count'] = ban_count
        
        if ban_count >= 5:
            cookie_attempts[cookie_hash]['permanent_ban'] = True
            print(f"Cookie {cookie_hash[:10]} Đã Bị Ngưng Hoạt Động Vĩnh Viễn Để Tránh Đầy Memory, Lí Do: Acc Die, CheckPoint v.v")
            
            for key in list(active_threads.keys()):
                if key.startswith(cookie_hash):
                    active_threads[key].stop()
                    del active_threads[key]

def cleanup_global_memory():
    global active_threads, cookie_attempts
    
    with cleanup_lock:
        current_time = time.time()
        
        expired_cookies = []
        for cookie_hash, data in cookie_attempts.items():
            if data['permanent_ban'] or (current_time - data['last_reset'] > 86400):
                expired_cookies.append(cookie_hash)
        
        for cookie_hash in expired_cookies:
            del cookie_attempts[cookie_hash]
            for key in list(active_threads.keys()):
                if key.startswith(cookie_hash):
                    active_threads[key].stop()
                    del active_threads[key]
        
        gc.collect()
        
        process = psutil.Process()
        memory_info = process.memory_info()
        print(f"Memory Usage: {memory_info.rss / (1024**3):.2f} GB")

def extract_keys(html):
    soup = BeautifulSoup(html, 'html.parser')
    code_div = soup.find('div', class_='plaintext') 
    if code_div:
        keys = [line.strip() for line in code_div.get_text().split('\n') if line.strip()]
        return keys
    return []

def checkkey():
    url = 'https://anotepad.com/notes/j5qi2ith'
    try:
        response = requests.get(url)
        response.raise_for_status()
    except Exception as e:
        print("Không thể lấy dữ liệu từ anotepad:", e)
        os.kill(os.getpid(), 9)

    md5_list = extract_keys(response.text)

    key = input("Nhập Key Để Tiếp Tục:\n").strip()
    hashed = hashlib.md5(key.encode()).hexdigest()

    if hashed in md5_list:
        print("Key Đúng")
    else:
        print("Key Saii. Thoát chương trình.")
        os.kill(os.getpid(), 9)

def parse_cookie_string(cookie_string):
    cookie_dict = {}
    cookies = cookie_string.split(";")
    for cookie in cookies:
        if "=" in cookie:
            key, value = cookie.split("=")
        else:
            pass
        try: cookie_dict[key] = value
        except: pass
    return cookie_dict

def generate_offline_threading_id() -> str:
    ret = int(time.time() * 1000)
    value = random.randint(0, 4294967295)
    binary_str = format(value, "022b")[-22:]
    msgs = bin(ret)[2:] + binary_str
    return str(int(msgs, 2))
    
def get_headers(
    url: str, options: dict = {}, ctx: dict = {}, customHeader: dict = {}
) -> dict:
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "Referer": "https://www.facebook.com/",
        "Host": url.replace("https://", "").split("/")[0],
        "Origin": "https://www.facebook.com",
        "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
        "Connection": "keep-alive",
    }

    if "user_agent" in options:
        headers["User-Agent"] = options["user_agent"]

    for key in customHeader:
        headers[key] = customHeader[key]

    if "region" in ctx:
        headers["X-MSGR-Region"] = ctx["region"]

    return headers

def get_from(input_str, start_token, end_token):
    start = input_str.find(start_token) + len(start_token)
    if start < len(start_token):
        return ""

    last_half = input_str[start:]
    end = last_half.find(end_token)
    if end == -1:
        raise ValueError(f"Could not find endTime `{end_token}` in the given string.")

    return last_half[:end]

def base36encode(number: int, alphabet="0123456789abcdefghijklmnopqrstuvwxyz"):
    if not isinstance(number, int):
        raise TypeError("number must be an integer")

    base36 = ""
    sign = ""

    if number < 0:
        sign = "-"
        number = -number

    if 0 <= number < len(alphabet):
        return sign + alphabet[number]

    while number != 0:
        number, i = divmod(number, len(alphabet))
        base36 = alphabet[i] + base36

    return sign + base36

def dataSplit(string1, string2, numberSplit1=None, numberSplit2=None, HTML=None, amount=None, string3=None, numberSplit3=None, defaultValue=None):
    if (defaultValue): numberSplit1, numberSplit2 = 1, 0
    if (amount == None):
        return HTML.split(string1)[numberSplit1].split(string2)[numberSplit2]
    elif (amount == 3):
        return HTML.split(string1)[numberSplit1].split(string2)[numberSplit2].split(string3)[numberSplit3]

def digitToChar(digit):
    if digit < 10:
        return str(digit)
    return chr(ord('a') + digit - 10)

def str_base(number, base):
    if number < 0:
        return "-" + str_base(-number, base)
    (d, m) = divmod(number, base)
    if d > 0:
        return str_base(d, base) + digitToChar(m)
    return digitToChar(m)

def generate_session_id():
    return random.randint(1, 2 ** 53)

def generate_client_id():
    def gen(length):
        return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return gen(8) + '-' + gen(4) + '-' + gen(4) + '-' + gen(4) + '-' + gen(12)

def json_minimal(data):
    return json.dumps(data, separators=(",", ":"))

class Counter:
    def __init__(self, initial_value=0):
        self.value = initial_value
        
    def increment(self):
        self.value += 1
        return self.value
        
    @property
    def counter(self):
        return self.value

def formAll(dataFB, FBApiReqFriendlyName=None, docID=None, requireGraphql=None):
    global _req_counter
    if '_req_counter' not in globals():
        _req_counter = Counter(0)
    
    __reg = _req_counter.increment()
    dataForm = {}
    
    if (requireGraphql == None):
        dataForm["fb_dtsg"] = dataFB["fb_dtsg"]
        dataForm["jazoest"] = dataFB["jazoest"]
        dataForm["__a"] = 1
        dataForm["__user"] = str(dataFB["FacebookID"])
        dataForm["__req"] = str_base(__reg, 36) 
        dataForm["__rev"] = dataFB["clientRevision"]
        dataForm["av"] = dataFB["FacebookID"]
        dataForm["fb_api_caller_class"] = "RelayModern"
        dataForm["fb_api_req_friendly_name"] = FBApiReqFriendlyName
        dataForm["server_timestamps"] = "true"
        dataForm["doc_id"] = str(docID)
    else:
        dataForm["fb_dtsg"] = dataFB["fb_dtsg"]
        dataForm["jazoest"] = dataFB["jazoest"]
        dataForm["__a"] = 1
        dataForm["__user"] = str(dataFB["FacebookID"])
        dataForm["__req"] = str_base(__reg, 36) 
        dataForm["__rev"] = dataFB["clientRevision"]
        dataForm["av"] = dataFB["FacebookID"]

    return dataForm

def mainRequests(url, data, cookies):
    return {
        "url": url,
        "data": data,
        "headers": {
            "authority": "www.facebook.com",
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9,vi;q=0.8",
            "content-type": "application/x-www-form-urlencoded",
            "origin": "https://www.facebook.com",
            "referer": "https://www.facebook.com/",
            "sec-ch-ua": "\"Not?A_Brand\";v=\"8\", \"Chromium\";v=\"108\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "sec-fetch-dest": "empty",
            "sec-fetch-mode": "cors",
            "sec-fetch-site": "same-origin",
            "user-agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
            "x-fb-friendly-name": "FriendingCometFriendRequestsRootQueryRelayPreloader",
            "x-fb-lsd": "YCb7tYCGWDI6JLU5Aexa1-"
        },
        "cookies": parse_cookie_string(cookies),
        "verify": True
    }

class fbTools:
    def __init__(self, dataFB, threadID="0"):
        self.threadID = threadID
        self.dataGet = None
        self.dataFB = dataFB
        self.ProcessingTime = None
        self.last_seq_id = None
    
    def getAllThreadList(self):
        randomNumber = str(int(format(int(time.time() * 1000), "b") + ("0000000000000000000000" + format(int(random.random() * 4294967295), "b"))[-22:], 2))
        dataForm = formAll(self.dataFB, requireGraphql=0)

        dataForm["queries"] = json.dumps({
            "o0": {
                "doc_id": "3336396659757871",
                "query_params": {
                    "limit": 20,
                    "before": None,
                    "tags": ["INBOX"],
                    "includeDeliveryReceipts": False,
                    "includeSeqID": True,
                }
            }
        })
        
        sendRequests = requests.post(**mainRequests("https://www.facebook.com/api/graphqlbatch/", dataForm, self.dataFB["cookieFacebook"]))
        response_text = sendRequests.text
        self.ProcessingTime = sendRequests.elapsed.total_seconds()
        
        if response_text.startswith("for(;;);"):
            response_text = response_text[9:]
        
        if not response_text.strip():
            print("Error: Empty response from Facebook API")
            return False
            
        try:
            response_parts = response_text.split("\n")
            first_part = response_parts[0]
            
            if first_part.strip():
                response_data = json.loads(first_part)
                self.dataGet = first_part
                
                if "o0" in response_data and "data" in response_data["o0"] and "viewer" in response_data["o0"]["data"] and "message_threads" in response_data["o0"]["data"]["viewer"]:
                    self.last_seq_id = response_data["o0"]["data"]["viewer"]["message_threads"]["sync_sequence_id"]
                    return True
                else:
                    print("Error: Expected fields not found in response")
                    return False
            else:
                print("Error: Empty first part of response")
                return False
                
        except json.JSONDecodeError as e:
            print(f"JSON Decode Error: {e}")
            print(f"Response first part: {response_parts[0][:100]}")
            return False
        except KeyError as e:
            print(f"Key Error: {e}")
            print("The expected data structure wasn't found in the response")
            return False
    
    def typeCommand(self, commandUsed):
        listData = []
        
        try:
            if self.dataGet is None:
                return "No data available. Make sure to call getAllThreadList first."
                
            data_to_parse = self.dataGet
            if data_to_parse.startswith("for(;;);"):
                data_to_parse = data_to_parse[9:]
                
            getData = json.loads(data_to_parse)["o0"]["data"]["viewer"]["message_threads"]["nodes"]
        except json.JSONDecodeError as e:
            return f"Failed to decode JSON response: {e}"
        except KeyError as e:
            try:
                error_data = json.loads(data_to_parse)["o0"]
                if "errors" in error_data:
                    return error_data["errors"][0]["summary"]
                else:
                    return f"Unexpected response structure. Missing key: {e}"
            except:
                return f"Unexpected response structure. Missing key: {e}"
        
        dataThread = None
        for getNeedIDThread in getData:
            thread_key = getNeedIDThread.get("thread_key", {})
            thread_fbid = thread_key.get("thread_fbid")
            if thread_fbid and str(thread_fbid) == str(self.threadID):
                dataThread = getNeedIDThread
                break
        
        if dataThread is not None:
            if commandUsed == "getAdmin":
                for dataID in dataThread.get("thread_admins", []):
                    listData.append(str(dataID["id"]))
                exportData = {
                    "adminThreadList": listData
                }
            elif commandUsed == "threadInfomation":
                threadInfoList = dataThread.get("customization_info", {})
                exportData = {
                    "nameThread": dataThread.get("name"), 
                    "IDThread": self.threadID, 
                    "emojiThread": threadInfoList.get("emoji"),
                    "messageCount": dataThread.get("messages_count"),
                    "adminThreadCount": len(dataThread.get("thread_admins", [])),
                    "memberCount": len(dataThread.get("all_participants", {}).get("edges", [])),
                    "approvalMode": "Bật" if (dataThread.get("approval_mode", 0) != 0) else "Tắt",
                    "joinableMode": "Bật" if (dataThread.get("joinable_mode", {}).get("mode") != "0") else "Tắt",
                    "urlJoinableThread": dataThread.get("joinable_mode", {}).get("link", "")
                }
            elif commandUsed == "exportMemberListToJson":
                getMemberList = dataThread.get("all_participants", {}).get("edges", [])
                for exportMemberList in getMemberList:
                    node = exportMemberList.get("node", {})
                    dataUserThread = node.get("messaging_actor", {})
                    if dataUserThread:
                        exportData = json.dumps({
                            dataUserThread.get("id", ""): {
                                "nameFB": str(dataUserThread.get("name", "")),
                                "idFacebook": str(dataUserThread.get("id", "")),
                                "profileUrl": str(dataUserThread.get("url", "")),
                                "avatarUrl": str(dataUserThread.get("big_image_src", {}).get("uri", "")),
                                "gender": str(dataUserThread.get("gender", "")),
                                "usernameFB": str(dataUserThread.get("username", ""))
                            }
                        }, skipkeys=True, allow_nan=True, ensure_ascii=False, indent=5)
                        listData.append(exportData)
                exportData = listData
            else:
                exportData = {
                    "err": "no data"
                }
                
            return exportData
            
        else:
            return "Không lấy được dữ liệu ThreadList, đã xảy ra lỗi T___T"
    
    def getListThreadID(self):
        try:
            if self.dataGet is None:
                return {
                    "ERR": "No data available. Make sure to call getAllThreadList first."
                }
                
            data_to_parse = self.dataGet
            if data_to_parse.startswith("for(;;);"):
                data_to_parse = data_to_parse[9:]
                
            threadIDList = []
            threadNameList = []
            try:
                getData = json.loads(data_to_parse)["o0"]["data"]["viewer"]["message_threads"]["nodes"]
                
                for getThreadID in getData:
                    thread_key = getThreadID.get("thread_key", {})
                    thread_fbid = thread_key.get("thread_fbid")
                    
                    if thread_fbid is not None:
                        threadIDList.append(thread_fbid)
                        threadNameList.append(getThreadID.get("name", "No Name"))
                        
                return {
                    "threadIDList": threadIDList,
                    "threadNameList": threadNameList,
                    "countThread": len(threadIDList)
                }
                
            except (KeyError, json.JSONDecodeError) as e:
                return {
                    "ERR": f"Error processing thread data: {str(e)}"
                }
                
        except Exception as errLog:
            return {
                "ERR": f"Unexpected error: {str(errLog)}"
            }

class MessageSender:
    def __init__(self, fbt, dataFB, fb_instance):
        self.fbt = fbt
        self.dataFB = dataFB
        self.fb_instance = fb_instance
        self.mqtt = None
        self.ws_req_number = 0
        self.ws_task_number = 0
        self.syncToken = None
        self.lastSeqID = None
        self.req_callbacks = {}
        self.cookie_hash = hashlib.md5(dataFB['cookieFacebook'].encode()).hexdigest()
        self.connect_attempts = 0
        self.last_cleanup = time.time()

    def cleanup_memory(self):
        current_time = time.time()
        if current_time - self.last_cleanup > 3600:
            self.req_callbacks.clear()
            gc.collect()
            self.last_cleanup = current_time

    def get_last_seq_id(self):
        success = self.fbt.getAllThreadList()
        if success:
            self.lastSeqID = self.fbt.last_seq_id
        else:
            print("Failed To Get Last Sequence ID. Check Facebook Authentication.")
            return

    def on_disconnect(self, client, userdata, rc):
        global cookie_attempts
        print(f"Disconnected With Code {rc}")
        
        cookie_attempts[self.cookie_hash]['count'] += 1
        current_time = time.time()
        
        if current_time - cookie_attempts[self.cookie_hash]['last_reset'] > 43200:
            cookie_attempts[self.cookie_hash]['count'] = 1
            cookie_attempts[self.cookie_hash]['last_reset'] = current_time
        
        if cookie_attempts[self.cookie_hash]['count'] >= 20:
            print(f"Cookie {self.cookie_hash[:10]} Bị Tạm Ngưng Connect Trong 12 Giờ Vì Disconnect, Nghi Vấn: Die Cookies, Check Point")
            cookie_attempts[self.cookie_hash]['banned_until'] = current_time + 43200
            return
        
        if rc != 0:
            print("Attempting To Reconnect...")
            try:
                time.sleep(min(cookie_attempts[self.cookie_hash]['count'] * 2, 30))
                client.reconnect()
            except:
                print("Reconnect Failed")

    def _messenger_queue_publish(self, client, userdata, flags, rc):
        print(f"Connected To MQTT With Code: {rc}")
        if rc != 0:
            print(f"Connection Failed With Code {rc}")
            return

        topics = [("/t_ms", 0)]
        client.subscribe(topics)

        queue = {
            "sync_api_version": 10,
            "max_deltas_able_to_process": 1000,
            "delta_batch_size": 500,
            "encoding": "JSON",
            "entity_fbid": self.dataFB['FacebookID']
        }

        if self.syncToken is None:
            topic = "/messenger_sync_create_queue"
            queue["initial_titan_sequence_id"] = self.lastSeqID
            queue["device_params"] = None
        else:
            topic = "/messenger_sync_get_diffs"
            queue["last_seq_id"] = self.lastSeqID
            queue["sync_token"] = self.syncToken

        print(f"Publishing To {topic}")
        client.publish(
            topic,
            json_minimal(queue),
            qos=1,
            retain=False,
        )

    def connect_mqtt(self):
        global cookie_attempts
        
        if cookie_attempts[self.cookie_hash]['permanent_ban']:
            print(f"Cookie {self.cookie_hash[:10]} Đã Bị Ngưng Connect Vĩnh Viễn, Lí Do: Die Coọkes, Check Point v.v")
            return False
            
        current_time = time.time()
        if current_time < cookie_attempts[self.cookie_hash]['banned_until']:
            remaining = cookie_attempts[self.cookie_hash]['banned_until'] - current_time
            print(f"Cookie {self.cookie_hash[:10]} Bị Tạm Khóa, Còn {remaining/3600:.1f} Giờ")
            return False

        if not self.lastSeqID:
            print("Error: No last_seq_id Available. Cannot Connect To MQTT.")
            return False

        chat_on = json_minimal(True)
        session_id = generate_session_id()
        user = {
            "u": self.dataFB["FacebookID"],
            "s": session_id,
            "chat_on": chat_on,
            "fg": False,
            "d": generate_client_id(),
            "ct": "websocket",
            "aid": 219994525426954,
            "mqtt_sid": "",
            "cp": 3,
            "ecp": 10,
            "st": ["/t_ms", "/messenger_sync_get_diffs", "/messenger_sync_create_queue"],
            "pm": [],
            "dc": "",
            "no_auto_fg": True,
            "gas": None,
            "pack": [],
        }

        host = f"wss://edge-chat.messenger.com/chat?region=eag&sid={session_id}"
        options = {
            "client_id": "mqttwsclient",
            "username": json_minimal(user),
            "clean": True,
            "ws_options": {
                "headers": {
                    "Cookie": self.dataFB['cookieFacebook'],
                    "Origin": "https://www.messenger.com",
                    "User-Agent": "Mozilla/5.0 (Linux; Android 9; SM-G973U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.100 Mobile Safari/537.36",
                    "Referer": "https://www.messenger.com/",
                    "Host": "edge-chat.messenger.com",
                },
            },
            "keepalive": 10,
        }

        self.mqtt = mqtt.Client(
            client_id="mqttwsclient",
            clean_session=True,
            protocol=mqtt.MQTTv31,
            transport="websockets",
        )

        self.mqtt.tls_set(certfile=None, keyfile=None, cert_reqs=ssl.CERT_NONE, tls_version=ssl.PROTOCOL_TLSv1_2)
        self.mqtt.on_connect = self._messenger_queue_publish
        self.mqtt.on_disconnect = self.on_disconnect
        self.mqtt.username_pw_set(username=options["username"])

        parsed_host = urlparse(host)
        self.mqtt.ws_set_options(
            path=f"{parsed_host.path}?{parsed_host.query}",
            headers=options["ws_options"]["headers"],
        )

        print(f"Connecting To {options['ws_options']['headers']['Host']}...")
        try:
            self.mqtt.connect(
                host=options["ws_options"]["headers"]["Host"],
                port=443,
                keepalive=options["keepalive"],
            )

            print("MQTT Connection Established")
            self.mqtt.loop_start()
            return True
        except Exception as e:
            print(f"MQTT Connection Error: {e}")
            cookie_attempts[self.cookie_hash]['count'] += 1
            return False

    def stop(self):
        if self.mqtt:
            print("Stopping MQTT Client...")
            try:
                self.mqtt.disconnect()
                self.mqtt.loop_stop()
            except:
                pass
        self.cleanup_memory()

    def upload_file(self, file_path):
        user_id = self.fb_instance.user_id
        url = "https://www.facebook.com/ajax/mercury/upload.php"
        headers = {
            'Cookie': self.dataFB['cookieFacebook'],
            'User-Agent': 'python-http/0.27.0',
            'Origin': 'https://www.facebook.com',
            'Referer': 'https://www.facebook.com/'
        }

        params = {
            'ads_manager_write_regions': 'true',
            '__aaid': '0',
            '__user': user_id,
            '__a': '1',
            '__hs': '20207.HYP:comet_pkg.2.1...0',
            'dpr': '3',
            '__ccg': 'GOOD',
            '__rev': '1022311521',
            'fb_dtsg': self.dataFB['fb_dtsg'],
            'jazoest': self.dataFB['jazoest'],
            '__crn': 'comet.fbweb.CometHomeRoute'
        }

        mime_type = 'image/jpeg'
        if file_path.lower().endswith(('.mp4', '.mov', '.avi', '.wmv')):
            mime_type = 'video/mp4'

        with open(file_path, 'rb') as file:
            files = {'farr': (file_path.split('/')[-1], file, mime_type)}
            response = requests.post(url, headers=headers, params=params, files=files)

        if response.status_code == 200:
            content = response.text.replace('for (;;);', '')
            try:
                data = json.loads(content)
                if 'payload' in data and 'metadata' in data['payload'] and '0' in data['payload']['metadata']:
                    metadata = data['payload']['metadata']['0']
                    if mime_type.startswith('video'):
                        file_id = metadata.get('video_id')
                        return {'id': file_id, 'type': 'video'}
                    else:
                        file_id = metadata.get('fbid') or metadata.get('image_id')
                        return {'id': file_id, 'type': 'image'}
                else:
                    with open('response_debug.json', 'w', encoding='utf-8') as f:
                        f.write(content)
                    raise Exception(f"JSON Structure Not As Expected. Response Saved To response_debug.json")
            except json.JSONDecodeError:
                raise Exception(f"Cannot Parse JSON From Response: {response.text}")
        else:
            raise Exception(f"Error Uploading File: {response.status_code}")

    def get_valid_mentions(self, text, mention):
        if not isinstance(mention, dict) and not isinstance(mention, list):
            raise ValueError("Mentions must be a dict or list of dict")

        mentions = mention if isinstance(mention, list) else [mention]
        valid_mentions = []
        current_offset = 0

        for mention in mentions:
            if "id" in mention and "tag" in mention:
                provided_offset = mention.get("offset")
                tag_len = 0

                if type(provided_offset) is int:
                    if provided_offset >= len(text):
                        break
                    is_length_exceed = provided_offset + len(mention["tag"]) > len(text)
                    tag_len = (
                        len(mention["tag"])
                        if not is_length_exceed
                        else len(text) - provided_offset
                    )
                    current_offset = provided_offset
                else:
                    if current_offset >= len(text):
                        break
                    find = text.find(mention["tag"], current_offset)
                    if find != -1:
                        is_length_exceed = find + len(mention["tag"]) > len(text)
                        tag_len = (
                            len(mention["tag"])
                            if not is_length_exceed
                            else len(text) - find
                        )
                        current_offset = find

                valid_mentions.append({
                    "i": mention["id"],
                    "o": current_offset,
                    "l": tag_len,
                })
                current_offset += tag_len

        return valid_mentions

    def send_message(self, text=None, thread_id=None, attachment=None, mention=None, message_id=None, callback=None):
        if self.mqtt is None:
            print("Error: Not Connected To MQTT")
            return False

        if thread_id is None:
            print("Error: Thread ID Is Required")
            return False

        if text is None and attachment is None:
            print("Error: Text Or Attachment Is Required")
            return False

        self.cleanup_memory()

        self.ws_req_number += 1
        content = {
            "app_id": "2220391788200892",
            "payload": {
                "data_trace_id": None,
                "epoch_id": int(generate_offline_threading_id()),
                "tasks": [],
                "version_id": "7545284305482586",
            },
            "request_id": self.ws_req_number,
            "type": 3,
        }

        text = str(text) if text is not None else ""
        if len(text) > 0:
            self.ws_task_number += 1
            task_payload = {
                "initiating_source": 0,
                "multitab_env": 0,
                "otid": generate_offline_threading_id(),
                "send_type": 1,
                "skip_url_preview_gen": 0,
                "source": 0,
                "sync_group": 1,
                "text": text,
                "text_has_links": 0,
                "thread_id": int(thread_id),
            }

            if message_id is not None:
                if type(message_id) is not str:
                    raise ValueError("message_id must be a string")
                task_payload["reply_metadata"] = {
                    "reply_source_id": message_id,
                    "reply_source_type": 1,
                    "reply_type": 0,
                }

            if mention is not None and len(text) > 0:
                valid_mentions = self.get_valid_mentions(text, mention)
                task_payload["mention_data"] = {
                    "mention_ids": ",".join([str(x["i"]) for x in valid_mentions]),
                    "mention_lengths": ",".join([str(x["l"]) for x in valid_mentions]),
                    "mention_offsets": ",".join([str(x["o"]) for x in valid_mentions]),
                    "mention_types": ",".join(["p" for _ in valid_mentions]),
                }

            task = {
                "failure_count": None,
                "label": "46",
                "payload": json.dumps(task_payload, separators=(",", ":")),
                "queue_name": str(thread_id),
                "task_id": self.ws_task_number,
            }

            content["payload"]["tasks"].append(task)

        self.ws_task_number += 1
        task_mark_payload = {
            "last_read_watermark_ts": int(time.time() * 1000),
            "sync_group": 1,
            "thread_id": int(thread_id),
        }

        task_mark = {
            "failure_count": None,
            "label": "21",
            "payload": json.dumps(task_mark_payload, separators=(",", ":")),
            "queue_name": str(thread_id),
            "task_id": self.ws_task_number,
        }

        content["payload"]["tasks"].append(task_mark)

        if attachment is not None:
            attachments = attachment if isinstance(attachment, list) else [attachment]
            for file_info in attachments:
                self.ws_task_number += 1
                if file_info["type"] == "image":
                    task_payload = {
                        "attachment_fbids": [file_info["id"]],
                        "otid": generate_offline_threading_id(),
                        "send_type": 3,
                        "source": 0,
                        "sync_group": 1,
                        "text": None,
                        "thread_id": int(thread_id),
                    }
                else:
                    task_payload = {
                        "attachment_fbids": [file_info["id"]],
                        "otid": generate_offline_threading_id(),
                        "send_type": 3,
                        "source": 0,
                        "sync_group": 1,
                        "text": None,
                        "thread_id": int(thread_id),
                    }

                if message_id is not None:
                    task_payload["reply_metadata"] = {
                        "reply_source_id": message_id,
                        "reply_source_type": 1,
                        "reply_type": 0,
                    }

                task = {
                    "failure_count": None,
                    "label": "46",
                    "payload": json.dumps(task_payload, separators=(",", ":")),
                    "queue_name": str(thread_id),
                    "task_id": self.ws_task_number,
                }

                content["payload"]["tasks"].append(task)

        content["payload"] = json.dumps(content["payload"], separators=(",", ":"))

        if callback is not None and callable(callback):
            self.req_callbacks[self.ws_req_number] = callback

        try:
            self.mqtt.publish(
                topic="/ls_req",
                payload=json.dumps(content, separators=(",", ":")),
                qos=1,
                retain=False,
            )
            return True
        except Exception as e:
            print(f"Error Publishing Message: {e}")
            return False

    def send_message_with_attachment(self, text, thread_id, file_path, message_id=None, callback=None):
        if self.mqtt is None:
            print("Error: Not Connected To MQTT")
            return False

        if thread_id is None:
            print("Error: Thread ID Is Required")
            return False

        try:
            file_info = self.upload_file(file_path)
            if not file_info:
                print("Failed To Upload File")
                return False

            self.cleanup_memory()

            self.ws_req_number += 1
            content = {
                "app_id": "2220391788200892",
                "payload": {
                    "data_trace_id": None,
                    "epoch_id": int(generate_offline_threading_id()),
                    "tasks": [],
                    "version_id": "7545284305482586",
                },
                "request_id": self.ws_req_number,
                "type": 3,
            }

            self.ws_task_number += 1
            task_payload = {
                "attachment_fbids": [file_info["id"]],
                "initiating_source": 0,
                "multitab_env": 0,
                "otid": generate_offline_threading_id(),
                "send_type": 3,
                "skip_url_preview_gen": 0,
                "source": 0,
                "sync_group": 1,
                "text": text,
                "text_has_links": 0,
                "thread_id": int(thread_id),
            }

            if message_id is not None:
                if type(message_id) is not str:
                    raise ValueError("message_id must be a string")
                task_payload["reply_metadata"] = {
                    "reply_source_id": message_id,
                    "reply_source_type": 1,
                    "reply_type": 0,
                }

            task = {
                "failure_count": None,
                "label": "46",
                "payload": json.dumps(task_payload, separators=(",", ":")),
                "queue_name": str(thread_id),
                "task_id": self.ws_task_number,
            }

            content["payload"]["tasks"].append(task)

            self.ws_task_number += 1
            task_mark_payload = {
                "last_read_watermark_ts": int(time.time() * 1000),
                "sync_group": 1,
                "thread_id": int(thread_id),
            }

            task_mark = {
                "failure_count": None,
                "label": "21",
                "payload": json.dumps(task_mark_payload, separators=(",", ":")),
                "queue_name": str(thread_id),
                "task_id": self.ws_task_number,
            }

            content["payload"]["tasks"].append(task_mark)

            content["payload"] = json.dumps(content["payload"], separators=(",", ":"))

            if callback is not None and callable(callback):
                self.req_callbacks[self.ws_req_number] = callback

            try:
                self.mqtt.publish(
                    topic="/ls_req",
                    payload=json.dumps(content, separators=(",", ":")),
                    qos=1,
                    retain=False,
                )
                return True
            except Exception as e:
                print(f"Error Publishing Message: {e}")
                return False

        except Exception as e:
            print(f"Error Sending Message With Attachment: {e}")
            return False

    def share_contact(self, text=None, sender_id=None, thread_id=None):
        if self.mqtt is None:
            print("Error: Not Connected To MQTT")
            return False

        if sender_id is None:
            print("Error: Sender ID Is Required")
            return False

        if thread_id is None:
            print("Error: Thread ID Is Required")
            return False

        self.cleanup_memory()

        self.ws_req_number += 1
        self.ws_task_number += 1

        content = {
            "app_id": "2220391788200892",
            "payload": {
                "tasks": [{
                    "label": 359,
                    "payload": json.dumps({
                        "contact_id": sender_id,
                        "sync_group": 1,
                        "text": text or "",
                        "thread_id": thread_id
                    }, separators=(",", ":")),
                    "queue_name": "xma_open_contact_share",
                    "task_id": self.ws_task_number,
                    "failure_count": None,
                }],
                "epoch_id": generate_offline_threading_id(),
                "version_id": "7214102258676893",
            },
            "request_id": self.ws_req_number,
            "type": 3
        }

        content["payload"] = json.dumps(content["payload"], separators=(",", ":"))

        try:
            self.mqtt.publish(
                topic="/ls_req",
                payload=json.dumps(content, separators=(",", ":")),
                qos=1,
                retain=False,
            )
            return True
        except Exception as e:
            print(f"Error Publishing Contact Share: {e}")
            return False

def send_messages_with_cookie(cookie, thread_id, message_files, delay, option=0, file_path=None, contact_uid=None):
    global cookie_attempts, active_threads
    
    cookie_hash = hashlib.md5(cookie.encode()).hexdigest()
    
    if cookie_attempts[cookie_hash]['permanent_ban']:
        print(f"Cookie {cookie_hash[:10]} Đã Bị Ngưng Hoạt Động Vĩnh Viễn\nLí Do: Cookies Die, CheckPoint V.V")
        return False
        
    current_time = time.time()
    if current_time < cookie_attempts[cookie_hash]['banned_until']:
        remaining = cookie_attempts[cookie_hash]['banned_until'] - current_time
        print(f"Cookie {cookie_hash[:10]} Bị Tạm Khóa, Còn {remaining/3600:.1f} Giờ\nLí Do: Checkpoint, Mõm, Cookies Die")
        return False

    try:
        fb = tuankiet(cookie)
        sender = MessageSender(fbTools({
            "FacebookID": fb.user_id,
            "fb_dtsg": fb.fb_dtsg,
            "clientRevision": fb.rev,
            "jazoest": fb.jazoest,
            "cookieFacebook": cookie
        }), {
            "FacebookID": fb.user_id,
            "fb_dtsg": fb.fb_dtsg,
            "clientRevision": fb.rev,
            "jazoest": fb.jazoest,
            "cookieFacebook": cookie
        }, fb)

        sender.get_last_seq_id()
        if not sender.connect_mqtt():
            handle_failed_connection(cookie_hash)
            return False

        print(f"Bắt Đầu Gửi Tin Nhắn Cho Box: {thread_id}")
        
        active_threads[f"{cookie_hash}_{thread_id}"] = sender

        try:
            while True:
                if len(message_files) > 1:
                    selected = random.choice(message_files)
                else:
                    selected = message_files[0]

                with open(selected, 'r', encoding='utf-8') as f:
                    content = f.read().strip()

                if option == 2:
                    uid_to_share = contact_uid or fb.user_id
                    sender.share_contact(content, uid_to_share, thread_id)
                elif option == 1:
                    sender.send_message_with_attachment(content, thread_id, file_path)
                else:
                    sender.send_message(content, thread_id)

                time.sleep(delay)
                
                if current_time - sender.last_cleanup > 600:
                    gc.collect()

        except KeyboardInterrupt:
            print(f"\nDừng Gửi Tin Nhắn Cho Box: {thread_id}")
        finally:
            sender.stop()
            if f"{cookie_hash}_{thread_id}" in active_threads:
                del active_threads[f"{cookie_hash}_{thread_id}"]

        return True

    except Exception as e:
        print(f"Lỗi Trong Luồng Gửi Tin Nhắn Cho Box {thread_id}: {e}")
        handle_failed_connection(cookie_hash)
        return False

def main():
    print("""
╔════════════════════════════════════════════════════════╗
║                FACEBOOK MESSAGE SENDER                ║
║                       ─────────                       ║
║        Send Messages, Share Contacts, Send Media      ║
╚════════════════════════════════════════════════════════╝
""")

    cookies = []
    if os.path.exists("cookies.txt"):
        with open("cookies.txt", "r", encoding="utf-8") as f:
            cookies = [c.strip() for c in f if c.strip()]

    if not cookies:
        cookies = [input("Nhập Cookie: ").strip()]

    valid_cookies, authenticated_ids = [], []
    for c in cookies:
        try:
            fb = tuankiet(c)
            if fb.user_id and not fb.user_id.startswith("Unable"):
                valid_cookies.append(c)
                authenticated_ids.append(fb.user_id)
        except:
            pass

    if not valid_cookies:
        print("Không Có Cookie Hợp Lệ, Thoát.")
        return

    global cookie_delays
    for cookie in valid_cookies:
        try:
            delay = float(input(f"Nhập Delay Cho Cookie {cookie[-30:]}: ").strip())
            cookie_delays[hashlib.md5(cookie.encode()).hexdigest()] = delay
        except:
            cookie_delays[hashlib.md5(cookie.encode()).hexdigest()] = 10

    id_boxes = []
    while True:
        box = input("Nhập ID Box (Nhập 'done' để ngưng): ").strip()
        if box.lower() == "done":
            break
        id_boxes.append(box)

    if not id_boxes:
        print("Chưa Nhập ID Box Nào. Thoát.")
        return

    message_files = []
    while True:
        mf = input("Nhập File Chứa Nội Dung (Nhập 'done' để ngưng): ").strip()
        if mf.lower() == "done":
            break
        if os.path.exists(mf):
            message_files.append(mf)
        else:
            print(f"File Không Tồn Tại: {mf}")

    if not message_files:
        print("Chưa Có File Nội Dung Nào. Thoát.")
        return

    print("""
╔════════════════════════════════════════════════════════╗
║                    SELECT AN OPTION                    ║
║                                                        ║
║              1. Send With Image Or Video               ║
║              2. Send With Contact Share                ║
║              3. Skip Choice Option                     ║
╚════════════════════════════════════════════════════════╝
""")

    try:
        option = int(input("Enter Choice (1-3): ").strip())
    except:
        print("Không Hợp Lệ Chọn Mặc Định 3")
        option = 3

    file_path, contact_uid = None, None
    if option == 1:
        file_path = input("Nhập Đường Dẫn File Ảnh/Video: ").strip()
        if not os.path.exists(file_path):
            print("File Không Tồn Tại. Thoát.")
            return
    elif option == 2:
        contact_uid = input("Nhập UID Cần Share Contact: ").strip()

    threads = []
    cleanup_timer = threading.Timer(1800, cleanup_global_memory)
    cleanup_timer.daemon = True
    cleanup_timer.start()

    for cookie in valid_cookies:
        cookie_hash = hashlib.md5(cookie.encode()).hexdigest()
        delay = cookie_delays[cookie_hash]
        
        for tid in id_boxes:
            t = threading.Thread(
                target=send_messages_with_cookie,
                args=(cookie, tid, message_files, delay, option, file_path, contact_uid)
            )
            t.daemon = True
            t.start()
            threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("Dừng Tất Cả Luồng Gửi Tin Nhắn.")
        cleanup_global_memory()
        
if __name__ == "__main__":
    checkkey()
    clr()
    main()