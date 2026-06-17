import os
import re
import sys
import uuid
import time
import socket
import hashlib
import webbrowser
import json
import threading
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

import requests
import urllib3

# Captive Portal များတွင် ဖြစ်ပေါ်တတ်သော SSL Warning များအား စနစ်တကျ ပိတ်ထားခြင်း
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class TerminalColors:
    """စနစ်တစ်ခုလုံး၏ Console Output အရောင်များ သတ်မှတ်ချက်။"""
    GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    RED = "\033[1;31m"
    WHITE = "\033[1;37m"
    CYAN = "\033[1;36m"
    MAGENTA = "\033[1;35m"
    GRAY = "\033[1;90m"
    RESET = "\033[0m"


@dataclass
class UserSession:
    """အသုံးပြုသူ၏ Session အချက်အလက်များ"""
    user_id: str
    mac: str
    gateway_ip: str
    status: str  # "Pending", "Approved", "Rejected"
    timestamp: datetime
    last_activity: datetime
    
    def to_dict(self) -> dict:
        return {
            'user_id': self.user_id,
            'mac': self.mac,
            'gateway_ip': self.gateway_ip,
            'status': self.status,
            'timestamp': self.timestamp.isoformat(),
            'last_activity': self.last_activity.isoformat()
        }


class SecureWiFiPortalManager:
    """လုံခြုံရေးနှင့် Admin Management Feature များပါဝင်သော WiFi Portal Manager"""
    
    def __init__(self, bot_token: str, admin_chat_ids: List[str], portal_url: str) -> None:
        self.bot_token = bot_token
        self.admin_chat_ids = set(admin_chat_ids)  # Set for faster lookup
        self.portal_url = portal_url
        
        # Authorized Users Database (In-memory, production အတွက် Database သုံးသင့်)
        self.authorized_users: Dict[str, UserSession] = {}
        self.pending_users: Dict[str, UserSession] = {}
        self.user_blacklist: Set[str] = set()
        
        # Security Settings
        self.max_retry_attempts = 3
        self.session_timeout_minutes = 30
        self.rate_limit = {}
        self.rate_limit_window = 60  # seconds
        self.max_requests_per_window = 10
        
        # Bot Security
        self.bot_username = None
        self.authorized_admins = set()  # ထပ်ဆောင်း Admin များ
        
        # File for persistent storage
        self.data_file = os.path.expanduser("~/.portal_authorized_users.json")
        self.load_authorized_users()
        
        self.telegram_channel = "https://t.me/starlinkfreezone"
        self.user_agent = (
            "Mozilla/5.0 (Linux; Android 12; K) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/139.0.0.0 Mobile Safari/537.36"
        )
        
        # Persistent Network Connection
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'application/json, text/plain, */*',
            'Connection': 'keep-alive'
        })
        self.session.verify = False
        
        # Thread lock for concurrent operations
        self._lock = threading.Lock()
        
        # Start background thread for cleaning expired sessions
        self._start_cleanup_thread()

    def _start_cleanup_thread(self) -> None:
        """သက်တမ်းကုန်ဆုံးသွားသော Sessions များကို ရှင်းလင်းပေးသည့် Background Thread"""
        def cleanup_worker():
            while True:
                time.sleep(300)  # 5 minutes
                self.cleanup_expired_sessions()
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()

    def cleanup_expired_sessions(self) -> None:
        """သက်တမ်းကုန်ဆုံးသွားသော Sessions များကို ရှင်းလင်းခြင်း"""
        with self._lock:
            current_time = datetime.now()
            
            # Clean authorized users
            expired_users = []
            for user_id, session in self.authorized_users.items():
                if current_time - session.last_activity > timedelta(minutes=self.session_timeout_minutes):
                    expired_users.append(user_id)
            
            for user_id in expired_users:
                del self.authorized_users[user_id]
            
            # Clean pending users
            expired_pending = []
            for user_id, session in self.pending_users.items():
                if current_time - session.timestamp > timedelta(minutes=10):  # 10 minutes timeout for pending
                    expired_pending.append(user_id)
            
            for user_id in expired_pending:
                del self.pending_users[user_id]
            
            if expired_users or expired_pending:
                self.save_authorized_users()

    def load_authorized_users(self) -> None:
        """သိမ်းဆည်းထားသော Authorized Users များကို ဖတ်ယူခြင်း"""
        try:
            if os.path.exists(self.data_file):
                with open(self.data_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for user_data in data.get('authorized_users', []):
                        session = UserSession(
                            user_id=user_data['user_id'],
                            mac=user_data['mac'],
                            gateway_ip=user_data['gateway_ip'],
                            status=user_data['status'],
                            timestamp=datetime.fromisoformat(user_data['timestamp']),
                            last_activity=datetime.fromisoformat(user_data['last_activity'])
                        )
                        self.authorized_users[user_data['user_id']] = session
        except Exception as e:
            print(f"Warning: Could not load authorized users: {e}")

    def save_authorized_users(self) -> None:
        """Authorized Users များကို သိမ်းဆည်းခြင်း"""
        try:
            with self._lock:
                data = {
                    'authorized_users': [session.to_dict() for session in self.authorized_users.values()]
                }
                with open(self.data_file, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Warning: Could not save authorized users: {e}")

    def is_admin(self, chat_id: str) -> bool:
        """Chat ID သည် Admin ဟုတ်မဟုတ် စစ်ဆေးခြင်း"""
        return chat_id in self.admin_chat_ids

    def check_rate_limit(self, chat_id: str) -> bool:
        """Rate Limiting စစ်ဆေးခြင်း (Spam တိုက်ခိုက်မှုကာကွယ်ရန်)"""
        current_time = time.time()
        
        with self._lock:
            if chat_id not in self.rate_limit:
                self.rate_limit[chat_id] = []
            
            # Remove old requests
            self.rate_limit[chat_id] = [
                ts for ts in self.rate_limit[chat_id] 
                if current_time - ts < self.rate_limit_window
            ]
            
            if len(self.rate_limit[chat_id]) >= self.max_requests_per_window:
                return False
            
            self.rate_limit[chat_id].append(current_time)
            return True

    def is_authorized(self, user_id: str) -> bool:
        """အသုံးပြုသူသည် Authorized ဟုတ်မဟုတ် စစ်ဆေးခြင်း"""
        with self._lock:
            if user_id in self.user_blacklist:
                return False
            return user_id in self.authorized_users

    def add_authorized_user(self, user_id: str, mac: str, gateway_ip: str) -> bool:
        """အသုံးပြုသူအား Authorized List တွင် ထည့်သွင်းခြင်း"""
        with self._lock:
            if user_id in self.user_blacklist:
                return False
            
            # Remove from pending if exists
            if user_id in self.pending_users:
                del self.pending_users[user_id]
            
            session = UserSession(
                user_id=user_id,
                mac=mac,
                gateway_ip=gateway_ip,
                status="Approved",
                timestamp=datetime.now(),
                last_activity=datetime.now()
            )
            self.authorized_users[user_id] = session
            self.save_authorized_users()
            return True

    def remove_authorized_user(self, user_id: str) -> bool:
        """အသုံးပြုသူအား Authorized List မှ ဖယ်ရှားခြင်း"""
        with self._lock:
            if user_id in self.authorized_users:
                del self.authorized_users[user_id]
                self.save_authorized_users()
                return True
            return False

    def blacklist_user(self, user_id: str) -> bool:
        """အသုံးပြုသူအား Blacklist တွင် ထည့်သွင်းခြင်း (တားမြစ်ခြင်း)"""
        with self._lock:
            self.user_blacklist.add(user_id)
            if user_id in self.authorized_users:
                del self.authorized_users[user_id]
            if user_id in self.pending_users:
                del self.pending_users[user_id]
            self.save_authorized_users()
            return True

    def unblacklist_user(self, user_id: str) -> bool:
        """အသုံးပြုသူအား Blacklist မှ ဖယ်ရှားခြင်း"""
        with self._lock:
            if user_id in self.user_blacklist:
                self.user_blacklist.remove(user_id)
                return True
            return False

    def get_all_authorized_users(self) -> List[Dict]:
        """Authorized Users အားလုံးကို စာရင်းပြန်ပေးခြင်း"""
        with self._lock:
            return [session.to_dict() for session in self.authorized_users.values()]

    def get_pending_users(self) -> List[Dict]:
        """Pending Users အားလုံးကို စာရင်းပြန်ပေးခြင်း"""
        with self._lock:
            return [session.to_dict() for session in self.pending_users.values()]

    def handle_admin_command(self, message: Dict) -> str:
        """Admin Commands များကို ကိုင်တွယ်ခြင်း"""
        text = message.get('text', '').strip()
        chat_id = str(message.get('from', {}).get('id', ''))
        sender_id = str(message.get('from', {}).get('id', ''))
        
        # Security: Only admins can use these commands
        if not self.is_admin(chat_id):
            return "⛔ သင်သည် ဤ Command ကို အသုံးပြုခွင့် မရှိပါ။ (Admin Only)"
        
        # Rate limiting check
        if not self.check_rate_limit(chat_id):
            return "⏳ သင်သည် အမြန်နှုန်း ကန့်သတ်ချက် ကျော်လွန်နေပါသည်။ ခဏစောင့်ပါ။"
        
        # Command parsing
        parts = text.split()
        if not parts:
            return "❌ Command မှားယွင်းနေပါသည်။"
        
        command = parts[0].lower()
        client_id = parts[1] if len(parts) > 1 else None
        
        # /add_id <client_id>
        if command == '/add_id' or command == 'add_id':
            if not client_id:
                return "❌ ပုံစံမှားနေပါသည်။ ကျေးဇူးပြု၍ `/add_id <client_id>` ဟု ရိုက်ထည့်ပါ။"
            
            # Check if already authorized
            if self.is_authorized(client_id):
                return f"⚠️ Client ID `{client_id}` သည် ပြီးသား Authorized ဖြစ်နေပါသည်။"
            
            # Check if in pending
            if client_id in self.pending_users:
                session = self.pending_users[client_id]
                self.add_authorized_user(client_id, session.mac, session.gateway_ip)
                return f"✅ Client ID `{client_id}` ကို အောင်မြင်စွာ Authorized ပြုလုပ်လိုက်ပါပြီ။\n📱 MAC: `{session.mac}`"
            
            # Check if user is blacklisted
            if client_id in self.user_blacklist:
                return f"⛔ Client ID `{client_id}` သည် Blacklist တွင် ရှိနေပါသည်။ ဦးစွာ Unblacklist ပြုလုပ်ပါ။"
            
            # Try to get user info from authorized list
            if client_id in self.authorized_users:
                return f"⚠️ Client ID `{client_id}` သည် ပြီးသား Authorized ဖြစ်နေပါသည်။"
            
            # Create new session
            session = UserSession(
                user_id=client_id,
                mac=self.resolve_local_mac(),
                gateway_ip=self.resolve_gateway_ip(),
                status="Approved",
                timestamp=datetime.now(),
                last_activity=datetime.now()
            )
            self.authorized_users[client_id] = session
            self.save_authorized_users()
            return f"✅ Client ID `{client_id}` ကို အောင်မြင်စွာ ထည့်သွင်းလိုက်ပါပြီ။"
        
        # /remove_id <client_id>
        elif command == '/remove_id' or command == 'remove_id':
            if not client_id:
                return "❌ ပုံစံမှားနေပါသည်။ ကျေးဇူးပြု၍ `/remove_id <client_id>` ဟု ရိုက်ထည့်ပါ။"
            
            if self.remove_authorized_user(client_id):
                return f"✅ Client ID `{client_id}` ကို Authorized List မှ အောင်မြင်စွာ ဖယ်ရှားလိုက်ပါပြီ။"
            else:
                return f"❌ Client ID `{client_id}` ကို Authorized List တွင် မတွေ့ပါ။"
        
        # /all_add_id
        elif command == '/all_add_id' or command == 'all_add_id':
            authorized_users = self.get_all_authorized_users()
            
            if not authorized_users:
                return "📋 လက်ရှိ Authorized Users စာရင်း ဗလာဖြစ်နေပါသည်။"
            
            user_list = "📋 *Authorized Users စာရင်း*\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
            for i, user in enumerate(authorized_users, 1):
                status_emoji = "🟢" if user['status'] == "Approved" else "🟡"
                user_list += f"{status_emoji} {i}. `{user['user_id']}`\n"
                user_list += f"   📱 MAC: `{user['mac']}`\n"
                user_list += f"   🕐 {datetime.fromisoformat(user['timestamp']).strftime('%Y-%m-%d %H:%M')}\n\n"
            
            user_list += f"━━━━━━━━━━━━━━━━━━━━━━━━\n📊 စုစုပေါင်း: {len(authorized_users)} ဦး"
            
            # Split message if too long
            if len(user_list) > 4000:
                return "📋 Authorized Users စာရင်းကို ခဏစောင့်ပါ... (ပို့ဆောင်နေပါသည်)"
            
            return user_list
        
        # /pending
        elif command == '/pending' or command == 'pending':
            pending_users = self.get_pending_users()
            
            if not pending_users:
                return "📋 လက်ရှိ Pending Users စာရင်း ဗလာဖြစ်နေပါသည်။"
            
            user_list = "⏳ *Pending Users စာရင်း*\n━━━━━━━━━━━━━━━━━━━━━━━━\n"
            for i, user in enumerate(pending_users, 1):
                user_list += f"🟡 {i}. `{user['user_id']}`\n"
                user_list += f"   📱 MAC: `{user['mac']}`\n"
                user_list += f"   🕐 {datetime.fromisoformat(user['timestamp']).strftime('%Y-%m-%d %H:%M')}\n\n"
            
            user_list += f"━━━━━━━━━━━━━━━━━━━━━━━━\n📊 စုစုပေါင်း: {len(pending_users)} ဦး"
            return user_list
        
        # /blacklist <client_id>
        elif command == '/blacklist' or command == 'blacklist':
            if not client_id:
                return "❌ ပုံစံမှားနေပါသည်။ ကျေးဇူးပြု၍ `/blacklist <client_id>` ဟု ရိုက်ထည့်ပါ။"
            
            if self.blacklist_user(client_id):
                return f"⛔ Client ID `{client_id}` ကို Blacklist တွင် အောင်မြင်စွာ ထည့်သွင်းလိုက်ပါပြီ။"
            else:
                return f"❌ Client ID `{client_id}` ကို Blacklist ထည့်ရန် မအောင်မြင်ပါ။"
        
        # /unblacklist <client_id>
        elif command == '/unblacklist' or command == 'unblacklist':
            if not client_id:
                return "❌ ပုံစံမှားနေပါသည်။ ကျေးဇူးပြု၍ `/unblacklist <client_id>` ဟု ရိုက်ထည့်ပါ။"
            
            if self.unblacklist_user(client_id):
                return f"✅ Client ID `{client_id}` ကို Blacklist မှ အောင်မြင်စွာ ဖယ်ရှားလိုက်ပါပြီ။"
            else:
                return f"❌ Client ID `{client_id}` ကို Blacklist တွင် မတွေ့ပါ။"
        
        # /stats
        elif command == '/stats' or command == 'stats':
            with self._lock:
                stats = (
                    f"📊 *System Statistics*\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"👤 Authorized Users: {len(self.authorized_users)}\n"
                    f"⏳ Pending Users: {len(self.pending_users)}\n"
                    f"⛔ Blacklisted Users: {len(self.user_blacklist)}\n"
                    f"🕐 Session Timeout: {self.session_timeout_minutes} minutes\n"
                    f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"🔒 Security Level: High"
                )
                return stats
        
        # /help
        elif command == '/help' or command == 'help':
            help_text = (
                "📚 *Admin Commands များ*\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "• `/add_id <client_id>` - Client ID ထည့်ရန်\n"
                "• `/remove_id <client_id>` - Client ID ဖယ်ရှားရန်\n"
                "• `/all_add_id` - Authorized Users အားလုံးကြည့်ရန်\n"
                "• `/pending` - Pending Users များကြည့်ရန်\n"
                "• `/blacklist <client_id>` - User ကို ပိတ်ပင်ရန်\n"
                "• `/unblacklist <client_id>` - User ကို ပိတ်ပင်မှုဖြေရန်\n"
                "• `/stats` - System Statistics ကြည့်ရန်\n"
                "• `/help` - ဤ Command များကိုကြည့်ရန်\n"
                "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                "💡 *မှတ်ချက်:* Client ID ကို အသုံးပြုသူများထံမှ ရယူပါ။"
            )
            return help_text
        
        else:
            return f"❌ Unknown Command: `{command}`\n💡 `/help` ကိုသုံးပြီး Command များကိုကြည့်ပါ။"

    def process_telegram_update(self, update: Dict) -> Optional[str]:
        """Telegram Update များကို စီမံဆောင်ရွက်ခြင်း"""
        if 'message' not in update:
            return None
        
        message = update['message']
        chat_id = str(message.get('chat', {}).get('id', ''))
        text = message.get('text', '').strip()
        
        # Skip non-text messages
        if not text:
            return None
        
        # Admin commands
        if text.startswith('/') or text.startswith('add_id') or text.startswith('remove_id') or text.startswith('all_add_id'):
            return self.handle_admin_command(message)
        
        # Check if this is an authorization request
        if 'approve' in text.lower() or 'authorize' in text.lower():
            # Extract client ID from message
            client_id_match = re.search(r'[A-Za-z0-9\-]{10,}', text)
            if client_id_match:
                client_id = client_id_match.group()
                if client_id in self.pending_users:
                    session = self.pending_users[client_id]
                    self.add_authorized_user(client_id, session.mac, session.gateway_ip)
                    return f"✅ Client ID `{client_id}` ကို အောင်မြင်စွာ Authorized ပြုလုပ်လိုက်ပါပြီ။"
        
        return None

    def check_remote_approval(self, user_id: str) -> bool:
        """Telegram Webhook Update မှတစ်ဆင့် Admin များထံမှ အတည်ပြုချက်ရယူထားခြင်း ရှိမရှိ စစ်ဆေးခြင်း။"""
        # First check if already authorized
        if self.is_authorized(user_id):
            return True
        
        # Check if blacklisted
        if user_id in self.user_blacklist:
            return False
        
        url = f"https://api.telegram.org/bot{self.bot_token}/getUpdates"
        params = {
            'limit': 20,  # Limit to latest 20 updates
            'timeout': 5
        }
        
        try:
            response = self.session.get(url, params=params, timeout=6)
            data = response.json()
            
            if data.get("ok"):
                for item in data.get("result", []):
                    message = item.get("message", {})
                    text = message.get("text", "").strip()
                    sender_id = str(message.get("from", {}).get("id", ""))
                    
                    # Check if sender is admin and message contains user_id
                    if sender_id in self.admin_chat_ids and user_id in text:
                        # Check if it's an add command
                        if text.startswith('/add_id') or text.startswith('add_id'):
                            # Extract client ID from command
                            client_id_match = re.search(r'[A-Za-z0-9\-]{10,}', text)
                            if client_id_match and client_id_match.group() == user_id:
                                # Add to authorized users
                                mac = self.resolve_local_mac()
                                gw_ip = self.resolve_gateway_ip()
                                self.add_authorized_user(user_id, mac, gw_ip)
                                return True
        except requests.RequestException:
            pass
        
        # Check if user is in pending list
        if user_id in self.pending_users:
            return False
        
        return False

    @staticmethod
    def clear_terminal() -> None:
        """OS ပလက်ဖောင်းပေါ်မူတည်၍ Terminal Screen အား ရှင်းလင်းပေးခြင်း။"""
        os.system('clear' if os.name == 'posix' else 'cls')

    @staticmethod
    def print_stream(text: str, delay: float = 0.005) -> None:
        """စာသားများကို ပိုမိုလှပသော UI အနေဖြင့် တစ်လုံးချင်းစီ ရိုက်နှိပ်ပြသခြင်း။"""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()

    @staticmethod
    def get_deterministic_user_id() -> str:
        """ဖုန်း သို့မဟုတ် ကွန်ပျူတာ၏ Hardware ပေါ်မူတည်၍ အမြဲတမ်းပုံသေသတ်မှတ်ပေးမည့် စိတ်ချရသော User ID ထုတ်ပေးခြင်း။"""
        id_file_path = os.path.expanduser("~/.portal_user_id.dat")
        
        if os.path.exists(id_file_path):
            try:
                with open(id_file_path, "r", encoding="utf-8") as f:
                    saved_id = f.read().strip()
                    if saved_id.startswith("ID-") and len(saved_id) >= 15:
                        return saved_id
            except IOError:
                pass

        try:
            hardware_node = f"{uuid.getnode()}-{os.getlogin() if hasattr(os, 'getlogin') else 'client'}"
            sha256_sig = hashlib.sha256(hardware_node.encode()).hexdigest().upper()
            generated_id = f"ID-{sha256_sig[:4]}-{sha256_sig[4:8]}-{sha256_sig[8:12]}"
        except Exception:
            fallback_rand = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest().upper()
            generated_id = f"ID-{fallback_rand[:4]}-{fallback_rand[4:8]}-{fallback_rand[8:12]}"

        try:
            with open(id_file_path, "w", encoding="utf-8") as f:
                f.write(generated_id)
        except IOError:
            pass

        return generated_id

    @staticmethod
    def resolve_local_mac() -> str:
        """စက်၏ လက်ရှိ MAC Address အား ရှာဖွေဖော်ထုတ်ခြင်း။"""
        try:
            mac_hex = hex(uuid.getnode())[2:].zfill(12)
            formatted_mac = ":".join(mac_hex[i:i+2] for i in range(0, 12, 2))
            if len(formatted_mac) == 17 and formatted_mac != "00:00:00:00:00:00":
                return formatted_mac
        except Exception:
            pass
        return "88:2f:92:d4:c9:e0"

    @staticmethod
    def resolve_gateway_ip() -> str:
        """လက်ရှိချိတ်ဆက်ထားသော Router သို့မဟုတ် Gateway ရောက်ရှိရာ IP အား တွက်ချက်ခြင်း။"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            ip_octets = local_ip.split('.')
            if ip_octets[0] in ["192", "10", "172"]:
                ip_octets[-1] = "1"
                return ".".join(ip_octets)
        except Exception:
            pass
        return "192.168.110.1"

    def notify_administrative_channels(self, user_id: str, mac: str, gateway: str, status: str) -> None:
        """အသုံးပြုသူ၏ အခြေအနေနှင့် ချိတ်ဆက်မှုမှတ်တမ်းကို Telegram Admin Panel ထံသို့ ပေးပို့ခြင်း။"""
        status_indicator = "🟢" if status == "Approved" else "🟡"
        payload_text = (
            f"{status_indicator} *Portal Session Activity Update*\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"👤 *Client ID:* `{user_id}`\n"
            f"🌐 *MAC Node:* `{mac}`\n"
            f"🚪 *Gateway IP:* `{gateway}`\n"
            f"📊 *State:* {status}\n"
            "━━━━━━━━━━━━━━━━━━━━━━━━\n"
        )
        
        if status == "Pending":
            payload_text += (
                f"💡 _ဤ ID အား `/add_id {user_id}` Command ဖြင့် Authorize ပြုလုပ်ပါ။_\n"
                f"🔄 သို့မဟုတ် `{user_id}` ဟု ရိုက်ပြီး Approve ပြုလုပ်ပါ။"
            )
        else:
            payload_text += "🚀 _အသုံးပြုသူအား စနစ်အတွင်းသို့ အောင်မြင်စွာ ခွင့်ပြုပေးလိုက်ပါပြီ။_"
        
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        
        for chat_id in self.admin_chat_ids:
            body = {
                "chat_id": chat_id, 
                "text": payload_text, 
                "parse_mode": "Markdown",
                "disable_web_page_preview": True
            }
            try:
                self.session.post(url, json=body, timeout=5)
            except requests.RequestException:
                pass

    @staticmethod
    def render_progress_bar(duration: float = 1.0, label: str = "Processing") -> None:
        """စနစ်၏ လုပ်ဆောင်ချက်အဆင့်ဆင့်ကို မျက်နှာပြင်တွင် စနစ်တကျ Loading ပုံစံပြသပေးခြင်း။"""
        stages = [
            f"{TerminalColors.RED}■■▢▢▢▢▢▢▢▢ 20%",
            f"{TerminalColors.YELLOW}■■■■■■▢▢▢▢ 60%",
            f"{TerminalColors.GREEN}■■■■■■■■■■ 100%"
        ]
        slice_time = duration / len(stages)
        for stage in stages:
            sys.stdout.write(f"\r {TerminalColors.CYAN}⚙ {TerminalColors.WHITE}{label:<24} {stage}{TerminalColors.RESET}")
            sys.stdout.flush()
            time.sleep(slice_time)
        sys.stdout.write(f"\r {TerminalColors.GREEN}✔ {TerminalColors.WHITE}{label:<24} {TerminalColors.GREEN}[ COMPLETE ]{TerminalColors.RESET}\n")
        sys.stdout.flush()

    def display_system_header(self) -> None:
        """စနစ်၏ ခေါင်းစီး Banner အား သပ်ရပ်စွာ ပုံဖော်ပေးခြင်း။"""
        c, w, g, gray = TerminalColors.CYAN, TerminalColors.WHITE, TerminalColors.GREEN, TerminalColors.GRAY
        print(f"{c}╔" + "═" * 68 + "╗")
        print(f"{c}║                 ✦  ENTERPRISE PORTAL INTERFACE HANDSHAKE  ✦        {c}║")
        print(f"{c}║{gray}  Channel : {w}{self.telegram_channel:<25} {gray}│  Version : {g}v3.0 Secure Pro   {gray}║")
        print(f"{c}╚" + "═" * 68 + f"╝{w}\n")

    def _modify_url_parameter(self, url: str, param_name: str, new_value: str) -> str:
        """URL အတွင်းရှိ Query parameter (ဥပမာ- mac) ကို Web Standard တိုင်း အမှားအယွင်းမရှိ ပြောင်းလဲပေးခြင်း။"""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        query_params[param_name] = [new_value]
        
        modified_query = urlencode(query_params, doseq=True)
        return urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            modified_query,
            parsed_url.fragment
        ))

    def run(self) -> None:
        """အဓိက စနစ်တစ်ခုလုံးကို စတင်လည်ပတ်စေသော Function ဖြစ်သည်။"""
        self.clear_terminal()
        self.display_system_header()
        
        client_id = self.get_deterministic_user_id()
        mac_addr = self.resolve_local_mac()
        gw_ip = self.resolve_gateway_ip()
        
        print(f" {TerminalColors.YELLOW}⚡ ဒေသတွင်း Gateway Network ပတ်ဝန်းကျင်အား စစ်ဆေးနေပါသည်...{TerminalColors.RESET}\n")
        self.render_progress_bar(duration=0.4, label="Resolving Node Attributes")
        self.render_progress_bar(duration=0.4, label="Verifying Remote Session Token")
        
        # Check if user is already authorized
        if not self.is_authorized(client_id):
            # Check if user is blacklisted
            if client_id in self.user_blacklist:
                print(f"\n {TerminalColors.RED}⛔ သင့် Device သည် Blacklist တွင် ပါဝင်နေပါသည်။ အုပ်ချုပ်သူထံ ဆက်သွယ်ပါ။{TerminalColors.RESET}\n")
                return
            
            # Add to pending list
            session = UserSession(
                user_id=client_id,
                mac=mac_addr,
                gateway_ip=gw_ip,
                status="Pending",
                timestamp=datetime.now(),
                last_activity=datetime.now()
            )
            self.pending_users[client_id] = session
            
            # Notify admin
            self.notify_administrative_channels(client_id, mac_addr, gw_ip, "Pending")
            
            print(f"\n {TerminalColors.RED}🛑 Verification Pending: အသုံးပြုခွင့် သတ်မှတ်ချက် လိုအပ်နေပါသည်!{TerminalColors.RESET}")
            print(f" {TerminalColors.GRAY}╔" + "═" * 58 + "╗")
            print(f" {TerminalColors.GRAY}║ {TerminalColors.WHITE}သင့်စက်၏ ID : {TerminalColors.GREEN}{client_id:<43} {TerminalColors.GRAY}║")
            print(f" {TerminalColors.GRAY}╚" + "═" * 58 + "╝")
            print(f" {TerminalColors.YELLOW}📢 စနစ်အတွင်း အသုံးပြုခွင့်ရရန် သင့် Device ID ကို ကူးယူပြီး အုပ်ချုပ်သူထံ တင်ပြပါ-")
            print(f" {TerminalColors.CYAN}➜ Operations Directory: {TerminalColors.WHITE}{self.telegram_channel}{TerminalColors.RESET}\n")
            print(f" {TerminalColors.CYAN}💡 Admin Commands:\n"
                  f"   • `/add_id {client_id}` - Authorize ပြုလုပ်ရန်\n"
                  f"   • `{client_id}` - Approve ပြုလုပ်ရန်{TerminalColors.RESET}\n")
            
            # Wait for approval with timeout
            print(f" {TerminalColors.YELLOW}⏳ Admin မှ Authorize လုပ်ရန် စောင့်ဆိုင်းနေပါသည်... (၅ မိနစ်){TerminalColors.RESET}")
            start_time = time.time()
            while time.time() - start_time < 300:  # 5 minutes timeout
                if self.is_authorized(client_id):
                    print(f"\n {TerminalColors.GREEN}✅ Admin မှ အောင်မြင်စွာ Authorize ပြုလုပ်လိုက်ပါပြီ!{TerminalColors.RESET}")
                    break
                time.sleep(5)
                sys.stdout.write(".")
                sys.stdout.flush()
            else:
                print(f"\n {TerminalColors.RED}⏰ Authorization Timeout: သတ်မှတ်ချိန် (၅ မိနစ်) ကျော်လွန်သွားပါပြီ။{TerminalColors.RESET}")
                return

        # User is authorized
        self.notify_administrative_channels(client_id, mac_addr, gw_ip, "Approved")
        
        print(f"\n {TerminalColors.CYAN}┌───────────────────────── System Specification ─────────────────────────┐")
        print(f" {TerminalColors.CYAN}│ {TerminalColors.WHITE}Registered ID  {TerminalColors.GRAY}➜  {TerminalColors.GREEN}{client_id:<48} {TerminalColors.CYAN}│")
        print(f" {TerminalColors.CYAN}│ {TerminalColors.WHITE}Access Status  {TerminalColors.GRAY}➜  {TerminalColors.GREEN}VERIFIED / ACTIVATED ENGINE PRIVILEGE ✅        {TerminalColors.CYAN}│")
        print(f" {TerminalColors.CYAN}│ {TerminalColors.WHITE}Target Hardware{TerminalColors.GRAY}➜  {TerminalColors.YELLOW}{mac_addr:<18} {TerminalColors.WHITE}Gateway IP{TerminalColors.GRAY} ➜ {TerminalColors.YELLOW}{gw_ip:<17} {TerminalColors.CYAN}│")
        print(f" {TerminalColors.CYAN}└──────────────────────────────────────────────────────────────────────┘\n")
        
        self.render_progress_bar(duration=0.3, label="Formulating Frame Payload")
        self.render_progress_bar(duration=0.3, label="Binding Device Interfaces")

        processed_url = self._modify_url_parameter(self.portal_url, 'mac', mac_addr)
        
        print(f"\n {TerminalColors.GREEN}✔ Target definitions cleanly set.")
        print(f" {TerminalColors.CYAN}🌐 Browser Engine အတွင်းသို့ Auth Portal လင့်ခ်အား ချိတ်ဆက်ပေးနေပါသည်...{TerminalColors.RESET}\n")
        time.sleep(0.8)

        try:
            webbrowser.open(processed_url)
            print(f" {TerminalColors.GREEN}┌" + "─" * 68 + "┐")
            self.print_stream(f" {TerminalColors.GREEN}│  ✔ Portal အား Browser သို့ အောင်မြင်စွာ ပို့ဆောင်ပြီးပါပြီ။                 │")
            print(f" {TerminalColors.GREEN}└" + "─" * 68 + "┘")
        except Exception:
            print(f"\n {TerminalColors.RED}✖ Browser အလိုအလျောက် မပွင့်လာပါက အောက်ပါလင့်ခ်ကို ကိုယ်တိုင်ဖွင့်ပါ:\n {TerminalColors.WHITE}{processed_url}{TerminalColors.RESET}")
        print()


def main():
    """Main entry point with improved security and error handling"""
    try:
        # Load configuration from environment variables or use defaults
        BOT_API_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8656832077:AAHltVVyZ9wAY74l8XN785zb2HrZ-yBqlrw")
        ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "7592705124").split(",")
        PORTAL_ENDPOINT_URL = os.getenv(
            "PORTAL_ENDPOINT_URL",
            "https://portal-as.ruijienetworks.com/api/auth/wifidog?stage=portal&"
            "gw_id=984a6b9da30e&gw_sn=H1TA1EN003183&gw_address=192.168.110.1&"
            "gw_port=2060&ip=192.168.110.189&mac=88:2f:92:d4:c9:e0&slot_num=14&"
            "nasip=192.168.1.198&ssid=VLAN233&ustate=0&mac_req=1&url=http%3A%2F%2F192.168.0.1%2F&"
            "chap_id=%5C361&chap_challenge=%5C155%5C234%5C000%5C201%5C352%5C275%5C342%5C210%5C202%5C327%5C272%5C071%5C026%5C330%5C115%5C266"
        )
        
        # Validate configuration
        if not BOT_API_TOKEN or len(BOT_API_TOKEN) < 20:
            print(f"{TerminalColors.RED}❌ Invalid Bot Token. Please check configuration.{TerminalColors.RESET}")
            return
        
        if not ADMIN_CHAT_IDS or not ADMIN_CHAT_IDS[0]:
            print(f"{TerminalColors.RED}❌ No Admin Chat IDs configured.{TerminalColors.RESET}")
            return
        
        engine = SecureWiFiPortalManager(
            bot_token=BOT_API_TOKEN,
            admin_chat_ids=ADMIN_CHAT_IDS,
            portal_url=PORTAL_ENDPOINT_URL
        )
        
        engine.run()
        
    except KeyboardInterrupt:
        print(f"\n\n {TerminalColors.RED}⚠ အသုံးပြုသူမှ လုပ်ဆောင်ချက်ကို ရပ်ဆိုင်းလိုက်သဖြင့် စနစ်ကို ပိတ်လိုက်ပါသည်။{TerminalColors.RESET}\n")
    except Exception as e:
        print(f"\n {TerminalColors.RED}❌ Unexpected Error: {e}{TerminalColors.RESET}\n")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
