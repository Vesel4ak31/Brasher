# Brasher
Brasher is a free dictionary-based brute-force attack tool written in Python. It can test 10 protocols and perform post-exploitation, including executing arbitrary code on a machine, running an arbitrary exploit from a file, and downloading and uploading files. Shell mode is also supported for some protocols. When testing SSH, after obtaining login credentials, you can also attempt to gain persistence in the system by specifying the --persist flag.

<img width="908" height="208" alt="изображение" src="https://github.com/user-attachments/assets/bccf26f7-7e24-4dec-adc0-643a2a7ee06d" />

# Installation

```
git clone https://github.com/Vesel4ak31/Brasher.git
cd Brasher
pip install -r requirements.txt --break-system-packages
```

To view all 51 of the tool's parameters, run:

```
python3 brasher.py -h
```


FLAG                       | DESCRIPTION
---------------------------|---------------------------------------------------------------------------
--host                     | Target host for the attack
-P, --passwords-list       | File containing a list of passwords (one per line)
-U, --usernames-list       | File containing a list of usernames (one per line)
-t, --timeout              | Timeout between connection attempts (default: 0.1s)
-u, --single-username      | Single username for the brute-force attack
-p, --single-password      | Single password for the brute-force attack
-G, --general-wordlist     | Wordlist file in `username:password` format (overrides -P and -U)
-sr, --save-results        | Save successful credentials to a file
-d, --delay                | Delay before starting the attack (seconds)
-shuc, --shuffle-count     | Number of times to shuffle the password list (default: 10)
--seed, --shuffle-seed     | Custom seed for shuffling (integer)
-ssf, --shuffle-seeds-file | File containing seeds (one per line)
-su, --shuffle-usernames   | Shuffle the usernames list before starting
-sp, --shuffle-passwords   | Shuffle the passwords list before starting
-sc, --shuffle-configs     | Shuffle OpenVPN config files before starting
-sk, --shuffle-keys        | Shuffle SSH keys before starting
-sh, --shuffle-hosts       | Shuffle the hosts list before starting
-ss, --shuffle-seeds       | Shuffle the seeds list before starting
-q, --quiet                | Disable all console output (only logs)
-b, --banner               | Show the banner and exit
-thr, --threads            | Number of threads to use (default: 5)
-pb, --progress-bar        | Show a progress bar during brute-force
-npb, --no-progress-bar    | Disable the progress bar
-pt, --port                | Port for the connection (default: 22)
-mr, --max-retries         | Maximum number of reconnection attempts
-o, --output-file          | File to write logs to
-nl, --no-log              | Disable logging
-ko, --keep-open           | Keep the connection open after successful login
-e, --exec, --execute      | Execute a command after successful authentication
-rt, --random-timeout      | Random timeout range (e.g., 0.5-2.5)
-ht, --host-timeout        | Timeout between testing different hosts
-ie, --ignore-errors       | Ignore errors and continue execution
-so, --success-only        | Show only successful attempts in output
-mt, --max-time            | Maximum runtime before exiting
-nc, --no-color            | Disable colored output
-m, --mode                 | Protocol mode: ssh, ftp, smb, telnet, mysql, postgres, redis, mongodb, pop3, ssh-key, openvpn
--log-mode                 | Log mode: w (overwrite) or a (append)
-H, --hosts-list           | File containing a list of target hosts (one per line)
--ssh-key                  | Path to a single SSH private key (for ssh-key mode)
-kl, --keys-list           | File containing paths to SSH private keys
-nb, --no-banner           | Skip displaying the banner
-s5a, --socks5-address     | SOCKS5 proxy IP address
-s5p, --socks5-port        | SOCKS5 proxy port
-s5u, --socks5-username    | SOCKS5 proxy username (if required)
-s5pass, --socks5-password | SOCKS5 proxy password (if required)
-s, --stop-on-success      | Stop after finding one valid credential pair
-time, --timer             | Display execution time at the end
-ru, --reverse-usernames   | Reverse the usernames list order
-rp, --reverse-passwords   | Reverse the passwords list order
-rc, --reverse-configs     | Reverse the OpenVPN configs list order
-rk, --reverse-keys        | Reverse the SSH keys list order
-rh, --reverse-hosts       | Reverse the hosts list order
-rs, --reverse-seeds       | Reverse the seeds list order
--min-length-username      | Minimum length of username to test
--max-length-username      | Maximum length of username to test
--min-length-password      | Minimum length of password to test
--max-length-password      | Maximum length of password to test
-nd, --no-duplicates       | Remove duplicate entries from wordlists
-db, --delay-between       | Delay (seconds) between attempts on the same host
-vf, -ovcf, --open-vpn-config-file | OpenVPN configuration file
-vu, -ovu, --open-vpn-username | Username for OpenVPN
-vp, -ovp, --open-vpn-password | Password for OpenVPN
-vc, -ovc, --open-vpn-connect | Connect via OpenVPN (flag)
-cw, -ovcfw, --open-vpn-config-file-wordlist | File with OpenVPN config paths
-uw, -ovuw, --open-vpn-usernames-wordlist | File with OpenVPN usernames
-pw, -ovpw, --open-vpn-passwords-wordlist | File with OpenVPN passwords
-ex, --exploit             | Execute commands from a specified exploit file
-uft, --upload-file-to     | Remote path for file upload
-dft, --download-file-to   | Local path for file download
-uff, --upload-file-from   | Local path for file upload
-dff, --download-file-from | Remote path for file download
--shell                    | Open an interactive shell after authentication
--persist                  | Install SSH key for persistent access (default: ~/.ssh/id_rsa.pub)
-j, --jitter               | Add jitter (random deviation) to timeout
-tp, --telnet-prompt       | Telnet prompt character (default: $)
--smb-client-name          | SMB client name (default: SMBuser)
--smb-server-name          | SMB server name (default: SMBServer)
--smb-share-name           | SMB share name (default: share)
--smb-remote-path          | Remote path for SMB (default: /)
--smb-domain               | SMB domain (if required for NTLM auth)


<img width="2280" height="1143" alt="изображение" src="https://github.com/user-attachments/assets/7631722c-a667-470a-91b8-cfe665f71a7c" />


# Use case

This tool can be safely used for brute-force attacks against wordlists. Below is an example of a typical command:

```
python3 brasher.py -u "root" -p 'EhGe1hK5400qjFgYqtRcdcNOg3efdmyOHT' --host 85.204.18.112 --mode "ssh" --port 22 --timeout 0.4 -e "cat .ssh"
```

<img width="806" height="289" alt="изображение" src="https://github.com/user-attachments/assets/7c5ce386-efc1-4e60-8d9d-ef12a4523ed0" />

This example demonstrates a typical usage scenario. Brasher's entire output is fairly minimal. Important note: the more threads, the greater the load on your system. If you use too many threads during real attacks, the intrusion detection system (IDS) will quickly block you.
For smooth operation, be sure to use the --random-timeout flag to specify the random timeout radius during testing, the --delay-between flag to set delays between tests, and the very interesting --shuffle-* flags, which will shuffle your wordlists as many times as necessary. You can fine-tune which wordlists to shuffle and which not: for example, if you only want to shuffle a list of passwords, use the --shuffle-passwords flag. The number of shuffles can be specified using the --shuffle-count flag.
A similar scheme works with the --reverse-* flags. You can reverse any wordlist you need. For example, if you want to reverse only a list of usernames, specify the --reverse-usernames flag. You can also remove duplicates from wordlists by specifying the --no-duplicates flag.
In addition to the convenient shuffling and reversal system, you can filter the maximum and minimum character lengths of usernames or passwords. For example, by specifying the --min-length-username 1 and --max-length-username 10 flags, Brasher will remove all usernames longer than 10 characters.

<img width="718" height="362" alt="изображение" src="https://github.com/user-attachments/assets/17b008b7-bd6f-4c11-8a01-7cae84cee00b" />


You can also use a SOCKS5 proxy. This is done with the --socks5-address, --socks5-port, --socks5-username, and --socks5-password flags. You can start the Tor service and attack through it simply by specifying the address and port. If you want to use a private proxy, you can also specify the username and password.
To reduce the likelihood of being blocked by IDS, I recommend using the --random-timeout, --host-timeout, --delay-between, --jitter, and --max-time flags. The first flag allows you to specify a range of timeout values. --host-timeout controls the timeout when testing multiple hosts. You can also specify a list of hosts to test using the --hosts-list flag. --delay-between adds delays before testing, --jitter adds an additional delay to the current delay, and --max-time allows you to specify a specific execution time. Here is an example command with all these flags. In addition to the above, it is recommended to specify the --shuffle-* and --reverse-* flags, as they eliminate patterns that might otherwise be revealed by viewing logs:

```
python3 brasher.py --hosts-list "hosts.txt" -P "passwords.txt" -U "users.txt" --random-timeout "1-30" --host-timeout 300 --delay-between 4 --max-time 300 --shuffle-usernames --shuffle-passwords --reverse-usernames --reverse-passwords --jitter -0.5 --socks5-address "88.204.41.118" --socks5-port 61837 --socks5-username "SM2GT7Je" --socks5-password "rZjc6DYh"
```
<img width="641" height="77" alt="изображение" src="https://github.com/user-attachments/assets/c0f15e4b-7bda-49b8-b39c-bdc41198b8f4" />

When using the -u and -p flags, you can specify only one username or password for testing. You can also use the --stop-on-success flag to terminate the test once the credentials are detected.
I'd like to mention a few more important flags.
The --general-wordlist flag is also very useful. Instead of two wordlists, you can specify a single list in which usernames and passwords are written in the format "username:password." This way, you don't have to waste time specifying two separate lists.
Another useful flag is --ignore-errors. It allows you to ignore program errors and continue running. If you specify the --quiet flag, nothing will be output to the console except for log entries. There are other flags, such as --banner and --no-banner, which display a banner and terminate the program, or hide it and continue running. There's also the --delay flag, which adds a delay before starting the program.

# Brute-Forcing with SSH Keys

Brasher supports brute-force mode using SSH keys. To do this, specify the --ssh-key flag. This is essentially the same as the --single-password flag: you just need to specify the path to the key file, and Paramiko will automatically detect its type. After specifying a list of usernames and the target key, the brute-force process begins.
You can also use the --keys-list flag, which is similar to --passwords-list. In this case, specify the paths to the target keys in the corresponding column. I decided to separate this mode into a separate paragraph because it's essentially a hack: in the main code, the key is actually substituted into the password field. This can be confusing when analyzing the code, so I thought it worth mentioning. You can use --passwords-list instead of --keys-list, and the result will be the same, but I don't see the point unless you're really lazy.

# Connecting and Bruteforcing OpenVPN

Yes, this feature has been available since the latest update. You can now connect to OpenVPN to hide your IP address using a username and password, as well as a configuration file. To specify that you want to connect to the VPN, be sure to include the --open-vpn-connect flag. To specify a single configuration file, use the --open-vpn-config-file flag, and to specify a list of configuration files, use the --open-vpn-config-file-wordlist flag. Important: The two flags above are separate parameters and are not substituted for --passwords-list.
To specify the OpenVPN username and a list of usernames, use the --open-vpn-username and --open-vpn-usernames-wordlist flags, respectively. The same applies to passwords: to specify the OpenVPN user password and a list of passwords, use the --open-vpn-password and --open-vpn-passwords-wordlist flags, respectively. These four flags are substituted for --usernames-list and --passwords-list. If your configuration file already contains the username and password, specifying them as separate flags is not necessary.



# Post-exploitation

Yes, Brasher can do that too. After receiving login credentials, you can specify multiple files for post-exploitation. You can simply specify --exec, and Brasher will send you the command output upon receipt, or you can specify --exploit, and simply select your file with commands to execute. You can also upload and download files to the target server. These features are only available for SSH, FTP, and SMB. You can download or upload any file. You can also enable shell mode. This feature is only available for SSH, FTP, and Telnet. This mode is essentially just an environment for processing your commands. Important: if you enter non-existent commands, shell mode may hang.
Another cool feature is the --persist flag. This flag is only supported over SSH. When specified, Brasher will attempt to add your key to the SSH key authentication list and allow you to connect using your key. This mode has not yet been fully tested. In fact, Brasher offers excellent post-exploitation capabilities: you can perform RCE-like attacks and do anything you want. Here's an example of running Brasher with post-exploitation enabled:

```
python3 brasher.py -u "root" -p 'EhGe1hK5400qjFgFLM9SbTyJu8Yr' --host 85.204.18.112 --mode "ssh" --port 22 --timeout 0.4 --exploit "exploit.py" --upload-file-to "/root/file.py" --upload-file-from "./exploit.py" --download-file-to "/home/result.txt" --download-file-from "./root/users.json" --shell --persist
```
<img width="729" height="96" alt="изображение" src="https://github.com/user-attachments/assets/c3c07c3f-7689-4d2f-b5db-39ed64901b7e" />

# Useful Options

I'll mention a few flags here. Similar ones include: --keep-open, --timer, and --shuffle-seed.
--keep-open will maintain the connection until you manually close it. Nothing happens while the connection is held.
--timer will start a timer for the entire execution period and display the total time at the end of the program. This flag is useful for benchmarking.
--shuffle-seed allows you to specify a custom seed for shuffling the word list. It must be any positive integer. The seed parameter specifies the sorting order. Use this flag with caution, as an incorrect value can make the shuffle non-random. If you need to use multiple seed values, specify the --shuffle-seeds-file flag. You can also shuffle and reverse the same file by specifying the --shuffle-seeds and --reverse-seeds flags, respectively. Useless, but interesting.
Here's an example command to run with these flags:

<img width="601" height="106" alt="изображение" src="https://github.com/user-attachments/assets/76fa4e14-b4c3-446f-a22c-4f424d22389f" />


```
python3 brasher.py -u "root" -p 'EhGe1TyJu8Yr' --host 85.204.18.112 --mode "ssh" --port 22 --timeout 0.4 --timer --shuffle-seeds --seed 30 --reverse-seeds --keep-open
```
<img width="535" height="61" alt="изображение" src="https://github.com/user-attachments/assets/8172b70c-72d2-4401-8979-d51a3cfd1016" />

# About logging, threads, and the progress bar

Let's start with logging. You can configure it using the -o parameter. If you don't specify a log file name, Brasher will create a file named after the current date. The logs will record detailed information. The time will be recorded as accurately as possible, including five decimal places for seconds. The message type will also be displayed: for example, when testing a parameter, the word "TESTING" will appear. Next, the service being tested and the message itself are specified. This approach ensures the accuracy necessary for subsequent security checks. You can disable logging with the --no-log flag.
Now about threads. You can specify their number using the -thr flag. By default, Brasher uses 10 threads. Threads increase performance: for example, using two threads will cut the scan time in half. However, more threads means more connections, which means a higher risk of being blocked by an intrusion detection system (IDS). Therefore, avoid using too many threads, especially on slow computers. It's also important to note that the Python GIL won't allow you to create, say, 1,000,000 threads.
You can use the --progress-bar flag to display a progress bar. Since the tqdm library doesn't support multithreading, Brasher automatically disables it if the number of threads exceeds 15. Disabling this feature significantly slows down tqdm. You can also forcefully disable the progress bar using the --no-progress-bar flag. If you want to perform an effective scan with a large number of threads and avoid IDS blocking, use the flags I mentioned earlier that reduce the detection probability.Here's an example command to run with these flags:

```
python3 brasher.py -u "root" -p 'EhGe18Yr' --host 85.204.18.112 --mode "ssh" --port 22 --timeout 0.4 --timer --shuffle-seeds --seed 30 --reverse-seeds --keep-open -pb -thr 100
```

<img width="1196" height="319" alt="изображение" src="https://github.com/user-attachments/assets/c577bd80-0779-4768-b1e0-ca8afa41d1cd" />


# Disclaimer

The author is not responsible for any unauthorized use of this tool to obtain credentials. This tool is intended and should be used exclusively for legitimate security testing and service verification on servers. Do not use it for malicious purposes!

# License

This tool is distributed under the MIT License. For your convenience, I've included the license here:

```
MIT License

Copyright (c) 2026 Vesel4ak

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE THEREOF.
```

#About improving the tool



This tool is truly great. I plan to add a lot of new flags to put it on par with giants like Hydra. At a minimum, we plan to implement the --mutate flag to specify a target file containing various lines for changing logins and passwords. I think this will be very useful. I'd also like to add a --resume flag so that, like Hydra, you can pause and resume from a certain point after stopping.
Another useful feature, in my opinion, is the introduction of a search mode for S3 storages. I've only seen this in the Gobuster tool and it's a really cool feature. Accordingly, since we are talking about web testing, it would be worth adding brute force authentication for web pages (for example, login.php). This would take the tool to the next level and allow it to become similar to Wfuzz or similar solutions. I'm also considering adding a --proxy-list flag to allow me to specify a list of proxies to test. Thus, when trying to crack passwords in web forms, you can use an HTTP proxy.
To be honest, such a tool can be developed almost endlessly. You can add 200 new flags, but then their usefulness becomes questionable. I believe that my last suggestions are truly necessary. I hope this tool will be useful to someone. It tries passwords and usernames quite quickly thanks to multi-threading - this is its advantage. It can be run on powerful computers by opening multiple threads for maximum performance.
Please, if you are a GitHub user, try this tool. I assure you, you won't regret it. I know the code is still pretty crude (as of 2026) and has a lot of bugs, but I'm trying to fix them. Most options are now safe to use: they all work, although some are still buggy. Try to find at least one online password cracking tool that provides such a flexible set of parameters for security testing. It would also be nice to add support for more protocols. Ideally, the number of testing options should reach 30–50.
