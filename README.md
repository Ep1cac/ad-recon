# AD-Recon
## Description
A tool that streamlines Active Directory security auditing. It performs a pass-the-password attack leveraging a set of valid credentials on hosts on the subnet and attempts to crack additional passwords that are found.

Current version is a prototype.

## Usage
```bash
sudo -t <subnet> -u <username> -p <password> -w <wordlist> 
```

