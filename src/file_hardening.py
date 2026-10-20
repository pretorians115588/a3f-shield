"""Best-effort OS DAC/ACL hardening. Not a security boundary vs admins/malware.

On Windows Windows ACL for current user only. On POSIX chmod 0600.
Failure is fatal so partially created sensitive data is not silently exposed.
"""
import csv,io,os,subprocess

def restrict_owner(path):
    if os.name!='nt':
        os.chmod(path,0o600)
        return
    info=subprocess.check_output(['whoami','/user','/fo','csv','/nh'],text=True)
    fields=next(csv.reader(io.StringIO(info)))
    sid=fields[1].strip()
    if not sid.startswith('S-1-'):raise OSError('Cannot identify Windows owner SID')
    # Remove inherited ACLs and replace explicit ACE for this user.
    # Windows administrators and SYSTEM can still bypass or take ownership.
    subprocess.run(['icacls',str(path),'/inheritance:r','/grant:r',f'*{sid}:(F)'],
                   check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
