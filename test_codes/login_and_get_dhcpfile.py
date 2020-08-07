import subprocess

if __name__=='__main__':
	subprocess.call('scp -r root@192.168.1.1://tmp/dhcp.leases . ', shell=True)
