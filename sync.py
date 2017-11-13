#!/usr/bin/env python

# Script to sync data from irma3 into the cluster.
#
# Will sync everything under /lupus/ngi on irma3 (except the irma3
# subdir) to /lupus/ngi on irma1. An other dest path can be given as arg1.  
#
# Note that: 
# 
# 1. This script assumes that all files to be populated are owned by group ngi-sw
# and with appropriate file permissions (group read/write, world read). This should
# be the case if the deployment bash init file have been sourced before installing sw. 

import pexpect 
import sys
import getpass 
import subprocess 
import argparse 

# TODO: Need to catch wrong token or wrong password. 
# TODO: Lots of errors that can go wrong.

# Execute SSH command to disable two factor.  
def disable_twofactor(user, host, password, token): 
	ssh_cmd = "ssh {0}@{1}".format(user, host)
	child = pexpect.spawn(ssh_cmd)
	send_password(child, user, host, password)
	send_token(child, user, host, token)

# Expect a password prompt and send our collected password
def send_password(user, host, password):  
	exp_pass = "{0}@{1}'s password:".format(user, host)
	child.expect(exp_pass)
	print('Sending SSH password')
	child.sendline(password)

# Expect a token prompt and send our collected token; 
# then expect a bash prompt. Or expect a bash prompt 
# immediately if our token grace period is enabled. 
def send_token(user, host, token): 
	exp_token = "Please enter the current code from your second factor:.\r\n"
	exp_success = ".*\$ " # Matches the end of a bash prompt 

	recv = child.expect([exp_token, exp_success])

	if recv == 0:
		print('Sending SSH token') 
		child.sendline(token)
		print('Waiting for success')
		child.expect(exp_success)
		child.sendline("Logged in with password + factor, logging out.") 
		child.sendline("exit")
	elif recv == 1:
		print('Logged in with password, logging out.')
		child.sendline("exit")

def signal_new_env(user, host, password, token): 
	signal_new_env = "/usr/bin/ssh {}@{} 'touch /tmp/.new_irma_env_deployed && chgrp ngi-sw /tmp/.n    ew_irma_env_deployed'".format(user, host)
	child = pexpect.spawn(signal_new_env)
	send_password(child, user, host, password)
	send_token(child, user, host, token)

def yes_or_no(question):
	reply = str(raw_input(question+' (y/n): ')).lower().strip()
  
	if reply[0] == 'y':
		return True
	if reply[0] == 'n':
		return False
	else:
		return yes_or_no("Please enter ")

# Find files which are not: 
#		- owned by group ngi-sw
#   - readable and writeable by group
#   - readable by world 
# Prompt the user if (s)he wants to continue anyway. 
def check_file_attributes(src_root_path): 
	print('Searching for files that are 1) not owned by group ngi-sw, 2) group readable/writable, 3) world readable')
	find_cmd = "/bin/bash -c 'find {0} ! -perm -g+rw -ls -or ! -perm -o+r -ls -or ! -group ngi-sw -ls -or ! -name wildwest -d | egrep -v \"\.swp|/lupus/ngi/irma3/\"'".format(src_root_path)

	perm_output = 0
	wrong_perm = False

	try: 
		perm_output = subprocess.check_output(find_cmd, shell=True, stderr=subprocess.STDOUT)
	except subprocess.CalledProcessError as e:
		# FIXME: grep returns 1 when it doesn't find any matches, so this will 
		# have to do for now if we want to ignore the error. Could cause problems 
		# if the find process itself would return an error code > 0 though. 
		# So a better solution is probably suitable later. 
		if e.returncode != 1:   
			print "An error occured with the find subprocess!"
			print "returncode", e.returncode
			print "output", e.output

	if isinstance(perm_output, str):
		print "Some files have wrong permissions:"
		print perm_output

		choice = yes_or_no("Do you want to continue syncing anyway? ")

		if choice:
			print "All right, will sync anyway."
			wrong_perm = True
		else: 
			print "All right, aborting."
			sys.exit()

	else: 
		print "Everything looks OK. Continuing with rsync."


# Sync our destignated folders.
def sync_to_cluster(user, host, password, src_root_path, dest, rsync_log_path): 
	excludes = "--exclude=*.swp --exclude=irma3/"
	rsync_cmd = "/bin/rsync -avzP --omit-dir-times --delete {0} --log-file={1} {2} {3}@{4}:{5}".format(excludes, rsync_log_path, src_root_path, user, host, dest) 
	# TODO: Do this cleaner? 
	dry_cmd = "/bin/rsync --dry-run -avzP --omit-dir-times --delete {0} {1} {2}@{3}:{4}".format(excludes, src_root_path, user, host, dest) 

	# First doing a dry-run to confirm sync. 
	print('Initiating a rsync dry-run')
	child = pexpect.spawn(dry_cmd)
	child.expect(exp_pass) 
	print('Sending dry-run password')
	child.sendline(password)
	child.interact()
	child.close()

	choice = yes_or_no("Dry run finished. Do you wish to perform an actual sync of these files? ")

	if choice:
		print "All right, will continue to sync."
	else:
		print "All right, aborting."
		sys.exit()

	print "Running", rsync_cmd

	with open(rsync_log_path, 'a') as rsync_log: 
		rsync_log.write("\n\nUser {0} started sync with command {1}\n".format(user, rsync_cmd))

		if wrong_perm: 
			rsync_log.write("!! WARNING !! Sync was initiated although some files had wrong permission: \n")
			rsync_log.write(perm_output + "\n")
 
		child = pexpect.spawn(rsync_cmd)
		child.expect(exp_pass)
		print('Sending rsync password')
		child.sendline(password)
		child.interact()
		child.close() # needed to get exit signal 

	with open(rsync_log_path, 'a') as rsync_log:
		# TODO: This might not be correct. Could get it to work with catching child.signalstatus
		# and child.exitstatus according to https://pexpect.readthedocs.org/en/stable/api/pexpect.html#spawn-class
		# so I've just tried manually to see what the status code gets set to when an interactive rsync has been
		# Ctrl-C'd. 
		if child.status == 65280:
			rsync_log.write("Sync initiated by {0} prematurely aborted (^C): {1}\n".format(user, child.status))
			print "Sync prematurely aborted (^C): {0}".format(child.status)
		else:
			rsync_log.write("Sync initiated by {0} fully completed.\n".format(user))	
			print "Sync fully completed!"

def get_token(msg): 
  return raw_input(msg)

def get_credentials(): 
	password = getpass.getpass("Enter your UPPMAX password: ")
	token = get_token("Enter your second factor: ")
	return (password, token)

if __name__ == '__main__': 
	parser = argparse.ArgumentParser()
	parser.add_argument("environment", choices=["production", "staging"], help="which environment to sync     over")
	parser.add_argument("-d", "--destination", help="the non-standard destination path on the remote host     to sync to")
	args = parser.parse_args()
 
	ngi_root = "/lupus/ngi/"
	src_root_path = ngi_root + args.environment + "/"
 
	if args.destination:
		dest = args.destination
	else:
		dest = src_root_path

	host = "irma2"
 	rsync_log_path = ngi_root + "/irma3/log/rsync.log"
 	user = getpass.getuser()

	password, token = get_credentials()
	disable_twofactor(user, host, password, token)
	check_file_attributes(src_root_path)	
	sync_to_cluster(user, host, src_root_path, dest, rsync_log_path)

	# Uppsala need to relaunch their services that are run in their crontab
  # when a new Irma environment has been deployed in production. Therefore we
  # here signal it by touching a file which a crontabbed job will pick up 
  # (which will reload everything for the correct user). Unfortunately the 
	# twofactor grace period is only 10 minutes, and as it will take longer than
	# that for the rsync to complete we have to prompt the user for the two factor 
	# again. We could signal the new env before launching the rsync, but that is 
	# not really robust, as the rsync might abort prematurely, and the services 
	# will also try to restart before the sync is finished.
	if args.environment == "production": 
		print "We will now signal the cluster that the new production environment has been deployed."
		token = get_token("Enter your second factor again: ")
		disable_twofactor(user, host, password, token)
		signal_new_env(user, host, password, token)
		print "Successfully signaled a new version deployed." 
