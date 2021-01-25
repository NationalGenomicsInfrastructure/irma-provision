#!/usr/bin/env python

# Script to sync data from irma3 into the cluster.
#
# Will sync everything under /lupus/ngi on irma3 (except the irma3
# subdir) to /lupus/ngi on irma1. An other dest path can be given as arg1.
#
# Note that:
#
# 1. This script assumes that all files to be pupulated are owned by group ngi-sw
# and with appropriate file permissions (group read/write, world read). This should
# be the case if the deployment bash init file have been sourced before installing sw.
from __future__ import print_function

import pexpect
import sys
import getpass
import subprocess
import argparse
import os

# TODO: Need to catch wrong token or wrong password.
# TODO: Lots of errors that can go wrong.

# Step 0. Settings to fetch from user or set globally for the sync.
parser = argparse.ArgumentParser()
parser.add_argument('-e','--environment', choices=['production', 'staging'], required=True, help='which environment to sync over')
parser.add_argument('-d','--deployment', help='which deployment to sync over')
parser.add_argument('--destination', help='the non-standard destination path on the remote host to sync to')
parser.add_argument('--dryrun', action='store_true', dest='dryrun', default=False, help='do a dry run first before the actual sync')
args = parser.parse_args()

ngi_root = '/lupus/ngi/'
src_root_path = os.path.join(ngi_root, '.', args.environment) #break url for relative path
src_path_link = ''

if args.deployment:
	src_path_link = os.path.join(src_root_path, 'latest')
	src_root_path = os.path.join(src_root_path, args.deployment)

if args.destination:
	dest = args.destination
else:
	dest = ngi_root

src_containers_path = os.path.join(ngi_root, '.', 'containers') #break url for relative path

host = 'irma2'
rsync_log_path = os.path.join(ngi_root, 'irma3/log/rsync.log')

user = getpass.getuser()
password = getpass.getpass('Enter your UPPMAX password: ')
token = input('Enter your second factor: ')


# Step 1. Execute SSH command to disable two factor.
ssh_cmd = 'ssh {0}@{1}'.format(user, host)
child = pexpect.spawn(ssh_cmd)


# Step 2. Expect a password prompt and send our collected password
exp_pass = "{0}@{1}'s password:".format(user, host)
child.expect(exp_pass)
print('Sending SSH password')
child.sendline(password)


# Step 3a. Expect a token prompt and send our collected token;
#          then expect a bash prompt
# Step 3b. Expect a bash prompt immediately if our token
#          grace period is enabled.
exp_token = 'Please enter the current code from your second factor:.\r\n'
exp_success = '.*\$ ' # Matches the end of a bash prompt

recv = child.expect([exp_token, exp_success])

if recv == 0:
	print('Sending SSH token')
	child.sendline(token)
	print('Waiting for success')
	child.expect(exp_success)
	child.sendline('Logged in with password + factor, logging out.')
	child.sendline("exit")
elif recv == 1:
	print('Logged in with password, logging out.')
	child.sendline('exit')


# Step 4. Find files which are not:
#         - owned by group ngi-sw
#         - readable and writeable by group
#         - readable by world
# Prompt the user if (s)he wants to continue anyway.
print('Searching for files that are 1) not owned by group ngi-sw, 2) group readable/writable, 3) world readable')
find_cmd = "/bin/bash -c 'find {0} ! -perm -g+rw -ls -or ! -perm -o+r -ls -or ! -group ngi-sw -ls -or ! -name wildwest -d | egrep -v \"\.swp|/lupus/ngi/irma3/\"'".format(src_root_path)

def yes_or_no(question):
	reply = str(input(question+' (y/n): ')).lower().strip()

	if reply[0] == 'y':
		return True
	if reply[0] == 'n':
		return False
	else:
		return yes_or_no('Please enter ')

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
		print('An error occured with the find subprocess!')
		print('returncode', e.returncode)
		print('output', e.output)

if isinstance(perm_output, str):
	print('Some files have wrong permissions:')
	print(perm_output)

	choice = yes_or_no('Do you want to continue syncing anyway? ')

	if choice:
		print('All right, will sync anyway')
		wrong_perm = True
	else:
		print('All right, aborting.')
		sys.exit()

else:
	print('Everything looks OK. Continuing with rsync.')


# Step 5. Sync our designated folders.
print('Syncing directories:\n{}\n{}'.format(src_root_path, src_containers_path))

excludes = '--exclude=*.swp --exclude=irma3/'
rsync_cmd = '/bin/rsync -avzP --relative --omit-dir-times {0} --log-file={1} {2} {3} {4} {5}@{6}:{7}'.format(excludes,
                                                                                               rsync_log_path,
                                                                                               src_root_path,
                                                                                               src_containers_path,
                                                                                               src_path_link,
                                                                                               user,
                                                                                               host,
                                                                                               dest)
# TODO: Do this cleaner?
if args.dryrun:
	dry_cmd = '/bin/rsync --dry-run -avzP --relative --omit-dir-times {0} {1} {2} {3} {4}@{5}:{6}'.format(excludes, src_root_path, src_containers_path, src_path_link, user, host, dest)

	# Do a dry-run to confirm sync.
	print('Initiating a rsync dry-run')
	child = pexpect.spawn(dry_cmd)
	child.expect(exp_pass)
	print('Sending dry-run password')
	child.sendline(password)
	child.interact()
	child.close()

	choice = yes_or_no('Dry run finished. Do you wish to perform an actual sync of these files? ')

	if choice:
		print('All right, will continue to sync.')
	else:
		print('All right, aborting.')
		sys.exit()

print('Running', rsync_cmd)

with open(rsync_log_path, 'a') as rsync_log:
	rsync_log.write('\n\nUser {0} started sync with command {1}\n'.format(user, rsync_cmd))

	if wrong_perm:
		rsync_log.write('!! WARNING !! Sync was initiated although some files had wrong permission: \n')
		rsync_log.write(perm_output + '\n')

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
                rsync_log.write('Sync initiated by {0} prematurely aborted (^C): {1}\n'.format(user, child.status))
                print('Sync prematurely aborted (^C): {0}'.format(child.status))
	else:
		rsync_log.write("Sync initiated by {0} fully completed.\n".format(user))
		print('Sync fully completed!')
