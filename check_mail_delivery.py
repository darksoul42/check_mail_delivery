#!/usr/bin/env python
# Check mail delivery plugin v2.1
# Version 1.0 features :
# - Confirms mail delivery from end to end, by sending e-mail and receiving random tokens
# - Also usable as a one-shot mail sending script
# - Check for specific header presence when POPing e-mails
#
# Version 2.0 improvements :
# - Now usable as a mass mail sender for stress testing a SMTP/POP chain
# - Limiting the accumulation of tokens to avoid POP meltdown
# - Multi-thread SMTP/POP phases
# - Multiple mailbox testing at the same time
# - Load list of mailboxes from a file in addition to CLI
# - Generation of a random body
# - Randomization the sender address
# - Extensive checksum validation of the sent random body
#
# Version 2.1 improvements :
# - Improved token handling
# - Added an option to consume tokens without deleting them for testing/accounting purposes
# - Improved multithread error handling
# - Fixed fatal error handling
#
# Author : Stephane LAPIE <stephane.lapie@darkbsd.org>

import getopt
import sys
import os
import time
import datetime
import smtplib
import poplib
import threading
import Queue
import socket
import re
import hashlib
import traceback
import random
import string
import getpass
import errno

from socket import AF_INET, AF_INET6
from email.utils import parsedate_tz, mktime_tz

def usage():
    print "Usage: %s [-s|--smtp-server mail.<DOMAIN>] [-p|--pop-server pop.<DOMAIN>] ([-t|--timeout 3600])" % sys.argv[0]
    print "    ([-T|--rcpt-to recipient@<DOMAIN>] [-U|--pop-username <USER>] [-P|--pop-password <PASS>] | [-i|--get-information-from])"
    print "    ([-W|--warning-delay 450] [-C|--critical-delay 1800] [-w|--warning-tokens 50] [-c|--critical-tokens 100])"
    print "    ([-H|--helo-name <uname -n>] [-F|--mail-from sender@<DOMAIN>] [-S|--subject <SUBJECT>])"
    print "    ([-L|--payload-prefix <string>] [-l|--label <LABEL>] [--show-date] [--show-mismatch-tokens])"
    print "    ([--ssl-pop] [-ssl-smtp] [-x|--no-send] [-X|--no-receive] [-D|--delay 2] [-E|--expire-token-delay 86400])"
    print "    ([-M|--locking-message 'unable to lock maildrop'] [-r|--require-headers <header1,header2,header3>])"
    print "    ([-R|--records-root /tmp/mail_check-history.u<UID>.<RECIPIENT>.<SMTP_SERVER>])"
    print "    ([-o|--performance-output] [-f|--performance-file /tmp/check_mail_delivery.rrd])"
    print "    ([-n|--num-mails 1] [-N|--num-threads 1-50])"
    print "    ([--randomize-body] [--min-message-body-size 1024] [--max-message-body-size 1048576]"
    print "    ([--max-message-size 65536] [--max-token-per-mailbox 5000] [--max-process-messages 512]"
    print "    ([--randomize-sender] [--ignore-sender-check] [--no-message-id] [--clean-mailbox] [--force-mismatch-tokens])"
    print "    ([-h|--help] [-v|--verbose] [-d|--dry-run])"
    print
    print "  Server information :"
    print "    --smtp-server, -s        mail.<DOMAIN>       The hostname of the SMTP mail server used for sending e-mails"
    print "    --pop-server, -p         pop.<DOMAIN>        The hostname of the POP3 mail server used for reading e-mails"
    print "    --timeout, -t            3600                Timeout allowed for operations"
    print
    print "  Recipient information :"
    print "    - Command line :"
    print "      --rcpt-to, -T          recipient@<DOMAIN>  Address of the recipient for sent e-mails"
    print "      --pop-username, -U     <USER>              Username for authentication against the POP3 mail server"
    print "      --pop-password, -P     <PASS>              Password for authentication against the POP3 mail server"
    print "    - Input file :"
    print "      --get-information-from, -i <LIST_FILE>     File containing a TSV list of recipients and POP username/passwords"
    print "                                                 Can be specified several times"
    print
    print "  Monitoring thresholds :"
    print "    --warning-delay, -W      450                 Delay before raising a WARNING for non-received e-mails"
    print "    --critical-delay, -C     1800                Delay before raising a CRITICAL for non-received e-mails"
    print "    --warning-tokens, -w     50                  Number of non-received tokens before raising a WARNING"
    print "    --critical-tokens, -c    100                 Number of non-received tokens before raising a CRITICAL"
    print
    print "  Extra cosmetic options :"
    print "    --helo-name, -H          <uname -n>          The hostname of the client sending e-mails"
    print "    --mail-from, -F          sender@<DOMAIN>     Address of the sender for sent e-mails"
    print "    --subject, -S            <SUBJECT>           Subject string included in sent e-mails"
    print "    --payload-prefix, -L     <string>            Sets a prefix to the payload token in sent e-mails"
    print "    --label, -l                                  Sets the label for displaying a result for Nagios"
    print "    --show-date                                  Displays date of execution in the output for tracking purposes"
    print "    --show-mismatch-tokens                       Displays the tokens for which a body checksum mismatch was found"
    print
    print "  Extra options for plugin behavior :"
    print "    --ssl-pop                                    Use SSL for connecting to the POP3 mail server"
    print "    --ssl-smtp                                   Use SSL for connecting to the SMTP mail server"
    print "    --no-send, -x                                Disable the SMTP send feature"
    print "    --no-receive, -X                             Disable the POP3 receive feature"
    print "    --delay, -D              2                   Sets the delay between the SMTP send phase and the POP3 receive phase"
    print "    --expire-token-delay, -E 86400               Expiration delay for existing tokens in the records"
    print "    --locking-message, -M    <string>            For POP3 reception, will ignore as OK the specified locking error"
    print "    --require-headers, -r    <header1,header2>   Define headers required in an e-mail"
    print "                                                 Useful if a server in the middle adds headers,"
    print "                                                 and you want to check whether it worked"
    print "    --records-root, -R       <dir>               Sets the directory for tracking sent/received tokens"
    print "                             SQL:<CONFIG_FILE>   If the argument begins with 'SQL:', read parameters from the file,"
    print "                                                 and manage tokens in the database"
    print
    print "  Performance tracking :"
    print "    --performance-output, -o                     Output execution performance data in a RRD database"
    print "    --performance-file, -f   <filename>          Filename for RRD database storing performance data"
    print
    print "  Stress test options :"
    print "    --num-mails, -n          1                   Number of e-mails to send per thread"
    print "    --num-threads, -N        1-50                Number of threads for sending e-mails"
    print "    --randomize-body                             Generate a random message body"
    print "                                                 Implies checksum verification upon reception"
    print "    --min-message-body-size  1024                Minimum size for an e-mail body, when generating a random body"
    print "    --max-message-body-size  1048576             Maximum size for an e-mail body, when generating a random body"
    print "    --max-message-size       65536               Maximum size for an e-mail when receiving it via POP3"
    print "                                                 When sending e-mails, the message will only go as far as 95% of this size"
    print "                                                 Maximum size for when receiving an e-mail"
    print "    --max-token-per-mailbox  5000                Maximum number of tokens allowed for one mailbox"
    print "                                                 This is to avoid creating a meltdown situation where a mailbox is so full"
    print "                                                 it will never be processed entirely"
    print "    --max-process-messages   512                 Maximum number of e-mails to process from POP3 in one go"
    print "    --randomize-sender                           Randomizes sender based on --mail-from parameter"
    print "                                                 This will include the random token, current mail number and total mail number"
    print "    --ignore-sender-check                        Ignore sender check. Implied when using --randomize-sender"
    print "    --no-message-id                              Do not add a Message-Id header, let the mail server add one"
    print "    --clean-mailbox                              Implies -x. Will forcefully empty the POP3 mailbox"
    print "                                                 Will also expire all accumulated tokens"
    print "    --force-mismatch-tokens                      Forces a mismatch on all tokens generated on execution."
    print "    --no-delete-tokens                           Marks processed tokens as '.deleted' but do not erase them."
    print
    print "    --help, -h                                   Displays this help message"
    print "    --verbose, -v                                Displays execution trace verbosely"
    print "    --dry-run, -d                                Does not actually run send or receive operations"
    print

def nagios_exit(label, final_result, final_message):
    print "%s %s - %s" % (label, nagios_return[final_result], final_message)
    sys.exit(final_result)

try:
    opts, args = getopt.getopt(sys.argv[1:], "hvdl:s:p:t:w:c:W:C:H:F:L:R:S:n:N:T:U:P:i:xXD:E:M:of:r:", ["help","verbose","dry-run","label=","show-date","show-mismatch-tokens","smtp-server=","pop-server=","timeout=","warning-tokens=","critical-tokens=","warning_delay=","critical_delay=","helo-name=","mail-from=","payload-prefix=","records-root=","subject=","num-mails=","num-threads=","rcpt-to=","pop-username=","pop-password=","get-information-from=","no-send","no-receive","delay=","expire-token-delay=","locking-message=","performance-output","performance-file=","ssl-smtp","ssl-pop","require-headers=","randomize-body","min-message-body-size=","max-message-body-size=","max-message-size=","max-token-per-mailbox=","max-process-messages=","randomize-sender","ignore-sender-check","no-message-id","clean-mailbox","force-mismatch-tokens","no-delete-tokens"])
except getopt.GetoptError as err:
    print str(err)
    usage()
    sys.exit(3)

MAX_THREADS = 50
MAX_LINE_LENGTH = 512

# Nagios result
final_result = 0
final_message = ""
nagios_return = { 0: "OK", 1: "WARNING", 2: "CRITICAL", 3: "UNKNOWN" }

# Mandatory parameters
smtp_server = None
pop_server = None
mail_from = None
recipients = []
pop_usernames = []
pop_passwords = []
input_files = []
# Optional parameters
verbose = False
dry_run = False
no_send = False
no_recv = False
clean_mailbox = False
records_root = None
label = "End-to-end mail monitoring"
show_date = False
start_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
show_mismatch_tokens = False
force_mismatch_tokens = False
no_delete_tokens = False
subject = None
locking_error_message = "unable to lock maildrop"
ssl_smtp = False
ssl_pop = False
performance_output = False
performance_file = None
required_headers = []
missing_headers = set()
found_md5_mismatches = set()
tokens_not_found = set()
# Default delays
timeout = 3600
pop_auth_timeout = 30
warning_tokens = 50
critical_tokens = 100
warning_delay = 450
critical_delay = 1800
send_recv_delay = 2
expire_token_delay = 86400
# Use current hostname as default HELO
helo_name = socket.gethostname()
# Payload prefix for identification
payload_prefix = ''
# Number of threads to run
num_threads = 1
# Number of mails to send
num_mails = 1

min_message_body_size = 1024
max_message_body_size = 65536
# Failsafe to ensure we don't kill ourselves with huge mails
max_message_size = 1048576
# Failsafe to ensure we don't process too many mails
max_pop_mail_count = 512
# Failsafe to ensure we don't overflow a mailbox with tokens
max_mbox_sent_tokens = 5000
# Generate a random body up to 95% of max_message_body_size
randomize_body = False
# Randomize sender address by adding random 8 alphanumeric characters to SENDER@DOMAIN -> SENDER.RANDOM@DOMAIN
randomize_sender = False
# Ignore the strict checking of the From: header when receiving and validating e-mails
ignore_sender_check = False
# Skip the addition of a Message-Id header
add_message_id = True
# Variable updated when we encounter a POP mailbox locking problem
pop_error = None
smtp_error = None
rrdtool_avail = False
try:
    import rrdtool
    rrdtool_avail = True
except ImportError:
    pass

for o, a in opts:
    if o in ("-h", "--help"):
        usage()
        sys.exit()
    if o in ("-v", "--verbose"):
        verbose = True
    if o in ("-d", "--dry-run"):
        dry_run = True
    if o in ("-l", "--label"):
        label = a
    if o == "--show-date":
        show_date = True
    if o == "--show-mismatch-tokens":
        show_mismatch_tokens = True
    if o in ("-s", "--smtp-server"):
        smtp_server = a
    if o in ("-p", "--pop-server"):
        pop_server = a
    if o in ("-t", "--timeout"):
        timeout = int(a)
    if o in ("-w", "--warning-tokens"):
        warning_tokens = int(a)
    if o in ("-c", "--critical-tokens"):
        critical_tokens = int(a)
    if o in ("-W", "--warning-delay"):
        warning_delay = int(a)
    if o in ("-C", "--critical-delay"):
        critical_delay = int(a)
    if o in ("-H", "--helo-name"):
        helo_name = a
    if o in ("-F", "--mail-from"):
        mail_from = a
    if o in ("-L", "--payload-prefix"):
        payload_prefix = a
    if o in ("-R", "--records-root"):
        records_root = a
    if o in ("-S", "--subject"):
        subject = a
    if o in ("-N", "--num-threads"):
        num_threads = int(a)
    if o in ("-n", "--num-mails"):
        num_mails = int(a)
    if o in ("-T", "--rcpt-to"):
        recipients = [addr for addr in a.split(",") if len(addr) > 0]
    if o in ("-U", "--pop-username"):
        pop_usernames = [user for user in a.split(",") if len(user) > 0]
    if o in ("-P", "--pop-password"):
        pop_passwords = [password for password in a.split(",") if len(password) > 0]
    if o in ("-i", "--get-information-from"):
        input_files.append(a)
    if o in ("-x", "--no-send"):
        no_send = True
    if o in ("-X", "--no-receive"):
        no_recv = True
    if o in ("-D", "--delay"):
        send_recv_delay = int(a)
    if o in ("-E", "--expire-token-delay"):
        expire_token_delay = int(a)
    if o in ("-M", "--locking-message"):
        locking_error_message = a
    if o == "--ssl-pop":
        ssl_pop = True
    if o == "--ssl-smtp":
        ssl_smtp = True
    if o in ("-o", "--performance-output"):
        performance_output = True
    if o in ("-f", "--performance-file"):
        performance_file = a
    if o in ("-r", "--require-headers"):
        required_headers = [h for h in a.split(",") if len(h) > 0]
    if o == "--randomize-body":
        randomize_body = True
    if o == "--min-message-body-size":
        min_message_body_size = int(a)
    if o == "--max-message-body-size":
        max_message_body_size = int(a)
    if o == "--max-message-size":
        max_message_size = int(a)
    if o == "--max-token-per-mailbox":
        max_mbox_sent_tokens = int(a)
    if o == "--max-process-messages":
        max_pop_mail_count = int (a)
    if o == "--randomize-sender":
        randomize_sender = True
    if o == "--ignore-sender-check":
        ignore_sender_check = True
    if o == "--no-message-id":
        add_message_id = False
    if o == "--clean-mailbox":
        clean_mailbox = True
    if o == "--force-mismatch-tokens":
        force_mismatch_tokens = True
    if o == "--no-delete-tokens":
        no_delete_tokens = True

# Validate mandatory parameters
missing = 0
if smtp_server is None:
    print "Missing SMTP server!"
    missing += 1
if pop_server is None:
    print "Missing POP3 server!"
    missing += 1
if len(input_files) > 0:
    stdin_processed = False
    for input_file in input_files:
        try:
            if input_file == "-":
                if stdin_processed: # Do not process standard input twice
                    raise ValueError("Recipient list: standard input was specified twice!")
                file_handle = sys.stdin
                stdin_processed = True
            else:
                file_handle = open(input_file, 'r')

            try:
                for line in file_handle:
                    line = line.rstrip()
                    recipient, pop_username, pop_password = line.split()
                    if not re.search("@", recipient):
                        raise ValueError("First element '{0}' did not even include a '@' character!".format(recipient))

                    recipients.append(recipient)
                    pop_usernames.append(pop_username)
                    pop_passwords.append(pop_password)
            except ValueError, err:
                final_result = 3 # UNKNOWN
                final_message = "Parsing error line '{0}' in file {1} : {2!r}".format(line, file_handle, err)
                nagios_exit(label, final_result, final_message)
            except Exception, err:
                final_result = 3 # UNKNOWN
                final_message = "Other error parsing line '{0}' in file {1} : {2!r}".format(line, file_handle, err)
                nagios_exit(label, final_result, final_message)
            file_handle.close()
        except ValueError, err:
            final_result = 3 # UNKNOWN
            final_message = "Invalid file '{0}' : {1!r}".format(input_file, err)
            nagios_exit(label, final_result, final_message)
        except Exception, err:
            final_result = 3 # UNKNOWN
            final_message = "Other error handling file '{0}' : {1!r}".format(input_file, err)
            nagios_exit(label, final_result, final_message)
if recipients is None:
    print "Missing recipient(s)!"
    missing += 1
if pop_usernames is None:
    print "Missing POP3 username(s)!"
    missing += 1
if pop_passwords is None:
    print "Missing POP3 password(s)!"
    missing += 1
if warning_delay > critical_delay:
    print "No sense in setting warning delay {0} above critical delay {1}!".format(warning_delay, critical_delay)
    usage()
    sys.exit(1)
if warning_tokens > critical_tokens:
    print "No sense in setting warning token count {0} above critial token count {1}!".format(warning_tokens, critical_tokens)
if warning_delay > expire_token_delay:
    print "No sense in setting warning delay {0} above token expiration delay {1}!".format(warning_delay, expire_token_delay)
    warning_delay = expire_token_delay
if critical_delay > expire_token_delay:
    print "No sense in setting critical delay {0} above token expiration delay {1}!".format(critical_delay, expire_token_delay)
    critical_delay = expire_token_delay
if missing > 0:
    usage()
    sys.exit(1)

len_recipients = len(recipients)
len_pop_usernames = len(pop_usernames)
len_pop_passwords = len(pop_passwords)
if len_recipients != len_pop_usernames or len_recipients != len_pop_passwords:
    print "Invalid arguments: Recipients (count: {0}) and usernames (count: {1}) and passwords (count: {2}) counts did not match up!".format(len_recipients, len_pop_usernames, len_pop_passwords)
    sys.exit(1)

# Regularize other parameters and extra options
if min_message_body_size < 1024:
    min_message_body_size = 1024
if max_message_size > 1048576:
    max_message_size = 1048576
if max_message_body_size > max_message_size:
    max_message_body_size = max_message_size
if randomize_sender: # If sender is randomized, no sense in checking it
    ignore_sender_check = True
if records_root is None: # Where to keep books about what we sent
    records_root = "/tmp"
if mail_from is None: # If no sender was specified, just make up <USER>@<HELO_NAME>
    mail_from = "%s@%s" % (getpass.getuser(), helo_name)
if subject is None: # If no mail subject specified, just make up "<LABEL> @ <DATE>"
    subject = "%s @ %s" % (label, time.strftime("%Y-%m-%d %H:%M:%S"))
if num_mails < 1:
    print "Invalid number of e-mails ({0}), must be greater than 1!".format(num_mails)
    sys.exit(1)
if num_threads < 1:
    print "Invalid number of threads ({0}), must be greater than 1!".format(num_threads)
    sys.exit(1)
if num_threads > MAX_THREADS:
    print "Not allowing more than {0} threads!".format(MAX_THREADS)
    sys.exit(1)
if clean_mailbox:
    no_send = True
    expire_token_delay = -1

# Construct an authentication map based on recipients, pop_usernames and pop_passwords
auth_map = {}
for n in range(len(recipients)):
    auth_map[recipients[n]] = [ pop_usernames[n], pop_passwords[n] ]

# Construct a set from the list of recipients, for easy access to unique recipients
recipient_set = set(recipients)

for rcpt_to in recipient_set:
    records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)
    # Create the token store if it did not exist.
    try:
        if not os.path.exists(records_dir) or not os.path.isdir(records_dir):
            if os.path.isfile(records_dir):
                os.remove(records_dir)
            os.mkdir(records_dir)
    except Exception, err:
        final_result = 3 # UNKNOWN
        final_message = "Error creating the records directory on creation {0} : {1!r}".format(records_dir, err)
        nagios_exit(label, final_result, final_message)

# Variables used for book-keeping and actually raising error messages
record_times = []
# Count how many emails have been sent
sent_mails = 0
# Total count of received emails we will process
processed_mails = 0
# Total count of deleted emails
deleted_mails = 0
# Count how many tokens we will have processed
processed_tokens = 0

def alarm_handler(signum, frame):
    raise Exception("Time-out during operation")

## ===
# Functions called from the main program

# send_mail_thread : main function for the sub-threads sending e-mails
# No return value, commits the number of sent e-mails to the queue
#
# * report_queue : Queue object for pushing the sent e-mail count
# * error_queue : Queue object for pushing SMTP errors (array of [error message, fatal])
# * records_root : Root directory for where token recording directories will be created
# * mail_from : Mail sender identity
# * rcpt_queue : Common queue for destination addresses between threads
# * rcpt_list : If rcpt_queue is not initialized or ends up empty, cycle across rcpt_list
# * subject : Mail subject
# * thread : Thread number
# * num_mails : How many mails to send per thread

def send_mail_thread(report_queue, error_queue, records_root, mail_from, rcpt_queue, rcpt_list, subject, thread, num_mails):
    if verbose:
        print "* Starting thread #{0} sending {1} mails.".format(thread, num_mails)

    # Connect to mail server and send stuff
    smtp = None
    try:
        if ssl_smtp:
            port = 465
            if verbose:
                print "* Thread #{0} : Connecting to SMTP server '{1}' port {2} (SSL)".format(thread, smtp_server, port)
            smtp = smtplib.SMTP_SSL(smtp_server, port)
        else:
            port = 25
            if verbose:
                print "* Thread #{0} : Connecting to SMTP server '{1}' port {2}".format(thread, smtp_server, port)
            smtp = smtplib.SMTP(smtp_server, port)

        if verbose:
            print "  * Thread #{0} : Sending EHLO...".format(thread)
        result = smtp.ehlo(helo_name)
        if verbose:
            if (result[0] / 10) == 25:
                print "  -> Thread #{0} : HELO was accepted with no problem : {1}".format(thread, result[0])
            else:
                print "  -> Thread #{0} : Unknown result for HELO : {1!r}".format(thread, result)

        # Put the number of sent mails on the queue
        report_queue.put(send_mail(smtp, records_root, mail_from, rcpt_queue, rcpt_list, subject, thread, num_mails))
    except smtplib.SMTPRecipientsRefused, err: # Refused SMTP recipients do not count as a fatal error
        if verbose:
            print "  (!) Could not send to any recipient. Error in thread {0} : {1!r}. Skipping.".format(thread, err)
        error_queue.put(["All recipients failed on thread #{0}".format(thread), False])
        pass # In this case, resume sending from where the exception was raised
    except smtplib.SMTPException, err:
        if verbose:
            print "  (!) Error in thread {0} : {1!r}. Skipping.".format(thread, err)
        error_queue.put(["SMTP error in thread {0} while sending mails: {1!r}".format(thread, err), True])
        return
    except socket.error as err:
        fatal = False # Ignore obvious connection errors
        if err.errno != errno.ECONNREFUSED and err.errno != errno.ETIMEDOUT: # If SMTP does not respond, or refuses connection
            fatal = True
        if verbose:
            print "  (!) Could not connect to the SMTP server. Error in thread {0} : {1!r}. Skipping.".format(thread, err)
        error_queue.put([err[1], fatal])
        smtp = None
    except Exception, err:
        if verbose:
            print "  (!) Other error in thread {0} while sending mails: {1!r}\n".format(thread, err)
        error_queue.put(["Other error in thread {0} while sending mails: {1!r}\n".format(thread, err) + traceback.format_exc(), True])
        return
    finally:
        if smtp is not None:
            smtp.quit()

# send_mail : call within a try/expect call (from send_mail_thread) that will handle smtplib exceptions
# Returns how many mails were sent for one SMTP connection
#
# * smtp : Current active session, instantiated from smtplib
# * records_root : Root directory for where token recording directories will be created
# * mail_from : Mail sender identity
# * rcpt_queue : Common queue for destination addresses between threads
# * rcpt_list : If rcpt_queue is not initialized or ends up empty, cycle across rcpt_list
# * subject : Mail subject
# * thread : Thread number
# * num_mails : How many mails to send per thread

def send_mail(smtp, records_root, mail_from, rcpt_queue, rcpt_list, subject, thread, num_mails):
    sent_mails = 0
    for n in range(num_mails):
        # If we have a queue, pop a recipient from it
        if rcpt_queue is None or rcpt_queue.empty():
            rcpt_to = rcpt_list[n % len(rcpt_list)]
        else:
            rcpt_to = rcpt_queue.get()

        # Initialize the records_dir for this specific e-mail recipient
        records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)

        # Generate a random payload string
        token = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(30))
        payload = payload_prefix + token

        prefix_keyword = ""
        if force_mismatch_tokens:
            prefix_keyword = "FORCE-MISMATCH"
        message_id = "<{0}{1}.{2}.{3}.{4}@{5}>".format(prefix_keyword, token, thread, n + 1, num_mails, helo_name) # Generate message ID

        # Prepare mail subject
        mail_subject = subject
        if thread is not None:
            mail_subject += " Thread #{0}".format(thread)
        mail_subject += " ({0} / {1})".format(n + 1, num_mails)

        previous_timestamp = get_timestamp_from_token(records_dir, payload)
        if previous_timestamp:
            if verbose:
                print "  (!) Thread #{0} : Duplicate token generated, previously at time {0}!".format(previous_timestamp)

        # Prepare mail contents
        mail_contents = []
        if add_message_id:
            mail_contents += [ "Message-Id: %s" % message_id ]
        mail_contents += [ "X-ETEM-Server: %s" % helo_name, "Subject: %s" % (mail_subject), "", payload ]
        random_body_md5 = None
        if randomize_body: # Generate random body up to 95% of max_message_body_size
            random_body_size = random.randint(min_message_body_size, int(max_message_body_size * 0.95))
            random_body = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random_body_size))
            mail_contents += [ "", "### BODY START ###" ]
            mail_contents += [random_body[i:i+MAX_LINE_LENGTH] for i in range (0, len(random_body), MAX_LINE_LENGTH)]
            mail_contents += [ "### BODY END ###" ]

            # Keep the checksum from the random_body generated
            m = hashlib.md5()
            m.update(random_body)
            random_body_md5 = m.hexdigest()

            if force_mismatch_tokens: # Still do the calculation, but throw away the result
                random_body_md5 = "<FORCE MISMATCH>"
        mail_contents += [ "-- ", "Monitoring running on %s" % helo_name ]

        # In case the sender needs to be randomized for mass sending tests
        if randomize_sender:
            sender = re.sub("@", ".{0}.{1}.{2}.{3}@".format(token, thread, n + 1, num_mails), mail_from)
        else:
            sender = mail_from

        if verbose:
            print "  * Thread #{0} : Sending mail {1} / {2} to '{3}'...".format(thread, n + 1, num_mails, rcpt_to)
            print "    * Thread #{0} : Identification payload : {1}".format(thread, payload)
            if randomize_body:
                print "    * Thread #{0} : Randomized body with a size of {1} bytes.".format(thread, random_body_size)
            if randomize_sender:
                print "    * Thread #{0} : Randomized sender with payload.".format(thread)
        refused = smtp.sendmail(sender, rcpt_to, "\r\n".join(mail_contents))
        if len(refused) > 0:
            if verbose:
                print "  -> Thread #{0} : Refused {1} recipients :".format(thread, len(refused))
                print "\n".join([("    - {0} : {1!r}".format(x,y)) for x,y in refused.iteritems()])
        else:
            if verbose:
                print "  -> Thread #{0} : All recipients OK!".format(thread)
            set_token(records_dir, payload, int(time.time()), random_body_md5) # Report the exact time it was sent
            sent_mails += 1
        if rcpt_queue is not None and not rcpt_queue.empty():
            rcpt_queue.task_done()
    return sent_mails

# process_pop_mail : called within acquire_pop_mails, processes and parses the text of a retrieved mail
# Returns how many tokens were processed, and how many mails were deleted (for one mail, only 0 or 1)
#
# * pop : POP3 server connection instance
# * thread : Thread number
# * message : Message number for the retrieved mail, valid within the context of the current POP3 session, used for deleting
# * retrieved_mail : Text of the retrieved mail
# * records_dir : Directory where tokens are recorded, used for token deletion
# * pop_username : POP3 mailbox username (for display purposes)
# * error_queue : Queue object for pushing SMTP errors (array of [error message, fatal])
# * delete_tokens : Accumulate tokens that should be deleted in acquire_pop_mails

def process_pop_mail(pop, thread, message, retrieved_mail, records_dir, pop_username, error_queue, delete_tokens):
    global verbose
    processed_tokens = 0
    deleted_mails = 0

    received_time = int(time.time())

    # Booleans used for parsing state
    headers = True
    received_parsing = False
    first_received_checked = False
    body_parsing = False

    # Informations recovered from the mail
    sender_ok = False
    subject_ok = False
    running_host_ok = False
    message_sent_time = None
    message_recv_time = None
    message_running_host = None
    ignore_mail = True # Ignored mail won't be deleted
    headers_validated = False # Only check once if all header conditions are met
    received_lines_buffer = []
    mail_required_headers = {}
    random_body_buffer = []
    random_body_md5 = None
    local_md5 = None
    token = None
    for header_to_check in required_headers:
        mail_required_headers[header_to_check] = False

    for line in retrieved_mail: # Match lines in search of our label
#        print "LINE : {0}".format(line)
        if headers:
            if received_parsing:
                if re.match("	", line): # Stack lines together
                    if verbose:
                        print "      * Stacking line as a part of Received header : {0}".format(line)
                    received_lines_buffer.append(line)
                    continue # Go to next line
                else: # End of TAB lines, and of Received header
                    received_parsing = False # Do NOT continue to next line, parse it as a proper header
                    full_header = " ".join(received_lines_buffer)
                    if verbose:
                        print "    * Full header : {0}".format(full_header)
                    message_recv_date = full_header.split(';')
                    if len(message_recv_date) > 1: # Not all headers might include this evidence
                        try:
                            message_recv_time = int(mktime_tz(parsedate_tz(message_recv_date[1])))
                            if verbose:
                                print "    * Message was allegedly received by mail server at : {0} / {1} (we did at : {2})".format(message_recv_date[1], message_recv_time, received_time)
                        except Exception, err:
                            message_recv_date = None
                            if verbose:
                                print "    (!) Parse error on the second line of a Received line: {0!r}".format(err)
            if not received_parsing:
                if not first_received_checked and re.match("Received: ", line):
                    if verbose:
                        print "    * Parsing first Received header..."
                    received_parsing = True
                    first_received_checked = True # Do not check any other Received lines
                elif re.match("X-ETEM-Server: ", line): # Custom header for 'End-to-End Monitoring'
                    message_running_host = " ".join(line.split(' ')[1:])
                    if verbose:
                        print "    * Message was sent from host : {0}.".format(message_running_host)
                    if message_running_host == helo_name:
                        if verbose:
                            print "      (/) Message origin host was what we expected."
                        running_host_ok = True
                    else:
                        if verbose:
                            print "      (!) Message origin host was not what we expected. Breaking processing now."
                        break
                elif re.match("Date: ", line): # Try to figure out when the mail was sent
                    try:
                        message_sent_date = " ".join(line.split(' ')[1:])
                        message_sent_time = int(mktime_tz(parsedate_tz(message_sent_date)))
                        if verbose:
                            print "    * Message was allegedly sent at : {0}".format(message_sent_time)
                        # If e-mail was too old anyway, delete it.
                        if (received_time - message_sent_time) > expire_token_delay:
                            if verbose:
                                print "    (!) Mail was older than {0} seconds. Deleting, and breaking processing now.".format(expire_token_delay)
                            ignore_mail = False
                            break
                    except Exception, err: # Likewise, if Date header is invalid, delete it.
                        message_sent_date = None
                        if verbose:
                            print "    (!) Parse error on the Date line: {0!r}. Deleting, and breaking processing now.".format(err)
                        ignore_mail = False
                        break
                elif re.match("From: ", line): # Get the mail sender and validate it
                    message_from = " ".join(line.split(' ')[1:])
                    if verbose:
                        print "    * Message was sent by : {0}".format(message_from)
                    if message_from == mail_from or ignore_sender_check:
                        if verbose:
                            print "      (/) Sender was what we expected."
                        sender_ok = True
                    else:
                        if verbose:
                            print "      (!) Sender was not what we expected. Breaking processing now."
                        break
                elif re.match("Subject: ", line): # Get the mail subject and validate it
                    message_subject = " ".join(line.split(' ')[1:])
                    if verbose:
                        print "    * Message subject : {0}".format(message_subject)
                    if re.match(label, message_subject):
                        if verbose:
                            print "      (/) Subject was what we expected."
                        subject_ok = True
                    else:
                        if verbose:
                            print "      (!) Subject was not what we expected. Breaking processing now."
                        break
                elif re.match("[-A-Za-z0-9]*: ", line): # Any other type of e-mail header
                    other_header = line.split(' ')[0].split(':')[0]
                    if other_header in required_headers:
                        if verbose:
                            print "      (/) Required header '{0}' found.".format(other_header)
                        mail_required_headers[other_header] = True
                elif line == "":
                    headers = False
        else: # Conclusion from the result of parsing headers
            if not headers_validated: # Only do this check once
                # Do not acquire tokens if sender, subject, running host are absent/invalid
                if not (subject_ok and sender_ok and running_host_ok):
                    if verbose:
                        print "    (!) One or more headers (sender, subject, running host) were invalid. Breaking processing now."
                        if not subject_ok:
                            print "      (!) Subject was not valid."
                        if not sender_ok:
                            print "      (!) Sender was not valid."
                        if not running_host_ok:
                            print "      (!) Running host was not valid."
                    break

                # A missing required header in an otherwise valid mail will cause a WARNING
                if len(required_headers) > 0:
                    if verbose:
                        print "    * Required header check"
                    for header_to_check in required_headers:
                        if not mail_required_headers[header_to_check]:
                            if verbose:
                                print "      (!) Required header '{0}' not found.".format(header_to_check)
                            error_queue.put([pop_username, "MISSING_HEADER:{0}".format(header_to_check), False])
                headers_validated = True

            if not body_parsing:
                # Expect first token-ish line after header separator to be the payload
                if re.search("^[A-Z0-9]+$", line):
                    if token is not None:
                        if verbose:
                            print "    (!) Found token-ish string '{0}', received at {1}, but already had found token '{2}'!".format(line, received_time, token)
                        continue # Go to next line
                    token = line
                    sent_timestamp = get_timestamp_from_token(records_dir, line)
                    if sent_timestamp is not None:
                        if message_recv_time is not None and message_recv_time < received_time:
                            delay = message_recv_time - sent_timestamp
                            if verbose:
                                print "    * Found token {0}, it had been sent at {1}, (allegedly) received at {2} ({3} second delay)".format(line, sent_timestamp, message_recv_time, delay)
                        else:
                            delay = received_time - sent_timestamp
                            if verbose:
                                print "    * Found token {0}, it had been sent at {1}, received at {2} ({3} second delay)".format(line, sent_timestamp, received_time, delay)
                        if (received_time - sent_timestamp) > expire_token_delay:
                            if verbose:
                                print "    (!) Token {0} was expired. Deleting.".format(line)
                        else:
                            record_times.append(delay)
                            processed_tokens += 1

                        # Consume token: recover contents of the token, mark token and mail for deletion
                        local_md5 = get_token(records_dir, token)
                    else: # Do not process token-ish strings for which we have no records, even if they otherwise have a full set of data
                        if verbose:
                            print "    (!) Found token-ish string '{0}', received at {1}, but no records for it! Deleting.".format(line, received_time)
                            error_queue.put([pop_username, "TOKEN_NOT_FOUND:{0}:".format(line), False])
                    # Mark mail for deletion
                    ignore_mail = False
                    if not randomize_body:
                        break # No need to process more if we found a token-ish line, and all other conditions have been filled
                elif re.search("^### BODY START ###$", line): # Start marker found
                    body_parsing = True
                    if verbose:
                        print "    * Randomized body parsing started (start marker found)."
            else:
                if re.search("^### BODY END ###$", line): # End marker found
                    body_parsing = False
                    random_body = full_header = "".join(random_body_buffer)
                    m = hashlib.md5()
                    m.update(random_body)
                    random_body_md5 = m.hexdigest()

                    if verbose:
                        print "    * Randomized body parsing complete (end marker found)."
                        print "      * Randomized body length : {0}".format(len(random_body))
                        print "      * Randomized body MD5 comparison :"
                        print "        - Locally saved MD5 hash : {0}".format(local_md5)
                        print "        - E-mail body MD5 hash : {0}".format(random_body_md5)
#                        print "        - E-mail body : {0}".format(random_body)
                        print "        - Match result : {0}".format(local_md5 == random_body_md5)
                    # If the token was a match but the random body had a mismatch, then it means the mail was corrupted!
                    if local_md5 is not None and len(local_md5) > 0 and local_md5 != random_body_md5: # Don't report if there was no local MD5, it could be a destroyed token, and we obviously can't validate these
                        error_queue.put([pop_username, "MD5_MISMATCH:{0}:{1}:{2}:".format(token, local_md5, random_body_md5), False])
                else:
                    random_body_buffer.append(line.strip(" "))
    if body_parsing: # If the parsing ends in the wrong state, raise an error
        print "    (!) Parsing ended in the wrong state : '### BODY END ###' not found!"
        error_queue.put([pop_username, "MD5_MISMATCH:{0}:{1}::".format(token, local_md5), False])
    if verbose:
        print "    * Will we ignore this mail ? {0}".format(ignore_mail)
    if not ignore_mail:
        pop.dele(message)
        if token is not None: # List token for deletion when we run the DELE command
            delete_tokens.append(token)
        deleted_mails += 1
    return (processed_tokens, deleted_mails)

# acquire_pop_mails : call within a try/expect call (from pop_thread) that will handle poplib exceptions
# Lists the mails on the POP3 server and calls process_pop_mail to parse and process the contents
# Returns how many mails were processed, how many tokens were processed, and how many mails were deleted
#
# * pop : Current active session, instantiated from poplib
# * thread : Thread number
# * records_dir : Directory where tokens are recorded, used for token deletion
# * pop_username : POP3 mailbox username (for display purposes)
# * error_queue : Queue object for pushing SMTP errors (array of [error message, fatal])
# * delete_tokens : Array to be passed to process_pop_mail() to accumulate processed tokens for deletion

def acquire_pop_mails(pop, thread, records_dir, pop_username, error_queue, delete_tokens):
    global verbose
    processed_mails = 0
    processed_tokens = 0
    deleted_mails = 0

    (mail_count, total_octets) = pop.stat()
    if verbose:
        print "  * Thread #{0} : STAT result : {1} messages, for a total of {2} bytes".format(thread, mail_count, total_octets)

    (list_response, mail_list, list_response_size) = pop.list()
    mail_list = [x.split(' ') for x in mail_list]
    if verbose:
        print "  * Thread #{0} : LIST result : {1} messages".format(thread, len(mail_list))

    for message, message_size in mail_list:
        if verbose:
            print "  * Thread #{0} : Retrieving message {1} for a size of {2} bytes...".format(thread, message, message_size)
        if int(message_size) > max_message_size: # Do not download a too big message, chances are we don't want it
            if verbose:
                print "  (!) Thread #{0} Message {1} was larger than {2} bytes, deleting without opening.".format(thread, message, max_message_size)
            pop.dele(message)
            deleted_mails += 1
            continue

        (response, retrieved_mail, retr_size) = pop.retr(message)
        sub_processed_tokens, sub_deleted_mails = process_pop_mail(pop, thread, message, retrieved_mail, records_dir, pop_username, error_queue, delete_tokens)
        processed_mails += 1
        processed_tokens += sub_processed_tokens
        deleted_mails += sub_deleted_mails
        if processed_mails >= max_pop_mail_count: # Stop processing mails there, will get the next ones after
            if verbose:
                print "  (!) Thread #{0} : Processed {1} messages, stopping here.".format(thread, max_pop_mail_count)
            break

    return (processed_mails, processed_tokens, deleted_mails)

# clean_pop_mails : call within a try/expect call that will handle poplib exceptions
# Lists the mails on the POP3 server and deletes them directly
# Returns how many mails were deleted
# 
# * pop : Current active session, instantiated from poplib
# * thread : Thread number

def clean_pop_mails(pop, thread):
    global verbose
    deleted_mails = 0

    (mail_count, total_octets) = pop.stat()
    if verbose:
        print "  * Thread #{0} : STAT result : {1} messages, for a total of {2} bytes".format(thread, mail_count, total_octets)

    (list_response, mail_list, list_response_size) = pop.list()
    mail_list = [x.split(' ') for x in mail_list]
    if verbose:
        print "  * Thread #{0} : LIST result : {1} messages".format(thread, len(mail_list))

    if verbose:
        print "  * Thread #{0} : Performing DELE on all messages...".format(thread)
    for message, message_size in mail_list:
        pop.dele(message)
        deleted_mails += 1

    return deleted_mails

# pop_authenticate: sub-function called from pop_thread to authenticate and handle login error conditions
# Returns a poplib.POP3 object or None
#
# * error_queue : Queue object for pushing POP3 errors (array of [username, error message, fatal])
# * pop_username : POP3 username
# * pop_password : POP3 password
# * thread : Thread number

def pop_authenticate(error_queue, pop_username, pop_password, thread):
    # Now, attempt authentication in a protected environment
    try:
        if ssl_pop:
            port = 995
            if verbose:
                print "* Thread #{0} : Connecting to POP3 server '{1}' port {2} (SSL) with user '{3}'".format(thread, pop_server, port, pop_username)
            pop = poplib.POP3_SSL(pop_server, port)
        else:
            port = 110
            if verbose:
                print "* Thread #{0} : Connecting to POP3 server '{1}' port {2} with user '{3}'".format(thread, pop_server, port, pop_username)
            pop = poplib.POP3(pop_server, port, timeout)
        if verbose:
            print "  * Thread #{0} : Sending POP username (with timeout {1}) : {2}...".format(thread, pop_auth_timeout, pop_username)
        result = pop.user(pop_username)
        if verbose:
            print "  * Thread #{0} : Sending POP password (with timeout {1}) : :) ...".format(thread, pop_auth_timeout)
        result = pop.pass_(pop_password)
    except poplib.error_proto, err:
        pop = None
        fatal = False
        if locking_error_message not in err.message:
            if verbose:
                print "  (!) Thread #{0} : Could not log in : {1!r}".format(thread, err)
            fatal = True
        else: # Ignore locking errors
            if verbose:
                print "  (!) Thread #{0} : Could not log in because mailbox was locked. Skipping.".format(thread)
        error_queue.put([pop_username, "POP3 error while authenticating: {0!r}".format(err), fatal])
    except socket.error as err:
        pop = None
        fatal = False
        if err.errno is not None and err.errno != errno.ECONNREFUSED and err.errno != errno.ETIMEDOUT: # If POP3 does not respond, or refuses connection
            fatal = True
        if verbose:
            print "  (!) Thread #{0} : Could not connect to the POP3 server. Error (errno : {1}) : {2!r}. Skipping.".format(thread, err.errno, err)
        if err.errno is not None:
            error_queue.put([pop_username, err[1], fatal])
        else:
            error_queue.put([pop_username, str(err), fatal])
    except timeout:
        if verbose:
            print "  (!) Timeout error in thread {0} while connecting to the POP3 server\n".format(thread)
        error_queue.put([pop_username, "Timeout error in thread {0} while connecting to the POP3 server".format(thread), True])
    except Exception, err:
        pop = None
        if verbose:
            print "  (!) Other error in thread {0} while connecting to the POP3 server: {1!r}\n".format(thread, err)
        error_queue.put([pop_username, "Other error in thread {0} while connecting to the POP3 server: {1!r}\n".format(thread, err) + traceback.format_exc(), True])

    return pop

# pop_thread : main function for the sub-threads receiving e-mails/cleaning boxes via POP3
# No return value, commits the number of received/processed/deleted e-mails to the queue
#
# * job_queue : Queue instructions from the main thread
#   * CLEAN <recipient> <login> <password> : Will clean up the specified account
#   * RETRIEVE <recipient> <login> <password> : Will retrieve and process all tokens from the specified account
#   * QUIT : End thread
# * report_queue : Queue object for pushing the sent e-mail count
# * error_queue : Queue object for pushing POP3 errors
# * records_root : Root directory for where token recording directories will be created
# * thread : Thread number

def pop_thread(job_queue, report_queue, error_queue, records_root, thread):
    pop = None
    is_running = True
    if verbose:
        print "* Starting thread #{0} receiving mails.".format(thread, num_mails)

    while is_running:
        # First, get the next task to process
        if verbose:
            print "  * Thread #{0} : Acquiring next job from queue.".format(thread)
        task = job_queue.get()
        task_data = task.split(" ")
        verb = task_data[0]
        delete_tokens = []
        if verb == "QUIT":
            if verbose:
                print "  * Thread #{0} : QUIT received. Breaking.".format(thread)
            is_running = False
            job_queue.task_done()
            return
        elif verb == "CLEAN" or verb == "RETRIEVE":
            if verbose:
                print "  * Thread #{0} : {1} received. Processing.".format(thread, verb)
            (rcpt_to, pop_username, pop_password) = task_data[1:]
            try:
                pop = pop_authenticate(error_queue, pop_username, pop_password, thread)
            except Exception, err: # Catch anything that we may not have caught otherwise
                pop = None
                if verbose:
                    print "  (!) Other error in thread #{0} caught in pop_thread() while connecting to the POP3 server: {1!r}\n".format(thread, err)
                error_queue.put([pop_username, "Other error in thread #{0} caught in pop_thread() while connecting to the POP3 server: {1!r}\n".format(thread, err) + traceback.format_exc(), True])
                # This should now go unimpeded to 'job_queue.task_done()'

        # If connection has succeeded, acquire and process mails (or clean house if asked to)
        records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)
        try:
            if pop is not None:
                if verb == "CLEAN":
                    tmp_deleted_mails = clean_pop_mails(pop, thread)
                    tmp_processed_mails = tmp_deleted_mails
                    tmp_processed_tokens = tmp_deleted_mails
                else:
                    tmp_processed_mails, tmp_processed_tokens, tmp_deleted_mails = acquire_pop_mails(pop, thread, records_dir, pop_username, error_queue, delete_tokens)

                report_queue.put([tmp_processed_mails, tmp_processed_tokens, tmp_deleted_mails])
        except poplib.error_proto, err:
            if verbose:
                print "  (!) POP3 error in thread #{0} while receiving mails: {1!r}\n".format(thread, err)
            error_queue.put([pop_username,  "POP3 error in thread #{0} while receiving mails: {1!r}".format(thread, err), True])
        except timeout:
            if verbose:
                print "  (!) Timeout error in thread #{0} while receiving mails\n".format(thread)
            error_queue.put([pop_username, "Timeout error in thread #{0} while receiving mails".format(thread), True])
            pop = None
        except socket.error as err:
            if verbose:
                print "  (!) Socket error (errno : {1}) in thread #{0} while receiving mails: {2!r}\n".format(thread, err.errno, err)
            if err.errno is not None:
                error_queue.put([pop_username, "Socket error in thread {0} while receiving mails: {1!r}".format(thread, err[1]), True])
            else:
                error_queue.put([pop_username, "Socket error in thread {0} while receiving mails: {1!r}".format(thread, str(err)), True])
            pop = None
        except Exception, err:
            if verbose:
                print "  (!) Other error in thread {0} while receiving mails: {1!r}\n".format(thread, err)
            error_queue.put([pop_username, "Other error in thread {0} while receiving mails: {1!r}\n".format(thread, err) + traceback.format_exc(), True])
        finally:
            if pop is not None:
                pop.quit()

                # Empty the token queue now that we have safely terminated the POP3 session
                # We only delete tokens now to ensure the e-mails are deleted from the server,
                # to avoid a state where we have deleted the tokens, but the e-mails somehow remained on the server.
                # This could happen when breaking execution in the middle, or if the POP3 session times out.
                for token in delete_tokens:
                    del_token(records_dir, token)

                pop = None

            # Flag the task as done to remove it from the queue
            if verbose:
                print "  * Thread #{0} : Reporting the job as done before looping back.".format(thread)
            job_queue.task_done()

## ===
# Helpers for managing tokens and the token store

# get_timestamp_from_records_dir : The timestamp of the token store should be the last time where a mail was successfully sent.
# Returns a timestamp or None
#
# * records_dir : Directory where tokens are recorded

def get_timestamp_from_records_dir(records_dir):
    try:
        return int(os.path.getmtime(records_dir))
    except Exception, err:
        if verbose:
            print "Error getting timestamp from records directory '{0}': {1!r}".format(records_dir, err)
        return None

# get_timestamp_from_token : Gets the timestamp for a given token that should exist as a file in the token store.
# Returns a timestamp or None if the token does not exist
#
# * records_dir : Directory where tokens are recorded
# * token : String to look for in the token store

def get_timestamp_from_token(records_dir, token):
    token_path = os.path.join(records_dir, token)
    try:
        return int(os.path.getmtime(token_path))
    except OSError as e:
        if e.errno != errno.ENOENT: # If it's already been deleted, well, okay.
            raise
        return None
    except Exception, err:
        if verbose:
            print "Error getting token '{0}': {1!r}".format(token_path, err)
        return None

# set_token : Creates a token as a local file in the token store, with the specified timestamp
# No return value
#
# * records_dir : Directory where tokens are recorded
# * token : String to register in the token store
# * timestamp : Value of the timestamp to register in the token store
# * contents : Contents for the token such as a MD5 hash for the whole e-mail's body

def set_token(records_dir, token, timestamp, contents=None):
    token_path = os.path.join(records_dir, token)
    try:
        os.utime(records_dir, (timestamp, timestamp))
        with open(token_path, 'a') as f:
            os.utime(token_path, (timestamp, timestamp))
            if contents is not None:
                f.write(str(contents))
    except Exception, err:
        if verbose:
            print "Error setting token '{0}' timestamp {1}: {2!r}".format(token_path, timestamp, err)

# get_token : Gets the contents from the specified token
# Returns the contents of the token file

def get_token(records_dir, token):
    token_path = os.path.join(records_dir, token)
    contents = None
    try:
        with open(token_path, 'r') as f:
            contents = f.read()
    except OSError as e:
        if e.errno != errno.ENOENT: # If it's already been deleted, well, okay.
            raise
        else:
            return None
    except Exception, err:
        if verbose:
            print "Error deleting token '{0}': {1!r}".format(token_path, err)
    finally:
        return contents

# del_token : Deletes the specified token from the token store
# Returns the contents of the token file
#
# * records_dir : Directory where tokens are recorded
# * token : String to look for and delete from the token store

def del_token(records_dir, token):
    token_path = os.path.join(records_dir, token)
    contents = None
    try:
        with open(token_path, 'r') as f:
            contents = f.read()
        if no_delete_tokens:
            os.rename(token_path, token_path + ".deleted")
        else:
            os.remove(token_path)
    except OSError as e:
        if e.errno != errno.ENOENT: # If it's already been deleted, well, okay.
            raise
        else:
            return None
    except Exception, err:
        if verbose:
            print "Error deleting token '{0}': {1!r}".format(token_path, err)
    finally:
        return contents

# list_tokens : Lists the contents of the token store
# Returns the list of token strings or None
#
# * records_dir : Directory where tokens are recorded

def list_tokens(records_dir):
    try:
        for root, dirs, files in os.walk(records_dir, topdown=False):
            if no_delete_tokens:
                return [x for x in files if ".deleted" not in x]
            else:
                return files
    except Exception, err:
        if verbose:
            print "Error listing tokens in '{0}': {1!r}".format(records_dir, err)
        return None

## ===
# Take a copy of the recipients for POP3
pop_phase_recipient_set = set(recipient_set)
pop_phase_recipients = list(recipients)
if not no_send: # First purge recipients which would go over the token limit
    # Remove mailboxes that have too many tokens
    for rcpt_to in set(recipient_set):
        records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)
        rcpt_to_token_count = len(list_tokens(records_dir))
        if rcpt_to_token_count + int(num_mails/len(recipient_set)) > max_mbox_sent_tokens:
            if verbose:
                print "* Excluding {0} from recipient list since current token count {1} would overflow {2} when adding {3} tokens ({4} mails over {5} recipients).".format(rcpt_to, rcpt_to_token_count, max_mbox_sent_tokens, int(num_mails/len(recipient_set)), num_mails, len(recipient_set))
            recipient_set.remove(rcpt_to)
            recipients = [x for x in recipients if x != rcpt_to]

if verbose:
    print "Summary of execution :"
    print "* Token recording root : %s" % (records_root)
    print "  * Tokens older than %s seconds will not be saved on exit" % (expire_token_delay)
    print "* Allowed timeout for operations : %s" % (timeout)
    print "* Sleep between operations : %s" % (send_recv_delay)
    if performance_output:
        print "* Outputting performance data"
        if performance_file is not None:
            print "  * Recording performance data in RRD file '{0}'".format(performance_file)
    if no_send:
        print "(!) Will skip sending mail to the SMTP server"
    print "* Sending {0} e-mails with {1} threads, for a total : {2} ({3} mailboxes, {4} e-mails per mailbox)".format(num_mails, num_threads, num_mails * num_threads, len(recipient_set), num_mails * num_threads / len(recipient_set))
    if ssl_smtp:
        print "  * SSL connection"
    print "  * With subject : '%s'" % (subject)
    print "  * From '%s' to '%s', via SMTP server '%s'" % (mail_from, recipients, smtp_server)
    print "  * Will identify as '%s' to SMTP server '%s'" % (helo_name, smtp_server)
    if randomize_body:
        print "  * Generate a random body with a size between [%s, %s]" % (min_message_body_size, max_message_body_size)
        if show_mismatch_tokens:
            print "  * Will display detailed info about tokens for which there was a MD5 mismatch"
        if force_mismatch_tokens:
            print "  * Will force MD5 mismatches for this run"
    if randomize_sender:
        print "  * Will randomize the specified sender address"
    if no_recv:
        print "(!) Will skip checking the POP3 server"
    print "* Reception of mail from POP3 server '%s'" % (pop_server)
    if ssl_pop:
        print "  * SSL connection"
    print "  * POP mailbox usernames to check : %s" % (pop_usernames)
    print "  * POP mailbox password : :)"
    print "  * If not received within %s seconds, raise a WARNING" % (warning_delay)
    print "  * If not received within %s seconds, raise a CRITICAL" % (critical_delay)
    print "  * Read up to {0} messages".format(max_pop_mail_count)
    print "  * Send up to {0} tokens per recipient".format(max_mbox_sent_tokens)
    if clean_mailbox:
        print "  * Will clean the mailboxes (force expiration of tokens)"
    if required_headers:
        print "  * Will check for the presence of the following headers : '{0}'".format("', '".join(required_headers))
    print

if dry_run:
    if verbose:
        print "Exiting now (dry-run)."
    sys.exit(0)

if verbose:
    print "Execution :"

#### Sending phase
smtp_phase_start_time = int(time.time())
if no_send or len(recipients) == 0:
    if verbose:
        if no_send:
            print "* Skipping sending : User request..."
        if len(recipients) == 0:
            print "* Skipping sending : No valid recipients..."
else:
    report_queue = Queue.Queue()
    error_queue = Queue.Queue()
    rcpt_queue = Queue.Queue()
    smtp_threads = []
    for n in range(num_threads): # Create threads
        if verbose:
            print "* Create SMTP thread #{0}.".format(n)
        t = threading.Thread(target=send_mail_thread, args=(report_queue, error_queue, records_root, mail_from, rcpt_queue, recipients, subject, n, num_mails))
        smtp_threads.append(t)
    for t in smtp_threads: # Launch threads
        t.start()
    for t in smtp_threads: # Wait for threads to end
        t.join()
    if verbose:
        print "* All SMTP threads concluded."
    for count in list(report_queue.queue):
        sent_mails += count

    fatal_error_found = False
    for error_msg, fatal in list(error_queue.queue):
        # Sort out error objects and fatal errors
        if fatal:
            final_result = 3 # UNKNOWN
            final_message += "; " + error_msg
            fatal_error_found = True

        if smtp_error is None:
            smtp_error = error_msg
        else:
            smtp_error += "; " + error_msg
    if verbose:
        print "* SMTP Threads : Result and error queues processed."

    if verbose:
        if num_threads == 1:
            print "* Sent {0} messages.".format(sent_mails)
        else:
            print "* Sent {0} messages over {1} threads.".format(sent_mails, num_threads)
        print

    if fatal_error_found: # If we found one or more fatal errors, exit now
        nagios_exit(label, final_result, final_message)

smtp_phase_end_time = int(time.time())

#### Receiving phase
pop3_phase_start_time = int(time.time())
if no_recv:
    if verbose:
        print "* Skipping receiving..."
else:
    if not no_send:
        if verbose:
            print "* Sleeping {0} seconds between phases...".format(send_recv_delay)
            print
        time.sleep(send_recv_delay)

    recipient_set = pop_phase_recipient_set
    recipients = pop_phase_recipients

    job_queue = Queue.Queue()
    report_queue = Queue.Queue()
    error_queue = Queue.Queue()
    pop_threads = []
    for n in range(min(len(recipient_set), num_threads)): # Create threads, only as much as needed, but not more than the max number specified
        if verbose:
            print "* Create POP3 thread #{0}.".format(n)
        t = threading.Thread(target=pop_thread, args=(job_queue, report_queue, error_queue, records_root, n))
        pop_threads.append(t)
    if verbose:
        print "* Sending tasks from recipient list to POP3 threads..."
    for rcpt_to in recipient_set: # Generate jobs to pre-fill queue before starting threads
        pop_username = auth_map[rcpt_to][0]
        pop_password = auth_map[rcpt_to][1]
        if clean_mailbox:
            verb = "CLEAN"
        else:
            verb = "RETRIEVE"
        if verbose:
            print "  * Sending task : {0} {1} {2} {3}".format(verb, rcpt_to, pop_username, ":)")
        job_queue.put("{0} {1} {2} {3}".format(verb, rcpt_to, pop_username, pop_password))
    if verbose:
        print "* All tasks sent to POP3 job queue."
    for t in pop_threads: # Launch threads
        t.start()
    if verbose:
        print "* Waiting for job queue to become empty..."
    job_queue.join() # Wait for job queue to become empty
    if verbose:
        print "* Sending order to QUIT to POP3 threads."
    for t in pop_threads: # Pile up order for threads to quit
        job_queue.put("QUIT")
    for t in pop_threads: # Wait for threads to end
        t.join()
    if verbose:
        print "* All POP3 threads concluded."
    for report in list(report_queue.queue): # Now add the acquired values to global statistics
        processed_mails += report[0]
        processed_tokens += report[1]
        deleted_mails += report[2]

    fatal_error_found = False
    for account, error_msg, fatal in list(error_queue.queue):
        # Sort out error objects and fatal errors
        if fatal:
            final_result = 3 # UNKNOWN
            final_message += "; " + error_msg
            fatal_error_found = True

        # Parse and eliminate from the process special errors
        if re.search("^MISSING_HEADER:", error_msg):
            header = error_msg.split(":")[1]
            missing_headers.add(header)
            error_msg = None
        elif re.search("^MD5_MISMATCH:", error_msg):
            token = error_msg.split(":")[1]
            found_md5_mismatches.add(token)
            error_msg = None
        elif re.search("^TOKEN_NOT_FOUND:", error_msg):
            token = error_msg.split(":")[1]
            tokens_not_found.add(token)
            error_msg = None

        if error_msg is not None:
            if pop_error is None:
                pop_error = "(" + account + "): " + error_msg
            else:
                pop_error += "; (" + account + "): " + error_msg

    if fatal_error_found: # If we found one or more fatal errors, exit now
        nagios_exit(label, final_result, final_message)

pop3_phase_end_time = int(time.time())

## ===
# Post processing

if verbose:
    print
    print "* Post-processing :"

# Determine warning or critical based on biggest delay, first on remaining records, then on received mails
longest_delay_not_received = 0
total_ondisk_tokens_count = 0
try:
    for rcpt_to in recipient_set:
        if verbose:
            print "  * Recipient : {0}".format(rcpt_to)
        records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)
        now = int(time.time())
        ondisk_tokens = list_tokens(records_dir)
        if ondisk_tokens is None:
            ondisk_tokens = []
        ondisk_tokens_count = len(ondisk_tokens)
        if verbose:
            print "    * Tokens on disk : {0}".format(ondisk_tokens_count)
            if (ondisk_tokens_count > 0):
                print "    * Token details :"
        for token in ondisk_tokens: # Purge older tokens, and count delay
            sent_timestamp = get_timestamp_from_token(records_dir, token)
            if sent_timestamp is None: # A token deleted under our feet?
                sent_timestamp = 0 # Make delay zero to ensure this token is ignored
            delay = now - sent_timestamp
            if longest_delay_not_received < delay: # Take in account expired tokens. This is important.
                longest_delay_not_received = delay

            if delay > expire_token_delay:
                if verbose:
                    print "      * Deleting expired token {0} sent at {1}".format(token, sent_timestamp)
                # Consume token and remove spool entry
                del_token(records_dir, token)
            elif verbose:
                if delay >= critical_delay:
                    print "      * Token {0} sent at {1} still not confirmed (delay : {2}) -> CRITICAL".format(token, sent_timestamp, delay)
                elif delay >= warning_delay:
                    print "      * Token {0} sent at {1} still not confirmed (delay : {2}) -> WARNING".format(token, sent_timestamp, delay)
                else:
                    print "      * Token {0} sent at {1} still not confirmed (delay : {2}) -> OK".format(token, sent_timestamp, delay)
        total_ondisk_tokens_count += ondisk_tokens_count
except Exception, err:
    final_result = 3 # UNKNOWN
    final_message = "Error with records directory in post-processing {0} : {1!r}".format(records_dir, err)
    final_message += traceback.format_exc()
    nagios_exit(label, final_result, final_message)

if verbose:
    print "  * Longest delay in non-received mails : {0}".format(longest_delay_not_received)

# Calculate delays
smtp_delay = smtp_phase_end_time - smtp_phase_start_time
pop3_delay = pop3_phase_end_time - pop3_phase_start_time

# Prepare final message
final_message = "{0} mailboxes : ".format(len(recipient_set))
if show_date:
    final_message += "Started at {0} - ".format(start_date)
final_message += "Sent {0} mails".format(sent_mails)
if not no_send and smtp_delay > 0:
    final_message += " in {0} seconds".format(smtp_delay)
final_message += ", processed {0} mails".format(processed_mails)
if not no_recv and pop3_delay > 0:
    final_message += " in {0} seconds".format(pop3_delay)
final_message += ", processed {0} tokens, deleted {1} mails".format(processed_tokens, deleted_mails)

# If SMTP was not used, mention it
if no_send:
    final_message += ". SMTP skipped on user command"
elif smtp_error is not None:
    final_message += ". SMTP skipped because of server error ({0!r})".format(smtp_error)

# If POP3 was not used, mention it
if no_recv:
    final_message += ". POP3 skipped on user command"
elif pop_error is not None:
    final_message += ". POP3 skipped ({0!r})".format(pop_error)

# If missing headers were found, mention it
if len(missing_headers) > 0:
    if final_result < 1:
        final_result = 1
    final_message += ". Missing required headers found : '{0}'".format("', '".join(missing_headers))

# If we found MD5 mismatches, mention it
if len(found_md5_mismatches) > 0:
    if final_result < 2:
        final_result = 2
    final_message += ". Mail body checksum validations failed {0} times".format(len(found_md5_mismatches))
    if show_mismatch_tokens:
        final_message += " (Tokens : '{0}')".format("', '".join(found_md5_mismatches))

# If we had tokens processed via POP3 but not found on the records directory, mention it
if len(tokens_not_found) > 0:
    if final_result < 1:
        final_result = 1
    final_message += ". {0} tokens processed but not found".format(len(found_md5_mismatches))
    final_message += " (Tokens : '{0}')".format("', '".join(tokens_not_found))

# Get timestamp from the records directory to find out since when we haven't been able to send e-mail
last_smtp_success = int(time.time())
global_last_smtp_delay = 0
for rcpt_to in recipient_set:
    records_dir = records_root + "/mail_check-history.u%s.r%s.s%s" % (os.getuid(), rcpt_to, smtp_server)
    recipient_last_smtp_success = get_timestamp_from_records_dir(records_dir)
    if last_smtp_success > recipient_last_smtp_success:
        last_smtp_success = recipient_last_smtp_success

    last_smtp_delay = 0
    if last_smtp_success is not None:
        last_smtp_delay = smtp_phase_end_time - last_smtp_success
        if verbose:
            print "  * Last managed to send an e-mail to {0} {1} seconds ago.".format(rcpt_to, last_smtp_delay)
        if global_last_smtp_delay < last_smtp_delay:
            global_last_smtp_delay = last_smtp_delay
    else:
        final_message += ". Error when trying to get timestamp from {0}!".format(records_dir)

# Update status accordingly to last SMTP delay
if global_last_smtp_delay >= warning_delay: # Only add to message for a warning
    final_message += ". Last managed to send a mail {0} seconds ago".format(global_last_smtp_delay)
if global_last_smtp_delay >= critical_delay:
    if final_result < 2:
        final_result = 2
elif global_last_smtp_delay >= warning_delay:
    if final_result < 1:
        final_result = 1

# Now we have the longest delay for non-received tokens, determine the final state
if total_ondisk_tokens_count > 0:
    if verbose:
        print "  * A total of {0} tokens not received for a delay of {1} seconds".format(total_ondisk_tokens_count, longest_delay_not_received)
    final_message += ". A total of {0} tokens not received for a delay of {1} seconds".format(total_ondisk_tokens_count, longest_delay_not_received)
    # Tokens sent but not received for too long indicate a problem
    if longest_delay_not_received >= critical_delay:
        if final_result < 2:
            final_result = 2
    elif longest_delay_not_received >= warning_delay:
        if final_result < 1:
            final_result = 1
    # If we have too many tokens on disk, this can indicate a problem
    if total_ondisk_tokens_count > critical_tokens:
        if final_result < 2:
            final_result = 2
    elif total_ondisk_tokens_count > warning_tokens:
        if final_result < 1:
            final_result = 1
else:
    final_message += ". Not waiting on any records"

# Now confirm delays on actually received mails
# Example : A token sent at 14:00, but being unable to POP until 14:20 will result in a WARNING for a non-received token
# -> At 14:20, upon POP'ing the mail, if the mail was confirmed as received at 14:00:05, it will only count as a 5 seconds delay -> OK
# -> At 14:20, upon POP'ing the mail, if the reception timestamp can not be confirmed, it will count as a 20 minutes delay -> WARNING
# This is to limit frivolous alerts as much as possible, and to report alerts only for meaningful and prolonged problems
longest_delay = 0
if len(record_times) > 0:
    longest_delay = sorted(record_times)[-1]
    if verbose:
        print "    * Recorded delays : {0}".format(record_times)
        print "    * Longest delay on received mails : {0}".format(longest_delay)
    final_message += ". Delivered mail encountered a delay of {0} seconds".format(longest_delay)
    if longest_delay >= critical_delay:
        if verbose:
            print "      * Longest delay in received mails was {0} seconds -> CRITICAL".format(longest_delay)
        if final_result < 2:
            final_result = 2
    elif longest_delay >= warning_delay:
        if verbose:
            print "      * Longest delay in received mails was {0} seconds -> WARNING".format(longest_delay)
        if final_result < 1:
            final_result = 1
else:
    if verbose:
        print "    * No recorded delays in this run."

# Add performance output information to the message
performance_data = (sent_mails, processed_mails, processed_tokens, deleted_mails, total_ondisk_tokens_count, longest_delay_not_received, longest_delay, global_last_smtp_delay)
if performance_output:
    final_message += " | 'sent_mails'={0}; 'processed_mails'={1}; 'processed_tokens'={2}; 'deleted_mails'={3}; 'non_processed_tokens'={4}; 'non_processed_delay'={5}; 'processed_delay'={6}; 'last_smtp_delay'={7};".format(*performance_data)

# Store the performance data in a RRD file
if performance_file is not None: 
    if rrdtool_avail:
        if verbose:
            print "    * Recording performance data in RRD file '{0}'".format(performance_file)
        try:
            if not os.path.exists(performance_file):
                ds_heartbeat = 600
                tokenmail_min = 0
                tokenmail_max = 131072
                delay_min = 0
                delay_max = 31536000
                rras = [
                        "RRA:AVERAGE:0.5:1:600",
                        "RRA:AVERAGE:0.5:6:700",
                        "RRA:AVERAGE:0.5:24:775",
                        "RRA:AVERAGE:0.5:288:797",
                        "RRA:MAX:0.5:1:600",
                        "RRA:MAX:0.5:6:700",
                        "RRA:MAX:0.5:24:775",
                        "RRA:MAX:0.5:288:797",
                        "RRA:MIN:0.5:1:600",
                        "RRA:MIN:0.5:6:700",
                        "RRA:MIN:0.5:24:775",
                        "RRA:MIN:0.5:288:797",
                        "RRA:LAST:0.5:1:600",
                        "RRA:LAST:0.5:6:700",
                        "RRA:LAST:0.5:24:775",
                        "RRA:LAST:0.5:288:797",
                        ]
                data_sources = [
                        "DS:sent_mails:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, tokenmail_min, tokenmail_max),
                        "DS:processed_mails:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, tokenmail_min, tokenmail_max),
                        "DS:processed_tokens:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, tokenmail_min, tokenmail_max),
                        "DS:deleted_mails:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, tokenmail_min, tokenmail_max),
                        "DS:non_proc_tokens:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, tokenmail_min, tokenmail_max),
                        "DS:non_proc_delay:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, delay_min, delay_max),
                        "DS:processed_delay:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, delay_min, delay_max),
                        "DS:last_smtp_delay:GAUGE:{0}:{1}:{2}".format(ds_heartbeat, delay_min, delay_max),
                        ]
                rrdtool.create(performance_file,
                        "--start", "now",
                        "--step", "300",
                        rras + data_sources
                        )
            rrdtool.update(performance_file, "N:{0}:{1}:{2}:{3}:{4}:{5}:{6}:{7}".format(*performance_data))
        except Exception, err:
            final_result = 3 # UNKNOWN
            final_message = "Other error while updating/creating RRD file '{0}' : {1!r}\n".format(performance_file, err)
            final_message += traceback.format_exc()
            nagios_exit(label, final_result, final_message)
    else:
        if verbose:
            print "    * Module 'rrdtool' was not available, skipping."

# Display final message

if verbose:
    print 

nagios_exit(label, final_result, final_message)
