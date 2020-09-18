# check_mail_delivery
Nagios plugin for checking mail delivery from SMTP to POP by sending generated tokens and confirming reception

This plugin can be used to simply monitor :
- The ability to send e-mail to a given SMTP server, to a given recipient
- The ability to receive e-mail from a given POP3 server and mailbox
- The ability to send e-mail to a given mailbox, via a chosen SMTP server, and check complete mail delivery (along with a delay between send and receive when executing everything at once)

It can also be used as a stress tester for generating and sending e-mails :
- With randomized bodies of customizable sizes (1024-65536)
- With multiple threads to send multiple e-mails

Mail delivery is checked in the following way :
- A token is generated when sending the e-mail
- Information about the generated token is then stored locally
- When receiving e-mail, the delivered e-mails against the stored tokens to measure delivery time

It can therefore react on :
- Excessive delay for successful delivery (warning: 450s, critical: 1800s)
- Excessive number of non-recovered tokens (indicating lost e-mails: warning: 50, critical: 100; with tokens expiring after 24 hours)
- Expected headers not present in the received e-mail

Extra features :
- Specify mailboxes in a TSV file in the following format :
```
recipient1_address@domain.com	<LOGIN1>	<PASSWORD1>
recipient2_address@domain.com	<LOGIN2>	<PASSWORD2>
```
- When used to stress test a mail server, senders can be randomized by using the token string (Though, this might result in a rejected email due to non-existing senders)
- Output of performance data as a Nagios string
- Output of performance data as an RRD graph
- Ignore a specific POP3 error message should a locking conflict occur
- Set a custom payload prefix in e-mails
- Set an upper limit on the number of tokens sent to a specific mail box
- Set an upper limit on the number of received messages that will be processed at a time
- Set an upper size limit on e-mails to be received ; Too big e-mails will be ignored
- Choose to let the script generate a Message-Id header for sent e-mails, or have the mail server produce one
