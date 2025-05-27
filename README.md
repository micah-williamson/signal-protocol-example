# TODO

* Drop used message keys


# Signal Protocol Example

Minimal implementation of signal protocol described in https://www.whatsapp.com/security/WhatsApp-Security-Whitepaper.pdf

```
Start
[Server] @bob registered
[Server] @alice registered
[Client @bob] Initializing chat session with @alice as initiator
[Server] Chat init requested for @alice
[Client @bob] Pre key signature verified
[Client @bob] Generated master secret: b'W1B\xb0\xaaX\x9cI\x16\xc4\xb06\xe6&\x8dR\x88T\xa423.\xdf\x90\xe8\x0e\xddyd\x15\xfb4\xb1\x84\xad\xbb\xf2\xfdeX\x00Y\xde\x03\x1a\xd5R\r|\xf1\xe4\xe3*\xb3%\xbb\xf4\xbf\x89\xa9\x96\x81\xb6\x0c\xdb"\x88\x8e\x9aW&\xc2jT\xdf\xb9oA5\x9c\x9d\xbdQ\x83`\xa1I\x0e\n\xb0\xf5|\xa0\x95rF\xcf\xa6\x0e\xde\xa8\xe9O\xa6]Ac\x1a9\x99\x87/\xc7D\x7f\xaef$\xacE\x94\xde\x16.\x10\xe8J@'
[Client @bob] Generated Root Key: b'B\xf2\xb7i\xab$J\xe3X\x0b\xa1\xee\xf6\xcf\x90\xdd\xb1^\x17\x17y\x81\xe7e\x10\x0fs\x1e\xbek@\x95'
[Client @bob] Generated Chain Key: b'\xda\xa6\xe1\xe3\x9e\x97+\x8er?#\xae\xa0\xb3\x7fG\xd7\xce\x7f\x87U{\xdd{:\x16C\xb4\xe91\x17r'
[Client @bob] Sending message [to @alice]: b'Hello alice'
[Server] Routing message From @bob to @alice
[Client @alice] Received message from @bob
[Client @alice] New contact. Initializing session
[Client @alice] Initializing chat session with @bob as recipient
[Client @alice] Generated master secret: b'W1B\xb0\xaaX\x9cI\x16\xc4\xb06\xe6&\x8dR\x88T\xa423.\xdf\x90\xe8\x0e\xddyd\x15\xfb4\xb1\x84\xad\xbb\xf2\xfdeX\x00Y\xde\x03\x1a\xd5R\r|\xf1\xe4\xe3*\xb3%\xbb\xf4\xbf\x89\xa9\x96\x81\xb6\x0c\xdb"\x88\x8e\x9aW&\xc2jT\xdf\xb9oA5\x9c\x9d\xbdQ\x83`\xa1I\x0e\n\xb0\xf5|\xa0\x95rF\xcf\xa6\x0e\xde\xa8\xe9O\xa6]Ac\x1a9\x99\x87/\xc7D\x7f\xaef$\xacE\x94\xde\x16.\x10\xe8J@'
[Client @alice] Generated Root Key: b'B\xf2\xb7i\xab$J\xe3X\x0b\xa1\xee\xf6\xcf\x90\xdd\xb1^\x17\x17y\x81\xe7e\x10\x0fs\x1e\xbek@\x95'
[Client @alice] Generated Chain Key: b'\xda\xa6\xe1\xe3\x9e\x97+\x8er?#\xae\xa0\xb3\x7fG\xd7\xce\x7f\x87U{\xdd{:\x16C\xb4\xe91\x17r'
[Client @alice] Got decrypted message: b'Hello alice'
[Client @bob] Sending message [to @alice]: b'It is a fine day'
[Server] Routing message From @bob to @alice
[Client @alice] Received message from @bob
[Client @alice] Got decrypted message: b'It is a fine day'
[Client @alice] Sending message [to @bob]: b'It is a fine day, Bob.'
[Client @alice] Taking over as sender and ratcheting root key
[Server] Routing message From @alice to @bob
[Client @bob] Received message from @alice
[Client @bob] Got new ephemeral key from sender. Ratcheting root key
[Client @bob] Got decrypted message: b'It is a fine day, Bob.'
[Client @alice] Sending message [to @bob]: b'What is 1+1?'
[Server] Routing message From @alice to @bob
[Client @bob] Received message from @alice
[Client @bob] Got decrypted message: b'What is 1+1?'
[Client @bob] Sending message [to @alice]: b'It is 2'
[Client @bob] Taking over as sender and ratcheting root key
[Server] Routing message From @bob to @alice
[Client @alice] Received message from @bob
[Client @alice] Got new ephemeral key from sender. Ratcheting root key
[Client @alice] Got decrypted message: b'It is 2'
Done
```

## Run

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
python3 main
```