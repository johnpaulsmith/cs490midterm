CS490 Midterm: DES, RC4, and AES Implementations in Java with GUI
=======================================

John Paul Smith

This was my midterm submission for CS490 - Cryptography. The requirements for
the project are to create a program that runs on a client machine used to send
encrypted messages securely to another program that runs separately on a server
machine. This server program decrypts the message, reads it, and then encrypts
it again and sends it back to the client. The client is essentially chatting
with a server-side parrot. The purpose of this assignment was to put us through
the tedious process of implementing common symmetrical encryption algorithms,
not to design a full-featured user-to-user chat program. I chose Java for this
because at the time I was just learning how to build GUIs using Swing and I
wanted a graphical interface to give the program some polish and to get bonus
points on the project. I ran out of time getting my own AES implementation
sorted out and it did not make it into the final submission. Instead, I just
used the javax.crypto classes to implement AES, which was allowed under the
assignment rules.

I used Wireshark (Ethereal) packet captures to prove that the programs were
indeed transforming the messages into ciphertext. For the server, I used a
virtualized Linux machine running on the Windows machine that hosted the
client. This made the testing much easier.

This project was how I spent my birthday weekend...

DES: http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf