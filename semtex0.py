import socket

client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

client.connect(("semtex.labs.overthewire.org",24001))

i=1

f=open("semtexpass","wb")

while True:
    bin=client.recv(1)
    if bin:
        if i%2==1:
            f.write(bin)
    else:
        break
    i+=1


client.close()
f.close()