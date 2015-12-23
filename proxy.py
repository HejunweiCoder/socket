import sys
import socket
import threading

def server_loop(local_host,local_port,remote_host,remote_port,receive_first):
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    try:
        server.bind((local_host,local_port))

        print("[*] Listening on %s:%d" % (local_host,local_port))

        server.listen(5)

        while True:
            client_socket , addr = server.accept()

            print("[==>] Received incoming connection from %s:%d" % (addr[0],addr[1]))

            proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,
                                                                       remote_host,
                                                                       remote_port,
                                                                       receive_first))
            proxy_thread.start()


    except:
        print("Failed to listen on %s:%d" % (local_host,local_port))
        print("Check for other listening sockets or correct permissions.")
        sys.exit(0)


def profxy_handle(client_socket,remote_host,remote_port,recevie_first):
    remote_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    remote_socket.connect((remote_host,remote_port))

    if recevie_first:
        remote_buffer = recevie_from(remote_socket)
        hexdump(remote_buffer)

        if recevie_first:
            remote_buffer = recevie_from(remote_socket)

            if len(remote_buffer):
                print("[<==] Sending %d bytes to localhost." % len(remote_buffer))
                client_socket.send(remote_buffer)

    #loop to send and receive

    while True:
        local_buffer=recevie_from(client_socket)
        if len(local_buffer):
            print("[==>] Received %d bytes from localhost." % len(local_buffer))
            hexdump(local_buffer)

            local_buffer = request_handle(local_buffer)

            remote_socket.send(local_buffer)
            print("[==>] Send to remote")

        remote_buffer = recevie_from(remote_socket)

        if len(remote_buffer):

            print("[<==] Received %d bytes from remote." % len(remote_buffer))
            hexdump(remote_buffer)

            #handle received data
            remote_buffer = respones_handle(remote_buffer)

            client_socket.send(remote_buffer)

            print("[<==] Send to localhost.")

        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()

            print("[*] No more data. closing connections.")

            break

def hexdump(src,length=16):
    result=[]
    digits = 4 if isinstance(src,unicode) else 2
    for i in range(0,len(src),length):
        s = src[i:i+length]
        hexa = b' '.join(["%0*X" % (digits,ord(x) for x in s)])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b'%04X %-*s %s' % (i,length*(digits + 1),hexa,text))

    print(b'\n'.join(result))

def receive_from(connection):
    buffer=""

    #set timeout 2s
    connection.settimeout(2)

    try:
        while True:
            data = connection.recv(4096)

            if not data:
                break

            buffer+=data

    except:
        pass
    return buffer


def request_handle(buffer):

    #we should add some handle to modify


    return buffer



def response_handle(buffer):

    #we should add some handle to modify

    return buffer


def main():
    if len(sys.argv[1:]) !=5:
        print("usage: proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")

        sys.exit(0)

        local_host=sys.argv[1]
        local_port=sys.argv[2]

        remote_host=sys.argv[3]
        remote_port=int(sys.argv[4])

        recevie_first = sys.argv[5]

        if "true"or"True" in recevie_first:
            recevie_first=True
        else:
            recevie_first=False

        server_loop(local_host,local_port,remote_host,remote_port,recevie_first)

main()

