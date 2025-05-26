from client import Client
from server import Server

def main():
    server = Server()

    bob = Client('@bob')
    bob.connect(server)

    alice = Client('@alice')
    alice.connect(server)

    bob.send('@alice', b'Hello alice')


if __name__ == '__main__':
    print('Start')
    main()
    print('Done')
