from client import Client
from server import Server

def main():
    server = Server()

    bob = Client('@bob')
    bob.connect(server)

    bob_companion = Client('@bob:1')
    bob.add_companion(bob_companion)

    alice = Client('@alice')
    alice.connect(server)

    bob.send('@alice', b'Hello alice')
    bob.send('@alice', b'It is a fine day')

    alice.send('@bob', b'It is a fine day, Bob.')
    alice.send('@bob', b'What is 1+1?')

    bob.send('@alice', b'It is 2')


if __name__ == '__main__':
    print('Start')
    main()
    print('Done')
