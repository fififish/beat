from thresprf import dealer, serialize, serialize1, group
import argparse
import cPickle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('players', help='The number of players')
    parser.add_argument('k', help='k')
    args = parser.parse_args()
    players = int(args.players)
    if args.k:
        k = int(args.k)
    else:
        k = players / 2  # N - 2 * t
    PK, SKs,gg = dealer(players=players, k=k)
    content = (PK.l, PK.k, serialize1(PK.VK), [serialize1(VKp) for VKp in PK.VKs],
               [(SK.i, serialize1(SK.SK)) for SK in SKs], serialize1(gg))
    print cPickle.dumps(content)

if __name__ == '__main__':
    main()
    