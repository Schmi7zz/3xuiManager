import argparse
import getpass
import sys

from xui_management.auth import hash_password
from xui_management.config import Store
from xui_management.panel import PanelError
from xui_management.server import serve


def main(argv=None):
    parser = argparse.ArgumentParser(prog="xui-management")
    parser.add_argument("-c", "--config", default="config.json")
    parser.add_argument("command", nargs="?", choices=("hashpw", "check"))
    args = parser.parse_args(argv)

    if args.command == "hashpw":
        password = getpass.getpass("Password for the restricted user: ")
        if password != getpass.getpass("Repeat: "):
            sys.exit("Passwords don't match")
        if len(password) < 8:
            sys.exit("Password must be at least 8 characters")
        print(hash_password(password))
        return 0

    store = Store(args.config)
    try:
        store.load()
    except FileNotFoundError:
        sys.exit("Config not found: {}".format(args.config))
    except (OSError, ValueError, KeyError) as exc:
        sys.exit("Could not read config: {}".format(exc))

    from xui_management.panel import PanelClient

    panel = PanelClient(store.data)
    if args.command == "check":
        try:
            panel.login(force=True)
        except PanelError as exc:
            sys.exit(str(exc))
        for inbound in panel.inbounds(fresh=True):
            print("id={:<5} port={:<6} {:<12} {}".format(
                inbound.get("id"), inbound.get("port"), inbound.get("protocol", ""), inbound.get("remark", "")
            ))
        return 0

    try:
        panel.login(force=True)
        print("Connected to 3x-ui")
    except PanelError as exc:
        print("WARNING: {}".format(exc), file=sys.stderr)
    serve(store, panel)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
