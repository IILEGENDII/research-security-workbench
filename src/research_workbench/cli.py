import argparse

from . import __version__


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="research-security", description="Evaluate local workstation evidence."
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.parse_args(argv)
    return 0
