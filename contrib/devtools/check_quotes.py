#! /usr/bin/python3
# Based on Rusty Russell's check_quotes.py from lnprototest, adapted
# from BOLTs to BIPs.  It checks any quotes, using the following incantations:
#  * `BIP#42:` for bip-0042.mediawiki.
#  * `BIP#var-budget:` a BIP file called bip-*var-budget*.mediawiki (presumably
#    one not yet assigned a number.
#  * `BIP-50143e388e#var-budget:` is only check if --include-commit=50143e388e
#     is specified, useful for unmerged BIP / BIP changes.
#
# Released under the terms of the MIT license.
import fileinput
import glob
import re
import sys
from argparse import ArgumentParser, REMAINDER, Namespace
from collections import namedtuple
from typing import Dict, List, Tuple, Optional

Quote = namedtuple("Quote", ["filename", "line", "text"])
whitespace_re = re.compile(r"\s+")


def collapse_whitespace(string: str) -> str:
    return whitespace_re.sub(" ", string)


def add_quote(
    quotes: Dict[int, List[Quote]],
    docname: str,
    filename: str,
    line: int,
    quote: str,
) -> None:
    if docname not in quotes:
        quotes[docname] = []
    quotes[docname].append(
        Quote(filename, line, collapse_whitespace(quote.strip()))
    )


def included_commit(args: Namespace, boltprefix: str) -> bool:
    # e.g. BIP-50143e388e#42
    for inc in args.include_commit:
        if boltprefix.startswith(inc):
            return True
    return False


# This looks like a BIP# line; return the document name and start of
# quote if we shouldn't ignore it.
def get_bipstart(
    args: Namespace, line: str, filename: str, linenum: int
) -> Tuple[Optional[int], Optional[str]]:
    if not line.startswith(args.comment_start + "BIP"):
        return None, None

    # Must have a '#'.
    parts = line[len(args.comment_start + "BIP"):].partition("#")
    if parts[2] == '':
        return None, None

    # e.g. BIP-50143e388e#42
    if parts[0].startswith("-") and not included_commit(args, parts[0][1:]):
        return None, None

    result = parts[2].split(':', 2)
    if len(result) != 2:
        print("{}:{}:expected : after BIP in {}".format(filename,
                                                        linenum,
                                                        line),
              file=sys.stderr)
        sys.exit(1)

    return result[0], result[1]


# We expect lines to start with COMMENT-MARKER "BIP"'
def gather_quotes(args: Namespace) -> Dict[str, List[Quote]]:
    bipquotes: Dict[int, List[Quote]] = {}
    curquote = None
    # These initializations simply keep flake8 happy
    curbip = 0
    filestart = ""
    linestart = 0
    for file_line in fileinput.input(args.files):
        line = file_line.strip()
        bipnum, quote = get_bipstart(
            args, line, fileinput.filename(), fileinput.filelineno()
        )
        if bipnum is not None:
            # End existing one if necessary.
            if curquote is not None:
                add_quote(bipquotes, curbip, filestart, linestart, curquote)

            linestart = fileinput.filelineno()
            filestart = fileinput.filename()
            curbip = bipnum
            curquote = quote
        elif curquote is not None:
            # If this is a continuation (and not an end!), add it.
            if ((args.comment_end is None
                 or not line.startswith(args.comment_end)) and line.startswith(args.comment_continue)):  # noqa: E501

                # Special case where end marker is on same line.
                if (args.comment_end is not None and line.endswith(args.comment_end)):  # noqa: E501
                    curquote += " " + line[len(args.comment_continue):-len(args.comment_end)]  # noqa: E501
                    add_quote(bipquotes, curbip, filestart, linestart,
                              curquote)
                    curquote = None
                else:
                    curquote += " " + line[len(args.comment_continue):]
            else:
                add_quote(bipquotes, curbip, filestart, linestart, curquote)
                curquote = None

    # Handle quote at eof.
    if curquote is not None:
        add_quote(bipquotes, curbip, filestart, linestart, curquote)

    return bipquotes


def load_bip(bipdir: str, docname: str) -> List[str]:
    """Return a list, divided into one-string-per-bip-section, with
    whitespace collapsed into single spaces.

    """
    # BIP#<num> is canonically mapped.  Others are wildcards.
    if docname.isdigit():
        pattern = f"{bipdir}/bip-{docname:04}.mediawiki"
    else:
        pattern = f"{bipdir}/bip-*{docname}*.mediawiki"
    bipfile = glob.glob(pattern)
    if len(bipfile) == 0:
        print("Cannot find bip {} in {}".format(docname, bipdir),
              file=sys.stderr)
        sys.exit(1)
    elif len(bipfile) > 1:
        print(
            "More than one bip {} in {}? {}".format(docname, bipdir, bipfile),
            file=sys.stderr,
        )
        sys.exit(1)

    # We divide it into sections, and collapse whitespace.
    bipsections = []
    with open(bipfile[0]) as f:
        sect = ""
        for line in f.readlines():
            if line.startswith("="):
                # Append with whitespace collapsed.
                bipsections.append(collapse_whitespace(sect))
                sect = ""
            sect += line
        bipsections.append(collapse_whitespace(sect))

    return bipsections


def find_quote_parts(textparts: List[str],
                     sectiontext: str,
                     offset: int) -> Optional[int]:
    """Returns offsets within sectiontext where each part starts"""
    offsets = []
    for part in textparts:
        while True:
            offset = sectiontext.find(textparts[0], offset)
            if offset == -1:
                return []

            offsets.append(offset)
            # All done if this is the last.
            if len(textparts) == 1:
                return offsets

            # Search for the rest.
            res = find_quote_parts(textparts[1:], sectiontext, offset + len(textparts[0]))
            if res != []:
                return offsets + res

            # Ensure progress!
            offset += 1

    return []


def find_quote(textparts: List[str],
               bipsections: List[str]) -> Tuple[Optional[str], List[int]]:
    """Returns None, [] or sectiontext, and offsets of where each textparts was found"""
    for sectiontext in bipsections:
        offsets = find_quote_parts(textparts, sectiontext, 0)
        if offsets != []:
            return sectiontext, offsets

    return None, []


def main(args: Namespace) -> None:
    bipquotes = gather_quotes(args)
    for bip in bipquotes:
        bipsections = load_bip(args.bipdir, bip)
        for quote in bipquotes[bip]:
            sect, _ = find_quote(quote.text.split("..."), bipsections)
            if not sect:
                print(f"{quote.filename}:{quote.line}:cannot find match",
                      file=sys.stderr)
                # Reduce the text until we find a match.
                for n in range(len(quote.text), -1, -1):
                    parts = quote.text[:n].split("...")
                    sect, offsets = find_quote(parts, bipsections)
                    if sect:
                        print(f"  common prefix: {parts[-1]}...",
                              file=sys.stderr)
                        print(f"  expected ...{quote.text[n:]:.45}",
                              file=sys.stderr)
                        print(f"  but have ...{sect[offsets[-1] + len(parts[-1]):]:.45}",
                              file=sys.stderr)
                        break
                sys.exit(1)
            elif args.verbose:
                print(f"{quote.filename}:{quote.line}:"
                      f"Matched {quote.text} in {sect}")


if __name__ == "__main__":
    parser = ArgumentParser(
        description="Check BIP quotes in the given files are correct"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    # e.g. for C code these are '/* ', '*' and '*/', Python '# ' and '# '
    parser.add_argument("--comment-start",
                        help='marker for start of "BIP#N" quote',
                        default="// ")
    parser.add_argument("--comment-continue",
                        help='marker for continued "BIP#N" quote',
                        default="//")
    parser.add_argument("--comment-end",
                        help='marker for end of "BIP#N" quote')
    parser.add_argument("--include-commit",
                        action="append",
                        help="Also parse BIP-<commit> quotes",
                        default=[])
    parser.add_argument("--bipdir",
                        help="Directory to look for BIP tests",
                        default="../bips")
    parser.add_argument("files",
                        help="Files to read in (or stdin)",
                        nargs=REMAINDER)

    args = parser.parse_args()
    main(args)
