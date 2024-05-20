#! /bin/sh -e

FAST=false
[ ! -f bench-adventure*.out ] 2>/dev/null || FAST=true
NOSLEEP=$FAST

if [ x$1 = x"--nosleep" ]; then NOSLEEP=true; fi

banner()
{
    $FAST || if [ "$#" -gt 0 ]; then echo "$@"; else cat; fi
}

dramatic_pause()
{
    $NOSLEEP || sleep "$1"
}

# benchname [basenum]
benchof()
{
    SECONDS=$(grep "^$1," "$BENCHF" | cut -d, -f7)
    NSEC=$(echo "$SECONDS * 10^9" | bc | cut -d. -f1)
    if [ -n "$2" ]; then
	echo "$NSEC - $2" | bc
    else
	echo "$NSEC"
    fi
}

warn()
{
    echo "*** THIS IS WEIRD: $@"
    echo "Please report these results for $MNAME:"
    cat "$BENCHF"
}

banner <<EOF
Welcome to  ____                      _     
           (  _ \\                    ( )    
           | (_) ) ____  ____    ___ | |__  
           |  _ ( / __ \\(  _ \\  / __)|  _ \\
           | (_) |  ___/( ( ) |( (__ | | | |
      ___  (____/ \\____)(_) (_) \\___)(_) (_)
    / _  )     / )                    / )_                  
   / (_) |____/ /_   _  ____   ____  / ___)  _  ___ ____  
  /  _  // _   // ) ( )/ __ \\ / _  \\/ / / ) ( )/ __) __ \\
 / / / /| (_| // /_/ //  ___// / ) / /_/ /_/ // / /  ___/
/_/ /_/ \\____/ \\____/ \\____)/_/ /_/\\__/\\____//_/  \\____)

EOF

dramatic_pause 5

banner <<EOF
West of House

You are standing in an open field west of a white house, with a boarded front door.

There is a small cat here.

EOF

$FAST || printf "> "
dramatic_pause 5

banner <<EOF
Sorry, not *that* kind of adventure!

EOF

dramatic_pause 1

# Linux, FreeBSD.
MACHINE=$(grep '^model name' /proc/cpuinfo) || MACHINE=$(sysctl hw.model) || MACHINE=unknown
MACHINE=$(echo "$MACHINE" | cut -d: -f2- | head -n1)

# Remove (TM) and (R) etc.
MNAME=$(echo $MACHINE | sed -e 's/(TM)\|(R)//g' -e 's/  */-/g')
echo "This is a test of your $MACHINE, which we'll call $MNAME"

BENCHF=`mktemp`
trap "rm -f $BENCHF" 0

./src/bench/bench_bitcoin -filter='EvalScript.*' -output-csv="$BENCHF"

# Literal NOP
NOPNOP_TIME=$(benchof EvalScriptNopNop)
DROPDROP_TIME=$(benchof EvalScriptDropDrop)

# They should be within a few percent.
if [ $DROPDROP_TIME -lt $NOPNOP_TIME ]; then
    PERCENT=$(echo "scale=10; ($DROPDROP_TIME / $NOPNOP_TIME - 1) * -100" | bc | cut -d. -f1)
    DESC="faster"
else
    PERCENT=$(echo "scale=10; ($DROPDROP_TIME / $NOPNOP_TIME - 1) * 100" | bc | cut -d. -f1)
    DESC="slower"
fi

banner <<EOF
We start with pushing two 4MB elements on the stack (the max allowed under the proposed rules, because that fits two of the largest possible transactions), and seeing how long it takes to do that and run a simple "NOP NOP" empty script.  This is our baseline.

That takes $NOPNOP_TIME nanoseconds.  A "DROP DROP" script should take about the same: $DROPDROP_TIME ($PERCENT% $DESC).
EOF

[ $PERCENT -lt 10 ] || warn "DROP time is $PERCENT slower!"

dramatic_pause 2

HOT_VERIFY_TIME=$(benchof EvalScriptVerifyDrop $DROPDROP_TIME)
COLD_VERIFY_TIME=$(benchof EvalScriptDropVerify $DROPDROP_TIME)

banner <<EOF
Now we look at the increase in time, when we simply read the 4MB value in script.  We use OP_VERIFY for this, and a 4MB element which is all zeros until the very last byte, so it has to look through them all.

We test two cases: where the element is the last thing we wrote (hot in the CPU's cache) and where it's older (colder in the CPU's cache):

Hot: +$HOT_VERIFY_TIME nanoseconds
Cold: +$COLD_VERIFY_TIME nanoseconds

EOF

dramatic_pause 2

HOT_DUP_TIME=$(benchof EvalScriptNipDup $DROPDROP_TIME)
COLD_DUP_TIME=$(benchof EvalScriptDropDup $DROPDROP_TIME)

banner <<EOF
Now let's copy a 4MB element (OP_DUP).  Again, we have a fresh one and an older one:

Hot copy: +$HOT_DUP_TIME nanoseconds
Cold copy: +$COLD_DUP_TIME nanoseconds

EOF

dramatic_pause 2

HOT_INVERT_TIME=$(benchof EvalScriptInvertDrop $DROPDROP_TIME)
COLD_INVERT_TIME=$(benchof EvalScriptDropInvert $DROPDROP_TIME)

banner <<EOF
Now let's rewrite a 4MB element (OP_INVERT).  Again, we have a fresh one and an older one:

Hot rewrite: +$HOT_INVERT_TIME nanoseconds
Cold rewrite: +$COLD_INVERT_TIME nanoseconds

EOF

