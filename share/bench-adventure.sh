#! /bin/sh -e

BANNERS=false
[ ! -f bench-adventure*.out ] 2>/dev/null || BANNERS=true
NOSLEEP=$BANNERS

for arg; do
    case "$1" in
	--nosleep)
	    NOSLEEP=true
	    ;;
	--full)
	    BANNERS=false
	    ;;
	--benchfrom=*)
	    BENCHFROM=${arg#--benchfrom=}
	    ;;
	*)
	    echo "Unknown arg $arg" >&2
	    exit 1
	    ;;
    esac
    shift
done

banner()
{
    $BANNERS || if [ "$#" -gt 0 ]; then echo "$@"; else cat; fi
}

dramatic_pause()
{
    $NOSLEEP || sleep "$1"
}

# benchname [op1len] [op2len]
run_bench()
{
    BENCHNAME="$1"
    if [ -n "$2" ]; then BENCHNAME="$BENCHNAME"-"$2"; fi
    if [ -n "$3" ]; then BENCHNAME="$BENCHNAME"-"$3"; fi
    if [ -z "$BENCHFROM" ]; then
	BENCHF=`mktemp`
	EVALSCRIPT_OP1_BYTES="$2" EVALSCRIPT_OP2_BYTES="$3" ./src/bench/bench_bitcoin -filter="$1" -output-csv="$BENCHF" -min-time=5000 > /dev/null
	grep "^$1," "$BENCHF"
	grep "^$1," "$BENCHF" | sed "s/^$1,/$BENCHNAME,/" >> $OUTFILE
	rm "$BENCHF"
    else
	grep "^$BENCHNAME," "$BENCHFROM"
    fi
}

# benchname [basenum] [op1len] [op2len]
benchof()
{
    # This can give "6.15529084665482e-05" which bc doesn't understand
    SECONDS=$(run_bench "$1" "$3" "$4" | cut -d, -f7)
    # So we use printf "%.20f" to canonicalize it:
    NSEC=$(echo "$(printf %.20f $SECONDS) * 10^9" | bc | cut -d. -f1)
    if [ -n "$2" ]; then
	echo "$NSEC - $2" | bc
    else
	echo "$NSEC"
    fi
}

result()
{
    PREFIX=$1
    TIME=$2
    shift 2
    echo "* $PREFIX: $TIME nanoseconds" "$@"
}

result_end()
{
    result "$@"
    echo
    dramatic_pause 2
}
    
warn()
{
    echo "*** THIS IS WEIRD: $1"
    echo "Please report these results for $MNAME:"
    shift
    for arg; do
	run_bench $arg
    done
}

percent_and_dir()
{
    if [ $1 -lt $2 ]; then
	PERCENT=$(echo "scale=10; ($1 / $2 - 1) * -100" | bc)
	DESC="faster"
    else
	PERCENT=$(echo "scale=10; ($1 / $2 - 1) * 100" | bc)
	DESC="slower"
    fi
    # Give us 2 sig figs only
    printf "%.2g%% %s" "$PERCENT" $DESC
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

$BANNERS || printf "> "
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
OUTFILE="bench-adventure-$MNAME.out"
if [ -f $OUTFILE ]; then
    i=2
    while true; do
	OUTFILE="bench-adventure-$MNAME-$i.out"
	[ -f "$OUTFILE" ] || break
	i=$((i+1))
    done
fi
echo "This is a test of your $MACHINE, which we'll call $MNAME (output into $OUTFILE)"
echo

banner <<EOF
Let's try checking 80,000 signatures (this is the maximum allowed in a block, so sets a reasonable target for "slowest block processing").
EOF

SCHNORR_TIME=$(benchof VerifySchnorr)
BLOCK_VALIDATION_NSEC=$((SCHNORR_TIME * 80000))
BLOCK_VALIDATION_SECONDS=$(printf %.4g $(echo $BLOCK_VALIDATION_NSEC / 10^9 | bc -l))
result "1 Schnorr signature check" $SCHNORR_TIME
result_end "A block full of 80,000 schnorr signatures" $BLOCK_VALIDATION_NSEC "($BLOCK_VALIDATION_SECONDS seconds)"

banner <<EOF
We start with pushing two 4MB elements on the stack (the max allowed under the proposed rules, because that fits two of the largest possible transactions), and seeing how long it takes to do that and run a simple "NOP NOP" empty script.  This is our baseline.
EOF

# Literal NOP
NOPNOP_TIME=$(benchof EvalScriptNopNop)
banner <<EOF
That takes $NOPNOP_TIME nanoseconds.

A "DROP DROP" script should take about the same:
EOF

DROPDROP_TIME=$(benchof EvalScriptDropDrop)

DESC=$(percent_and_dir $DROPDROP_TIME $NOPNOP_TIME)

banner <<EOF
... $DROPDROP_TIME ($DESC).

EOF

[ $(echo "$(echo $DESC | cut -d% -f1) >= 5" | bc) = 0 ] || warn "DROP time is $DESC!" EvalScriptNopNop EvalScriptDropDrop

dramatic_pause 2

banner <<EOF
Now we look at the increase in time, when we simply read the 4MB value in script.  We use OP_VERIFY for this, and two 4MB element which are all zeros until the very last byte, so it has to look through them all.  Similarly, we look at simply comparing them:

EOF

VERIFY_TIME=$(benchof EvalScriptVerifyVerify $DROPDROP_TIME)
result "Verifying 4MBx2" "$VERIFY_TIME"
EQUALS_TIME=$(benchof EvalScriptEqual $DROPDROP_TIME)
result_end "Comparing 4MBx2" "$EQUALS_TIME"

banner <<EOF
Now let's copy a 4MB element (twice, to be fair) (OP_DUP).

EOF

DUP_TIME=$(benchof EvalScriptDropDupDropDup $DROPDROP_TIME)
result_end "Copy 4MBx2" "$DUP_TIME"

banner <<EOF
Now let's rewrite both 4MB elements (OP_INVERT):

EOF

INVERT_TIME=$(benchof EvalScriptInvertDropInvert $DROPDROP_TIME)
result_end "Rewrite 4MBx2" "$INVERT_TIME"

banner <<EOF
We can actually split this into two halves, we can see that doing only 4MB can be more than twice as fast as doing 8MB (technically part1 is fresher in the cache than part2, but that often is only in the noise):

EOF

INVERT1_TIME=$(benchof EvalScriptInvert $DROPDROP_TIME)
result "Rewrite 4MB (part 1)" "$INVERT1_TIME" "("$(percent_and_dir $INVERT1_TIME $(($INVERT_TIME / 2)) )")"
INVERT2_TIME=$(benchof EvalScriptDropInvert $DROPDROP_TIME)
result_end "Rewrite 4MB (part 2)" "$INVERT2_TIME" "("$(percent_and_dir $INVERT2_TIME $(($INVERT_TIME / 2)) )")"

# 1 byte invert = INVERT_TIME / 8M.
# => bytes per block validation = BLOCK_VALIDATION_NSEC / (INVERT_TIME / 8M)
BYTES_OF_INVERT_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $INVERT_TIME" | bc)
MB_INVERT_PER_BLOCK=$(printf %.2fMB $(echo "$BYTES_OF_INVERT_PER_BLOCK / 1000000" | bc -l))

BYTES_OF_VERIFY_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $VERIFY_TIME" | bc)
MB_VERIFY_PER_BLOCK=$(printf %.2fMB $(echo "$BYTES_OF_VERIFY_PER_BLOCK / 1000000" | bc -l))
		      
banner <<EOF
So, if it takes $BLOCK_VALIDATION_SECONDS seconds for a worst-case block signature validation, we could invert about $BYTES_OF_INVERT_PER_BLOCK bytes ($MB_INVERT_PER_BLOCK) during that time, or verify $BYTES_OF_VERIFY_PER_BLOCK bytes ($MB_VERIFY_PER_BLOCK)!

EOF

banner <<EOF
Combining two 4MB elements:

EOF

AND_TIME=$(benchof EvalScriptAnd $DROPDROP_TIME)
result "AND 4MBx2" $AND_TIME
OR_TIME=$(benchof EvalScriptOr $DROPDROP_TIME)
result "OR 4MBx2" $OR_TIME
ADD_TIME=$(benchof EvalScriptAdd $DROPDROP_TIME)
result "Add 4MBx2" $ADD_TIME
ADD_OVERFLOW_TIME=$(benchof EvalScriptAddOverflow $DROPDROP_TIME)
result "Add 4MBx2 (with overflow)" $ADD_OVERFLOW_TIME
SUB_TIME=$(benchof EvalScriptSub $DROPDROP_TIME)
result_end "Sub 4MBx2" $SUB_TIME

banner <<EOF
Multiplying (we use smaller elements here!):

EOF

# We need new basis for comparison for these!
DROPDROP_40K=$(benchof EvalScriptDropDrop "" 40000 40000)
DROPDROP_40K_1=$(benchof EvalScriptDropDrop "" 40000 1)
MUL_40K_40K_TIME=$(benchof EvalScriptMul $DROPDROP_40K 40000 40000)
result "40,000 x 40,000" $MUL_40K_40K_TIME
MUL_40K_1_TIME=$(benchof EvalScriptMul $DROPDROP_40K_1 1 40000)
result "40,000 x 1" $MUL_40K_1_TIME
MUL_1_40K_TIME=$(benchof EvalScriptMul $DROPDROP_40K_1 40000 1)
result_end "1 x 40,000" $MUL_1_40K_TIME

banner <<EOF
Dividing:

EOF

DIV_4M_4M_TIME=$(benchof EvalScriptDiv $DROPDROP_TIME)
result "4MB / 4MB" $DIV_4M_4M_TIME
DROPDROP_4M_1=$(benchof EvalScriptDropDrop "" 1)
DIV_4M_1_TIME=$(benchof EvalScriptDiv $DROPDROP_4M_1 1)
result_end "4MB / 1" $DIV_4M_1_TIME

banner <<EOF
Finally, SHA256 for comparison:

EOF

SHA256_TIME=$(benchof EvalScriptSHA256DropSHA256 $DROPDROP_TIME)
result_end "4MBx2 SHA256" $SHA256_TIME

SHA256_INVERT_RATIO=$(printf %.4g $(echo "$SHA256_TIME / $INVERT_TIME" | bc -l))

banner <<EOF
This implies that SHA256 is about $SHA256_INVERT_RATIO times more expensive than a simple modify.

EOF

if [ -z "$BENCHFROM" ]; then
    echo Here are the final results:
    cat $OUTFILE
fi
