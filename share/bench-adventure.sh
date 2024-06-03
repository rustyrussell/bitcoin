#! /bin/sh -e

BANNERS=false
[ ! -f bench-adventure*.out ] 2>/dev/null || BANNERS=true
NOSLEEP=$BANNERS

DEFAULT_LARGE=4000000
DEFAULT_SMALL=400000

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
	# First time, we include header.
	[ -r "$OUTFILE" ] || head -n1 "$BENCHF" > $OUTFILE
	grep "^$1," "$BENCHF" | sed "s/^$1,/$BENCHNAME,/" | tee -a $OUTFILE
	rm "$BENCHF"
    else
	grep "^$BENCHNAME," "$BENCHFROM"
    fi
}

# benchname [op1len] [op2len]
benchof()
{
    # This can give "6.15529084665482e-05" which bc doesn't understand
    SECONDS=$(run_bench "$1" "$2" "$3" | cut -d, -f7)
    # So we use printf "%.20f" to canonicalize it:
    echo "$(printf %.20f $SECONDS) * 10^9" | bc | cut -d. -f1
}

# benchname reltime [op1len] [op2len]
benchrel()
{
    [ -n "$2" ] || exit 1
    NSEC=$(benchof $1 $3 $4)
    echo "$NSEC - $2" | bc
}

# benchname reltime
large_benchrel()
{
    benchrel $1 $2 $DEFAULT_LARGE $DEFAULT_LARGE
}

# benchname reltime
small_benchrel()
{
    benchrel $1 $2 $DEFAULT_SMALL $DEFAULT_SMALL
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
	run_bench $arg $DEFAULT_LARGE $DEFAULT_LARGE
	run_bench $arg $DEFAULT_SMALL $DEFAULT_SMALL
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
We consider two possibilities.  In the first ("small) we set the maximum stack size at 400 kilobytes, with a maximum of 800 kilobytes: this lets you fit two standard transactions on the stack.

In the second ("large") we use 4MB stack elements, which fits two largest possible legal transactions on the stack.

First we set a baseline: push two elements on the stack, and seeing how long it takes to do that and run a simple "NOP NOP" empty script:
EOF

# Literal NOP
LARGE_NOPNOP_TIME=$(benchof EvalScriptNopNop $DEFAULT_LARGE $DEFAULT_LARGE)
SMALL_NOPNOP_TIME=$(benchof EvalScriptNopNop $DEFAULT_SMALL $DEFAULT_SMALL)

banner <<EOF
4MBx2:   $LARGE_NOPNOP_TIME nanoseconds.
400kBx2: $SMALL_NOPNOP_TIME nanoseconds.

A "DROP DROP" script should take about the same:
EOF

LARGE_DROPDROP_TIME=$(benchof EvalScriptDropDrop $DEFAULT_LARGE $DEFAULT_LARGE)
SMALL_DROPDROP_TIME=$(benchof EvalScriptDropDrop $DEFAULT_SMALL $DEFAULT_SMALL)

LARGE_DESC=$(percent_and_dir $LARGE_DROPDROP_TIME $LARGE_NOPNOP_TIME)
SMALL_DESC=$(percent_and_dir $SMALL_DROPDROP_TIME $SMALL_NOPNOP_TIME)

banner <<EOF
4MBx2 DROP DROP:   $LARGE_DROPDROP_TIME ($LARGE_DESC).
400kBx2 DROP DROP: $SMALL_DROPDROP_TIME ($SMALL_DESC).

EOF

[ $(echo "$(echo $LARGE_DESC | cut -d% -f1) >= 10" | bc) = 0 ] || warn "Large DROP time is $LARGE_DESC!" EvalScriptNopNop EvalScriptDropDrop
[ $(echo "$(echo $SMALL_DESC | cut -d% -f1) >= 10" | bc) = 0 ] || warn "Small DROP time is $SMALL_DESC!" EvalScriptNopNop EvalScriptDropDrop

dramatic_pause 2

banner <<EOF
Now we look at the increase in time, when we simply read the maximal stack values in script.  We use OP_VERIFY (twice) for this, and two elements which are all zeros until the very last byte, so it has to look through them all.  Similarly, we look at simply comparing them:

EOF

LARGE_VERIFY_TIME=$(large_benchrel EvalScriptVerifyVerify $LARGE_DROPDROP_TIME)
result "Verifying 4MB x 2" "$LARGE_VERIFY_TIME"
SMALL_VERIFY_TIME=$(small_benchrel EvalScriptVerifyVerify $SMALL_DROPDROP_TIME)
result "Verifying 400kB x 2" "$SMALL_VERIFY_TIME"
LARGE_EQUALS_TIME=$(large_benchrel EvalScriptEqual $LARGE_DROPDROP_TIME)
result "Comparing 4MB x 2" "$LARGE_EQUALS_TIME"
SMALL_EQUALS_TIME=$(small_benchrel EvalScriptEqual $SMALL_DROPDROP_TIME)
result_end "Comparing 400kB x 2" "$SMALL_EQUALS_TIME"

banner <<EOF
Now let's copy a single maximal element (twice, to be fair) (OP_DUP).

EOF

LARGE_DUP_TIME=$(large_benchrel EvalScriptDropDupDropDup $LARGE_DROPDROP_TIME)
SMALL_DUP_TIME=$(benchrel EvalScriptDropDupDropDup $SMALL_DROPDROP_TIME $DEFAULT_SMALL $DEFAULT_SMALL)
result "Copy 4MB x 2  " "$LARGE_DUP_TIME"
result_end "Copy 400kB x 2" "$SMALL_DUP_TIME"

banner <<EOF
Now let's rewrite both maximal elements (OP_INVERT):

EOF

LARGE_INVERT_TIME=$(large_benchrel EvalScriptInvertDropInvert $LARGE_DROPDROP_TIME)
result "Rewrite 4MB x 2  " "$LARGE_INVERT_TIME"
SMALL_INVERT_TIME=$(benchrel EvalScriptInvertDropInvert $SMALL_DROPDROP_TIME $DEFAULT_SMALL $DEFAULT_SMALL)
result_end "Rewrite 400kB x 2" "$SMALL_INVERT_TIME"

banner <<EOF
We can actually split this into two halves, we can see that doing only half the size can be more than twice as fast as doing the whole thing (technically part1 is fresher in the cache than part2, but that often is only in the noise):

EOF

LARGE_INVERT1_TIME=$(large_benchrel EvalScriptInvert $LARGE_DROPDROP_TIME)
result "Rewrite 4MB (part 1)  " "$LARGE_INVERT1_TIME" "("$(percent_and_dir $LARGE_INVERT1_TIME $(($LARGE_INVERT_TIME / 2)) )")"
LARGE_INVERT2_TIME=$(large_benchrel EvalScriptDropInvert $LARGE_DROPDROP_TIME)
result "Rewrite 4MB (part 2)  " "$LARGE_INVERT2_TIME" "("$(percent_and_dir $LARGE_INVERT2_TIME $(($LARGE_INVERT_TIME / 2)) )")"
SMALL_INVERT1_TIME=$(benchrel EvalScriptInvert $SMALL_DROPDROP_TIME $DEFAULT_SMALL $DEFAULT_SMALL)
result "Rewrite 400kB (part 1)" "$SMALL_INVERT1_TIME" "("$(percent_and_dir $SMALL_INVERT1_TIME $(($SMALL_INVERT_TIME / 2)) )")"
SMALL_INVERT2_TIME=$(benchrel EvalScriptDropInvert $SMALL_DROPDROP_TIME $DEFAULT_SMALL $DEFAULT_SMALL)
result_end "Rewrite 400kB (part 2)" "$SMALL_INVERT2_TIME" "("$(percent_and_dir $SMALL_INVERT2_TIME $(($SMALL_INVERT_TIME / 2)) )")"

# 1 byte invert = INVERT_TIME / 8M.
# => bytes per block validation = BLOCK_VALIDATION_NSEC / (INVERT_TIME / 8M)
LARGE_BYTES_OF_INVERT_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $LARGE_INVERT_TIME" | bc)
LARGE_MB_INVERT_PER_BLOCK=$(printf %.2fMB $(echo "$LARGE_BYTES_OF_INVERT_PER_BLOCK / 1000000" | bc -l))

LARGE_BYTES_OF_VERIFY_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $LARGE_VERIFY_TIME" | bc)
LARGE_MB_VERIFY_PER_BLOCK=$(printf %.2fMB $(echo "$LARGE_BYTES_OF_VERIFY_PER_BLOCK / 1000000" | bc -l))

SMALL_BYTES_OF_INVERT_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $SMALL_INVERT_TIME" | bc)
SMALL_MB_INVERT_PER_BLOCK=$(printf %.2fMB $(echo "$SMALL_BYTES_OF_INVERT_PER_BLOCK / 1000000" | bc -l))

SMALL_BYTES_OF_VERIFY_PER_BLOCK=$(echo "$BLOCK_VALIDATION_NSEC * 8000000 / $SMALL_VERIFY_TIME" | bc)
SMALL_MB_VERIFY_PER_BLOCK=$(printf %.2fMB $(echo "$SMALL_BYTES_OF_VERIFY_PER_BLOCK / 1000000" | bc -l))

banner <<EOF
So, if it takes $BLOCK_VALIDATION_SECONDS seconds for a worst-case block signature validation, how much could we do in that time?

Invert (modifying bytes):
   4MB stack limit:   $LARGE_BYTES_OF_INVERT_PER_BLOCK bytes ($LARGE_MB_INVERT_PER_BLOCK)
   400kB stack limit: $SMALL_BYTES_OF_INVERT_PER_BLOCK bytes ($SMALL_MB_INVERT_PER_BLOCK)

Verify (reading bytes):
   4MB stack limit:   $LARGE_BYTES_OF_VERIFY_PER_BLOCK bytes ($LARGE_MB_VERIFY_PER_BLOCK)
   400kB stack limit: $SMALL_BYTES_OF_VERIFY_PER_BLOCK bytes ($SMALL_MB_VERIFY_PER_BLOCK)
EOF

banner <<EOF
Combining two elements:

EOF

LARGE_AND_TIME=$(large_benchrel EvalScriptAnd $LARGE_DROPDROP_TIME)
result "AND 4MBx2  " $LARGE_AND_TIME
SMALL_AND_TIME=$(small_benchrel EvalScriptAnd $SMALL_DROPDROP_TIME)
result "AND 400kBx2" $SMALL_AND_TIME

LARGE_OR_TIME=$(large_benchrel EvalScriptOr $LARGE_DROPDROP_TIME)
result "OR 4MBx2   " $LARGE_OR_TIME
SMALL_OR_TIME=$(small_benchrel EvalScriptOr $SMALL_DROPDROP_TIME)
result "OR 400kB   " $SMALL_OR_TIME

LARGE_ADD_TIME=$(large_benchrel EvalScriptAdd $LARGE_DROPDROP_TIME)
result "Add 4MBx2  " $LARGE_ADD_TIME
SMALL_ADD_TIME=$(small_benchrel EvalScriptAdd $SMALL_DROPDROP_TIME)
result "Add 400kBx2" $SMALL_ADD_TIME

LARGE_ADD_OVERFLOW_TIME=$(large_benchrel EvalScriptAddOverflow $DROPDROP_TIME)
result "Add 4MBx2 (with overflow)  " $LARGE_ADD_OVERFLOW_TIME
SMALL_ADD_OVERFLOW_TIME=$(small_benchrel EvalScriptAddOverflow $DROPDROP_TIME)
result "Add 400kBx2 (with overflow)" $SMALL_ADD_OVERFLOW_TIME

LARGE_SUB_TIME=$(large_benchrel EvalScriptSub $LARGE_DROPDROP_TIME)
result "Sub 4MBx2  " $LARGE_SUB_TIME
SMALL_SUB_TIME=$(small_benchrel EvalScriptSub $SMALL_DROPDROP_TIME)
result_end "Sub 400kBx2" $SMALL_SUB_TIME

banner <<EOF
Multiplying (we use smaller elements here!):

EOF

# We need new basis for comparison for these!
DROPDROP_40K=$(benchof EvalScriptDropDrop 40000 40000)
DROPDROP_40K_1=$(benchof EvalScriptDropDrop 40000 1)
MUL_40K_40K_TIME=$(benchrel EvalScriptMul $DROPDROP_40K 40000 40000)
result "40,000 x 40,000" $MUL_40K_40K_TIME
MUL_40K_1_TIME=$(benchrel EvalScriptMul $DROPDROP_40K_1 1 40000)
result "40,000 x 1     " $MUL_40K_1_TIME
MUL_1_40K_TIME=$(benchrel EvalScriptMul $DROPDROP_40K_1 40000 1)
result_end "1 x 40,000     " $MUL_1_40K_TIME

banner <<EOF
Dividing:

EOF

LARGE_DIV_4M_4M_TIME=$(large_benchrel EvalScriptDiv $LARGE_DROPDROP_TIME)
result "4MB / 4MB    " $LARGE_DIV_4M_4M_TIME
SMALL_DIV_4M_4M_TIME=$(small_benchrel EvalScriptDiv $SMALL_DROPDROP_TIME)
result "400kB / 400kB" $SMALL_DIV_4M_4M_TIME

LARGE_DROPDROP_4M_1=$(benchof EvalScriptDropDrop 1 $DEFAULT_LARGE)
LARGE_DIV_4M_1_TIME=$(large_benchrel EvalScriptDiv $LARGE_DROPDROP_4M_1 1)
result "4MB / 1  " $LARGE_DIV_4M_1_TIME
SMALL_DROPDROP_4M_1=$(benchof EvalScriptDropDrop 1 $DEFAULT_SMALL)
SMALL_DIV_4M_1_TIME=$(small_benchrel EvalScriptDiv $SMALL_DROPDROP_4M_1 1)
result_end "400kB / 1" $SMALL_DIV_4M_1_TIME

banner <<EOF
Finally, SHA256 for comparison:

EOF

LARGE_SHA256_TIME=$(large_benchrel EvalScriptSHA256DropSHA256 $LARGE_DROPDROP_TIME)
result "4MBx2 SHA256  " $LARGE_SHA256_TIME
SMALL_SHA256_TIME=$(small_benchrel EvalScriptSHA256DropSHA256 $SMALL_DROPDROP_TIME)
result_end "400kBx2 SHA256" $SMALL_SHA256_TIME

LARGE_SHA256_VERIFY_RATIO=$(printf %.4g $(echo "$LARGE_SHA256_TIME / $LARGE_INVERT_TIME" | bc -l))
SMALL_SHA256_VERIFY_RATIO=$(printf %.4g $(echo "$SMALL_SHA256_TIME / $SMALL_INVERT_TIME" | bc -l))

banner <<EOF
This implies that SHA256 is about $LARGE_SHA256_VERIFY_RATIO times more expensive than a simple modify for the 4MB limit, or $SMALL_SHA256_VERIFY_RATIO times more expensive for the 400kB limit

EOF

if [ -z "$BENCHFROM" ]; then
    echo Here are the final results:
    cat $OUTFILE
fi
