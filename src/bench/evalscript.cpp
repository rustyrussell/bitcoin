#include <bench/bench.h>

#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <unistd.h>

/* To figure out worst possible case for a block, note that you can
 * have 400 of these!  Also, this limit only applies for v0 and v1 segwit.
 */
#define BENCH_SCRIPT_SIZE (10000)

static size_t get_bytes(size_t default_val)
{
	const char *env = getenv("EVALSCRIPT_BYTES");
	if (!env)
		return default_val;
	return atol(env);
}	

static void BenchEvalScript(benchmark::Bench& bench,
							const CScript &script,
							std::vector<std::vector<unsigned char> > &stack,
							size_t size)
{
	BaseSignatureChecker checker;
	ScriptExecutionData sdata;
	bench.batch(BENCH_SCRIPT_SIZE).unit("ops").run([&] {
		assert(EvalScript(stack, script, 0, checker,
						  SigVersion::TAPSCRIPT, sdata, NULL));
	});
}

// If the only limit were total stack usage
static const size_t MAX_POSSIBLE_STACK = MAX_SCRIPT_ELEMENT_SIZE * MAX_STACK_SIZE;
// If we're doing OP_DUP or OP_EQUAL each one can only use half the possible stack.
static const size_t MAX_POSSIBLE_STACK_2OF = MAX_POSSIBLE_STACK / 2;
// Two dups?  Can only use a third
static const size_t MAX_POSSIBLE_STACK_3OF = MAX_POSSIBLE_STACK / 3;

static void EvalScriptDupDrop(benchmark::Bench& bench)
{
	CScript script;
	std::vector<std::vector<unsigned char> > stack;
	size_t ops = 0;

	// Create maximum theoretical script
	while (script.size() < BENCH_SCRIPT_SIZE) {
		script << OP_DUP << OP_DROP;
		ops++;
	}

	stack.resize(1);
	stack[0].resize(get_bytes(MAX_POSSIBLE_STACK_2OF));

	BenchEvalScript(bench, script, stack, MAX_POSSIBLE_STACK_2OF * ops);
}
BENCHMARK(EvalScriptDupDrop, benchmark::LOW);

static void EvalScriptDupDupEqualVerify(benchmark::Bench& bench)
{
	CScript script;
	std::vector<std::vector<unsigned char> > stack;
	size_t ops = 0;

	// Create maximum theoretical script
	while (script.size() < BENCH_SCRIPT_SIZE) {
		script << OP_DUP << OP_DUP << OP_EQUALVERIFY;
		ops++;
	}

	// Note: lshift could make it easier to make large things
	stack.resize(1);
	stack[0].resize(get_bytes(MAX_POSSIBLE_STACK_3OF));

	BenchEvalScript(bench, script, stack, stack[0].size() * ops);
}
BENCHMARK(EvalScriptDupDupEqualVerify, benchmark::LOW);

static void EvalScriptDupSHADrop(benchmark::Bench& bench)
{
	CScript script;
	std::vector<std::vector<unsigned char> > stack;
	size_t ops = 0;

	// Create maximum theoretical script
	while (script.size() < BENCH_SCRIPT_SIZE) {
		script << OP_DUP << OP_SHA256 << OP_DROP;
		ops++;
	}

	stack.resize(1);
	stack[0].resize(get_bytes(MAX_POSSIBLE_STACK_2OF));

	BenchEvalScript(bench, script, stack, stack[0].size() * ops);
}
BENCHMARK(EvalScriptDupSHADrop, benchmark::LOW);

static void EvalScriptDupNopDrop(benchmark::Bench& bench)
{
	CScript script;
	std::vector<std::vector<unsigned char> > stack;
	size_t ops = 0;

	// Create maximum theoretical script
	while (script.size() < BENCH_SCRIPT_SIZE) {
		script << OP_DUP << OP_NOP4 << OP_DROP;
		ops++;
	}

	stack.resize(1);
	stack[0].resize(get_bytes(MAX_POSSIBLE_STACK_2OF));

	BenchEvalScript(bench, script, stack, stack[0].size() * ops);
}
BENCHMARK(EvalScriptDupNopDrop, benchmark::LOW);

static void EvalScriptDupDup2DropMax(benchmark::Bench& bench)
{
	CScript script;
	std::vector<std::vector<unsigned char> > stack;
	size_t ops = 0;

	// Create maximum theoretical script
	while (script.size() < BENCH_SCRIPT_SIZE) {
		script << OP_DUP << OP_DUP << OP_2DROP;
		ops++;
	}

	// Note: lshift could make it easier to make large things
	stack.resize(1);
	stack[0].resize(MAX_POSSIBLE_STACK_3OF);

	BenchEvalScript(bench, script, stack, MAX_POSSIBLE_STACK_3OF * ops);
}
BENCHMARK(EvalScriptDupDup2DropMax, benchmark::LOW);
