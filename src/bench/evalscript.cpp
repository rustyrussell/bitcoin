#include <bench/bench.h>

#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <unistd.h>

static size_t get_op_bytes(size_t default_val, const char *var)
{
	const char *env = getenv(var);
	if (!env)
		return default_val;
	return atol(env);
}

static size_t get_op1_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_op_bytes(default_val, "EVALSCRIPT_OP1_BYTES");
}

static size_t get_op2_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_op_bytes(default_val, "EVALSCRIPT_OP2_BYTES");
}

// 800M is not much these days!
#define NUM_STACKS 100

// op1 is top of stack, op2 is second on stack.
static void BenchEvalScript(benchmark::Bench& bench,
							const CScript &script,
							const std::vector<unsigned char> &op1,
							const std::vector<unsigned char> &op2)
{
	BaseSignatureChecker checker;
	ScriptExecutionData sdata;

	// Runs can interfere with each other, cache-wise, so try to keep them cold.
	std::vector<std::vector<unsigned char> > stacks[NUM_STACKS];
	for (auto &s: stacks) {
		s.resize(2);
		s[1] = op1;
		s[0] = op2;
	}

	size_t i = 0;
	bench.unit("ops").run([&] {
		std::vector<std::vector<unsigned char> > &stack = stacks[i % NUM_STACKS];
#if 0
		ankerl::nanobench::doNotOptimizeAway(memcmp(stack[0].data(),
													stack[0].data() + stack[0].size() / 2,
													stack[0].size() / 2));
		// Warm top of stack.
		ankerl::nanobench::doNotOptimizeAway(memcmp(stack[1].data(),
													stack[1].data() + stack[1].size() / 2,
													stack[1].size() / 2));
#endif
		assert(EvalScript(stack, script, 0, checker,
						  SigVersion::TAPSCRIPT_V2, sdata, NULL));

		// Some evals don't clear the stack, others do: since some libs
		// are slow at this (returning memory to OS?) keep it uniform!
		while (stack.size() > 0)
			stack.pop_back();

		// Refresh in case we loop
		stack.resize(2);
		stack[1] = op1;
		stack[0] = op2;
		i++;
	});
}

// Empty case.
static void EvalScriptNopNop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_NOP4 << OP_NOP4;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptNopNop, benchmark::LOW);

// BIP#ops: We assume that the manipulation of the stack vector itself (e.g. OP_DROP) is negligible.
static void EvalScriptDropDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDrop, benchmark::LOW);

// Cache hot
static void EvalScriptVerifyDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	// Right at the tail, to force worst-case traversal
	op1.at(op1.size()-1) = 1;
	op2.at(op2.size()-1) = 1;
	script << OP_VERIFY << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptVerifyDrop, benchmark::LOW);

// Cache cold
static void EvalScriptDropVerify(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	// Right at the tail, to force worst-case traversal
	op1.at(op1.size()-1) = 1;
	op2.at(op2.size()-1) = 1;
	script << OP_DROP << OP_VERIFY;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropVerify, benchmark::LOW);

// This modifies the element, so we can compare read costs vs r/w costs.
// Cache hot
static void EvalScriptInvertDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_INVERT << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptInvertDrop, benchmark::LOW);

// Cache cold
static void EvalScriptDropInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropInvert, benchmark::LOW);

// Invert both variant
static void EvalScriptInvertDropInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_INVERT << OP_DROP << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptInvertDropInvert, benchmark::LOW);

// This writes the element, so we can compare read costs vs write costs.
// Cache cold
static void EvalScriptNipDup(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_NIP << OP_DUP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptNipDup, benchmark::LOW);

// cache hot
static void EvalScriptDropDup(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_DUP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDup, benchmark::LOW);
