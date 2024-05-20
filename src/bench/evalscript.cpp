#include <bench/bench.h>

#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <unistd.h>

static size_t get_op_bytes(size_t default_val, const char *var)
{
	if (!var)
		return default_val;
	return atol(var);
}

static size_t get_op1_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_op_bytes(default_val, "EVALSCRIPT_OP1_BYTES");
}

static size_t get_op2_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_op_bytes(default_val, "EVALSCRIPT_OP2_BYTES");
}

// op1 is top of stack, op2 is second on stack.
static void BenchEvalScript(benchmark::Bench& bench,
							const CScript &script,
							const std::vector<unsigned char> > &op1,
							const std::vector<unsigned char> > &op2)
{
	BaseSignatureChecker checker;
	ScriptExecutionData sdata;
	bench.unit("ops").run([&] {
		std::vector<std::vector<unsigned char> > stack;
		// Deliberately, top of stack is the cache-colder one, for worst-case
		stack.resize(2);
		stack[1] = op1;
		stack[0] = op2;
		assert(EvalScript(stack, script, 0, checker,
						  SigVersion::TAPSCRIPT, sdata, NULL));
	});
}

// Empty case.
static void EvalScriptNopNop(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_NOP4 << OP_NOP4;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptNopNop, benchmark::LOW);

// BIP#ops: We assume that the manipulation of the stack vector itself (e.g. OP_DROP) is negligible.
static void EvalScriptDropDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDrop, benchmark::LOW);

static void EvalScriptVerifyDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	// Right at the tail, to force worst-case traversal
	op1.at(op1.size()-1) = 1;
	script << OP_VERIFY << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptVerifyDrop, benchmark::LOW);

// This variant uses the cache-hot(ter) stack element.
static void EvalScriptDropVerify(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	// Right at the tail, to force worst-case traversal
	op1.at(op1.size()-1) = 1;
	script << OP_DROP << OP_VERIFY;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropVerify, benchmark::LOW);

// This modifies the element, so we can compare read costs vs r/w costs.
static void EvalScriptInvertDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_INVERT << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptInvertDrop, benchmark::LOW);

// Hot cache variant
static void EvalScriptDropInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropInvert, benchmark::LOW);

// This writes the element, so we can compare read costs vs write costs.
static void EvalScriptNipDup(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_NIP << OP_DUP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptNipDup, benchmark::LOW);

// Hot cache variant
static void EvalScriptDropDup(benchmark::Bench& bench)
{
	std::vector<unsigned char> > op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_DUP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDup, benchmark::LOW);
