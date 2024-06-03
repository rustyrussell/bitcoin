#include <bench/bench.h>

#include <consensus/consensus.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/val64.h>
#include <unistd.h>

static size_t get_val(size_t default_val, const char *var)
{
	const char *env = getenv(var);
	if (!env || atol(env) == 0)
		return default_val;
	return atol(env);
}

static size_t get_op1_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_val(default_val, "EVALSCRIPT_OP1_BYTES");
}

static size_t get_op2_bytes(size_t default_val = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
	return get_val(default_val, "EVALSCRIPT_OP2_BYTES");
}

// op1 is top of stack, op2 is second on stack.
static void BenchEvalScript(benchmark::Bench& bench,
							const CScript &script,
							const std::vector<unsigned char> &op1,
							const std::vector<unsigned char> &op2)
{
	BaseSignatureChecker checker;
	ScriptExecutionData sdata;
	ScriptError serror;
	size_t cooling = get_val(0, "EVALSCRIPT_COOLING_BYTES");

	std::vector<unsigned char> cool1(cooling/2, 1), cool2(cooling/2, 1);

	bench.warmup(10).unit("ops").run([&] {
		std::vector<std::vector<unsigned char> > stack(2);
		ankerl::nanobench::doNotOptimizeAway(stack[0] = op2);

		// In case we want to clear cache, write out a crap load.
		for (size_t i = 0; i < cooling / 2; i++) {
			cool1[i] = (i < op1.size() ? op1[i] : i) + cooling;
			cool2[i] = (i < op2.size() ? op2[i] : i) - cooling;
		}

		// Set up stack: do manual copy so it's cache hot!
		stack[1].resize(op1.size());
		for (size_t i = 0; i < stack[1].size(); i++)
			stack[1][i] = op1[i];

		if (!EvalScript(stack, script, 0, checker,
						SigVersion::TAPSCRIPT_V2, sdata, &serror)) {
			std::cerr << "EvalScript error " << ScriptErrorString(serror) << std::endl;
			assert(0);
		}

		// Empty stack manually for better comparison!
		while (!stack.empty())
			stack.pop_back();
	});
}

// Empty case.
static void EvalScriptNopNop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_NOP4 << OP_NOP4;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptNopNop, benchmark::LOW);

// BIP#ops: We assume that the manipulation of the stack vector itself (e.g. OP_DROP) is negligible.
static void EvalScriptDropDrop(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_DROP << OP_DROP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDrop, benchmark::LOW);

// Verify both
static void EvalScriptVerifyVerify(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	// Right at the tail, to force worst-case traversal
	op1.at(op1.size()-1) = 1;
	op2.at(op2.size()-1) = 1;
	script << OP_VERIFY << OP_VERIFY;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptVerifyVerify, benchmark::LOW);

// Check they're equal
static void EvalScriptEqual(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 1);
	CScript script;

	script << OP_EQUAL;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptEqual, benchmark::LOW);

// Make a copy, twice
static void EvalScriptDropDupDropDup(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DROP << OP_DUP << OP_DROP << OP_DUP;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropDupDropDup, benchmark::LOW);

// This modifies the element, so we can compare read costs vs r/w costs.
static void EvalScriptInvertDropInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_INVERT << OP_DROP << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptInvertDropInvert, benchmark::LOW);

static void EvalScriptDropInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_DROP << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDropInvert, benchmark::LOW);

static void EvalScriptInvert(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_INVERT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptInvert, benchmark::LOW);

// Simple binary ops
static void EvalScriptAnd(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_AND;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptAnd, benchmark::LOW);

static void EvalScriptOr(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_OR;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptOr, benchmark::LOW);

static void EvalScriptAdd(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_ADD;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptAdd, benchmark::LOW);

static void EvalScriptAddOverflow(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()-1, 0xFF), op2(get_op2_bytes()-1);
	CScript script;

	op2[0] = 1;
	script << OP_ADD;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptAddOverflow, benchmark::LOW);

static void EvalScriptSub(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(), 1), op2(get_op2_bytes(), 2);
	CScript script;

	script << OP_SUB;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptSub, benchmark::LOW);

static void EvalScriptMul(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / 100), 1),
		op2(get_op2_bytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / 100), 1);
	CScript script;

	script << OP_MUL;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptMul, benchmark::LOW);

static void EvalScriptDiv(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_DIV;

	for (size_t i = 0; i < op1.size(); i++)
		op1[i] = 255-i;

	for (size_t i = 0; i < op2.size(); i++)
		op2[i] = 1+i;
	
	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDiv, benchmark::LOW);

static void EvalScriptUpshift1(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()-1, 1), op2(get_op2_bytes()-1, 2);
	CScript script;

	script << 1 << OP_LSHIFT << OP_DROP << 1 << OP_LSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptUpshift1, benchmark::LOW);

static void EvalScriptUpshift16000001(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()-2000001, 1), op2(get_op2_bytes()-2000001, 2);
	CScript script;
	// We need this encoded as normal LE, not CScriptNum!
	Val64 num64(16000001);
	const std::vector<unsigned char> num = num64.move_to_valtype();
	
	script << num << OP_LSHIFT << OP_DROP << num << OP_LSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptUpshift16000001, benchmark::LOW);

static void EvalScriptUpshift16000000(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()-2000000, 1), op2(get_op2_bytes()-2000000, 2);
	CScript script;
	// We need this encoded as normal LE, not CScriptNum!
	Val64 num64(16000000);
	const std::vector<unsigned char> num = num64.move_to_valtype();

	script << num << OP_LSHIFT << OP_DROP << num << OP_LSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptUpshift16000000, benchmark::LOW);

static void EvalScriptDownshift1(benchmark::Bench& bench)
{
	// Need 1 byte capacity for push of 1!
	std::vector<unsigned char> op1(get_op1_bytes()-1, 1), op2(get_op2_bytes());
	CScript script;

	script << 1 << OP_RSHIFT << OP_DROP << 1 << OP_RSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDownshift1, benchmark::LOW);

static void EvalScriptDownshift16000001(benchmark::Bench& bench)
{
	// Need 3 byte capacity for push of 16000001!
	std::vector<unsigned char> op1(get_op1_bytes() - 3, 1), op2(get_op2_bytes(), 2);
	CScript script;
	// We need this encoded as normal LE, not CScriptNum!
	Val64 num64(16000001);
	const std::vector<unsigned char> num = num64.move_to_valtype();

	script << num << OP_RSHIFT << OP_DROP << num << OP_RSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDownshift16000001, benchmark::LOW);

static void EvalScriptDownshift16000000(benchmark::Bench& bench)
{
	// Need 3 byte capacity for push of 16000001!
	std::vector<unsigned char> op1(get_op1_bytes()-3, 1), op2(get_op2_bytes(), 2);
	CScript script;
	// We need this encoded as normal LE, not CScriptNum!
	Val64 num64(16000000);
	const std::vector<unsigned char> num = num64.move_to_valtype();

	script << num << OP_RSHIFT << OP_DROP << num << OP_RSHIFT;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptDownshift16000000, benchmark::LOW);

static void EvalScriptSHA256DropSHA256(benchmark::Bench& bench)
{
	std::vector<unsigned char> op1(get_op1_bytes()), op2(get_op2_bytes());
	CScript script;

	script << OP_SHA256 << OP_DROP << OP_SHA256;

	BenchEvalScript(bench, script, op1, op2);
}
BENCHMARK(EvalScriptSHA256DropSHA256, benchmark::LOW);
