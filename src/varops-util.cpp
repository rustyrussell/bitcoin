#include <script/script.h>
#include <script/val64.h>
#include <key_io.h>
#include <util/strencodings.h>
#include <iostream>
#include <optional>

static bool GetPushFromString(const std::string& name,
                              std::vector<unsigned char>& vec)
{
    if (!name.starts_with("PUSH-"))
        return false;

    // Convert the hexadecimal string to a vector of bytes
    for (size_t i = strlen("PUSH-"); i < name.length(); i += 2) {
        std::string byteString = name.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoul(byteString, nullptr, 16));
        vec.push_back(byte);
    }
    return true;
}

static bool GetOpCodeFromString(const std::string& name,
                                opcodetype& opcode)
{
    // Dumb, but simple
    for (size_t i = 0; i < 256; i++) {
        std::string opname = GetOpName(static_cast<opcodetype>(i));
        if (opname == name || opname == "OP_" + name) {
            opcode = static_cast<opcodetype>(i);
            return true;
        }
    }
    return false;
}

// We can have unknown values on the stack, or we can have known values.
struct stackVal {
    // Known value
    stackVal(const std::vector<unsigned char> &v): is_known(true), vchVal(v), worst_case_size(0) {
        if (v.size() > max_stack_element_size)
            max_stack_element_size = v.size();
    }
    // Unknown value
    stackVal(size_t size): is_known(false), worst_case_size(size) {
        if (size > max_stack_element_size)
            max_stack_element_size = size;
    }

    // Get size in bytes
    size_t size() const { return is_known ? vchVal.size() : worst_case_size; }

    // Get value with ceiling.
    uint64_t value(uint64_t max, size_t &varcost) {
        std::vector<unsigned char> vec = vchVal;
        if (!is_known) {
            varcost += size();
            return max;
        }
        return Val64(vec).to_u64_ceil(max, varcost);
    }

    bool is_known;

    // If known
    std::vector<unsigned char> vchVal;

    // If unknown
    size_t worst_case_size;

    static size_t max_stack_element_size;
};

size_t stackVal::max_stack_element_size;

// Unknown stack values are assumed to be max_stack_element_size
static void stack_minsize(std::vector<stackVal> &stack, size_t min)
{
    while (stack.size() < min)
        stack.insert(stack.begin(), stackVal(stackVal::max_stack_element_size));
}

// To make experienced Bitcoin Core devs feel at home :)
#define stacktop(i)  (stack.at(stack.size()+(i)))

static stackVal pop_back_val(std::vector<stackVal> &stack)
{
    stackVal v = stack.back();
    stack.pop_back();
    return v;
}

static std::string printable(const std::vector<unsigned char> &vch)
{
    std::stringstream ss;
    size_t i;

    i = 0;
    for (auto c: vch) {
        ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(c);
        if (++i > 64) {
            ss << "... (total size "
               << std::dec << std::setfill(' ') << std::setw(0) << vch.size()
               << ")";
            break;
        }
    }
    return ss.str();
}

static size_t analyze_varops(size_t max_stacksize, const CScript &script, bool verbose)
{
    size_t total_varops_cost = 0;
    // We keep information about top of stack, since the pattern PUSH, OP is so common.
    std::vector<stackVal> stack, altstack;

    // Reset max_stack_element_size for this use
    stackVal::max_stack_element_size = 0;

    // This will set max_stack_element_size, too.
    stack.push_back(stackVal(max_stacksize));

    for (CScript::const_iterator pc = script.begin();  pc < script.end(); ) {
        std::vector<unsigned char> vchPushValue;
        opcodetype opcode;
        size_t varops_cost = 0;
        std::string opcode_name;

        if (!script.GetOp(pc, opcode, vchPushValue))
            throw std::runtime_error("bad opcode?");

        if (0 < opcode && opcode <= OP_PUSHDATA4) {
            stack.push_back(stackVal(vchPushValue));

            std::stringstream ss;
            ss << "PUSH-" << printable(vchPushValue);
            opcode_name = ss.str();
        } else {
            opcode_name = GetOpName(opcode);
            switch (opcode) {
            case OP_PUSHDATA1:
            case OP_PUSHDATA2:
            case OP_PUSHDATA4:
                assert(!"Handled above");
                break;

            case OP_0:
                stack.push_back(stackVal(std::vector<unsigned char>()));
                break;

            // These are ignored:
            case OP_1NEGATE:
            case OP_RESERVED:
            case OP_NOP:
            case OP_VER:
            case OP_IF:
            case OP_NOTIF:
            case OP_VERIF:
            case OP_VERNOTIF:
            case OP_ELSE:
            case OP_ENDIF:
            case OP_RETURN:
            case OP_RESERVED1:
            case OP_RESERVED2:
            case OP_NEGATE:
            case OP_ABS:
            case OP_CODESEPARATOR:
            case OP_NOP1:
            case OP_NOP4:
            case OP_NOP5:
            case OP_NOP6:
            case OP_NOP7:
            case OP_NOP8:
            case OP_NOP9:
            case OP_NOP10:
            case OP_INVALIDOPCODE:
            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY:
                break;

            case OP_1:
            case OP_2:
            case OP_3:
            case OP_4:
            case OP_5:
            case OP_6:
            case OP_7:
            case OP_8:
            case OP_9:
            case OP_10:
            case OP_11:
            case OP_12:
            case OP_13:
            case OP_14:
            case OP_15:
            case OP_16:
                stack.push_back(stackVal(std::vector<unsigned char>((int)opcode - (int)(OP_1 - 1))));
                break;

            //
            // These are zero cost
            //
            case OP_TOALTSTACK:
                stack_minsize(stack, 1);
                altstack.push_back(pop_back_val(stack));
                break;

            case OP_FROMALTSTACK:
                stack_minsize(altstack, 1);
                stack.push_back(pop_back_val(altstack));
                break;

            case OP_ROT:
                stack_minsize(stack, 3);
                std::swap(stacktop(-3), stacktop(-2));
                std::swap(stacktop(-2), stacktop(-1));
                break;
                
            case OP_SWAP:
                stack_minsize(stack, 2);
                std::swap(stacktop(-2), stacktop(-1));
                break;

            case OP_2DROP:
                stack_minsize(stack, 2);
                stack.pop_back();
                stack.pop_back();
                break;

            case OP_DROP:
                stack_minsize(stack, 1);
                stack.pop_back();
                break;

            case OP_NIP:
                stack_minsize(stack, 2);
                stack.erase(stack.end() - 2);
                break;
                    
            case OP_2ROT:
                stack_minsize(stack, 6);
                std::rotate(stack.end()-6, stack.end()-4, stack.end());
                break;

            case OP_2SWAP:
                stack_minsize(stack, 4);
                std::swap(stacktop(-4), stacktop(-2));
                std::swap(stacktop(-3), stacktop(-1));
                break;

            case OP_RIPEMD160:
                stack.push_back(stackVal(20));
                break;

            case OP_SHA1:
                stack.push_back(stackVal(20));
                break;

            case OP_DEPTH:
                // Max 0x03E8 (1000)
                stack.push_back(std::vector<unsigned char>{0xe8, 0x03});
                break;

            case OP_SIZE:
                // Max 0x3D0900 (4000000)
                stack.push_back(std::vector<unsigned char>{0x00, 0x09, 0x3d});
                break;

                // These simply cost operand length
                // BIP#ops:
                // |-
                // |OP_VERIFY
                // |Operand length (COMPARINGZERO)
                // |-
                // |OP_NOT
                // |Operand length (COMPARINGZERO)
                // |-
                // |OP_0NOTEQUAL
                // |Operand length (COMPARINGZERO)
                // |-
                // |OP_EQUAL
                // |If length unequal: 0, otherwise length (COMPARING)
                // |-
                // |OP_EQUALVERIFY
                // |If length unequal: 0, otherwise length (COMPARING)
            case OP_VERIFY:
                stack_minsize(stack, 1);
                varops_cost += stack.back().size();
                stack.pop_back();
                break;

            case OP_NOT:
            case OP_0NOTEQUAL:
                stack_minsize(stack, 1);
                varops_cost += stack.back().size();
                stack.pop_back();
                stack.push_back(stackVal(1));
                break;

            case OP_EQUAL:
            case OP_EQUALVERIFY:
                stack_minsize(stack, 2);
                varops_cost += stack.back().size();
                stack.pop_back();
                varops_cost += stack.back().size();
                stack.pop_back();
                if (opcode == OP_EQUAL)
                    stack.push_back(stackVal(1));
                break;

            // Hashing
            // BIP#ops:
            // |OP_SHA256
            // |(Length of the operand) * 10
            // |-
            // |OP_HASH160
            // |(Length of the operand) * 10
            // |-
            // |OP_HASH256
            // |(Length of the operand) * 10
            case OP_SHA256:
            case OP_HASH256:
                stack_minsize(stack, 1);
                varops_cost = stack.back().size() * 10;
                stack.pop_back();
                stack.push_back(stackVal(32));
                break;
            case OP_HASH160:
                stack_minsize(stack, 1);
                varops_cost = stack.back().size() * 10;
                stack.pop_back();
                stack.push_back(stackVal(20));
                break;

            // crypto
            // FIXME: calc varops cost!
            case OP_CHECKSIG:
            case OP_CHECKSIGVERIFY:
                stack_minsize(stack, 2);
                stack.pop_back();
                stack.pop_back();
                if (opcode == OP_CHECKSIG)
                    stack.push_back(stackVal(1));
                break;
                
            // BIP#ops:
            // | OP_CHECKSIGADD
            // | MAX(1, length of number operand) * 3
            case OP_CHECKSIGADD: {
                stack_minsize(stack, 3);
                stack.pop_back();
                stackVal num = stack.back();
                stack.pop_back();
                stack.pop_back();
                stack.push_back(num);
            }
            // Fall through...

            // BIP#ops:
            // |OP_1ADD
            // |MAX(1, operand length) * 3
            case OP_1ADD: {
                stack_minsize(stack, 1);
                stackVal num = stack.back();
                stack.pop_back();

                varops_cost = std::max(size_t(1), num.size()) * 3;

                // Simplification: if val < 255 be precise.
                uint64_t val = num.value(size_t(255), varops_cost) + 1;
                if (val < 256) {
                    stack.push_back(stackVal(std::vector<unsigned char>{(unsigned char)val}));
                } else {
                    // Worst case: adding 1 increases length by 1
                    stack.push_back(stackVal(num.size() + 1));
                }
                break;
            }
            //
            // stack ops
            //

            // BIP#ops:
            // |OP_2DUP
            // |Sum of two operand lengths (COPYING)
            // |Sum of lengths of new stack entries
            case OP_2DUP:
            {
                stack_minsize(stack, 2);

                const stackVal &v1 = stacktop(-2);
                const stackVal &v2 = stacktop(-1);
                stack.push_back(v1);
                stack.push_back(v2);
                varops_cost = v1.size() + v2.size();
                break;
            }
            
            // BIP#ops:
            // |OP_3DUP
            // |Sum of three operand lengths (COPYING)
            // |Sum of lengths of new stack entries
            case OP_3DUP:
            {
                stack_minsize(stack, 3);

                const stackVal &v1 = stacktop(-3);
                const stackVal &v2 = stacktop(-2);
                const stackVal &v3 = stacktop(-1);
                stack.push_back(v1);
                stack.push_back(v2);
                stack.push_back(v3);
                varops_cost = v1.size() + v2.size() + v3.size();
                break;
            }

            // BIP#ops:
            // |OP_2OVER
            // |Sum of lengths of third and fourth-top stack entries (before) (COPYING)
            // |Sum of lengths of new stack entries
            case OP_2OVER: {
                stack_minsize(stack, 4);

                const stackVal &v1 = stacktop(-4);
                const stackVal &v2 = stacktop(-3);
                stack.push_back(v1);
                stack.push_back(v2);
                varops_cost = v1.size() + v2.size();
                break;
            }

            // BIP#ops:
            // |OP_IFDUP
            // |(Length of top stack entry (before)) * 2 (COMPARINGZERO + COPYING)
            case OP_IFDUP:
                stack_minsize(stack, 1);
                varops_cost = stack.back().size() * 2;
                break;
            
            // BIP#ops:
            // |OP_DUP
            // |Length of top stack entry (before) (COPYING)
            // |Length of new stack entry
            case OP_DUP:
                stack_minsize(stack, 1);
                varops_cost = stack.back().size();
                break;

            // BIP#ops:
            // |OP_OVER
            // |Length of second-top stack entry (before) (COPYING)
            // |Length of new stack entry
            case OP_OVER: {
                stack_minsize(stack, 1);
                const stackVal &v1 = stacktop(-2);
                stack.push_back(v1);
                varops_cost = v1.size();
                break;
            }

            // BIP#ops:
            // |OP_PICK
            // |Length of top stack entry + Length of N-th-from-top stack entry (before) (LENGTHCONV + COPYING)
            // |-
            case OP_PICK:
                stack_minsize(stack, 2);
                varops_cost = stack.back().size() + stackVal::max_stack_element_size;
                if (verbose)
                    std::cout << "OP_PICK: giving up on stack analysis" << std::endl;
                stack.clear();
                break;

            // BIP#ops:
            // |OP_TUCK
            // |Length of second-from-top stack entry (before) (COPYING)
            // |Length of new stack entry
            case OP_TUCK: {
                stack_minsize(stack, 2);

                const stackVal &v1 = stacktop(-1);
                stack.insert(stack.end()-2, v1);
                varops_cost = v1.size();
                break;
            }

            // BIP#ops:
            // |OP_ROLL
            // |Length of top stack entry (LENGTHCONV)
            case OP_ROLL:
                // Leave stack as unknown worst case.
                stack_minsize(stack, 1);
                varops_cost = stack.back().size();
                if (verbose)
                    std::cout << "OP_ROLL: giving up on stack analysis" << std::endl;
                stack.clear();
                break;

            //
            // splice ops
            //

            // BIP#ops:
            // |OP_CAT
            // |Sum of two operand lengths (COPYING)
            // |Length of new stack entry
            case OP_CAT: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                if (v1.is_known && v2.is_known) {
                    v1.vchVal.insert(v1.vchVal.begin(), v2.vchVal.begin(), v2.vchVal.end());
                    stack.push_back(v1);
                } else {
                    stack.push_back(stackVal(v1.size() + v2.size()));
                }
                varops_cost = stack.back().size();
                break;
            }

            // BIP#ops:
            // |OP_SUBSTR
            // |(Sum of lengths of LEN and BEGIN operands) + MIN(Value of first operand (LEN), Length of operand A - Value of BEGIN, 0) (LENGTHCONV + COPYING)
            case OP_SUBSTR: {
                stack_minsize(stack, 3);

                stackVal lenval = pop_back_val(stack);
                stackVal beginval = pop_back_val(stack);

                uint64_t begin = beginval.value(stack.back().size(), varops_cost);
                uint64_t len = lenval.value(stack.back().size() - begin, varops_cost);
                varops_cost += len;
                // Leave final on stack, as worst case
                break;
            }

            // BIP#ops:
            // |OP_LEFT
            // |Length of OFFSET operand (LENGTHCONV)
            case OP_LEFT:
                stack_minsize(stack, 2);
                varops_cost = pop_back_val(stack).size();
                // Leave final on stack, as worst case
                break;

            // BIP#ops:
            // |OP_RIGHT
            // |Length of OFFSET operand + MAX(Length of A - Value of OFFSET, 0) (LENGTHCONV + COPYING)
            // |Length of OFFSET operand + Length of new stack entry
            case OP_RIGHT:
                stack_minsize(stack, 2);
                varops_cost = pop_back_val(stack).size();
                varops_cost += stack.back().size();
                // Leave final on stack, as worst case
                break;

            //
            // bit logic
            //

            // BIP#ops:
            // |OP_INVERT
            // |(Length of operand) * 2
            case OP_INVERT: {
                stack_minsize(stack, 1);
                stackVal v = pop_back_val(stack);
                varops_cost = v.size() * 2;
                stack.push_back(stackVal(v.size()));
                break;
            }

            // BIP#ops:
            // |OP_AND
            // |Sum of two operand lengths
            case OP_AND: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = v1.size() + v2.size();
                stack.push_back(stackVal(std::max(v1.size(), v2.size())));
                break;
            }

            // BIP#ops:
            // |OP_OR
            // |(Lesser of the two operand lengths) * 2

            // BIP#ops:
            // |OP_XOR
            // |(Lesser of the two operand lengths) * 2
            case OP_OR:
            case OP_XOR: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = std::min(v1.size(), v2.size()) * 2;
                stack.push_back(stackVal(std::min(v1.size(), v2.size())));
                break;
            }

            //
            // numeric
            //

            // BIP#ops:
            // |OP_1SUB
            // |MAX(1, operand length) * 2
            case OP_1SUB: {
                stack_minsize(stack, 1);
                stackVal v1 = pop_back_val(stack);
                varops_cost = std::max(size_t(1), v1.size()) * 2;
                stack.push_back(stackVal(v1.size()));
                break;
            }

            // BIP#ops:
            // |OP_2MUL
            // |Operand length * 3
            case OP_2MUL: {
                stack_minsize(stack, 1);
                stackVal v1 = pop_back_val(stack);
                varops_cost = v1.size() * 3;
                stack.push_back(stackVal(v1.size() + 1));
                break;
            }

            // BIP#ops:
            // |OP_2DIV
            // |Operand length * 2
            case OP_2DIV: {
                stack_minsize(stack, 1);
                stackVal v1 = pop_back_val(stack);
                varops_cost = v1.size() * 2;
                stack.push_back(stackVal(v1.size()));
                break;
            }

            // BIP#ops:
            // |OP_ADD
            // |Greater of two operand lengths * 3
            case OP_ADD: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = std::max(v1.size(), v2.size()) * 3;
                stack.push_back(stackVal(std::max(v1.size(), v2.size()) + 1));
                break;
            }

            // BIP#ops:
            // |OP_SUB
            // |Greater of two operand lengths * 2
            case OP_SUB: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = std::max(v1.size(), v2.size()) * 2;
                stack.push_back(stackVal(std::max(v1.size(), v2.size()) + 1));
                break;
            }

            // BIP#ops:
            // |OP_MUL
            // |Length of A + length of B + (length of A + 7) / 8 * (length of B) * 4
            case OP_MUL: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = v1.size() + v2.size() + (v1.size() + 7) / 8 * uint64_t(v2.size()) * 4;
                stack.push_back(stackVal(v1.size() + v2.size()));
                break;
            }
                
            // BIP#ops:
            // |OP_DIV
            // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4

            // BIP#ops:
            // |OP_MOD
            // |Length of A * 9 + length of B * 2 + (length of A)^2 / 4
            case OP_DIV:
            case OP_MOD: {
                stack_minsize(stack, 2);
                stackVal v1 = pop_back_val(stack);
                stackVal v2 = pop_back_val(stack);
                varops_cost = v1.size() * 9 + v2.size() * 2 + uint64_t(v1.size()) * v1.size() / 4;
                stack.push_back(stackVal(v1.size()));
                break;
            }

            // BIP#ops:
            // |OP_UPSHIFT
            // |Length of BITS + (Value of BITS) / 8 + Length of A (LENGTHCONV + ZEROING + COPYING).  If BITS % 8 != 0, add (Length of A) * 2.
            case OP_LSHIFT: {
                stack_minsize(stack, 2);
                stackVal vbits = pop_back_val(stack);
                stackVal va = pop_back_val(stack);
                uint64_t num_bits;

                // Worst (legal) case is 4MB shift.
                num_bits = vbits.value(4000000 * 8, varops_cost);
                
                varops_cost = num_bits / 8 + va.size();
                if (!vbits.is_known || num_bits == 4000000 * 8 || (num_bits % 8) != 0)
                    varops_cost += va.size() * 2;
                stack.push_back(stackVal(va.size() + (num_bits + 7) / 8));
                break;
            }
                
            // BIP#ops:
            // |OP_DOWNSHIFT
            // |Length of BITS + MAX((Length of A - (Value of BITS) / 8), 0) * 2
            case OP_RSHIFT: {
                stack_minsize(stack, 2);
                stackVal vbits = pop_back_val(stack);
                stackVal va = pop_back_val(stack);
                uint64_t num_bits;

                num_bits = vbits.value(va.size() * 8, varops_cost);
                varops_cost += (va.size() - num_bits / 8) * 2;
                stack.push_back(stackVal(va.size() - num_bits / 8));
                break;
            }
            
            // BIP#ops:
            // |OP_BOOLAND
            // |Sum of two operand lengths
            // |-
            // |OP_BOOLOR
            // |Sum of two operand lengths
            // |-
            // |OP_NUMEQUAL
            // |Sum of two operand lengths
            // |-
            // |OP_NUMEQUALVERIFY
            // |Sum of two operand lengths
            // |-
            // |OP_NUMNOTEQUAL
            // |Sum of two operand lengths
            // |-
            // |OP_LESSTHAN
            // |Sum of two operand lengths
            // |-
            // |OP_GREATERTHAN
            // |Sum of two operand lengths
            // |-
            // |OP_LESSTHANOREQUAL
            // |Sum of two operand lengths
            // |-
            // |OP_GREATERTHANOREQUAL
            // |Sum of two operand lengths
            // |-
            // |OP_MIN
            // |Sum of two operand lengths
            // |-
            // |OP_MAX
            // |Sum of two operand lengths
            case OP_BOOLAND:
            case OP_BOOLOR:
            case OP_NUMEQUAL:
            case OP_NUMEQUALVERIFY:
            case OP_NUMNOTEQUAL:
            case OP_LESSTHAN:
            case OP_GREATERTHAN:
            case OP_LESSTHANOREQUAL:
            case OP_GREATERTHANOREQUAL:
            case OP_MIN:
            case OP_MAX: {
                stack_minsize(stack, 2);
                stackVal vb = pop_back_val(stack);
                stackVal va = pop_back_val(stack);

                varops_cost += va.size() + vb.size();
                if (opcode != OP_NUMEQUALVERIFY)
                    stack.push_back(stackVal(1));
                break;
            }
                
            // BIP#ops:
            // |OP_WITHIN
            // |3rd from stack top operand length * 2 + sum of other two operand lengths
            case OP_WITHIN: {
                stack_minsize(stack, 3);
                stackVal vc = pop_back_val(stack);
                stackVal vb = pop_back_val(stack);
                stackVal va = pop_back_val(stack);

                varops_cost += va.size() * 2 + vb.size() + vc.size();
                stack.push_back(stackVal(1));
                break;
            }

            // BIP#ops:
            // | OP_CHECKLOCKTIMEVERIFY
            // | Length of operand (LENGTHCONV)
            // |-
            // | OP_CHECKSEQUENCEVERIFY
            // | Length of operand (LENGTHCONV)
            case OP_CHECKLOCKTIMEVERIFY:
            case OP_CHECKSEQUENCEVERIFY: {
                stack_minsize(stack, 1);
                varops_cost = stack.back().size();
                break;
            }
            }
        }

        if (verbose) {
            std::cout << opcode_name << " cost=" << varops_cost;
            if (stack.size() != 0) {
                std::cout << " stacktop-size=" << stack.back().size();
                if (stack.back().is_known)
                    std::cout << " stacktop=" << printable(stack.back().vchVal);
            }
            std::cout << std::endl;
        }
        total_varops_cost += varops_cost;
    }

    return total_varops_cost;
}

// We assume only a single stack entry of size max_stacksize.
static size_t budget(const CScript &script, size_t max_stacksize)
{
    // BIP#ops:
    // A per-transaction "varops budget" is determined by multiplying the
    // total transaction weight by the fixed factor 5200.
    return (script.size() + max_stacksize) * 5200;
}

static size_t bisect(size_t succeeds,
                     size_t fails,
                     const CScript &script,
                     bool verbose)
{
    if (succeeds == fails + 1 || succeeds == fails - 1)
        return succeeds;

    size_t mid = (succeeds + fails) / 2;
    if (verbose)
        std::cout << "Checking " << succeeds << "-" << fails << " With " << mid << " byte input elements:" << std::endl;
    size_t cost = analyze_varops(mid, script, verbose);
    if (verbose)
        std::cout << "... cost was " << cost
                  << " budget was " << budget(script, mid)
                  << std::endl;
    if (cost > budget(script, mid))
        fails = mid;
    else
        succeeds = mid;

    return bisect(succeeds, fails, script, verbose);
}

static int usage()
{
    std::cerr << "Usage: varops-util [-v] script..." << std::endl;
    std::cerr << "Where script is one or more of:" << std::endl;
    std::cerr << "- OP_X (or X) for an opcode" << std::endl;
    std::cerr << "- PUSH-hex for a PUSH operation" << std::endl;

    return EXIT_FAILURE;
}

int main(int argc, char* argv[])
{
    CScript script;
    bool verbose = false;

    if (argc == 1)
        return usage();
    for (int i = 1; argv[i] != NULL; i++) {
        opcodetype opcode;
        const std::string code = argv[i];
        std::vector<unsigned char> vec;
        if (code == "-v")
            verbose = true;
        else if (GetPushFromString(code, vec)) {
            script << vec;
        } else if (GetOpCodeFromString(code, opcode))
            script << opcode;
        else {
            std::cerr << "Invalid opcode: " << code << std::endl;
            return usage();
        }
    }

    // It's possible that a (perverse) script exceeds budget *unless* it has a
    // large argument (since you get more budget for larger args).  Say two
    // large pushes and an OP_MUL.  We take that into account too.

    if (verbose)
        std::cout << "With 0 byte input elements:" << std::endl;
    size_t zero_input_cost = analyze_varops(0, script, verbose);
    if (verbose)
        std::cout << "... cost was " << zero_input_cost
                  << " budget was " << budget(script, 0)
                  << std::endl;

    if (verbose)
        std::cout << "With 4000000 bytes input elements:" << std::endl;
    size_t max_input_cost = analyze_varops(4000000, script, verbose);
    if (verbose)
        std::cout << "... cost was " << max_input_cost
                  << " budget was " << budget(script, 4000000)
                  << std::endl;

    if (zero_input_cost > budget(script, 0)) {
        if (max_input_cost > budget(script, 4000000)) {
            // This may not be quite true: our analysis is simplified.
            std::cout << "This script always exceeds its budget"
                      << std::endl;
            return 0;
        }
        size_t min_input = bisect(4000000, 0, script, verbose);
        std::cout << "Minimum input size "
                  << min_input
                  << std::endl;
        return 0;
    }

    if (max_input_cost > budget(script, 4000000)) {
        size_t max_input = bisect(0, 4000000, script, verbose);
        std::cout << "Maximum input size "
                  << max_input
                  << std::endl;
        return 0;
    }

    // Normal case: under budget
    std::cout << "Worst case, uses "
              << 100.0 * max_input_cost / budget(script, 4000000)
              << "% of budget (for 4MB input): "
              << max_input_cost
              << " of "
              << budget(script, 4000000)
              << std::endl;

    return 0;
}

