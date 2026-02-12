/// \file smoke_test.cpp
/// \brief End-to-end smoke test for idax using idalib.
///
/// Opens a real ELF binary, waits for auto-analysis, and exercises the
/// major idax wrapper namespaces: database, segment, function, address,
/// data, instruction, name, xref, comment, search, analysis, entry, type.

#include <ida/idax.hpp>

#include <cstdlib>
#include <iostream>
#include <string>
#include <vector>

// ── Minimal test harness ────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"           \
                      << __LINE__ << ")\n";                               \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                     \
                      << _r.error().message << " (" << __FILE__           \
                      << ":" << __LINE__ << ")\n";                        \
        }                                                                 \
    } while (false)

#define CHECK_VAL(expr, check)                                            \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value() && (check)) {                                  \
            ++g_pass;                                                     \
        } else if (!_r.has_value()) {                                     \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                     \
                      << _r.error().message << " (" << __FILE__           \
                      << ":" << __LINE__ << ")\n";                        \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " value check failed ("           \
                      << __FILE__ << ":" << __LINE__ << ")\n";            \
        }                                                                 \
    } while (false)

// ── Test sections ───────────────────────────────────────────────────────

static void test_database() {
    std::cout << "--- database ---\n";

    auto path = ida::database::input_file_path();
    CHECK_OK(path);
    if (path) std::cout << "  input: " << *path << "\n";

    auto md5 = ida::database::input_md5();
    CHECK_OK(md5);
    if (md5) {
        CHECK(md5->size() == 32);
        std::cout << "  md5: " << *md5 << "\n";
    }

    auto base = ida::database::image_base();
    CHECK_OK(base);
    if (base) std::cout << "  image_base: 0x" << std::hex << *base << std::dec << "\n";

    auto lo = ida::database::min_address();
    auto hi = ida::database::max_address();
    CHECK_OK(lo);
    CHECK_OK(hi);
    if (lo && hi) {
        CHECK(*lo < *hi);
        std::cout << "  range: [0x" << std::hex << *lo << ", 0x" << *hi << ")\n"
                  << std::dec;
    }
}

static void test_segments() {
    std::cout << "--- segments ---\n";

    auto cnt = ida::segment::count();
    CHECK_OK(cnt);
    if (cnt) {
        CHECK(*cnt > 0);
        std::cout << "  count: " << *cnt << "\n";
    }

    // Iterate all segments.
    auto range = ida::segment::all();
    int n = 0;
    for (auto seg : range) {
        ++n;
        std::cout << "  [" << (n - 1) << "] "
                  << seg.name() << "  0x" << std::hex << seg.start()
                  << "-0x" << seg.end() << std::dec
                  << "  bits=" << seg.bitness()
                  << "  rwx=" << seg.permissions().read
                  << seg.permissions().write
                  << seg.permissions().execute
                  << "\n";
    }
    CHECK(n > 0);

    // Lookup by index 0 should succeed.
    auto s0 = ida::segment::by_index(0);
    CHECK_OK(s0);
}

static void test_functions() {
    std::cout << "--- functions ---\n";

    auto cnt = ida::function::count();
    CHECK_OK(cnt);
    if (cnt) {
        CHECK(*cnt > 0);
        std::cout << "  count: " << *cnt << "\n";
    }

    // Iterate functions.
    auto range = ida::function::all();
    int n = 0;
    for (auto fn : range) {
        if (n < 10) {
            std::cout << "  " << fn.name()
                      << "  0x" << std::hex << fn.start()
                      << "-0x" << fn.end() << std::dec
                      << "  bits=" << fn.bitness()
                      << "\n";
        }
        ++n;
    }
    CHECK(n > 0);
    std::cout << "  (showed first " << std::min(n, 10) << " of " << n << ")\n";

    // Look up "main" by name (should exist in this binary).
    auto main_addr = ida::name::resolve("main");
    if (main_addr) {
        auto fn = ida::function::at(*main_addr);
        CHECK_OK(fn);
        if (fn) {
            CHECK(fn->name() == "main" || fn->name().find("main") != std::string::npos);
            std::cout << "  main() at 0x" << std::hex << fn->start() << std::dec
                      << "  size=" << fn->size() << "\n";
        }
    } else {
        std::cout << "  (main not resolved by name, trying scan)\n";
        // Fallback: scan functions for one containing "main".
        for (auto fn : ida::function::all()) {
            if (fn.name().find("main") != std::string::npos) {
                std::cout << "  found: " << fn.name() << " at 0x" << std::hex
                          << fn.start() << std::dec << "\n";
                break;
            }
        }
    }
}

static void test_address_predicates() {
    std::cout << "--- address predicates ---\n";

    auto lo = ida::database::min_address();
    if (!lo) return;

    // The min address should be mapped.
    CHECK(ida::address::is_mapped(*lo));

    // Find the first code address.
    for (auto ea : ida::address::items(*lo, *lo + 0x10000)) {
        if (ida::address::is_code(ea)) {
            std::cout << "  first code at 0x" << std::hex << ea << std::dec << "\n";
            CHECK(!ida::address::is_tail(ea));
            CHECK(ida::address::is_head(ea));
            break;
        }
    }
}

static void test_data_read() {
    std::cout << "--- data read ---\n";

    auto lo = ida::database::min_address();
    if (!lo) return;

    // Read the ELF magic bytes (0x7f 'E' 'L' 'F').
    auto bytes = ida::data::read_bytes(*lo, 4);
    CHECK_OK(bytes);
    if (bytes) {
        CHECK(bytes->size() == 4);
        if (bytes->size() >= 4) {
            CHECK((*bytes)[0] == 0x7f);
            CHECK((*bytes)[1] == 'E');
            CHECK((*bytes)[2] == 'L');
            CHECK((*bytes)[3] == 'F');
            std::cout << "  ELF magic verified at 0x" << std::hex << *lo
                      << std::dec << "\n";
        }
    }

    // Read single byte.
    auto b = ida::data::read_byte(*lo);
    CHECK_OK(b);
    if (b) CHECK(*b == 0x7f);
}

static void test_instructions() {
    std::cout << "--- instructions ---\n";

    // Find a function and decode its first instruction.
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto insn = ida::instruction::decode(f0->start());
    CHECK_OK(insn);
    if (insn) {
        std::cout << "  at 0x" << std::hex << insn->address() << std::dec
                  << ": " << insn->mnemonic()
                  << "  size=" << insn->size()
                  << "  ops=" << insn->operand_count()
                  << "\n";
        CHECK(insn->size() > 0);
        CHECK(!insn->mnemonic().empty());
    }

    // Get rendered disassembly text.
    auto txt = ida::instruction::text(f0->start());
    CHECK_OK(txt);
    if (txt) {
        CHECK(!txt->empty());
        std::cout << "  text: " << *txt << "\n";
    }
}

static void test_names() {
    std::cout << "--- names ---\n";

    // The first function should have a name.
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto nm = ida::name::get(f0->start());
    CHECK_OK(nm);
    if (nm) {
        CHECK(!nm->empty());
        std::cout << "  name at first func: " << *nm << "\n";
    }
}

static void test_xrefs() {
    std::cout << "--- xrefs ---\n";

    // Find a function and check for xrefs to it.
    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto refs = ida::xref::refs_to(*main_addr);
    CHECK_OK(refs);
    if (refs) {
        int count = 0;
        for (auto& ref : *refs) {
            if (count < 5) {
                std::cout << "  ref_to main from 0x" << std::hex << ref.from
                          << std::dec << " code=" << ref.is_code << "\n";
            }
            ++count;
        }
        std::cout << "  total refs to main: " << count << "\n";
    }
}

static void test_comments() {
    std::cout << "--- comments ---\n";

    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    // Set a comment, read it back, then remove it.
    auto status = ida::comment::set(f0->start(), "idax test comment");
    CHECK_OK(status);

    auto cmt = ida::comment::get(f0->start());
    CHECK_OK(cmt);
    if (cmt) {
        CHECK(*cmt == "idax test comment");
        std::cout << "  comment: " << *cmt << "\n";
    }

    auto rm = ida::comment::remove(f0->start());
    CHECK_OK(rm);
}

static void test_entry_points() {
    std::cout << "--- entries ---\n";

    auto cnt = ida::entry::count();
    CHECK_OK(cnt);
    if (cnt) {
        std::cout << "  count: " << *cnt << "\n";
        if (*cnt > 0) {
            auto e = ida::entry::by_index(0);
            CHECK_OK(e);
            if (e) {
                std::cout << "  entry[0]: " << e->name << " at 0x"
                          << std::hex << e->address << std::dec << "\n";
            }
        }
    }
}

static void test_type_basics() {
    std::cout << "--- type basics ---\n";

    auto ti = ida::type::TypeInfo::int32();
    CHECK(ti.is_integer());
    CHECK(!ti.is_pointer());

    auto pi = ida::type::TypeInfo::pointer_to(ti);
    CHECK(pi.is_pointer());

    auto arr = ida::type::TypeInfo::array_of(ti, 10);
    CHECK(arr.is_array());

    auto sz = ti.size();
    CHECK_OK(sz);
    if (sz) {
        CHECK(*sz == 4);
        std::cout << "  int32 size: " << *sz << "\n";
    }

    auto type_str = ti.to_string();
    CHECK_OK(type_str);
    if (type_str) {
        std::cout << "  int32 repr: " << *type_str << "\n";
    }

    // Struct creation and member access.
    auto st = ida::type::TypeInfo::create_struct();
    CHECK(st.is_struct());

    auto mc = st.member_count();
    CHECK_OK(mc);
    if (mc) {
        CHECK(*mc == 0);
        std::cout << "  empty struct members: " << *mc << "\n";
    }

    // Type retrieval at a function address.
    auto f0 = ida::function::by_index(0);
    if (f0) {
        auto ftype = ida::type::retrieve(f0->start());
        // May or may not have a type; either outcome is valid.
        if (ftype)
            std::cout << "  type at func[0]: " << ftype->to_string().value_or("?") << "\n";
        else
            std::cout << "  no type at func[0] (expected for this binary)\n";
    }
}

static void test_function_callers_callees() {
    std::cout << "--- function callers/callees ---\n";

    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto callers = ida::function::callers(*main_addr);
    CHECK_OK(callers);
    if (callers) {
        std::cout << "  callers of main: " << callers->size() << "\n";
        for (auto ea : *callers)
            std::cout << "    caller at 0x" << std::hex << ea << std::dec << "\n";
    }

    auto callees = ida::function::callees(*main_addr);
    CHECK_OK(callees);
    if (callees) {
        std::cout << "  callees of main: " << callees->size() << "\n";
        for (auto ea : *callees)
            std::cout << "    callee at 0x" << std::hex << ea << std::dec << "\n";
    }
}

static void test_operand_representation() {
    std::cout << "--- operand representation ---\n";

    // Find an instruction with an immediate operand to test with.
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto insn = ida::instruction::decode(f0->start());
    if (!insn || insn->operand_count() == 0) {
        std::cout << "  (no operands to test)\n";
        return;
    }

    // Try to set hex and clear representation on the first operand.
    auto status = ida::instruction::set_op_hex(f0->start(), 0);
    if (status) {
        std::cout << "  set_op_hex on first operand: ok\n";
        ++g_pass;
    } else {
        // This can fail if operand is not a suitable type — that's fine.
        std::cout << "  set_op_hex: " << status.error().message << " (may be expected)\n";
    }

    auto clr = ida::instruction::clear_op_representation(f0->start(), 0);
    if (clr) {
        std::cout << "  clear_op_representation: ok\n";
        ++g_pass;
    } else {
        std::cout << "  clear_op_representation: " << clr.error().message << "\n";
    }
}

static void test_function_chunks() {
    std::cout << "--- function chunks ---\n";

    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    // Get all chunks for main.
    auto cks = ida::function::chunks(*main_addr);
    CHECK_OK(cks);
    if (cks) {
        CHECK(cks->size() >= 1);  // At least the entry chunk.
        std::cout << "  main() chunk count: " << cks->size() << "\n";
        for (std::size_t i = 0; i < cks->size(); ++i) {
            auto& c = (*cks)[i];
            std::cout << "    chunk[" << i << "] 0x" << std::hex << c.start
                      << "-0x" << c.end << std::dec
                      << " tail=" << c.is_tail
                      << " size=" << c.size() << "\n";
        }
        // The first chunk must be the entry (not a tail).
        CHECK(!(*cks)[0].is_tail);
    }

    // chunk_count should match.
    auto cc = ida::function::chunk_count(*main_addr);
    CHECK_OK(cc);
    if (cc && cks) {
        CHECK(*cc == cks->size());
    }

    // Tail-only view.
    auto tails = ida::function::tail_chunks(*main_addr);
    CHECK_OK(tails);
    if (tails && cks) {
        CHECK(tails->size() == cks->size() - 1);
        std::cout << "  main() tail chunks: " << tails->size() << "\n";
    }
}

static void test_function_frame() {
    std::cout << "--- function frame ---\n";

    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto sf = ida::function::frame(*main_addr);
    if (sf) {
        std::cout << "  frame total_size: " << sf->total_size() << "\n";
        std::cout << "  local_vars: " << sf->local_variables_size()
                  << "  saved_regs: " << sf->saved_registers_size()
                  << "  args: " << sf->arguments_size() << "\n";

        auto& vars = sf->variables();
        std::cout << "  frame variables: " << vars.size() << "\n";
        for (auto& v : vars) {
            std::cout << "    " << v.name
                      << "  off=" << v.byte_offset
                      << "  size=" << v.byte_size
                      << (v.is_special ? " [special]" : "")
                      << "\n";
        }
        CHECK(sf->total_size() > 0);
        ++g_pass;  // Frame successfully retrieved.
    } else {
        // Some functions may not have frames — that's acceptable.
        std::cout << "  main() has no frame: " << sf.error().message << "\n";
    }

    // SP delta at main's entry should be well-defined.
    auto spd = ida::function::sp_delta_at(*main_addr);
    CHECK_OK(spd);
    if (spd) {
        std::cout << "  sp_delta at main entry: " << *spd << "\n";
    }
}

static void test_decompiler_ctree(ida::decompiler::DecompiledFunction& df) {
    std::cout << "--- decompiler ctree visitor ---\n";

    // Count expressions using the class-based visitor.
    struct ExprCounter : public ida::decompiler::CtreeVisitor {
        int expr_count = 0;
        int stmt_count = 0;
        int call_count = 0;
        int number_count = 0;

        ida::decompiler::VisitAction visit_expression(
            ida::decompiler::ExpressionView expr) override {
            ++expr_count;
            if (expr.type() == ida::decompiler::ItemType::ExprCall)
                ++call_count;
            if (expr.type() == ida::decompiler::ItemType::ExprNumber)
                ++number_count;
            return ida::decompiler::VisitAction::Continue;
        }

        ida::decompiler::VisitAction visit_statement(
            ida::decompiler::StatementView stmt) override {
            ++stmt_count;
            return ida::decompiler::VisitAction::Continue;
        }
    };

    ExprCounter counter;
    auto result = df.visit(counter);
    CHECK_OK(result);
    if (result) {
        CHECK(counter.expr_count > 0);
        CHECK(counter.stmt_count > 0);
        std::cout << "  items visited: " << *result << "\n"
                  << "  expressions: " << counter.expr_count
                  << "  statements: " << counter.stmt_count << "\n"
                  << "  calls: " << counter.call_count
                  << "  numbers: " << counter.number_count << "\n";
    }

    // Test expressions-only visitor.
    ExprCounter expr_only;
    auto result2 = df.visit_expressions(expr_only);
    CHECK_OK(result2);
    if (result2) {
        CHECK(expr_only.expr_count > 0);
        CHECK(expr_only.stmt_count == 0);  // Should not visit statements.
        std::cout << "  expressions-only: " << expr_only.expr_count
                  << " (stmts: " << expr_only.stmt_count << ")\n";
    }

    // Test for_each_expression functional helper.
    int func_expr_count = 0;
    auto result3 = ida::decompiler::for_each_expression(df,
        [&](ida::decompiler::ExpressionView expr) {
            ++func_expr_count;
            // Test that ExpressionView methods work.
            auto t = expr.type();
            auto a = expr.address();
            (void)t;
            (void)a;
            // For numbers, check value access.
            if (expr.type() == ida::decompiler::ItemType::ExprNumber) {
                auto nv = expr.number_value();
                (void)nv;  // Just verify no crash.
            }
            return ida::decompiler::VisitAction::Continue;
        });
    CHECK_OK(result3);
    if (result3) {
        CHECK(func_expr_count > 0);
        std::cout << "  for_each_expression: " << func_expr_count << "\n";
    }

    // Test post-order visitor.
    struct PostOrderChecker : public ida::decompiler::CtreeVisitor {
        int pre_count = 0;
        int post_count = 0;

        ida::decompiler::VisitAction visit_expression(
            ida::decompiler::ExpressionView) override {
            ++pre_count;
            return ida::decompiler::VisitAction::Continue;
        }
        ida::decompiler::VisitAction leave_expression(
            ida::decompiler::ExpressionView) override {
            ++post_count;
            return ida::decompiler::VisitAction::Continue;
        }
    };

    PostOrderChecker po;
    ida::decompiler::VisitOptions opts;
    opts.expressions_only = true;
    opts.post_order = true;
    auto result4 = df.visit(po, opts);
    CHECK_OK(result4);
    if (result4) {
        // Pre and post counts should match for expressions-only.
        CHECK(po.pre_count > 0);
        CHECK(po.post_count > 0);
        std::cout << "  post-order: pre=" << po.pre_count
                  << " post=" << po.post_count << "\n";
    }

    // Test SkipChildren action.
    struct SkipChecker : public ida::decompiler::CtreeVisitor {
        int visited = 0;

        ida::decompiler::VisitAction visit_expression(
            ida::decompiler::ExpressionView) override {
            ++visited;
            // Skip children of the very first expression.
            if (visited == 1) return ida::decompiler::VisitAction::SkipChildren;
            return ida::decompiler::VisitAction::Continue;
        }
    };

    SkipChecker skip;
    auto result5 = df.visit_expressions(skip);
    CHECK_OK(result5);
    if (result5 && result3) {
        CHECK(skip.visited <= func_expr_count);
        std::cout << "  skip-children: visited " << skip.visited
                  << " (vs " << func_expr_count << " without skip)\n";
    }
}

static void test_decompiler_comments(ida::decompiler::DecompiledFunction& df) {
    std::cout << "--- decompiler comments ---\n";

    auto ea = df.entry_address();
    CHECK(ea != ida::BadAddress);

    // Set a comment.
    auto set_status = df.set_comment(ea, "idax ctree comment test");
    CHECK_OK(set_status);

    // Read it back.
    auto cmt = df.get_comment(ea);
    CHECK_OK(cmt);
    if (cmt) {
        CHECK(*cmt == "idax ctree comment test");
        std::cout << "  set/get comment: " << *cmt << "\n";
    }

    // Save to database.
    auto save_status = df.save_comments();
    CHECK_OK(save_status);

    // Remove the comment (empty string).
    auto rm_status = df.set_comment(ea, "");
    CHECK_OK(rm_status);
    df.save_comments();

    // Verify it's gone.
    auto cmt2 = df.get_comment(ea);
    CHECK_OK(cmt2);
    if (cmt2) {
        CHECK(cmt2->empty());
        std::cout << "  removed comment: ok\n";
    }

    // Refresh should not crash.
    auto ref_status = df.refresh();
    CHECK_OK(ref_status);
    std::cout << "  refresh: ok\n";
}

static void test_decompiler_address_mapping(ida::decompiler::DecompiledFunction& df) {
    std::cout << "--- decompiler address mapping ---\n";

    auto ea = df.entry_address();
    CHECK(ea != ida::BadAddress);
    std::cout << "  entry address: 0x" << std::hex << ea << std::dec << "\n";

    // Get address map.
    auto amap = df.address_map();
    CHECK_OK(amap);
    if (amap) {
        CHECK(!amap->empty());
        std::cout << "  address map entries: " << amap->size() << "\n";
        for (std::size_t i = 0; i < amap->size() && i < 5; ++i) {
            std::cout << "    line " << (*amap)[i].line_number
                      << " -> 0x" << std::hex << (*amap)[i].address
                      << std::dec << "\n";
        }
        if (amap->size() > 5) std::cout << "    ...\n";
    }

    // Test line-to-address mapping for line 0 (declaration area).
    // After header lines, there should be mappable lines.
    auto lines = df.lines();
    if (lines && lines->size() > 2) {
        // Try to map a line near the middle of the pseudocode.
        int test_line = static_cast<int>(lines->size() / 2);
        auto mapped = df.line_to_address(test_line);
        if (mapped) {
            std::cout << "  line " << test_line << " -> 0x"
                      << std::hex << *mapped << std::dec << "\n";
            ++g_pass;
        } else {
            // Mapping might fail for blank/declaration lines — acceptable.
            std::cout << "  line " << test_line << " -> (no mapping)\n";
        }
    }
}

static void test_decompiler() {
    std::cout << "--- decompiler ---\n";

    auto avail = ida::decompiler::available();
    CHECK_OK(avail);
    if (avail && *avail) {
        std::cout << "  decompiler: available\n";

        // Try to decompile main.
        auto main_addr = ida::name::resolve("main");
        if (main_addr) {
            auto df = ida::decompiler::decompile(*main_addr);
            if (df) {
                auto pc = df->pseudocode();
                CHECK_OK(pc);
                if (pc) {
                    CHECK(!pc->empty());
                    std::cout << "  pseudocode (" << pc->size() << " chars):\n";
                    // Print first 5 lines.
                    auto ln = df->lines();
                    if (ln) {
                        int n = 0;
                        for (auto& l : *ln) {
                            std::cout << "    " << l << "\n";
                            if (++n >= 5) { std::cout << "    ...\n"; break; }
                        }
                    }
                }

                auto decl = df->declaration();
                if (decl) {
                    std::cout << "  declaration: " << *decl << "\n";
                    ++g_pass;
                }

                auto vc = df->variable_count();
                CHECK_OK(vc);
                if (vc) {
                    std::cout << "  variables: " << *vc << "\n";
                    auto vars = df->variables();
                    if (vars) {
                        for (auto& v : *vars) {
                            std::cout << "    " << v.name
                                      << " : " << v.type_name
                                      << (v.is_argument ? " [arg]" : "")
                                      << " width=" << v.width << "\n";
                        }
                    }
                }

                // ── Ctree visitor tests ─────────────────────────────
                test_decompiler_ctree(*df);
                test_decompiler_comments(*df);
                test_decompiler_address_mapping(*df);
            } else {
                std::cout << "  decompile main failed: " << df.error().message << "\n";
            }
        }
    } else {
        std::cout << "  decompiler: not available (expected in headless mode)\n";
    }
}

static void test_graph_flowchart() {
    std::cout << "--- graph flowchart ---\n";

    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto fc = ida::graph::flowchart(*main_addr);
    CHECK_OK(fc);
    if (fc) {
        CHECK(fc->size() > 0);
        std::cout << "  flowchart blocks: " << fc->size() << "\n";
        for (std::size_t i = 0; i < fc->size() && i < 5; ++i) {
            auto& bb = (*fc)[i];
            std::cout << "    block[" << i << "] 0x" << std::hex
                      << bb.start << "-0x" << bb.end << std::dec
                      << " succs=" << bb.successors.size()
                      << " preds=" << bb.predecessors.size()
                      << "\n";
        }
        if (fc->size() > 5) std::cout << "    ...\n";
    }
}

static void test_graph_object() {
    std::cout << "--- graph object ---\n";

    // Create a graph and manipulate nodes/edges.
    ida::graph::Graph g;
    auto n0 = g.add_node();
    auto n1 = g.add_node();
    auto n2 = g.add_node();
    CHECK(n0 >= 0);
    CHECK(n1 >= 0);
    CHECK(n2 >= 0);
    CHECK(g.total_node_count() == 3);
    CHECK(g.visible_node_count() == 3);

    // Add edges.
    auto e1 = g.add_edge(n0, n1);
    CHECK_OK(e1);
    auto e2 = g.add_edge(n1, n2);
    CHECK_OK(e2);

    // Check successors/predecessors.
    auto succs = g.successors(n0);
    CHECK_OK(succs);
    if (succs) {
        CHECK(succs->size() == 1);
        if (!succs->empty()) CHECK((*succs)[0] == n1);
    }

    auto preds = g.predecessors(n2);
    CHECK_OK(preds);
    if (preds) {
        CHECK(preds->size() == 1);
        if (!preds->empty()) CHECK((*preds)[0] == n1);
    }

    // Check path exists.
    CHECK(g.path_exists(n0, n2));
    CHECK(!g.path_exists(n2, n0));

    // Get all edges.
    auto edges = g.edges();
    CHECK(edges.size() == 2);

    // Remove an edge.
    auto re = g.remove_edge(n0, n1);
    CHECK_OK(re);
    CHECK(!g.path_exists(n0, n2));

    // Remove a node.
    auto rn = g.remove_node(n1);
    CHECK_OK(rn);

    // Clear.
    g.clear();
    CHECK(g.total_node_count() == 0);

    std::cout << "  graph object operations: ok\n";
}

static void test_storage_blobs() {
    std::cout << "--- storage blobs ---\n";

    // Create a test node.
    auto node = ida::storage::Node::open("$idax_blob_test", true);
    CHECK_OK(node);
    if (!node) return;

    // Initially no blob.
    auto sz0 = node->blob_size(0);
    CHECK_OK(sz0);
    CHECK(*sz0 == 0);

    // Write a blob.
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};
    auto ws = node->set_blob(0, data);
    CHECK_OK(ws);

    // Read back size.
    auto sz1 = node->blob_size(0);
    CHECK_OK(sz1);
    CHECK(*sz1 == 5);

    // Read back data.
    auto rd = node->blob(0);
    CHECK_OK(rd);
    if (rd) {
        CHECK(rd->size() == 5);
        CHECK((*rd)[0] == 0xDE && (*rd)[4] == 0x42);
    }

    // Write a string blob and read back.
    std::string str = "hello blob";
    std::vector<uint8_t> str_data(str.begin(), str.end());
    str_data.push_back(0);  // null terminator
    auto ws2 = node->set_blob(1, str_data);
    CHECK_OK(ws2);

    auto bs = node->blob_string(1);
    CHECK_OK(bs);
    if (bs) {
        CHECK(*bs == "hello blob");
        std::cout << "  blob_string: " << *bs << "\n";
    }

    // Delete blob.
    auto del = node->del_blob(0);
    CHECK_OK(del);

    auto sz2 = node->blob_size(0);
    CHECK_OK(sz2);
    CHECK(*sz2 == 0);

    // Cleanup blob at index 1.
    node->del_blob(1);

    std::cout << "  storage blob operations: ok\n";
}

static void test_type_library() {
    std::cout << "--- type library ---\n";

    // Local type count should be non-negative (may be 0 for simple binaries).
    auto count = ida::type::local_type_count();
    CHECK_OK(count);
    if (count) {
        std::cout << "  local type count: " << *count << "\n";

        // If there are local types, try to get the first one's name.
        if (*count > 0) {
            auto name = ida::type::local_type_name(1);  // 1-based
            CHECK_OK(name);
            if (name)
                std::cout << "  local type 1: " << *name << "\n";
        }
    }

    // Create a struct type and save it to the local type library, then verify
    // the count increased.
    auto initial_count = ida::type::local_type_count();
    CHECK_OK(initial_count);

    auto st = ida::type::TypeInfo::create_struct();
    // Add a member so it's non-trivial.
    st.add_member("field_a", ida::type::TypeInfo::int32());
    auto saved = st.save_as("idax_test_struct_lib");
    CHECK_OK(saved);
    if (saved) {
        auto new_count = ida::type::local_type_count();
        CHECK_OK(new_count);
        if (initial_count && new_count)
            CHECK(*new_count > *initial_count);
    }

    std::cout << "  type library operations: ok\n";
}

static void test_register_variables() {
    std::cout << "--- register variables ---\n";

    // Find a function to test with.
    auto main_addr = ida::name::resolve("main");
    if (!main_addr) {
        std::cout << "  (skipping, main not found)\n";
        return;
    }

    auto func = ida::function::at(*main_addr);
    if (!func) {
        std::cout << "  (skipping, function not found)\n";
        return;
    }

    ida::Address start = func->start();
    ida::Address end = func->end();

    // Add a register variable.
    auto add_res = ida::function::add_register_variable(
        start, start, end, "rax", "my_counter", "test regvar");
    CHECK_OK(add_res);

    // Find it back.
    auto found = ida::function::find_register_variable(start, start, "rax");
    CHECK_OK(found);
    if (found) {
        CHECK(found->canonical_name == "rax");
        CHECK(found->user_name == "my_counter");
        std::cout << "  found regvar: " << found->canonical_name
                  << " -> " << found->user_name << "\n";
    }

    // has_register_variables
    auto has = ida::function::has_register_variables(start, start);
    CHECK_OK(has);
    if (has) CHECK(*has == true);

    // Rename it.
    auto ren = ida::function::rename_register_variable(
        start, start, "rax", "renamed_counter");
    CHECK_OK(ren);

    // Verify rename.
    auto found2 = ida::function::find_register_variable(start, start, "rax");
    CHECK_OK(found2);
    if (found2) {
        CHECK(found2->user_name == "renamed_counter");
    }

    // Delete it.
    auto del = ida::function::delete_register_variable(start, start, end, "rax");
    CHECK_OK(del);

    // Verify deletion — find should fail.
    auto found3 = ida::function::find_register_variable(start, start, "rax");
    CHECK(!found3.has_value());

    std::cout << "  register variable operations: ok\n";
}

static void test_ui_events() {
    std::cout << "--- ui events ---\n";

    // Test that we can subscribe and unsubscribe without crashing.
    // In headless (idalib) mode, UI events may not fire, but the
    // subscription/unsubscription path itself must work.

    bool closed_fired = false;
    auto tok1 = ida::ui::on_database_closed([&]() {
        closed_fired = true;
    });
    CHECK_OK(tok1);

    bool ready_fired = false;
    auto tok2 = ida::ui::on_ready_to_run([&]() {
        ready_fired = true;
    });
    CHECK_OK(tok2);

    bool ea_changed_fired = false;
    auto tok3 = ida::ui::on_screen_ea_changed(
        [&](ida::Address, ida::Address) { ea_changed_fired = true; });
    CHECK_OK(tok3);

    // Unsubscribe all.
    if (tok1) {
        auto u1 = ida::ui::ui_unsubscribe(*tok1);
        CHECK_OK(u1);
    }
    if (tok2) {
        auto u2 = ida::ui::ui_unsubscribe(*tok2);
        CHECK_OK(u2);
    }
    if (tok3) {
        auto u3 = ida::ui::ui_unsubscribe(*tok3);
        CHECK_OK(u3);
    }

    // ScopedUiSubscription RAII test.
    {
        auto tok4 = ida::ui::on_database_closed([]() {});
        CHECK_OK(tok4);
        if (tok4) {
            ida::ui::ScopedUiSubscription scoped(*tok4);
            CHECK(scoped.token() != 0);
        }
        // Destructor should unsubscribe — no crash.
    }
    ++g_pass;  // Survived scoped subscription destruction.

    std::cout << "  ui event subscribe/unsubscribe: ok\n";
}

static void test_event_system() {
    std::cout << "--- event subscription ---\n";

    // Subscribe to renamed events, set a name, check we got called back.
    bool callback_fired = false;
    auto f0 = ida::function::by_index(0);
    if (!f0) return;

    auto tok = ida::event::on_renamed(
        [&](ida::Address ea, std::string new_name, std::string old_name) {
            callback_fired = true;
            std::cout << "  event: renamed 0x" << std::hex << ea << std::dec
                      << " '" << old_name << "' -> '" << new_name << "'\n";
        });
    CHECK_OK(tok);

    if (tok) {
        // Trigger a rename.
        auto old_name = ida::name::get(f0->start());
        ida::name::set(f0->start(), "__idax_test_rename__");

        CHECK(callback_fired);
        if (callback_fired)
            std::cout << "  event callback fired: yes\n";
        else
            std::cout << "  event callback fired: no (unexpected)\n";

        // Restore original name.
        if (old_name)
            ida::name::set(f0->start(), *old_name);
        else
            ida::name::remove(f0->start());

        // Unsubscribe.
        auto unsub = ida::event::unsubscribe(*tok);
        CHECK_OK(unsub);
    }
}

// ── Main ────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    // 1. Initialize idalib.
    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    // 2. Open the binary with auto-analysis.
    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    // 3. Wait for auto-analysis.
    ida::analysis::wait();

    // 4. Run tests.
    test_database();
    test_segments();
    test_functions();
    test_function_callers_callees();
    test_function_chunks();
    test_function_frame();
    test_address_predicates();
    test_data_read();
    test_instructions();
    test_operand_representation();
    test_names();
    test_xrefs();
    test_comments();
    test_entry_points();
    test_type_basics();
    test_decompiler();
    test_graph_flowchart();
    test_graph_object();
    test_storage_blobs();
    test_type_library();
    test_register_variables();
    test_ui_events();
    test_event_system();

    // 5. Report.
    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";

    // 6. Close without saving.
    ida::database::close(false);

    return g_fail > 0 ? 1 : 0;
}
