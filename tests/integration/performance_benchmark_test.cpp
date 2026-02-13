/// \file performance_benchmark_test.cpp
/// \brief Performance benchmark test for idax core operations.
///
/// This is NOT a correctness test — it records timing baselines for major
/// wrapper operations and verifies they complete within reasonable bounds.
/// All timings are printed to stdout.  The test only fails if an operation
/// produces an incorrect result (e.g. a decode that should succeed fails).

#include <ida/idax.hpp>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

// ── Minimal test harness ────────────────────────────────────────────────

static int g_pass = 0;
static int g_fail = 0;
static int g_skip = 0;

#define CHECK(cond, msg)                                                      \
    do {                                                                       \
        if (cond) { ++g_pass; }                                                \
        else { ++g_fail; std::printf("  FAIL: %s\n", msg); }                  \
    } while (0)

#define SKIP(msg)                                                              \
    do { ++g_skip; std::printf("  SKIP: %s\n", msg); } while (0)

// ── Timer utility ───────────────────────────────────────────────────────

struct Timer {
    std::chrono::steady_clock::time_point start;
    Timer() : start(std::chrono::steady_clock::now()) {}
    double elapsed_ms() const {
        auto end = std::chrono::steady_clock::now();
        return std::chrono::duration<double, std::milli>(end - start).count();
    }
};

// ── Helpers ─────────────────────────────────────────────────────────────

/// Resolve main()'s address, or return BadAddress if not found.
static ida::Address resolve_main() {
    auto r = ida::name::resolve("main");
    if (r) return *r;
    return ida::BadAddress;
}

// ═══════════════════════════════════════════════════════════════════════════
// 1) Instruction decode throughput
// ═══════════════════════════════════════════════════════════════════════════

static void bench_instruction_decode() {
    std::printf("[bench] instruction decode throughput\n");

    auto fn = ida::function::by_index(0);
    if (!fn) {
        SKIP("no functions available for instruction decode benchmark");
        return;
    }

    const ida::Address start = fn->start();
    const ida::Address end   = fn->end();

    std::size_t count       = 0;
    std::size_t fail_count  = 0;
    ida::Address ea         = start;

    Timer t;
    while (ea < end) {
        auto insn = ida::instruction::decode(ea);
        if (!insn) {
            ++fail_count;
            // Advance by 1 byte to avoid infinite loop on undecoded bytes.
            ++ea;
            continue;
        }
        if (insn->size() == 0) break;
        ea += insn->size();
        ++count;
    }
    double ms = t.elapsed_ms();

    double ops_sec = (ms > 0.0) ? (static_cast<double>(count) / ms * 1000.0) : 0.0;
    std::printf("  [bench] instruction_decode: %zu ops in %.3fms (%.0f ops/sec)\n",
                count, ms, ops_sec);

    CHECK(count > 0, "decoded at least one instruction");
    CHECK(fail_count == 0, "all instruction decodes succeeded in first function");
}

// ═══════════════════════════════════════════════════════════════════════════
// 2) Function iteration throughput
// ═══════════════════════════════════════════════════════════════════════════

static void bench_function_iteration() {
    std::printf("[bench] function iteration throughput\n");

    std::vector<std::pair<ida::Address, std::string>> funcs;

    Timer t;
    for (auto f : ida::function::all()) {
        funcs.emplace_back(f.start(), f.name());
    }
    double ms = t.elapsed_ms();

    double ops_sec = (ms > 0.0) ? (static_cast<double>(funcs.size()) / ms * 1000.0) : 0.0;
    std::printf("  [bench] function_iteration: %zu functions in %.3fms (%.0f funcs/sec)\n",
                funcs.size(), ms, ops_sec);

    CHECK(!funcs.empty(), "iterated at least one function");
    // Sanity: every function should have a non-zero start address.
    bool all_valid = true;
    for (auto& [addr, name] : funcs) {
        if (addr == ida::BadAddress) { all_valid = false; break; }
    }
    CHECK(all_valid, "all function start addresses are valid");
}

// ═══════════════════════════════════════════════════════════════════════════
// 3) Binary pattern search
// ═══════════════════════════════════════════════════════════════════════════

static void bench_binary_pattern_search() {
    std::printf("[bench] binary pattern search\n");

    auto lo = ida::database::min_address();
    if (!lo) {
        SKIP("cannot determine min_address for binary pattern search");
        return;
    }

    Timer t;
    auto found = ida::search::binary_pattern("7F 45 4C 46", *lo);
    double ms = t.elapsed_ms();

    std::printf("  [bench] binary_pattern_search: 1 ops in %.3fms\n", ms);

    if (found) {
        std::printf("  found ELF magic at 0x%llx\n",
                    static_cast<unsigned long long>(*found));
        CHECK(true, "ELF magic pattern found");
    } else {
        // Not all fixture binaries may have ELF magic in the loaded database.
        // This is acceptable — we just note it.
        std::printf("  ELF magic not found (may be stripped from database image)\n");
        SKIP("ELF magic not found in database");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 4) Address predicate scan (item iteration)
// ═══════════════════════════════════════════════════════════════════════════

static void bench_address_item_scan() {
    std::printf("[bench] address item scan\n");

    // Get the first segment's bounds.
    auto segs = ida::segment::all();
    auto seg_it = segs.begin();
    if (seg_it == segs.end()) {
        SKIP("no segments available for item scan benchmark");
        return;
    }
    auto seg = *seg_it;
    const ida::Address start = seg.start();
    const ida::Address end   = seg.end();

    std::size_t item_count = 0;

    Timer t;
    for (auto addr : ida::address::items(start, end)) {
        (void)addr;
        ++item_count;
    }
    double ms = t.elapsed_ms();

    double ops_sec = (ms > 0.0) ? (static_cast<double>(item_count) / ms * 1000.0) : 0.0;
    std::printf("  [bench] address_item_scan: %zu items in %.3fms (%.0f items/sec)\n",
                item_count, ms, ops_sec);
    std::printf("  segment: [0x%llx, 0x%llx) name=%s\n",
                static_cast<unsigned long long>(start),
                static_cast<unsigned long long>(end),
                seg.name().c_str());

    CHECK(item_count > 0, "scanned at least one item in first segment");
}

// ═══════════════════════════════════════════════════════════════════════════
// 5) Xref enumeration
// ═══════════════════════════════════════════════════════════════════════════

static void bench_xref_enumeration() {
    std::printf("[bench] xref enumeration\n");

    ida::Address main_ea = resolve_main();
    if (main_ea == ida::BadAddress) {
        SKIP("main() not found — cannot benchmark xref enumeration");
        return;
    }

    Timer t;
    auto refs = ida::xref::refs_to(main_ea);
    double ms = t.elapsed_ms();

    if (refs) {
        std::printf("  [bench] xref_enumeration: %zu refs in %.3fms\n",
                    refs->size(), ms);
        CHECK(true, "xref enumeration completed successfully");
        // Print first few refs for visibility.
        for (std::size_t i = 0; i < refs->size() && i < 5; ++i) {
            std::printf("    ref[%zu]: from=0x%llx to=0x%llx\n",
                        i,
                        static_cast<unsigned long long>((*refs)[i].from),
                        static_cast<unsigned long long>((*refs)[i].to));
        }
    } else {
        std::printf("  [bench] xref_enumeration: error: %s\n",
                    refs.error().message.c_str());
        CHECK(false, "xref enumeration should not fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 6) Name resolution batch
// ═══════════════════════════════════════════════════════════════════════════

static void bench_name_resolution() {
    std::printf("[bench] name resolution batch\n");

    // Collect all function start addresses first.
    std::vector<ida::Address> addrs;
    for (auto f : ida::function::all()) {
        addrs.push_back(f.start());
    }

    if (addrs.empty()) {
        SKIP("no functions available for name resolution benchmark");
        return;
    }

    std::size_t resolved = 0;
    std::size_t failed   = 0;

    Timer t;
    for (auto addr : addrs) {
        auto name = ida::name::get(addr);
        if (name && !name->empty()) {
            ++resolved;
        } else {
            ++failed;
        }
    }
    double ms = t.elapsed_ms();

    double ops_sec = (ms > 0.0) ? (static_cast<double>(addrs.size()) / ms * 1000.0) : 0.0;
    std::printf("  [bench] name_resolution: %zu/%zu resolved in %.3fms (%.0f ops/sec)\n",
                resolved, addrs.size(), ms, ops_sec);

    CHECK(resolved > 0, "resolved at least one function name");
}

// ═══════════════════════════════════════════════════════════════════════════
// 7) Decompile latency
// ═══════════════════════════════════════════════════════════════════════════

static void bench_decompile_latency() {
    std::printf("[bench] decompile latency\n");

    auto avail = ida::decompiler::available();
    if (!avail || !*avail) {
        SKIP("decompiler not available — skipping latency benchmark");
        return;
    }

    ida::Address main_ea = resolve_main();
    if (main_ea == ida::BadAddress) {
        SKIP("main() not found — cannot benchmark decompilation");
        return;
    }

    Timer t;
    auto df = ida::decompiler::decompile(main_ea);
    double ms = t.elapsed_ms();

    if (df) {
        // df is move-only: use -> to access methods.
        auto pc = df->pseudocode();
        std::size_t lines = 0;
        if (pc) lines = pc->size();

        std::printf("  [bench] decompile_latency: %.3fms (pseudocode: %zu chars)\n",
                    ms, lines);
        CHECK(true, "decompilation succeeded");
    } else {
        std::printf("  [bench] decompile_latency: failed in %.3fms: %s\n",
                    ms, df.error().message.c_str());
        CHECK(false, "decompilation should not fail for main()");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 8) Data read throughput
// ═══════════════════════════════════════════════════════════════════════════

static void bench_data_read() {
    std::printf("[bench] data read throughput\n");

    auto lo = ida::database::min_address();
    if (!lo) {
        SKIP("cannot determine min_address for data read benchmark");
        return;
    }

    static constexpr std::size_t read_size = 4096;

    Timer t;
    auto bytes = ida::data::read_bytes(*lo, read_size);
    double ms = t.elapsed_ms();

    if (bytes) {
        std::printf("  [bench] data_read: %zu bytes in %.3fms\n",
                    bytes->size(), ms);
        CHECK(bytes->size() > 0, "read returned non-empty data");
        // Quick sanity: ELF magic check (0x7F 'E' 'L' 'F').
        if (bytes->size() >= 4) {
            bool elf = ((*bytes)[0] == 0x7F && (*bytes)[1] == 0x45 &&
                        (*bytes)[2] == 0x4C && (*bytes)[3] == 0x46);
            if (elf) {
                std::printf("  first 4 bytes: ELF magic confirmed\n");
            } else {
                std::printf("  first 4 bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n",
                            (*bytes)[0], (*bytes)[1], (*bytes)[2], (*bytes)[3]);
            }
        }
    } else {
        std::printf("  [bench] data_read: error: %s\n",
                    bytes.error().message.c_str());
        // The fixture may not have 4096 contiguous loadable bytes at
        // min_address; this is acceptable.
        SKIP("data read returned error (may be sparse mapping)");
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 9) Comment set/get throughput
// ═══════════════════════════════════════════════════════════════════════════

static void bench_comment_throughput() {
    std::printf("[bench] comment set/get throughput\n");

    // Find a code address to use as the target.
    auto fn = ida::function::by_index(0);
    if (!fn) {
        SKIP("no functions available for comment benchmark");
        return;
    }

    const ida::Address ea = fn->start();
    static constexpr int iterations = 100;

    // Save original comment so we can restore it.
    auto original = ida::comment::get(ea, false);

    std::size_t set_ok = 0;
    std::size_t get_ok = 0;

    Timer t;
    for (int i = 0; i < iterations; ++i) {
        // Build a unique comment string per iteration.
        char buf[64];
        std::snprintf(buf, sizeof(buf), "bench_comment_%d", i);

        auto sr = ida::comment::set(ea, buf, false);
        if (sr) ++set_ok;

        auto gr = ida::comment::get(ea, false);
        if (gr && !gr->empty()) ++get_ok;
    }
    double ms = t.elapsed_ms();

    // Clean up: restore original comment.
    if (original && !original->empty()) {
        ida::comment::set(ea, *original, false);
    } else {
        ida::comment::remove(ea, false);
    }

    double ops_sec = (ms > 0.0) ? (static_cast<double>(iterations * 2) / ms * 1000.0) : 0.0;
    std::printf("  [bench] comment_set_get: %d iterations (%zu set, %zu get) in %.3fms (%.0f ops/sec)\n",
                iterations, set_ok, get_ok, ms, ops_sec);

    CHECK(set_ok == static_cast<std::size_t>(iterations),
          "all comment sets succeeded");
    CHECK(get_ok == static_cast<std::size_t>(iterations),
          "all comment gets succeeded");
}

// ═══════════════════════════════════════════════════════════════════════════
// 10) Type creation throughput
// ═══════════════════════════════════════════════════════════════════════════

static void bench_type_creation() {
    std::printf("[bench] type creation throughput\n");

    static constexpr int count = 100;

    // Phase A: create 100 int32 types.
    Timer t_int;
    std::vector<ida::type::TypeInfo> int_types;
    int_types.reserve(count);
    for (int i = 0; i < count; ++i) {
        int_types.push_back(ida::type::TypeInfo::int32());
    }
    double ms_int = t_int.elapsed_ms();

    // Phase B: create 100 pointer-to-int32 types.
    Timer t_ptr;
    std::vector<ida::type::TypeInfo> ptr_types;
    ptr_types.reserve(count);
    for (int i = 0; i < count; ++i) {
        ptr_types.push_back(ida::type::TypeInfo::pointer_to(int_types[i]));
    }
    double ms_ptr = t_ptr.elapsed_ms();

    double total_ms = ms_int + ms_ptr;
    double ops_sec = (total_ms > 0.0)
                         ? (static_cast<double>(count * 2) / total_ms * 1000.0)
                         : 0.0;

    std::printf("  [bench] type_create_int32:    %d ops in %.3fms\n", count, ms_int);
    std::printf("  [bench] type_create_pointer:  %d ops in %.3fms\n", count, ms_ptr);
    std::printf("  [bench] type_creation_total:  %d ops in %.3fms (%.0f ops/sec)\n",
                count * 2, total_ms, ops_sec);

    CHECK(static_cast<int>(int_types.size()) == count,
          "created 100 int32 types");
    CHECK(static_cast<int>(ptr_types.size()) == count,
          "created 100 pointer-to-int32 types");

    // Quick sanity: verify types report correct properties.
    CHECK(int_types[0].is_integer(), "int32 reports as integer");
    CHECK(ptr_types[0].is_pointer(), "pointer_to(int32) reports as pointer");
}

// ═══════════════════════════════════════════════════════════════════════════
// Summary printer
// ═══════════════════════════════════════════════════════════════════════════

static void print_summary() {
    std::printf("\n");
    std::printf("╔══════════════════════════════════════════════════╗\n");
    std::printf("║  Performance Benchmark Summary                   ║\n");
    std::printf("╠══════════════════════════════════════════════════╣\n");
    std::printf("║  Passed:  %-5d                                  ║\n", g_pass);
    std::printf("║  Failed:  %-5d                                  ║\n", g_fail);
    std::printf("║  Skipped: %-5d                                  ║\n", g_skip);
    std::printf("╚══════════════════════════════════════════════════╝\n");
}

// ═══════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::printf("Usage: %s <binary>\n", argv[0]);
        return 1;
    }

    std::printf("=== idax Performance Benchmark ===\n");
    std::printf("fixture: %s\n\n", argv[1]);

    // ── Initialize idalib ───────────────────────────────────────────────
    auto init_r = ida::database::init(argc, argv);
    if (!init_r) {
        std::printf("FATAL: init failed: %s\n", init_r.error().message.c_str());
        return 1;
    }

    // ── Open fixture database ───────────────────────────────────────────
    auto open_r = ida::database::open(argv[1]);
    if (!open_r) {
        std::printf("FATAL: cannot open fixture: %s\n",
                    open_r.error().message.c_str());
        return 1;
    }

    // ── Wait for auto-analysis ──────────────────────────────────────────
    {
        Timer t;
        ida::analysis::wait();
        double ms = t.elapsed_ms();
        std::printf("[bench] auto_analysis_wait: %.3fms\n\n", ms);
    }

    // ── Run benchmarks ──────────────────────────────────────────────────
    bench_instruction_decode();
    std::printf("\n");

    bench_function_iteration();
    std::printf("\n");

    bench_binary_pattern_search();
    std::printf("\n");

    bench_address_item_scan();
    std::printf("\n");

    bench_xref_enumeration();
    std::printf("\n");

    bench_name_resolution();
    std::printf("\n");

    bench_decompile_latency();
    std::printf("\n");

    bench_data_read();
    std::printf("\n");

    bench_comment_throughput();
    std::printf("\n");

    bench_type_creation();

    // ── Summary ─────────────────────────────────────────────────────────
    print_summary();

    // ── Close without saving ────────────────────────────────────────────
    ida::database::close(false);

    return g_fail > 0 ? 1 : 0;
}
