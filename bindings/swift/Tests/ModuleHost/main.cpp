// Actual IDA kernel dispatch; no direct calls to addon bootstrap functions.
#include <type_traits>
#include <cctype>
#include <pro.h>
#include <idp.hpp>
#include <loader.hpp>
#include <idalib.hpp>
#include <kernwin.hpp>
#include <ua.hpp>
#include <bytes.hpp>
#include <diskio.hpp>
#include <cstdio>
#include <cstring>

bool equal_name(const char* first, const char* second) {
    while (*first != '\0' && *second != '\0') {
        if (std::tolower(static_cast<unsigned char>(*first++))
            != std::tolower(static_cast<unsigned char>(*second++)))
            return false;
    }
    return *first == *second;
}

int main(int argc, char** argv) {
    if (argc < 4)
        return 2;
    const char* mode = argv[1];
    enable_console_messages(true);
    if (init_library() != 0)
        return 1;
    const char* options = std::strcmp(mode, "processor") == 0
        ? "-pswtoy -Tbinary -b0x1000" : nullptr;
    if (open_database(argv[2], false, options) != 0)
        return 1;
    bool passed = false;
    if (std::strcmp(mode, "plugin") == 0 && argc == 5) {
        plugin_t* first = load_plugin(argv[3]);
        plugin_t* second = load_plugin(argv[4]);
        // Load both before running either. A shared global factory would make
        // one descriptor call the other's implementation.
        passed = first != nullptr && second != nullptr && first != second
            && (first->flags & PLUGIN_MULTI) != 0
            && (first->flags & (PLUGIN_MOD | PLUGIN_HIDE)) == 0
            && (second->flags & (PLUGIN_MULTI | PLUGIN_MOD | PLUGIN_HIDE))
                == (PLUGIN_MULTI | PLUGIN_MOD | PLUGIN_HIDE)
            && run_plugin(first, 4242) && run_plugin(second, 5252)
            && run_plugin(first, 6262);
    } else if (std::strcmp(mode, "loader") == 0) {
        char name[QMAXFILE]{};
        passed = get_loader_name(name, sizeof(name)) >= 0
            && equal_name(name, argv[3]);
        std::printf("IDAX_SWIFT_HOST_LOADER=%s\n", name);
    } else if (std::strcmp(mode, "processor") == 0) {
        char name[QMAXFILE]{};
        get_idp_name(name, sizeof(name));
        insn_t instruction;
        const int size = decode_insn(&instruction, inf_get_min_ea());
        qstring line;
        const bool rendered = generate_disasm_line(&line, inf_get_min_ea(), GENDSM_FORCE_CODE);
        passed = equal_name(name, argv[3]) && size == 1 && instruction.itype == 0
            && rendered && line.find("nop") != qstring::npos;
        std::printf("IDAX_SWIFT_HOST_PROCESSOR=%s size=%d itype=%u\n",
                    name, size, instruction.itype);
    }
    close_database(false);
    std::puts(passed ? "IDAX_SWIFT_HOST_DISPATCH=PASS" : "IDAX_SWIFT_HOST_DISPATCH=FAIL");
    return passed ? 0 : 1;
}
