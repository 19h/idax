/// \file auto_enum_port_plugin.cpp
/// \brief idax C++23 port of the Auto Enum IDAPython plugin.
///
/// The global action enriches imported function prototypes with named enum
/// argument types.  The local action annotates selector-dependent call
/// operands in the current decompiled function.  The in-tree corpus is a
/// representative, dependency-free subset of the original Linux/Windows data;
/// the table-driven engine is intentionally independent of the corpus size.
/// Upstream Auto Enum copyright/license: auto_enum_port_LICENSE.txt.

#include <ida/idax.hpp>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

using namespace std::string_view_literals;

constexpr std::string_view kPrototypeAction = "idax:auto_enum:prototypes";
constexpr std::string_view kCallAction = "idax:auto_enum:call";
constexpr std::string_view kMenuPath = "Edit/Plugins/";

struct MemberSpec {
    std::string_view name;
    std::uint64_t value;
};

struct EnumSpec {
    std::string_view id;
    std::span<const MemberSpec> members;
};

struct ArgumentSpec {
    std::string_view name;
    std::string_view enum_id;
};

struct FunctionSpec {
    std::string_view name;
    std::span<const ArgumentSpec> arguments;
};

struct SpecialSpec {
    std::string_view function_name;
    std::size_t selector_index;
    std::uint64_t selector_value;
    std::size_t target_index;
    std::string_view enum_id;
};

constexpr std::array kOpenFlags = {
    MemberSpec{"RSYNC", 1052672}, MemberSpec{"WRONLY", 1},
    MemberSpec{"DIRECT", 16384}, MemberSpec{"DIRECTORY", 65536},
    MemberSpec{"DSYNC", 4096}, MemberSpec{"RDONLY", 0},
    MemberSpec{"CREAT", 64}, MemberSpec{"TRUNC", 512},
    MemberSpec{"RDWR", 2}, MemberSpec{"CLOEXEC", 524288},
    MemberSpec{"NOFOLLOW", 131072}, MemberSpec{"APPEND", 1024},
    MemberSpec{"LARGEFILE", 32768}, MemberSpec{"ASYNC", 8192},
    MemberSpec{"NDELAY", 2048}, MemberSpec{"TMPFILE", 4259840},
    MemberSpec{"NOATIME", 262144}, MemberSpec{"EXCL", 128},
    MemberSpec{"PATH", 2097152}, MemberSpec{"NOCTTY", 256},
};

constexpr std::array kAddressFamilies = {
    MemberSpec{"MPLS", 28}, MemberSpec{"UNIX", 1},
    MemberSpec{"BLUETOOTH", 31}, MemberSpec{"INET6", 10},
    MemberSpec{"INET", 2}, MemberSpec{"KEY", 15},
    MemberSpec{"IB", 27}, MemberSpec{"RDS", 21},
    MemberSpec{"TIPC", 30}, MemberSpec{"NETLINK", 16},
    MemberSpec{"VSOCK", 40}, MemberSpec{"CAN", 29},
    MemberSpec{"KCM", 41}, MemberSpec{"X25", 9},
    MemberSpec{"AX25", 3}, MemberSpec{"IPX", 4},
    MemberSpec{"DECnet", 12}, MemberSpec{"PACKET", 17},
    MemberSpec{"ALG", 38}, MemberSpec{"APPLETALK", 5},
    MemberSpec{"PPPOX", 24}, MemberSpec{"XDP", 44},
    MemberSpec{"LLC", 26},
};

constexpr std::array kSocketTypes = {
    MemberSpec{"SEQPACKET", 5}, MemberSpec{"PACKET", 10},
    MemberSpec{"NONBLOCK", 2048}, MemberSpec{"CLOEXEC", 524288},
    MemberSpec{"RDM", 4}, MemberSpec{"DGRAM", 2},
    MemberSpec{"RAW", 3}, MemberSpec{"STREAM", 1},
};

constexpr std::array kProtectionFlags = {
    MemberSpec{"WRITE", 2}, MemberSpec{"EXEC", 4},
    MemberSpec{"NONE", 0}, MemberSpec{"READ", 1},
};

constexpr std::array kMapFlags = {
    MemberSpec{"NORESERVE", 16384}, MemberSpec{"NONBLOCK", 65536},
    MemberSpec{"FIXED", 16}, MemberSpec{"FIXED_NOREPLACE", 1048576},
    MemberSpec{"PRIVATE", 2}, MemberSpec{"32BIT", 64},
    MemberSpec{"GROWSDOWN", 256}, MemberSpec{"LOCKED", 8192},
    MemberSpec{"EXECUTABLE", 4096}, MemberSpec{"ANON", 32},
    MemberSpec{"SYNC", 524288}, MemberSpec{"STACK", 131072},
    MemberSpec{"HUGETLB", 262144}, MemberSpec{"DENYWRITE", 2048},
    MemberSpec{"POPULATE", 32768}, MemberSpec{"HUGE_2MB", 1409286144},
    MemberSpec{"FILE", 0}, MemberSpec{"SHARED", 1},
};

constexpr std::array kPrctlOptions = {
    MemberSpec{"SET_PDEATHSIG", 1}, MemberSpec{"GET_PDEATHSIG", 2},
    MemberSpec{"GET_DUMPABLE", 3}, MemberSpec{"SET_DUMPABLE", 4},
    MemberSpec{"GET_UNALIGN", 5}, MemberSpec{"SET_UNALIGN", 6},
    MemberSpec{"GET_KEEPCAPS", 7}, MemberSpec{"SET_KEEPCAPS", 8},
    MemberSpec{"SET_NAME", 15}, MemberSpec{"GET_NAME", 16},
    MemberSpec{"GET_SECCOMP", 21}, MemberSpec{"SET_SECCOMP", 22},
    MemberSpec{"CAPBSET_READ", 23}, MemberSpec{"CAPBSET_DROP", 24},
    MemberSpec{"SET_NO_NEW_PRIVS", 38}, MemberSpec{"GET_NO_NEW_PRIVS", 39},
};

constexpr std::array kAccessModes = {
    MemberSpec{"F_OK", 0}, MemberSpec{"R_OK", 4},
    MemberSpec{"W_OK", 2}, MemberSpec{"X_OK", 1},
};

constexpr std::array kSocketLevels = {
    MemberSpec{"SOL_IP", 0}, MemberSpec{"SOL_SOCKET", 1},
    MemberSpec{"SOL_TCP", 6}, MemberSpec{"SOL_UDP", 17},
    MemberSpec{"SOL_IPV6", 41}, MemberSpec{"SOL_ICMPV6", 58},
    MemberSpec{"SOL_SCTP", 132}, MemberSpec{"SOL_RAW", 255},
};

constexpr std::array kIpProtocols = {
    MemberSpec{"IP", 0}, MemberSpec{"ICMP", 1}, MemberSpec{"IGMP", 2},
    MemberSpec{"IPIP", 4}, MemberSpec{"TCP", 6}, MemberSpec{"EGP", 8},
    MemberSpec{"PUP", 12}, MemberSpec{"UDP", 17}, MemberSpec{"IDP", 22},
    MemberSpec{"TP", 29}, MemberSpec{"DCCP", 33}, MemberSpec{"IPV6", 41},
    MemberSpec{"ROUTING", 43}, MemberSpec{"FRAGMENT", 44},
    MemberSpec{"RSVP", 46}, MemberSpec{"GRE", 47}, MemberSpec{"ESP", 50},
    MemberSpec{"AH", 51}, MemberSpec{"ICMPV6", 58}, MemberSpec{"NONE", 59},
    MemberSpec{"DSTOPTS", 60}, MemberSpec{"MTP", 92}, MemberSpec{"BEETPH", 94},
    MemberSpec{"ENCAP", 98}, MemberSpec{"PIM", 103}, MemberSpec{"COMP", 108},
    MemberSpec{"L2TP", 115}, MemberSpec{"SCTP", 132}, MemberSpec{"MH", 135},
    MemberSpec{"UDPLITE", 136}, MemberSpec{"MPLS", 137},
    MemberSpec{"ETHERNET", 143}, MemberSpec{"RAW", 255},
    MemberSpec{"SMC", 256}, MemberSpec{"MPTCP", 262},
};

constexpr std::array kNetlinkProtocols = {
    MemberSpec{"ROUTE", 0}, MemberSpec{"UNUSED", 1},
    MemberSpec{"USERSOCK", 2}, MemberSpec{"FIREWALL", 3},
    MemberSpec{"SOCK_DIAG", 4}, MemberSpec{"NFLOG", 5},
    MemberSpec{"XFRM", 6}, MemberSpec{"SELINUX", 7},
    MemberSpec{"ISCSI", 8}, MemberSpec{"AUDIT", 9},
    MemberSpec{"FIB_LOOKUP", 10}, MemberSpec{"CONNECTOR", 11},
    MemberSpec{"NETFILTER", 12}, MemberSpec{"IP6_FW", 13},
    MemberSpec{"DNRTMSG", 14}, MemberSpec{"KOBJECT_UEVENT", 15},
    MemberSpec{"GENERIC", 16}, MemberSpec{"SCSITRANSPORT", 18},
    MemberSpec{"ECRYPTFS", 19}, MemberSpec{"RDMA", 20},
    MemberSpec{"CRYPTO", 21}, MemberSpec{"SMC", 22},
};

constexpr std::array kSeccompModes = {
    MemberSpec{"STRICT", 1}, MemberSpec{"FILTER", 2},
};

constexpr std::array kSocketOptions = {
    MemberSpec{"DEBUG", 1}, MemberSpec{"REUSEADDR", 2},
    MemberSpec{"TYPE", 3}, MemberSpec{"ERROR", 4},
    MemberSpec{"DONTROUTE", 5}, MemberSpec{"BROADCAST", 6},
    MemberSpec{"SNDBUF", 7}, MemberSpec{"RCVBUF", 8},
    MemberSpec{"KEEPALIVE", 9}, MemberSpec{"OOBINLINE", 10},
    MemberSpec{"NO_CHECK", 11}, MemberSpec{"PRIORITY", 12},
    MemberSpec{"LINGER", 13}, MemberSpec{"REUSEPORT", 15},
    MemberSpec{"RCVLOWAT", 18}, MemberSpec{"SNDLOWAT", 19},
    MemberSpec{"RCVTIMEO", 20}, MemberSpec{"SNDTIMEO", 21},
    MemberSpec{"ACCEPTCONN", 30}, MemberSpec{"PROTOCOL", 38},
    MemberSpec{"DOMAIN", 39}, MemberSpec{"COOKIE", 57},
};

constexpr std::array kTcpOptions = {
    MemberSpec{"NODELAY", 1}, MemberSpec{"MAXSEG", 2},
    MemberSpec{"CORK", 3}, MemberSpec{"KEEPIDLE", 4},
    MemberSpec{"KEEPINTVL", 5}, MemberSpec{"KEEPCNT", 6},
    MemberSpec{"SYNCNT", 7}, MemberSpec{"LINGER2", 8},
    MemberSpec{"DEFER_ACCEPT", 9}, MemberSpec{"WINDOW_CLAMP", 10},
    MemberSpec{"INFO", 11}, MemberSpec{"QUICKACK", 12},
    MemberSpec{"CONGESTION", 13}, MemberSpec{"USER_TIMEOUT", 18},
    MemberSpec{"FASTOPEN", 23}, MemberSpec{"INQ", 36},
};

constexpr std::array kProcessAccess = {
    MemberSpec{"ALL_ACCESS", 65535}, MemberSpec{"CREATE_PROCESS", 128},
    MemberSpec{"CREATE_THREAD", 2}, MemberSpec{"DUP_HANDLE", 64},
    MemberSpec{"QUERY_INFORMATION", 1024},
    MemberSpec{"QUERY_LIMITED_INFORMATION", 4096},
    MemberSpec{"SET_INFORMATION", 512}, MemberSpec{"SET_QUOTA", 256},
    MemberSpec{"SUSPEND_RESUME", 2048}, MemberSpec{"TERMINATE", 1},
    MemberSpec{"VM_OPERATION", 8}, MemberSpec{"VM_READ", 16},
    MemberSpec{"VM_WRITE", 32},
};

constexpr std::array kEnums = {
    EnumSpec{"O_2", kOpenFlags}, EnumSpec{"AF_1", kAddressFamilies},
    EnumSpec{"SOCK_1", kSocketTypes}, EnumSpec{"PROT", kProtectionFlags},
    EnumSpec{"PROT_1", kProtectionFlags}, EnumSpec{"MAP", kMapFlags},
    EnumSpec{"PR", kPrctlOptions}, EnumSpec{"53482", kAccessModes},
    EnumSpec{"31061", kSocketLevels}, EnumSpec{"IPPROTO", kIpProtocols},
    EnumSpec{"NETLINK", kNetlinkProtocols},
    EnumSpec{"SECCOMP_MODE", kSeccompModes}, EnumSpec{"SO", kSocketOptions},
    EnumSpec{"TCP", kTcpOptions}, EnumSpec{"PROCESS", kProcessAccess},
};

constexpr std::array kOpenArgs = {
    ArgumentSpec{"pathname", ""}, ArgumentSpec{"oflag", "O_2"},
    ArgumentSpec{"mode", ""},
};
constexpr std::array kSocketArgs = {
    ArgumentSpec{"domain", "AF_1"}, ArgumentSpec{"type", "SOCK_1"},
    ArgumentSpec{"protocol", ""},
};
constexpr std::array kMmapArgs = {
    ArgumentSpec{"addr", ""}, ArgumentSpec{"length", ""},
    ArgumentSpec{"prot", "PROT"}, ArgumentSpec{"flags", "MAP"},
    ArgumentSpec{"fd", ""}, ArgumentSpec{"offset", ""},
};
constexpr std::array kMprotectArgs = {
    ArgumentSpec{"addr", ""}, ArgumentSpec{"len", ""},
    ArgumentSpec{"prot", "PROT_1"},
};
constexpr std::array kPrctlArgs = {
    ArgumentSpec{"option", "PR"}, ArgumentSpec{"arg2", ""},
    ArgumentSpec{"arg3", ""}, ArgumentSpec{"arg4", ""},
    ArgumentSpec{"arg5", ""},
};
constexpr std::array kAccessArgs = {
    ArgumentSpec{"pathname", ""}, ArgumentSpec{"mode", "53482"},
};
constexpr std::array kSetsockoptArgs = {
    ArgumentSpec{"fd", ""}, ArgumentSpec{"level", "31061"},
    ArgumentSpec{"optname", ""}, ArgumentSpec{"optval", ""},
    ArgumentSpec{"optlen", ""},
};
constexpr std::array kOpenProcessArgs = {
    ArgumentSpec{"dwDesiredAccess", "PROCESS"},
    ArgumentSpec{"bInheritHandle", ""},
};

constexpr std::array kFunctions = {
    FunctionSpec{"open", kOpenArgs}, FunctionSpec{"open64", kOpenArgs},
    FunctionSpec{"socket", kSocketArgs}, FunctionSpec{"mmap", kMmapArgs},
    FunctionSpec{"mmap64", kMmapArgs}, FunctionSpec{"mprotect", kMprotectArgs},
    FunctionSpec{"prctl", kPrctlArgs}, FunctionSpec{"access", kAccessArgs},
    FunctionSpec{"setsockopt", kSetsockoptArgs},
    FunctionSpec{"OpenProcess", kOpenProcessArgs},
};

constexpr std::array kSpecials = {
    SpecialSpec{"socket", 0, 2, 2, "IPPROTO"},
    SpecialSpec{"socket", 0, 16, 2, "NETLINK"},
    SpecialSpec{"prctl", 0, 22, 1, "SECCOMP_MODE"},
    SpecialSpec{"setsockopt", 1, 1, 2, "SO"},
    SpecialSpec{"setsockopt", 1, 6, 2, "TCP"},
};

struct PrototypeSummary {
    std::size_t imports{0};
    std::size_t matched_functions{0};
    std::size_t changed_functions{0};
    std::size_t changed_arguments{0};
    std::size_t ineligible_arguments{0};
    std::size_t recoverable_failures{0};
};

struct CallSummary {
    std::size_t calls_at_cursor{0};
    std::size_t matched_selectors{0};
    std::size_t changed_operands{0};
    std::size_t recoverable_failures{0};
};

template <typename... Args>
std::string format(const char* pattern, Args&&... args) {
    const int required = std::snprintf(nullptr, 0, pattern,
                                       std::forward<Args>(args)...);
    if (required <= 0)
        return {};
    std::string output(static_cast<std::size_t>(required) + 1, '\0');
    std::snprintf(output.data(), output.size(), pattern,
                  std::forward<Args>(args)...);
    output.pop_back();
    return output;
}

std::string error_text(const ida::Error& error) {
    return error.context.empty() ? error.message
                                 : error.message + " (" + error.context + ")";
}

bool numeric_id(std::string_view value) {
    return !value.empty()
        && std::all_of(value.begin(), value.end(),
                       [](unsigned char c) { return std::isdigit(c) != 0; });
}

std::string enum_name(std::string_view id) {
    return "ENUM_" + std::string(id);
}

const EnumSpec* find_enum(std::string_view id) {
    auto found = std::find_if(kEnums.begin(), kEnums.end(),
        [&](const EnumSpec& spec) { return spec.id == id; });
    return found == kEnums.end() ? nullptr : &*found;
}

const FunctionSpec* find_function(std::string_view name) {
    auto found = std::find_if(kFunctions.begin(), kFunctions.end(),
        [&](const FunctionSpec& spec) { return spec.name == name; });
    return found == kFunctions.end() ? nullptr : &*found;
}

std::string normalize_import_name(std::string_view input) {
    std::string name(input);
    if (name.starts_with("__imp_"))
        name.erase(0, 6);
    if (!name.empty() && (name.front() == '.' || name.front() == '_'))
        name.erase(0, 1);
    if (const auto suffix = name.find('@'); suffix != std::string::npos)
        name.erase(suffix);
    return name;
}

ida::Result<ida::type::TypeInfo> ensure_enum(std::string_view id) {
    const std::string name = enum_name(id);
    auto existing = ida::type::TypeInfo::by_name(name);
    if (existing) {
        if (!existing->is_enum())
            return std::unexpected(ida::Error::conflict(
                "Auto Enum name is occupied by a non-enum type", name));
        return existing;
    }
    if (existing.error().category != ida::ErrorCategory::NotFound)
        return std::unexpected(existing.error());

    const EnumSpec* spec = find_enum(id);
    if (spec == nullptr)
        return std::unexpected(ida::Error::not_found("Enum corpus entry not found",
                                                     std::string(id)));

    std::vector<ida::type::EnumMember> members;
    members.reserve(spec->members.size());
    const bool preserve_names = numeric_id(id);
    for (const auto& source : spec->members) {
        std::string member_name;
        if (source.value == 0) {
            member_name = "NULL";
        } else if (preserve_names) {
            member_name = std::string(source.name);
        } else {
            member_name = std::string(id) + "_" + std::string(source.name);
        }
        members.push_back({std::move(member_name), source.value, {}});
    }

    auto created = ida::type::TypeInfo::enum_type(members, 4, false);
    if (!created)
        return std::unexpected(created.error());
    if (auto saved = created->save_as(name); !saved)
        return std::unexpected(saved.error());
    return ida::type::TypeInfo::by_name(name);
}

std::optional<std::size_t> select_argument(
    const ida::type::FunctionDetails& details,
    const ArgumentSpec& wanted,
    std::size_t fallback,
    const std::unordered_set<std::size_t>& used) {
    if (!wanted.name.empty()) {
        for (std::size_t index = 0; index < details.arguments.size(); ++index) {
            if (!used.contains(index) && details.arguments[index].name == wanted.name)
                return index;
        }
    }
    if (fallback < details.arguments.size() && !used.contains(fallback))
        return fallback;
    return std::nullopt;
}

ida::Result<PrototypeSummary> enrich_import_prototypes() {
    auto modules = ida::database::import_modules();
    if (!modules)
        return std::unexpected(modules.error());

    PrototypeSummary summary;
    for (const auto& module : *modules) {
        for (const auto& symbol : module.symbols) {
            ++summary.imports;
            const FunctionSpec* spec = find_function(normalize_import_name(symbol.name));
            if (spec == nullptr)
                continue;
            ++summary.matched_functions;

            auto original = ida::type::retrieve(symbol.address);
            if (!original) {
                ++summary.recoverable_failures;
                continue;
            }
            auto details = original->function_details();
            if (!details) {
                ++summary.recoverable_failures;
                continue;
            }

            ida::type::TypeInfo updated = *original;
            std::unordered_set<std::size_t> used;
            std::size_t changed_here = 0;
            for (std::size_t position = 0; position < spec->arguments.size(); ++position) {
                const auto& wanted = spec->arguments[position];
                if (wanted.enum_id.empty())
                    continue;
                const auto selected = select_argument(*details, wanted, position, used);
                if (!selected) {
                    ++summary.recoverable_failures;
                    continue;
                }
                used.insert(*selected);
                const auto& current = details->arguments[*selected].type;
                if (!current.is_integer() || current.is_enum() || current.is_pointer()) {
                    ++summary.ineligible_arguments;
                    continue;
                }

                auto replacement = ensure_enum(wanted.enum_id);
                if (!replacement) {
                    ++summary.recoverable_failures;
                    continue;
                }
                auto next = updated.with_function_argument_type(*selected, *replacement);
                if (!next) {
                    ++summary.recoverable_failures;
                    continue;
                }
                updated = std::move(*next);
                ++changed_here;
            }

            if (changed_here == 0)
                continue;
            if (auto applied = updated.apply(symbol.address); !applied) {
                ++summary.recoverable_failures;
                continue;
            }
            ++summary.changed_functions;
            summary.changed_arguments += changed_here;
        }
    }
    return summary;
}

std::optional<std::uint64_t> numeric_value(ida::decompiler::ExpressionView expr) {
    if (expr.type() == ida::decompiler::ItemType::ExprNumber) {
        auto value = expr.number_value();
        if (value)
            return *value;
    }
    if (expr.type() == ida::decompiler::ItemType::ExprCast) {
        auto inner = expr.left();
        if (inner && inner->type() == ida::decompiler::ItemType::ExprNumber) {
            auto value = inner->number_value();
            if (value)
                return *value;
        }
    }
    return std::nullopt;
}

std::string call_name(ida::decompiler::ExpressionView call) {
    auto callee = call.call_callee();
    if (!callee)
        return {};
    for (int depth = 0; depth < 4; ++depth) {
        if (callee->type() != ida::decompiler::ItemType::ExprCast
            && callee->type() != ida::decompiler::ItemType::ExprDeref
            && callee->type() != ida::decompiler::ItemType::ExprRef) {
            break;
        }
        auto inner = callee->left();
        if (!inner)
            break;
        callee = std::move(inner);
    }
    if (callee->type() == ida::decompiler::ItemType::ExprObject) {
        auto address = callee->object_address();
        if (address) {
            auto name = ida::name::get(*address);
            if (name)
                return normalize_import_name(*name);
        }
    }
    if (callee->type() == ida::decompiler::ItemType::ExprHelper) {
        auto name = callee->helper_name();
        if (name)
            return normalize_import_name(*name);
    }
    return {};
}

ida::Result<CallSummary> annotate_call_at_cursor(ida::Address cursor) {
    auto containing = ida::function::at(cursor);
    if (!containing)
        return std::unexpected(containing.error());
    auto decompiled = ida::decompiler::decompile(containing->start());
    if (!decompiled)
        return std::unexpected(decompiled.error());

    CallSummary summary;
    auto visited = ida::decompiler::for_each_expression(
        *decompiled,
        [&](ida::decompiler::ExpressionView expression) {
            if (expression.type() != ida::decompiler::ItemType::ExprCall
                || expression.address() != cursor) {
                return ida::decompiler::VisitAction::Continue;
            }
            ++summary.calls_at_cursor;
            const std::string function_name = call_name(expression);
            auto argument_count = expression.call_argument_count();
            if (!argument_count) {
                ++summary.recoverable_failures;
                return ida::decompiler::VisitAction::Continue;
            }

            for (const auto& special : kSpecials) {
                if (special.function_name != function_name
                    || special.selector_index >= *argument_count
                    || special.target_index >= *argument_count) {
                    continue;
                }
                auto selector = expression.call_argument(special.selector_index);
                if (!selector || numeric_value(*selector) != special.selector_value)
                    continue;
                ++summary.matched_selectors;

                auto target = expression.call_argument(special.target_index);
                auto enumeration = ensure_enum(special.enum_id);
                if (!target || !enumeration
                    || target->address() == ida::BadAddress) {
                    ++summary.recoverable_failures;
                    continue;
                }
                auto applied = ida::instruction::set_operand_enum(
                    target->address(), -1, enum_name(special.enum_id));
                if (!applied) {
                    ++summary.recoverable_failures;
                    continue;
                }
                ++summary.changed_operands;
            }
            return ida::decompiler::VisitAction::Continue;
        });
    if (!visited)
        return std::unexpected(visited.error());
    if (summary.changed_operands > 0) {
        (void)decompiled->refresh();
        ida::ui::refresh_all_views();
    }
    return summary;
}

ida::Status run_prototype_action() {
    auto summary = enrich_import_prototypes();
    if (!summary)
        return std::unexpected(summary.error());
    if (summary->changed_functions > 0)
        ida::ui::refresh_all_views();
    const std::string report = format(
        "Auto Enum prototype enrichment complete\n"
        "Imports scanned: %zu\nMatched functions: %zu\n"
        "Changed functions: %zu\nChanged arguments: %zu\n"
        "Ineligible arguments: %zu\nRecoverable failures: %zu",
        summary->imports, summary->matched_functions,
        summary->changed_functions, summary->changed_arguments,
        summary->ineligible_arguments, summary->recoverable_failures);
    ida::ui::message("[auto-enum:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

ida::Status run_call_action() {
    auto cursor = ida::ui::screen_address();
    if (!cursor)
        return std::unexpected(cursor.error());
    auto summary = annotate_call_at_cursor(*cursor);
    if (!summary)
        return std::unexpected(summary.error());
    const std::string report = format(
        "Auto Enum call annotation complete\n"
        "Calls at cursor: %zu\nMatched selectors: %zu\n"
        "Changed operands: %zu\nRecoverable failures: %zu",
        summary->calls_at_cursor, summary->matched_selectors,
        summary->changed_operands, summary->recoverable_failures);
    ida::ui::message("[auto-enum:idax] " + report + "\n");
    ida::ui::info(report);
    return ida::ok();
}

class AutoEnumPortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "Auto Enum Port",
            .hotkey = "Ctrl-Alt-Shift-E",
            .comment = "Enrich imported prototypes and selector-dependent call operands with enums",
            .help = "Ports Auto Enum's import prototype and per-call enum workflows using opaque idax types.",
        };
    }

    bool init() override {
        if (!register_action(kPrototypeAction,
                             "Auto Enum: Enrich Imported Prototypes",
                             "Apply corpus-backed enum types to imported function arguments",
                             [] { return run_prototype_action(); })) {
            return false;
        }
        if (!register_action(kCallAction,
                             "Auto Enum: Annotate Call at Cursor",
                             "Apply selector-dependent enum display to a call operand",
                             [] { return run_call_action(); })) {
            unregister_all();
            return false;
        }
        return true;
    }

    ida::Status run(std::size_t) override { return run_prototype_action(); }

    ~AutoEnumPortPlugin() override { unregister_all(); }

private:
    bool register_action(
        std::string_view id,
        std::string_view label,
        std::string_view tooltip,
        std::function<ida::Status()> handler) {
        ida::plugin::Action action;
        action.id = std::string(id);
        action.label = std::string(label);
        action.tooltip = std::string(tooltip);
        action.handler = std::move(handler);
        action.enabled = [] { return true; };
        if (!ida::plugin::register_action(action))
            return false;
        if (!ida::plugin::attach_to_menu(kMenuPath, id)) {
            (void)ida::plugin::unregister_action(id);
            return false;
        }
        registered_.emplace_back(id);
        return true;
    }

    void unregister_all() {
        for (auto it = registered_.rbegin(); it != registered_.rend(); ++it) {
            (void)ida::plugin::detach_from_menu(kMenuPath, *it);
            (void)ida::plugin::unregister_action(*it);
        }
        registered_.clear();
    }

    std::vector<std::string> registered_;
};

} // namespace

IDAX_PLUGIN(AutoEnumPortPlugin)
