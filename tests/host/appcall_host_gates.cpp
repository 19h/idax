/// Invoke the public Appcall wrapper in an already suspended debugger process.
#include <fstream>
#include <cstdint>
#include <exception>
#include <vector>

#include <ida/debugger.hpp>
#include <ida/name.hpp>
#include <ida/type.hpp>

#ifdef _WIN32
#define IDAX_HOST_EXPORT __declspec(dllexport)
#else
#define IDAX_HOST_EXPORT __attribute__((visibility("default")))
#endif

extern "C" IDAX_HOST_EXPORT int idax_run_appcall_host_gates(const char* log_path) {
    if (log_path == nullptr || log_path[0] == '\0')
        return 2;
    std::ofstream log(log_path, std::ios::trunc);
    if (!log)
        return 2;
    try {
        const auto state = ida::debugger::state();
        const auto backend = ida::debugger::current_backend();
        if (!state || *state != ida::debugger::ProcessState::Suspended
            || !backend || !backend->supports_appcall) {
            log << "FAIL: a suspended Appcall-capable debugger process is required\n";
            return 1;
        }
        log << "Backend: " << backend->name << "; state=Suspended\n";
        struct Case { const char* name; std::int64_t argument; bool pointer; std::int64_t expected; };
        const Case cases[] = {{"ref4", 0, true, -1}, {"ref1", 41, false, 42},
                              {"ref1", -42, false, -41}, {"ref3", 38, false, 41}};
        std::size_t passed = 0;
        for (const auto& test : cases) {
            auto target = ida::name::resolve(test.name);
            if (!target) {
                log << "FAIL: unresolved fixture symbol " << test.name << '\n';
                return 1;
            }
            std::vector<ida::type::TypeInfo> types;
            types.push_back(test.pointer
                ? ida::type::TypeInfo::pointer_to(ida::type::TypeInfo::int32())
                : ida::type::TypeInfo::int32());
            auto type = ida::type::TypeInfo::function_type(ida::type::TypeInfo::int32(), types);
            if (!type) {
                log << "FAIL: function type " << type.error().message << '\n';
                return 1;
            }
            ida::debugger::AppcallRequest request;
            request.function_address = *target;
            request.function_type = *type;
            request.options.timeout_milliseconds = 5000;
            ida::debugger::AppcallValue value;
            if (test.pointer) {
                value.kind = ida::debugger::AppcallValueKind::Address;
                value.address_value = 0;
            } else {
                value.kind = ida::debugger::AppcallValueKind::SignedInteger;
                value.signed_value = test.argument;
            }
            request.arguments.push_back(value);
            const auto result = ida::debugger::appcall(request);
            if (!result) {
                log << "FAIL: " << test.name << ": " << result.error().message
                    << "; " << result.error().context << '\n';
                return 1;
            }
            const auto& returned = result->return_value;
            if (returned.kind != ida::debugger::AppcallValueKind::SignedInteger
                || returned.signed_value != test.expected) {
                log << "FAIL: " << test.name << ": kind=" << static_cast<int>(returned.kind)
                    << "; signed=" << returned.signed_value << "; expected=" << test.expected << '\n';
                return 1;
            }
            log << "PASS: " << test.name << '(' << test.argument << ") = "
                << returned.signed_value << '\n';
            ++passed;
        }
        log << "appcall_host_gates: " << passed << " passed, 0 failed, 0 skipped\n";
    } catch (const std::exception& error) {
        log << "FAIL: exception: " << error.what() << '\n';
        return 1;
    } catch (...) {
        log << "FAIL: unknown exception\n";
        return 1;
    }
    log.flush();
    return log ? 0 : 2;
}
