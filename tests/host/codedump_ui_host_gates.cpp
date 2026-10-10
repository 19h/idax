/// Interactive-host adapter for the existing native modal/clipboard assertions.

#include <fstream>
#include <iostream>
#include <streambuf>

#include <ida/ui.hpp>

int run_codedump_parity_host_gates(int argc, char** argv, bool interactive_host);

namespace {
class EvidenceStream {
public:
    explicit EvidenceStream(std::ostream& stream, std::streambuf* output)
        : stream_(stream), previous_(stream.rdbuf(output)) {}
    ~EvidenceStream() { stream_.rdbuf(previous_); }
private:
    std::ostream& stream_;
    std::streambuf* previous_;
};
}

#ifdef _WIN32
#define IDAX_HOST_EXPORT __declspec(dllexport)
#else
#define IDAX_HOST_EXPORT __attribute__((visibility("default")))
#endif

extern "C" IDAX_HOST_EXPORT int idax_run_codedump_ui_host_gates(const char* log_path) {
    if (log_path == nullptr || log_path[0] == '\0')
        return 2;
    std::ofstream log(log_path, std::ios::trunc);
    if (!log)
        return 2;
    EvidenceStream out(std::cout, log.rdbuf());
    EvidenceStream errors(std::cerr, log.rdbuf());
    std::cout << "Interactive IDA host; clipboard backend="
              << ida::ui::clipboard_backend() << '\n';
    const int status = run_codedump_parity_host_gates(0, nullptr, true);
    log.flush();
    return log ? status : 2;
}
