/// \file idalib_lumina_port.cpp
/// \brief idax-first scaffold for `idalib-dump` `ida_lumina` parity.
///
/// The original `ida_lumina` utility depends on Lumina client calls that do not
/// yet exist in the public idax API surface. This scaffold keeps the headless
/// session setup in idax style and reports the missing capability explicitly.

#include <ida/idax.hpp>

#include <cstdlib>
#include <iostream>
#include <string>

namespace {

class DatabaseSession {
public:
    ida::Status open(std::string_view input_path) {
        if (auto init_status = ida::database::init(); !init_status) {
            return std::unexpected(init_status.error());
        }
        if (auto open_status = ida::database::open(input_path, ida::database::OpenMode::Analyze);
            !open_status) {
            return std::unexpected(open_status.error());
        }
        is_open_ = true;
        if (auto wait_status = ida::analysis::wait(); !wait_status) {
            return std::unexpected(wait_status.error());
        }
        return ida::ok();
    }

    ~DatabaseSession() {
        if (is_open_) {
            ida::database::close(false);
        }
    }

private:
    bool is_open_{false};
};

std::string error_text(const ida::Error& error) {
    if (error.context.empty()) {
        return error.message;
    }
    return error.message + " (" + error.context + ")";
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary_file>\n";
        return EXIT_FAILURE;
    }

    DatabaseSession session;
    if (auto open_status = session.open(argv[1]); !open_status) {
        std::cerr << "failed to initialize analysis session: "
                  << error_text(open_status.error()) << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "[gap] idax does not yet expose Lumina push/query APIs.\n";
    std::cout << "      Porting ida_lumina requires a public ida::lumina facade.\n";
    return EXIT_FAILURE;
}
