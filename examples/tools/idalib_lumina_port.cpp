/// \file idalib_lumina_port.cpp
/// \brief idax-first scaffold for `idalib-dump` `ida_lumina` workflows.

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

    auto main_address = ida::name::resolve("main");
    if (!main_address) {
        std::cerr << "could not resolve function address for 'main': "
                  << error_text(main_address.error()) << "\n";
        return EXIT_FAILURE;
    }

    auto pull_result = ida::lumina::pull(*main_address);
    if (!pull_result) {
        std::cerr << "Lumina pull failed: "
                  << error_text(pull_result.error()) << "\n";
        return EXIT_FAILURE;
    }

    auto push_result = ida::lumina::push(*main_address);
    if (!push_result) {
        std::cerr << "Lumina push failed: "
                  << error_text(push_result.error()) << "\n";
        return EXIT_FAILURE;
    }

    std::cout << "pull: requested=" << pull_result->requested
              << " succeeded=" << pull_result->succeeded
              << " failed=" << pull_result->failed << "\n";
    std::cout << "push: requested=" << push_result->requested
              << " succeeded=" << push_result->succeeded
              << " failed=" << push_result->failed << "\n";
    return EXIT_SUCCESS;
}
