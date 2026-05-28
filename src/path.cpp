/// \file path.cpp
/// \brief Portable path helper implementation.

#include <ida/path.hpp>

#include <filesystem>
#include <system_error>

namespace ida::path {

std::string basename(std::string_view path_text) {
    std::filesystem::path p{std::string(path_text)};
    return p.filename().string();
}

std::string dirname(std::string_view path_text) {
    std::filesystem::path p{std::string(path_text)};
    return p.parent_path().string();
}

bool is_directory(std::string_view path_text) {
    std::error_code ec;
    return std::filesystem::is_directory(std::filesystem::path{std::string(path_text)}, ec);
}

} // namespace ida::path
