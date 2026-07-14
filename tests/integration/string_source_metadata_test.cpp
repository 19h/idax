/// \file string_source_metadata_test.cpp
/// \brief Exact real-IDA coverage for string-list and source-file metadata.

#include <ida/idax.hpp>
#include "../test_harness.hpp"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string>

namespace {

struct StringOptionsRestore {
    ida::data::StringListOptions options;

    ~StringOptionsRestore() {
        (void)ida::data::configure_string_list(options);
    }
};

struct TemporaryFixture {
    std::filesystem::path directory;
    std::filesystem::path binary;

    ~TemporaryFixture() {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
    }
};

void copy_fixture(const std::filesystem::path& source,
                  TemporaryFixture& fixture) {
    const auto nonce = std::chrono::steady_clock::now()
        .time_since_epoch().count();
    fixture.directory = std::filesystem::temp_directory_path()
        / ("idax_string_source_metadata_" + std::to_string(nonce));
    std::filesystem::create_directories(fixture.directory);
    fixture.binary = fixture.directory / source.filename();
    std::filesystem::copy_file(source, fixture.binary,
                               std::filesystem::copy_options::overwrite_existing);
}

void test_string_list_contract() {
    SECTION("data: configured string-list snapshot");

    auto original = ida::data::string_list_options();
    CHECK_OK(original);
    if (!original)
        return;
    StringOptionsRestore restore{*original};

    ida::data::StringListOptions invalid;
    invalid.string_types.clear();
    CHECK_ERR(ida::data::configure_string_list(invalid),
              ida::ErrorCategory::Validation);
    invalid.string_types = {-1};
    CHECK_ERR(ida::data::configure_string_list(invalid),
              ida::ErrorCategory::Validation);
    invalid.string_types = {256};
    CHECK_ERR(ida::data::configure_string_list(invalid),
              ida::ErrorCategory::Validation);
    invalid.string_types = {0};
    invalid.minimum_length = -1;
    CHECK_ERR(ida::data::configure_string_list(invalid),
              ida::ErrorCategory::Validation);

    ida::data::StringListOptions configured;
    configured.string_types = {0, 1};
    configured.minimum_length = 5;
    configured.only_7bit = true;
    configured.ignore_instructions = false;
    configured.display_only_existing_strings = false;
    CHECK_OK(ida::data::configure_string_list(configured));

    auto roundtrip = ida::data::string_list_options();
    CHECK_OK(roundtrip);
    if (roundtrip) {
        CHECK(roundtrip->string_types == configured.string_types);
        CHECK(roundtrip->minimum_length == configured.minimum_length);
        CHECK(roundtrip->only_7bit == configured.only_7bit);
        CHECK(roundtrip->ignore_instructions == configured.ignore_instructions);
        CHECK(roundtrip->display_only_existing_strings
              == configured.display_only_existing_strings);
    }

    auto strings = ida::data::string_literals(false);
    CHECK_OK(strings);
    if (strings) {
        CHECK(!strings->empty());
        CHECK(std::all_of(strings->begin(), strings->end(), [](const auto& item) {
            return item.address != ida::BadAddress
                && item.byte_length > 0
                && (item.string_type == 0 || item.string_type == 1)
                && !item.text.empty();
        }));
        const auto known = std::find_if(strings->begin(), strings->end(),
            [](const auto& item) {
                return item.text.find("ref4: entered with %d") != std::string::npos;
            });
        CHECK(known != strings->end());
        if (known != strings->end()) {
            CHECK(known->string_type == 0);
            CHECK(known->byte_length >= known->text.size());
        }
    }

    CHECK_OK(ida::data::rebuild_string_list());
    CHECK_OK(ida::data::clear_string_list());
}

void test_source_file_contract() {
    SECTION("lines: source-file range lifecycle");

    auto last = ida::segment::last();
    CHECK_OK(last);
    if (!last)
        return;
    constexpr ida::Address kAlignment = 0x10000;
    constexpr ida::AddressSize kSegmentSize = 0x1000;
    if (last->end() > ida::BadAddress - (2 * kAlignment)) {
        CHECK(false);
        return;
    }
    const ida::Address base = (last->end() + kAlignment - 1)
        & ~(kAlignment - 1);
    auto created = ida::segment::create(base, base + kSegmentSize,
                                         "__idax_source_metadata", "DATA",
                                         ida::segment::Type::Data);
    CHECK_OK(created);
    if (!created)
        return;

    struct Cleanup {
        ida::Address base;
        ~Cleanup() {
            (void)ida::lines::remove_source_file(base + 0x120);
            (void)ida::segment::remove(base);
        }
    } cleanup{base};

    CHECK_ERR(ida::lines::add_source_file({}, "source.cpp"),
              ida::ErrorCategory::Validation);
    CHECK_ERR(ida::lines::add_source_file({base + 0x100, base + 0x180}, ""),
              ida::ErrorCategory::Validation);
    CHECK_ERR(ida::lines::source_file_at(ida::BadAddress),
              ida::ErrorCategory::Validation);
    CHECK_ERR(ida::lines::remove_source_file(ida::BadAddress),
              ida::ErrorCategory::Validation);

    const ida::address::Range expected{base + 0x100, base + 0x180};
    CHECK_OK(ida::lines::add_source_file(expected,
                                         "/src/network/transport.cpp"));

    auto source = ida::lines::source_file_at(base + 0x120);
    CHECK_OK(source);
    if (source) {
        CHECK(source->filename == "/src/network/transport.cpp");
        CHECK(source->range.start == expected.start);
        CHECK(source->range.end == expected.end);
        CHECK(source->range.contains(base + 0x120));
    }
    CHECK_ERR(ida::lines::source_file_at(base + 0x180),
              ida::ErrorCategory::NotFound);

    CHECK_OK(ida::lines::remove_source_file(base + 0x120));
    CHECK_ERR(ida::lines::source_file_at(base + 0x120),
              ida::ErrorCategory::NotFound);
    CHECK_ERR(ida::lines::remove_source_file(base + 0x120),
              ida::ErrorCategory::NotFound);
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: string_source_metadata_test <binary>\n";
        return 2;
    }
    TemporaryFixture fixture;
    try {
        copy_fixture(argv[1], fixture);
    } catch (const std::filesystem::filesystem_error& error) {
        std::cerr << "fixture copy failed: " << error.what() << "\n";
        return 2;
    }

    char* init_args[] = {argv[0]};
    auto initialized = ida::database::init(1, init_args);
    if (!initialized) {
        std::cerr << "database init failed: " << initialized.error().message << "\n";
        return 2;
    }
    auto opened = ida::database::open(fixture.binary.string(), true);
    if (!opened) {
        std::cerr << "database open failed: " << opened.error().message << "\n";
        return 2;
    }

    test_string_list_contract();
    test_source_file_contract();

    auto closed = ida::database::close(false);
    CHECK_OK(closed);
    return idax_test::report("string_source_metadata_test");
}
