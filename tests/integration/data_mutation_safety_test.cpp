/// \file data_mutation_safety_test.cpp
/// \brief Integration checks for ida::data mutation safety behavior.

#include <ida/idax.hpp>

#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

#define CHECK(expr)                                                       \
    do {                                                                  \
        if (expr) {                                                       \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " (" << __FILE__ << ":"       \
                      << __LINE__ << ")\n";                             \
        }                                                                 \
    } while (false)

#define CHECK_OK(expr)                                                    \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (_r.has_value()) {                                             \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => error: "                   \
                      << _r.error().message << " (" << __FILE__         \
                      << ":" << __LINE__ << ")\n";                     \
        }                                                                 \
    } while (false)

#define CHECK_ERR(expr, category_value)                                  \
    do {                                                                  \
        auto _r = (expr);                                                 \
        if (!_r.has_value()                                               \
            && _r.error().category == (category_value)) {                 \
            ++g_pass;                                                     \
        } else {                                                          \
            ++g_fail;                                                     \
            std::cerr << "FAIL: " #expr " => expected error category "  \
                      << static_cast<int>(category_value) << " ("         \
                      << __FILE__ << ":" << __LINE__ << ")\n";          \
        }                                                                 \
    } while (false)

void test_patch_and_original(ida::Address ea) {
    std::cout << "--- patch/original semantics ---\n";

    auto original = ida::data::read_byte(ea);
    CHECK_OK(original);
    if (!original)
        return;

    const std::uint8_t patched =
        (*original == 0xFFu) ? 0x00u : static_cast<std::uint8_t>(*original + 1u);

    CHECK_OK(ida::data::patch_byte(ea, patched));

    auto after_patch = ida::data::read_byte(ea);
    CHECK_OK(after_patch);
    if (after_patch)
        CHECK(*after_patch == patched);

    auto preserved_original = ida::data::original_byte(ea);
    CHECK_OK(preserved_original);
    if (preserved_original)
        CHECK(*preserved_original == *original);

    CHECK_OK(ida::data::revert_patch(ea));

    auto after_restore = ida::data::read_byte(ea);
    CHECK_OK(after_restore);
    if (after_restore)
        CHECK(*after_restore == *original);

    auto second_revert = ida::data::revert_patch(ea);
    CHECK(!second_revert.has_value());
    if (!second_revert)
        CHECK(second_revert.error().category == ida::ErrorCategory::NotFound);
}

void test_write_roundtrip(ida::Address ea) {
    std::cout << "--- write roundtrip ---\n";

    auto original = ida::data::read_bytes(ea, 4);
    CHECK_OK(original);
    if (!original || original->size() != 4)
        return;

    std::vector<std::uint8_t> mutated = *original;
    for (auto& b : mutated)
        b ^= 0x5Au;

    if (mutated == *original)
        mutated[0] ^= 0x01u;

    CHECK_OK(ida::data::write_bytes(ea, mutated));

    auto read_mutated = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_mutated);
    if (read_mutated)
        CHECK(*read_mutated == mutated);

    CHECK_OK(ida::data::write_bytes(ea, *original));

    auto read_restored = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_restored);
    if (read_restored)
        CHECK(*read_restored == *original);
}

void test_typed_value_facade(ida::Address ea) {
    std::cout << "--- typed value facade ---\n";

    auto i32 = ida::type::TypeInfo::int32();
    auto read_i32 = ida::data::read_typed(ea, i32);
    CHECK_OK(read_i32);
    if (read_i32) {
        CHECK(read_i32->kind == ida::data::TypedValueKind::SignedInteger
              || read_i32->kind == ida::data::TypedValueKind::UnsignedInteger);
    }

    auto byte_array = ida::type::TypeInfo::array_of(ida::type::TypeInfo::uint8(), 4);
    auto typed_bytes = ida::data::read_typed(ea, byte_array);
    CHECK_OK(typed_bytes);
    if (typed_bytes) {
        CHECK(typed_bytes->kind == ida::data::TypedValueKind::Bytes);
        if (typed_bytes->kind == ida::data::TypedValueKind::Bytes)
            CHECK(typed_bytes->bytes.size() == 4);
    }

    auto original = ida::data::read_bytes(ea, 4);
    CHECK_OK(original);
    if (!original || original->size() != 4)
        return;

    ida::data::TypedValue mutated;
    mutated.kind = ida::data::TypedValueKind::Bytes;
    mutated.bytes = *original;
    for (auto& b : mutated.bytes)
        b ^= 0xA5u;

    if (mutated.bytes == *original)
        mutated.bytes[0] ^= 0x01u;

    CHECK_OK(ida::data::write_typed(ea, byte_array, mutated));

    auto read_mutated = ida::data::read_bytes(ea, 4);
    CHECK_OK(read_mutated);
    if (read_mutated)
        CHECK(*read_mutated == mutated.bytes);

    CHECK_OK(ida::data::write_bytes(ea, *original));

    ida::data::TypedValue wrong_size;
    wrong_size.kind = ida::data::TypedValueKind::Bytes;
    wrong_size.bytes = {0x41, 0x42};
    auto mismatch = ida::data::write_typed(ea, byte_array, wrong_size);
    CHECK(!mismatch.has_value());
    if (!mismatch)
        CHECK(mismatch.error().category == ida::ErrorCategory::Validation);
}

void test_define_undefine_unknown() {
    std::cout << "--- define/undefine unknown ---\n";

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (!lo)
        return;

    auto hi = ida::database::max_address();
    CHECK_OK(hi);
    if (!hi)
        return;

    auto unknown = ida::search::next_unknown(*lo);
    if (!unknown) {
        CHECK(unknown.error().category == ida::ErrorCategory::NotFound);
        std::cout << "  (no unknown bytes found in fixture; skipping mutation check)\n";
        return;
    }

    CHECK_OK(ida::data::define_byte(*unknown, 1));
    CHECK(ida::address::is_data(*unknown));

    CHECK_OK(ida::data::undefine(*unknown, 1));
    CHECK(ida::address::is_unknown(*unknown));

    if (*unknown + 4 < *hi) {
        auto make_float = ida::data::define_float(*unknown, 1);
        if (!make_float) {
            CHECK(make_float.error().category == ida::ErrorCategory::SdkFailure);
            std::cout << "  (define_float unsupported at selected address; skipping)\n";
        } else {
            CHECK_OK(make_float);
            auto size = ida::address::item_size(*unknown);
            CHECK_OK(size);
            if (size)
                CHECK_OK(ida::data::undefine(*unknown, *size));
        }
    }

    if (*unknown + 8 < *hi) {
        auto make_double = ida::data::define_double(*unknown, 1);
        if (!make_double) {
            CHECK(make_double.error().category == ida::ErrorCategory::SdkFailure);
            std::cout << "  (define_double unsupported at selected address; skipping)\n";
        } else {
            CHECK_OK(make_double);
            auto size = ida::address::item_size(*unknown);
            CHECK_OK(size);
            if (size)
                CHECK_OK(ida::data::undefine(*unknown, *size));
        }
    }
}

void test_element_definition_units() {
    std::cout << "--- data-definition element counts ---\n";

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
                                        "__idax_data_units", "DATA",
                                        ida::segment::Type::Data);
    CHECK_OK(created);
    if (!created)
        return;

    const auto check_default = [&](ida::AddressSize width, auto define) {
        auto status = define();
        CHECK_OK(status);
        if (!status)
            return;
        auto size = ida::address::item_size(base);
        CHECK_OK(size);
        if (size)
            CHECK(*size == width);
        CHECK_OK(ida::data::undefine(base, width));
    };

    check_default(1,  [&] { return ida::data::define_byte(base); });
    check_default(2,  [&] { return ida::data::define_word(base); });
    check_default(4,  [&] { return ida::data::define_dword(base); });
    check_default(8,  [&] { return ida::data::define_qword(base); });
    check_default(16, [&] { return ida::data::define_oword(base); });
    check_default(32, [&] { return ida::data::define_yword(base); });
    check_default(64, [&] { return ida::data::define_zword(base); });
    check_default(4,  [&] { return ida::data::define_float(base); });
    check_default(8,  [&] { return ida::data::define_double(base); });

    using DefineFunction = ida::Status (*)(ida::Address, ida::AddressSize);
    struct Definition {
        ida::AddressSize width;
        DefineFunction define;
    };
    std::vector<Definition> definitions{
        {1, &ida::data::define_byte},
        {2, &ida::data::define_word},
        {4, &ida::data::define_dword},
        {8, &ida::data::define_qword},
        {16, &ida::data::define_oword},
        {32, &ida::data::define_yword},
        {64, &ida::data::define_zword},
        {4, &ida::data::define_float},
        {8, &ida::data::define_double},
    };

    const auto check_extended_real = [&](const auto& size,
                                         DefineFunction define) {
        if (size) {
            check_default(*size, [&] { return define(base, 1); });
            definitions.push_back({*size, define});
            return;
        }
        CHECK(size.error().category == ida::ErrorCategory::Unsupported);
        auto unavailable = define(base, 1);
        CHECK(!unavailable.has_value());
        if (!unavailable) {
            CHECK(unavailable.error().category
                  == ida::ErrorCategory::Unsupported);
        }
    };

    check_extended_real(ida::data::tbyte_element_size(),
                        &ida::data::define_tbyte);
    check_extended_real(ida::data::packed_real_element_size(),
                        &ida::data::define_packed_real);

    constexpr ida::AddressSize kElementCount = 3;
    for (const auto& definition : definitions) {
        auto status = definition.define(base, kElementCount);
        CHECK_OK(status);
        if (!status)
            continue;
        const ida::AddressSize expected = definition.width * kElementCount;
        auto size = ida::address::item_size(base);
        CHECK_OK(size);
        if (size)
            CHECK(*size == expected);
        // `undefine` remains byte-count based.
        CHECK_OK(ida::data::undefine(base, expected));
    }

    auto zero = ida::data::define_dword(base, 0);
    CHECK(!zero.has_value());
    if (!zero)
        CHECK(zero.error().category == ida::ErrorCategory::Validation);

    for (const auto define : {&ida::data::define_tbyte,
                              &ida::data::define_packed_real}) {
        auto extended_zero = define(base, 0);
        CHECK(!extended_zero.has_value());
        if (!extended_zero) {
            CHECK(extended_zero.error().category
                  == ida::ErrorCategory::Validation);
        }
    }

    const auto overflowing_count =
        std::numeric_limits<ida::AddressSize>::max() / 64 + 1;
    auto multiplication_overflow =
        ida::data::define_zword(base, overflowing_count);
    CHECK(!multiplication_overflow.has_value());
    if (!multiplication_overflow) {
        CHECK(multiplication_overflow.error().category
              == ida::ErrorCategory::Validation);
    }

    auto range_overflow = ida::data::define_word(ida::BadAddress - 1, 1);
    CHECK(!range_overflow.has_value());
    if (!range_overflow)
        CHECK(range_overflow.error().category == ida::ErrorCategory::Validation);

    CHECK_OK(ida::segment::remove(base));
}

void test_custom_data_lifecycle() {
    std::cout << "--- custom data type/format lifecycle ---\n";

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
                                        "__idax_custom_data", "DATA",
                                        ida::segment::Type::Data);
    CHECK_OK(created);
    if (!created)
        return;

    struct Cleanup {
        ida::Address segment_start;
        ida::data::CustomDataTypeId fixed_type;
        ida::data::CustomDataTypeId variable_type;
        ida::data::CustomDataFormatId format;
        ~Cleanup() {
            if (fixed_type.value != 0)
                (void)ida::data::unregister_custom_data_type(fixed_type);
            if (variable_type.value != 0)
                (void)ida::data::unregister_custom_data_type(variable_type);
            if (format.value != 0)
                (void)ida::data::unregister_custom_data_format(format);
            (void)ida::segment::remove(segment_start);
        }
    } cleanup{base};

    int creation_filter_calls = 0;
    int size_callback_calls = 0;
    int render_calls = 0;
    int scan_calls = 0;
    int analyze_calls = 0;

    ida::data::CustomDataTypeDefinition fixed_definition;
    fixed_definition.name = "idax_p31_fixed_u16";
    fixed_definition.menu_name = "idax P31 fixed u16";
    fixed_definition.assembler_keyword = "p31_u16";
    fixed_definition.value_size = 2;
    fixed_definition.allow_duplicates = false;
    fixed_definition.may_create_at =
        [&](ida::Address address, ida::AddressSize byte_length) {
            ++creation_filter_calls;
            return address == base && byte_length == 2;
        };
    auto fixed_type = ida::data::register_custom_data_type(fixed_definition);
    CHECK_OK(fixed_type);
    if (!fixed_type)
        return;
    cleanup.fixed_type = *fixed_type;

    CHECK_ERR(ida::data::register_custom_data_type(fixed_definition),
              ida::ErrorCategory::Conflict);

    ida::data::CustomDataFormatDefinition format_definition;
    format_definition.name = "idax_p31_u16_format";
    format_definition.menu_name = "idax P31 u16 format";
    format_definition.value_size = 0;
    format_definition.text_width = 12;
    format_definition.render =
        [&](std::span<const std::uint8_t> value,
            const ida::data::CustomDataFormatContext& context)
            -> ida::Result<std::string> {
            ++render_calls;
            if (value.size() != 2)
                return std::unexpected(ida::Error::validation("expected two bytes"));
            return std::string("u16:") + std::to_string(
                static_cast<unsigned>(value[0])
                | (static_cast<unsigned>(value[1]) << 8))
                + "@" + std::to_string(context.address);
        };
    format_definition.scan =
        [&](std::string_view text,
            const ida::data::CustomDataFormatContext&)
            -> ida::Result<std::vector<std::uint8_t>> {
            ++scan_calls;
            if (text != "4660") {
                return std::unexpected(ida::Error::validation(
                    "expected decimal 4660"));
            }
            return std::vector<std::uint8_t>{0x34, 0x12};
        };
    format_definition.analyze =
        [&](const ida::data::CustomDataFormatContext& context) {
            CHECK(context.address == base);
            ++analyze_calls;
        };
    auto format = ida::data::register_custom_data_format(format_definition);
    CHECK_OK(format);
    if (!format)
        return;
    cleanup.format = *format;

    auto found_type = ida::data::find_custom_data_type(fixed_definition.name);
    CHECK_OK(found_type);
    if (found_type)
        CHECK(*found_type == *fixed_type);
    auto found_format = ida::data::find_custom_data_format(format_definition.name);
    CHECK_OK(found_format);
    if (found_format)
        CHECK(*found_format == *format);

    auto type_info = ida::data::custom_data_type(*fixed_type);
    CHECK_OK(type_info);
    if (type_info) {
        CHECK(type_info->name == fixed_definition.name);
        CHECK(type_info->value_size == 2);
        CHECK(!type_info->allow_duplicates);
        CHECK(type_info->visible_in_menu);
        CHECK(type_info->has_creation_filter);
        CHECK(!type_info->variable_size);
    }
    auto format_info = ida::data::custom_data_format(*format);
    CHECK_OK(format_info);
    if (format_info) {
        CHECK(format_info->name == format_definition.name);
        CHECK(format_info->value_size == 0);
        CHECK(format_info->text_width == 12);
        CHECK(format_info->visible_in_menu);
        CHECK(format_info->can_render);
        CHECK(format_info->can_scan);
        CHECK(format_info->can_analyze);
    }

    auto types = ida::data::custom_data_types(2, 2);
    CHECK_OK(types);
    if (types) {
        CHECK(std::any_of(types->begin(), types->end(), [&](const auto& info) {
            return info.id == *fixed_type;
        }));
    }
    CHECK_ERR(ida::data::custom_data_types(3, 2),
              ida::ErrorCategory::Validation);

    CHECK_OK(ida::data::attach_custom_data_format(*fixed_type, *format));
    CHECK_ERR(ida::data::attach_custom_data_format(*fixed_type, *format),
              ida::ErrorCategory::Conflict);
    auto attached = ida::data::is_custom_data_format_attached(
        *fixed_type, *format);
    CHECK_OK(attached);
    if (attached)
        CHECK(*attached);
    auto formats = ida::data::custom_data_formats(*fixed_type);
    CHECK_OK(formats);
    if (formats) {
        CHECK(formats->size() == 1);
        if (!formats->empty())
            CHECK(formats->front().id == *format);
    }

    CHECK_OK(ida::data::attach_custom_data_format_to_standard_types(*format));
    auto standard_attached =
        ida::data::is_custom_data_format_attached_to_standard_types(*format);
    CHECK_OK(standard_attached);
    if (standard_attached)
        CHECK(*standard_attached);
    auto standard_formats = ida::data::standard_custom_data_formats();
    CHECK_OK(standard_formats);
    if (standard_formats) {
        CHECK(std::any_of(standard_formats->begin(), standard_formats->end(),
                          [&](const auto& info) {
            return info.id == *format;
        }));
    }
    CHECK_OK(ida::data::detach_custom_data_format_from_standard_types(*format));
    CHECK_ERR(ida::data::detach_custom_data_format_from_standard_types(*format),
              ida::ErrorCategory::NotFound);

    ida::data::CustomDataFormatContext context;
    context.address = base;
    context.operand_index = -1;
    context.type_id = *fixed_type;
    const std::vector<std::uint8_t> value{0x34, 0x12};
    auto rendered = ida::data::render_custom_data(*format, value, context);
    CHECK_OK(rendered);
    if (rendered)
        CHECK(*rendered == "u16:4660@" + std::to_string(base));
    CHECK(render_calls == 1);
    auto scanned = ida::data::scan_custom_data(*format, "4660", context);
    CHECK_OK(scanned);
    if (scanned)
        CHECK(*scanned == value);
    CHECK(scan_calls == 1);
    CHECK_ERR(ida::data::scan_custom_data(*format, "invalid", context),
              ida::ErrorCategory::SdkFailure);
    CHECK(scan_calls == 2);
    CHECK_OK(ida::data::analyze_custom_data(*format, context));
    CHECK(analyze_calls == 1);

    CHECK_OK(ida::data::define_custom(base, 2, *fixed_type, *format));
    CHECK(creation_filter_calls == 1);
    auto fixed_item = ida::data::custom_data_at(base);
    CHECK_OK(fixed_item);
    if (fixed_item) {
        CHECK(fixed_item->type_id == *fixed_type);
        CHECK(fixed_item->format_id == *format);
        CHECK(fixed_item->byte_length == 2);
    }
    CHECK_OK(ida::data::undefine(base, 2));
    CHECK_ERR(ida::data::custom_data_at(base), ida::ErrorCategory::NotFound);

    auto fixed_size = ida::data::custom_data_item_size(*fixed_type, base, 2);
    CHECK_OK(fixed_size);
    if (fixed_size)
        CHECK(*fixed_size == 2);
    CHECK_ERR(ida::data::custom_data_item_size(*fixed_type, base, 1),
              ida::ErrorCategory::Validation);
    CHECK_OK(ida::data::define_custom_inferred(
        base, *fixed_type, *format, 2));
    CHECK_OK(ida::data::undefine(base, 2));

    ida::data::CustomDataTypeDefinition variable_definition;
    variable_definition.name = "idax_p31_pascal_data";
    variable_definition.value_size = 1;
    variable_definition.calculate_size =
        [&](ida::Address address, ida::AddressSize maximum_size) {
            ++size_callback_calls;
            auto length = ida::data::read_byte(address);
            if (!length)
                return ida::AddressSize{0};
            const ida::AddressSize size = static_cast<ida::AddressSize>(*length) + 1;
            return size <= maximum_size ? size : ida::AddressSize{0};
        };
    auto variable_type =
        ida::data::register_custom_data_type(variable_definition);
    CHECK_OK(variable_type);
    if (!variable_type)
        return;
    cleanup.variable_type = *variable_type;
    CHECK_OK(ida::data::attach_custom_data_format(*variable_type, *format));

    const std::vector<std::uint8_t> pascal{3, 'a', 'b', 'c'};
    CHECK_OK(ida::data::write_bytes(base, pascal));
    auto variable_size = ida::data::custom_data_item_size(
        *variable_type, base, 4);
    CHECK_OK(variable_size);
    if (variable_size)
        CHECK(*variable_size == 4);
    CHECK(size_callback_calls == 1);
    CHECK_ERR(ida::data::custom_data_item_size(*variable_type, base, 3),
              ida::ErrorCategory::SdkFailure);
    CHECK(size_callback_calls == 2);
    const int calls_before_creation = size_callback_calls;
    CHECK_OK(ida::data::define_custom_inferred(
        base, *variable_type, *format, 4));
    CHECK(size_callback_calls > calls_before_creation);
    auto variable_item = ida::data::custom_data_at(base);
    CHECK_OK(variable_item);
    if (variable_item)
        CHECK(variable_item->byte_length == 4);
    CHECK_OK(ida::data::undefine(base, 4));

    CHECK_OK(ida::data::detach_custom_data_format(*fixed_type, *format));
    CHECK_ERR(ida::data::detach_custom_data_format(*fixed_type, *format),
              ida::ErrorCategory::NotFound);
    CHECK_OK(ida::data::attach_custom_data_format(*fixed_type, *format));

    CHECK_OK(ida::data::unregister_custom_data_type(*fixed_type));
    cleanup.fixed_type = {};
    CHECK_ERR(ida::data::find_custom_data_type(fixed_definition.name),
              ida::ErrorCategory::NotFound);
    auto format_survives = ida::data::custom_data_format(*format);
    CHECK_OK(format_survives);

    CHECK_OK(ida::data::unregister_custom_data_type(*variable_type));
    cleanup.variable_type = {};
    CHECK_OK(ida::data::unregister_custom_data_format(*format));
    cleanup.format = {};
    CHECK_ERR(ida::data::find_custom_data_format(format_definition.name),
              ida::ErrorCategory::NotFound);
}

void test_error_paths() {
    std::cout << "--- mutation safety error paths ---\n";

    auto bad_read = ida::data::read_byte(ida::BadAddress);
    CHECK(!bad_read.has_value());
    if (!bad_read)
        CHECK(bad_read.error().category == ida::ErrorCategory::NotFound);

    auto bad_original = ida::data::original_dword(ida::BadAddress);
    CHECK(!bad_original.has_value());
    if (!bad_original)
        CHECK(bad_original.error().category == ida::ErrorCategory::NotFound);

    auto lo = ida::database::min_address();
    auto hi = ida::database::max_address();
    CHECK_OK(lo);
    CHECK_OK(hi);
    if (!lo || !hi)
        return;

    auto empty_pattern = ida::data::find_binary_pattern(*lo, *hi, "");
    CHECK(!empty_pattern.has_value());
    if (!empty_pattern)
        CHECK(empty_pattern.error().category == ida::ErrorCategory::Validation);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <binary>\n";
        return 1;
    }

    auto init = ida::database::init(argc, argv);
    if (!init) {
        std::cerr << "init_library failed: " << init.error().message << "\n";
        return 1;
    }

    auto open = ida::database::open(argv[1], true);
    if (!open) {
        std::cerr << "open_database failed: " << open.error().message << "\n";
        return 1;
    }

    CHECK_OK(ida::analysis::wait());

    auto lo = ida::database::min_address();
    CHECK_OK(lo);
    if (lo) {
        test_patch_and_original(*lo);
        test_write_roundtrip(*lo);
        test_typed_value_facade(*lo);
    }

    test_define_undefine_unknown();
    test_element_definition_units();
    test_custom_data_lifecycle();
    test_error_paths();

    CHECK_OK(ida::database::close(false));

    std::cout << "\n=== Results: " << g_pass << " passed, " << g_fail
              << " failed ===\n";
    return g_fail > 0 ? 1 : 0;
}
