#include "forms.h"
#include "support.hpp"
#include <array>
#include <cstdlib>
#include <cstring>
#include <ida/ui.hpp>
#include <memory>
#include <vector>

namespace {
constexpr size_t maximum_fields = 64;
char* copy_text(const std::string& text) {
    auto* result = static_cast<char*>(std::malloc(text.size() + 1));
    if (!result)
        throw std::bad_alloc();
    std::memcpy(result, text.data(), text.size());
    result[text.size()] = 0;
    return result;
}
void validate_label(const char* text) {
    if (!text)
        throw ida::Error::validation("Missing form label");
    if (std::strpbrk(text, "<>%:#\r\n"))
        throw ida::Error::validation(
            "Form titles, labels and choices cannot contain markup delimiters");
}
std::string markup(const char* title, const IdaxSwiftFormField* fields, size_t count) {
    if (title)
        validate_label(title);
    if (count > maximum_fields)
        throw ida::Error::validation("Form supports at most 64 bound fields");
    if (count && !fields)
        throw ida::Error::validation("Missing form fields");
    std::string result;
    if (title) {
        result.append(title);
        result.append("\n\n");
    }
    for (size_t i = 0; i < count; ++i) {
        const auto& field = fields[i];
        validate_label(field.label);
        if (field.width < 0 || field.visible_width < 0)
            throw ida::Error::validation("Form widths cannot be negative");
        if (field.kind == 1 || field.kind == 2) {
            if (!field.choice_count || !field.choices || field.choice_count > 65535 ||
                (field.kind == 1 && field.choice_count > 16))
                throw ida::Error::validation("Invalid form choice group size");
            std::vector<std::string_view> choices;
            choices.reserve(field.choice_count);
            for (size_t j = 0; j < field.choice_count; ++j) {
                validate_label(field.choices[j]);
                choices.emplace_back(field.choices[j]);
            }
            ida::ui::detail::append_choice_group(result, field.label, field.kind == 1 ? 'C' : 'R',
                                                 choices);
        } else {
            char type;
            switch (field.kind) {
            case 0:
                type = 'D';
                break;
            case 3:
                type = '$';
                break;
            case 4:
                type = 'q';
                break;
            case 5:
                type = 'f';
                break;
            default:
                throw ida::Error::validation("Unknown form field kind");
            }
            ida::ui::detail::append_form_field(
                result, field.label, type,
                field.kind == 5 ? (field.for_saving ? 1 : 0) : field.width, field.visible_width);
        }
    }
    return result;
}
struct Slot {
    sval_t integer{};
    ea_t address{};
    ushort bits{};
    qstring text;
    std::array<char, QMAXPATH> path{};
    void* prepare(const IdaxSwiftFormField& field) {
        switch (field.kind) {
        case 0:
            if (field.integer < static_cast<int64_t>(std::numeric_limits<sval_t>::min()) ||
                field.integer > static_cast<int64_t>(std::numeric_limits<sval_t>::max()))
                throw ida::Error::validation("Form integer is out of SDK range");
            integer = static_cast<sval_t>(field.integer);
            return &integer;
        case 1:
        case 2:
            bits = field.bits;
            return &bits;
        case 3:
            address = static_cast<ea_t>(field.address);
            return &address;
        case 4:
            if (!field.text)
                throw ida::Error::validation("Missing form text");
            text = field.text;
            return &text;
        case 5:
            if (!field.text)
                throw ida::Error::validation("Missing form path");
            {
                size_t size = std::strlen(field.text);
                if (size >= path.size())
                    throw ida::Error::validation("Form path exceeds QMAXPATH");
                std::memcpy(path.data(), field.text, size);
                return path.data();
            }
        default:
            throw ida::Error::validation("Unknown form binding kind");
        }
    }
};
template <size_t... I>
int ask(const char* text, const std::array<void*, maximum_fields>& arguments,
        std::index_sequence<I...>) {
    // The SDK's form decoder consumes pointers to the prepared storage. Extra
    // variadic arguments are unused. No host va_list layout is synthesized.
    return ::ask_form(text, arguments[I]...);
}
} // namespace
extern "C" {
int idax_swift_form_markup(const char* title, const IdaxSwiftFormField* fields, size_t count,
                           char** out, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (out)
            *out = nullptr;
        if (!out)
            return idax::swift::write_error(ida::Error::validation("Missing form markup output"),
                                            error);
        *out = copy_text(markup(title, fields, count));
        return 0;
    });
}
int idax_swift_form_ask(const char* title, IdaxSwiftFormField* fields, size_t count, int* accepted,
                        IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (accepted)
            *accepted = 0;
        if (idax::swift::require_runtime_thread(error))
            return -1;
        if (!accepted)
            return idax::swift::write_error(
                ida::Error::validation("Missing form acceptance output"), error);
        auto form = markup(title, fields, count);
        auto valid_markup = ida::ui::detail::validate_form_markup(form);
        if (!valid_markup)
            return idax::swift::write_error(valid_markup.error(), error);
        if (idax_swift_runtime_begin_activity(error))
            return -1;
        struct Activity {
            ~Activity() { idax_swift_runtime_end_activity(); }
        } activity;
        std::vector<std::unique_ptr<Slot>> slots;
        slots.reserve(count);
        std::array<void*, maximum_fields> arguments{};
        for (size_t i = 0; i < count; ++i) {
            auto slot = std::make_unique<Slot>();
            arguments[i] = slot->prepare(fields[i]);
            slots.push_back(std::move(slot));
        }
        int result = ask(form.c_str(), arguments, std::make_index_sequence<maximum_fields>{});
        if (result < 0)
            return idax::swift::write_error(ida::Error::sdk("ask_form failed"), error);
        if (result == 0)
            return 0;
        for (size_t i = 0; i < count; ++i) {
            auto& field = fields[i];
            const auto& slot = *slots[i];
            switch (field.kind) {
            case 0:
                field.integer = static_cast<int64_t>(slot.integer);
                break;
            case 1:
            case 2:
                field.bits = slot.bits;
                break;
            case 3:
                field.address = static_cast<uint64_t>(slot.address);
                break;
            case 4:
                field.output_text = copy_text(std::string(slot.text.c_str(), slot.text.length()));
                break;
            case 5:
                field.output_text = copy_text(slot.path.data());
                break;
            }
        }
        *accepted = 1;
        return 0;
    });
}
void idax_swift_form_free_outputs(IdaxSwiftFormField* fields, size_t count) {
    if (!fields)
        return;
    for (size_t i = 0; i < count; ++i) {
        std::free(fields[i].output_text);
        fields[i].output_text = nullptr;
    }
}
int idax_swift_form_ask_markup(const char* text, int* accepted, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (accepted)
            *accepted = 0;
        if (idax::swift::require_runtime_thread(error))
            return -1;
        if (!text || !accepted)
            return idax::swift::write_error(ida::Error::validation("Missing form markup or output"),
                                            error);
        if (std::strpbrk(text, "<%"))
            return idax::swift::write_error(
                ida::Error::validation("Bound controls require FormBuilder"), error);
        auto result = ida::ui::ask_form(text);
        if (!result)
            return idax::swift::write_error(result.error(), error);
        *accepted = *result;
        return 0;
    });
}
}
