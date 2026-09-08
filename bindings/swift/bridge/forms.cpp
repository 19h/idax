#include "forms.h"
#include "support.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <ida/ui.hpp>
#include <memory>
#include <string_view>
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

// The SDK FORM_C grammar consumes one pointer per scalar/dynamic label and
// one ushort pointer at each C/c/R/r group's closing >ID> marker. E and b
// consume two pointers; callback %/ has special first-argument ordering.
// Unsupported pointer/control kinds must be rejected before constructing the
// varargs call. This parser validates storage compatibility, not GUI rendering.
class BoundMarkup {
    std::string_view text_;
    const IdaxSwiftFormField* fields_;
    size_t count_;
    size_t argument_{};
    std::array<size_t, 4> group_sizes_{};
    std::array<size_t, maximum_fields> char_capacities_{};

    [[noreturn]] void invalid(const char* message) const {
        throw ida::Error::validation(message, "Form argument " + std::to_string(argument_));
    }
    static bool digit(char c) { return c >= '0' && c <= '9'; }
    static std::string_view trim(std::string_view value) {
        while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
            value.remove_prefix(1);
        while (!value.empty() &&
               (value.back() == ' ' || value.back() == '\t' || value.back() == '\r'))
            value.remove_suffix(1);
        return value;
    }
    static bool equal_keyword(std::string_view value, std::string_view keyword) {
        if (value.size() != keyword.size())
            return false;
        for (size_t i = 0; i < value.size(); ++i) {
            char c = value[i];
            if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
            if (c != keyword[i]) return false;
        }
        return true;
    }
    static bool directive(std::string_view line, std::string_view keyword) {
        return line.size() > keyword.size() &&
               equal_keyword(line.substr(0, keyword.size()), keyword) &&
               (line[keyword.size()] == ' ' || line[keyword.size()] == '\t');
    }
    size_t body_begin() const {
        size_t cursor = 0;
        bool in_help = false;
        while (cursor < text_.size()) {
            size_t end = text_.find('\n', cursor);
            if (end == std::string_view::npos) end = text_.size();
            const auto line = trim(text_.substr(cursor, end - cursor));
            const auto next = end < text_.size() ? end + 1 : end;
            if (in_help) {
                if (equal_keyword(line, "ENDHELP")) in_help = false;
            } else if (equal_keyword(line, "HELP")) {
                in_help = true;
            } else if (!(directive(line, "STARTITEM") || directive(line, "BUTTON") ||
                         equal_keyword(line, "AUTOSYNC") ||
                         (!line.empty() && line.front() == '@'))) {
                return next; // The title does not consume an argument.
            }
            cursor = next;
        }
        if (in_help) invalid("Unterminated form HELP block");
        return cursor;
    }
    void reject_callbacks() const {
        for (size_t i = 0; i < text_.size(); ++i) {
            if (text_[i] != '%') continue;
            ++i;
            if (i < text_.size() && text_[i] == '%') continue;
            while (i < text_.size() && digit(text_[i])) ++i;
            if (i < text_.size() && (text_[i] == '/' || text_[i] == '*'))
                invalid("Form callbacks and native user-data placeholders are not supported");
        }
    }
    int width_value(std::string_view width) const {
        if (width.empty()) return -1;
        if (width.front() == '+') width.remove_prefix(1);
        int result{};
        const auto parsed = std::from_chars(width.data(), width.data() + width.size(), result);
        if (parsed.ec != std::errc() || parsed.ptr != width.data() + width.size())
            invalid("Malformed or out-of-range form field width");
        return result;
    }
    void consume(char type, bool dynamic, std::string_view width = {}) {
        if (argument_ == count_)
            invalid("Form has more placeholders than typed arguments");
        const int kind = fields_[argument_].kind;
        bool compatible = false;
        // EA64 scalar types share signed/unsigned 64-bit storage. Both forms
        // preserve all bits when a caller chooses a different numeric format.
        static_assert(sizeof(sval_t) == sizeof(int64_t) && sizeof(ea_t) == sizeof(uint64_t));
        if (std::strchr("SNnLlMmuDOoYsH$", type)) {
            compatible = kind == 0 || kind == 3;
        } else if (std::strchr("qiIyp", type)) {
            compatible = kind == 4;
        } else if (type == 'C' || type == 'c') {
            compatible = kind == 1;
        } else if (type == 'R' || type == 'r') {
            compatible = kind == 2;
        } else if (type == 'f' || type == 'F') {
            compatible = kind == 5;
            char_capacities_[argument_] = QMAXPATH;
            if (!dynamic && type == 'f' && !width.empty()) {
                const int mode = width_value(width);
                if (mode != 0 && mode != 1)
                    invalid("File form control must select open (0) or save (1) mode");
            }
        } else if (type == 'X') {
            compatible = kind == 5;
            const int requested = width_value(width);
            const size_t capacity = requested < 0 ? MAXSTR : static_cast<size_t>(requested);
            if (capacity == 0)
                invalid("Command form control requires a nonzero buffer capacity");
            char_capacities_[argument_] = capacity;
        } else if (dynamic && (type == 'A' || type == 'h')) {
            compatible = kind == 5; // Native dynamic labels use char*, not qstring*.
            char_capacities_[argument_] = 1;
        } else {
            invalid("Unsupported native form placeholder type");
        }
        if (!compatible)
            invalid("Form placeholder is incompatible with its typed argument");
        ++argument_;
    }
    static int group_index(char type) {
        switch (type) {
        case 'C': return 0;
        case 'c': return 1;
        case 'R': return 2;
        case 'r': return 3;
        default: return -1;
        }
    }
    size_t input(size_t opening) {
        const size_t end = text_.find('>', opening + 1);
        if (end == std::string_view::npos)
            invalid("Unterminated form control");
        const auto field = text_.substr(opening + 1, end - opening - 1);
        if (field.find('<') != std::string_view::npos)
            invalid("Nested form controls are not supported");
        for (size_t i = 0; i < field.size(); ++i) {
            if (field[i] != '%') continue;
            if (i + 1 == field.size() || field[i + 1] != '%')
                invalid("Nested substitutions in field labels are not supported");
            ++i; // Preserve native escaped percent signs in labels and hints.
        }
        size_t next = end + 1;
        if (field == "|" || field == "-") return next;
        if (field.starts_with("=:")) {
            // A tab may end with an optional decimal field ID and another >.
            size_t suffix = next;
            while (suffix < text_.size() && digit(text_[suffix])) ++suffix;
            return suffix < text_.size() && text_[suffix] == '>' ? suffix + 1 : next;
        }
        size_t label = 0;
        if (!field.empty() && field.front() == '#') {
            const auto last_hint = field.rfind('#');
            if (last_hint == 0) invalid("Unterminated form field hint");
            label = last_hint + 1;
        }
        const auto colon = field.find(':', label);
        if (colon == std::string_view::npos || colon + 1 == field.size())
            invalid("Form control is missing its native type");
        const char type = field[colon + 1];
        size_t spec_end = colon + 2;
        while (spec_end < field.size() && digit(field[spec_end])) ++spec_end;
        const int group = group_index(type);
        if (group >= 0) {
            if (spec_end != field.size()) invalid("Malformed checkbox or radio control");
            const auto size = ++group_sizes_[group];
            if (size > (group < 2 ? size_t(16) : size_t(65536)))
                invalid("Form choice group exceeds its UInt16 storage");
            size_t suffix = next;
            while (suffix < text_.size() && digit(text_[suffix])) ++suffix;
            if (suffix < text_.size() && text_[suffix] == '>') {
                consume(type, false);
                group_sizes_[group] = 0;
                return suffix + 1;
            }
            return next;
        }
        if (spec_end == field.size() || field[spec_end] != ':')
            invalid("Malformed form type or field identifier");
        const auto width_end = field.find(':', spec_end + 1);
        if (width_end == std::string_view::npos)
            invalid("Form control is missing its visible-width field");
        const auto width = field.substr(spec_end + 1, width_end - spec_end - 1);
        (void)width_value(width);
        const auto visible_end = field.find(':', width_end + 1);
        if (visible_end == std::string_view::npos)
            invalid("Form control is missing its help-context delimiter");
        (void)width_value(field.substr(width_end + 1, visible_end - width_end - 1));
        consume(type, false, width);
        return next;
    }
public:
    BoundMarkup(std::string_view text, const IdaxSwiftFormField* fields, size_t count)
        : text_(text), fields_(fields), count_(count) {}
    std::array<size_t, maximum_fields> validate() {
        auto valid = ida::ui::detail::validate_form_markup(text_);
        if (!valid) throw valid.error();
        if (count_ > maximum_fields || (count_ && !fields_))
            invalid("Invalid form argument extent; at most 64 arguments are supported");
        reject_callbacks();
        for (size_t cursor = body_begin(); cursor < text_.size();) {
            if (text_[cursor] == '<') {
                cursor = input(cursor);
            } else if (text_[cursor] == '%') {
                ++cursor;
                if (cursor < text_.size() && text_[cursor] == '%') {
                    ++cursor;
                    continue;
                }
                while (cursor < text_.size() && digit(text_[cursor])) ++cursor;
                if (cursor == text_.size()) invalid("Incomplete dynamic form label");
                consume(text_[cursor++], true);
            } else {
                ++cursor;
            }
        }
        for (const auto size : group_sizes_)
            if (size) invalid("Unclosed checkbox or radio group");
        if (argument_ != count_)
            invalid("Form has fewer placeholders than typed arguments");
        return char_capacities_;
    }
};
struct Slot {
    sval_t integer{};
    ea_t address{};
    ushort bits{};
    qstring text;
    std::vector<char> path;
    void* prepare(const IdaxSwiftFormField& field, size_t char_capacity) {
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
                const size_t size = std::strlen(field.text);
                path.resize(std::max(char_capacity, size + 1), '\0');
                std::memcpy(path.data(), field.text, size + 1);
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
int ask_bound(const char* form, IdaxSwiftFormField* fields, size_t count, int* accepted,
              IdaxSwiftError* error) {
    if (accepted) *accepted = 0;
    if (!form || !accepted)
        throw ida::Error::validation("Missing form markup or acceptance output");
    const auto char_capacities = BoundMarkup(form, fields, count).validate();
    if (idax::swift::require_runtime_thread(error)) return -1;
    if (idax_swift_runtime_begin_activity(error)) return -1;
    struct Activity {
        ~Activity() { idax_swift_runtime_end_activity(); }
    } activity;
    std::vector<std::unique_ptr<Slot>> slots;
    slots.reserve(count);
    std::array<void*, maximum_fields> arguments{};
    for (size_t i = 0; i < count; ++i) {
        auto slot = std::make_unique<Slot>();
        arguments[i] = slot->prepare(fields[i], char_capacities[i]);
        slots.push_back(std::move(slot));
    }
    const int result = ask(form, arguments, std::make_index_sequence<maximum_fields>{});
    if (result < -1)
        return idax::swift::write_error(ida::Error::sdk("ask_form failed"), error);
    // With a NO button the SDK distinguishes Cancel (-1) from No (0).
    // Neither outcome commits any prepared value.
    if (result <= 0) return 0;
    // Copy every output before reporting acceptance. Swift then converts all
    // copied outputs before committing any caller-owned binding cell.
    for (size_t i = 0; i < count; ++i) {
        auto& field = fields[i];
        const auto& slot = *slots[i];
        switch (field.kind) {
        case 0: field.integer = static_cast<int64_t>(slot.integer); break;
        case 1:
        case 2: field.bits = slot.bits; break;
        case 3: field.address = static_cast<uint64_t>(slot.address); break;
        case 4: field.output_text = copy_text(std::string(slot.text.c_str(), slot.text.length())); break;
        case 5: field.output_text = copy_text(slot.path.data()); break;
        }
    }
    *accepted = 1;
    return 0;
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
        const auto form = markup(title, fields, count);
        return ask_bound(form.c_str(), fields, count, accepted, error);
    });
}
int idax_swift_form_validate_bound(const char* form, const IdaxSwiftFormField* fields, size_t count,
                                  IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        if (!form) throw ida::Error::validation("Missing form markup");
        const auto char_capacities = BoundMarkup(form, fields, count).validate();
        for (size_t i = 0; i < count; ++i) {
            Slot slot;
            (void)slot.prepare(fields[i], char_capacities[i]);
        }
        return 0;
    });
}
int idax_swift_form_ask_bound(const char* form, IdaxSwiftFormField* fields, size_t count,
                             int* accepted, IdaxSwiftError* error) {
    return idax::swift::protect(error, [&] {
        return ask_bound(form, fields, count, accepted, error);
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
        return ask_bound(text, nullptr, 0, accepted, error);
    });
}
}
