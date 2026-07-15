#include "ui_python.hpp"

#include <array>
#include <limits>
#include <memory>
#include <unordered_map>

namespace idax::python {

namespace {

class PythonFormBinding {
public:
    virtual ~PythonFormBinding() = default;
    virtual ida::Status prepare() = 0;
    virtual void* sdk_argument() = 0;
    virtual void commit() = 0;
};

class PythonFormSvalBinding : public PythonFormBinding {
public:
    explicit PythonFormSvalBinding(std::int64_t value) : value(value) {}
    ida::Status prepare() override {
        if (value < static_cast<std::int64_t>((std::numeric_limits<sval_t>::min)())
            || value > static_cast<std::int64_t>((std::numeric_limits<sval_t>::max)())) {
            return std::unexpected(ida::Error::validation(
                "Form integer value is out of SDK range"));
        }
        sdk_value_ = static_cast<sval_t>(value);
        return ida::ok();
    }
    void* sdk_argument() override { return &sdk_value_; }
    void commit() override { value = static_cast<std::int64_t>(sdk_value_); }
    std::int64_t value{0};
private:
    sval_t sdk_value_{0};
};

class PythonFormIntBinding final : public PythonFormSvalBinding {
public:
    using PythonFormSvalBinding::PythonFormSvalBinding;
};

class PythonFormU16Binding final : public PythonFormBinding {
public:
    explicit PythonFormU16Binding(std::uint16_t value) : value(value) {}
    ida::Status prepare() override {
        sdk_value_ = static_cast<ushort>(value);
        return ida::ok();
    }
    void* sdk_argument() override { return &sdk_value_; }
    void commit() override { value = static_cast<std::uint16_t>(sdk_value_); }
    std::uint16_t value{0};
private:
    ushort sdk_value_{0};
};

class PythonFormAddressBinding final : public PythonFormBinding {
public:
    explicit PythonFormAddressBinding(ida::Address value) : value(value) {}
    ida::Status prepare() override {
        sdk_value_ = static_cast<ea_t>(value);
        return ida::ok();
    }
    void* sdk_argument() override { return &sdk_value_; }
    void commit() override { value = static_cast<ida::Address>(sdk_value_); }
    ida::Address value{ida::BadAddress};
private:
    ea_t sdk_value_{BADADDR};
};

class PythonFormTextBinding final : public PythonFormBinding {
public:
    explicit PythonFormTextBinding(std::string value) : value(std::move(value)) {}
    ida::Status prepare() override {
        if (value.find('\0') != std::string::npos)
            return std::unexpected(ida::Error::validation(
                "Form text contains an embedded NUL"));
        sdk_value_ = qstring(value.data(), value.size());
        return ida::ok();
    }
    void* sdk_argument() override { return &sdk_value_; }
    void commit() override {
        value = std::string(sdk_value_.c_str(), sdk_value_.length());
    }
    std::string value;
private:
    qstring sdk_value_;
};

class PythonFormPathBinding final : public PythonFormBinding {
public:
    PythonFormPathBinding(std::string value, bool for_saving)
        : value(std::move(value)), for_saving(for_saving) {}
    ida::Status prepare() override {
        if (value.find('\0') != std::string::npos)
            return std::unexpected(ida::Error::validation(
                "Form path contains an embedded NUL"));
        if (value.size() >= buffer_.size())
            return std::unexpected(ida::Error::validation(
                "Form path exceeds QMAXPATH"));
        buffer_.fill('\0');
        std::copy(value.begin(), value.end(), buffer_.begin());
        return ida::ok();
    }
    void* sdk_argument() override { return buffer_.data(); }
    void commit() override { value = std::string(buffer_.data()); }
    std::string value;
    bool for_saving{true};
private:
    std::array<char, QMAXPATH> buffer_{};
};

bool ask_form_bindings(std::string_view markup,
                       const std::vector<py::object>& objects) {
    ensure_runtime_thread("ui.ask_form");
    if (markup.empty())
        throw_error(ida::Error::validation("Form markup cannot be empty"));
    if (markup.find('\0') != std::string_view::npos)
        throw_error(ida::Error::validation("Form markup contains an embedded NUL"));
    if (objects.size() > 16)
        throw_error(ida::Error::validation(
            "Python forms support at most 16 bound fields"));

    std::vector<PythonFormBinding*> bindings;
    std::vector<void*> arguments;
    bindings.reserve(objects.size());
    arguments.reserve(objects.size());
    for (const auto& object : objects) {
        auto* binding = object.cast<PythonFormBinding*>();
        unwrap(binding->prepare());
        bindings.push_back(binding);
        arguments.push_back(binding->sdk_argument());
    }

    qstring qmarkup(markup.data(), markup.size());
    int result = -1;
    switch (arguments.size()) {
    case 0: result = ::ask_form(qmarkup.c_str()); break;
    case 1: result = ::ask_form(qmarkup.c_str(), arguments[0]); break;
    case 2: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1]); break;
    case 3: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2]); break;
    case 4: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3]); break;
    case 5: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4]); break;
    case 6: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5]); break;
    case 7: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]); break;
    case 8: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7]); break;
    case 9: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8]); break;
    case 10: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9]); break;
    case 11: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10]); break;
    case 12: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10], arguments[11]); break;
    case 13: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10], arguments[11], arguments[12]); break;
    case 14: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10], arguments[11], arguments[12], arguments[13]); break;
    case 15: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10], arguments[11], arguments[12], arguments[13], arguments[14]); break;
    case 16: result = ::ask_form(qmarkup.c_str(), arguments[0], arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6], arguments[7], arguments[8], arguments[9], arguments[10], arguments[11], arguments[12], arguments[13], arguments[14], arguments[15]); break;
    default: break;
    }
    if (result < 0)
        throw_error(ida::Error::sdk("ask_form failed"));
    if (result > 0) {
        for (auto* binding : bindings)
            binding->commit();
    }
    return result > 0;
}

void append_form_field(std::string& markup, std::string_view label,
                       char type, int width, int visible_width) {
    markup.push_back('<');
    markup.append(label);
    markup.push_back(':');
    markup.push_back(type);
    markup.push_back(':');
    if (width >= 0)
        markup.append(std::to_string(width));
    markup.push_back(':');
    if (visible_width >= 0)
        markup.append(std::to_string(visible_width));
    markup.append("::>\n");
}

void append_choice_group(std::string& markup, std::string_view label,
                         char type, const std::vector<std::string>& choices) {
    const std::vector<std::string> fallback{
        label.empty() ? std::string("Value") : std::string(label)};
    const auto& values = choices.empty() ? fallback : choices;
    for (std::size_t index = 0; index < values.size(); ++index) {
        markup.push_back('<');
        if (index == 0 && !label.empty()) {
            markup.append("##");
            markup.append(label);
            markup.append("##");
        }
        markup.append(values[index]);
        markup.push_back(':');
        markup.push_back(type);
        markup.push_back('>');
        if (index + 1 == values.size())
            markup.push_back('>');
        markup.push_back('\n');
    }
}

class PythonFormBuilder {
public:
    explicit PythonFormBuilder(std::string title) {
        markup_ = std::move(title);
        markup_.append("\n\n");
    }

    py::object add_int(std::string label, std::int64_t value,
                       int width, int visible_width) {
        append_form_field(markup_, label, 'D', width, visible_width);
        return add(PythonFormIntBinding(value));
    }
    py::object add_sval(std::string label, std::int64_t value,
                        int width, int visible_width) {
        append_form_field(markup_, label, 'D', width, visible_width);
        return add(PythonFormSvalBinding(value));
    }
    py::object add_bitset(std::string label, std::uint16_t value,
                          const std::vector<std::string>& choices) {
        append_choice_group(markup_, label, 'C', choices);
        return add(PythonFormU16Binding(value));
    }
    py::object add_radio(std::string label, std::uint16_t value,
                         const std::vector<std::string>& choices) {
        append_choice_group(markup_, label, 'R', choices);
        return add(PythonFormU16Binding(value));
    }
    py::object add_address(std::string label, ida::Address value,
                           int width, int visible_width) {
        append_form_field(markup_, label, '$', width, visible_width);
        return add(PythonFormAddressBinding(value));
    }
    py::object add_text(std::string label, std::string value,
                        int width, int visible_width) {
        append_form_field(markup_, label, 'q', width, visible_width);
        return add(PythonFormTextBinding(std::move(value)));
    }
    py::object add_path(std::string label, std::string value,
                        bool for_saving, int visible_width) {
        append_form_field(markup_, label, 'f', for_saving ? 1 : 0, visible_width);
        return add(PythonFormPathBinding(std::move(value), for_saving));
    }
    bool ask() const { return ask_form_bindings(markup_, bindings_); }
    const std::string& markup() const noexcept { return markup_; }
    const std::vector<py::object>& bindings() const noexcept { return bindings_; }

private:
    template <typename Binding>
    py::object add(Binding binding) {
        py::object object = py::cast(std::move(binding));
        bindings_.push_back(object);
        return object;
    }

    std::string markup_;
    std::vector<py::object> bindings_;
};

class PythonProgress {
public:
    std::string phase;
    std::size_t processed{0};
    std::size_t total{0};
    std::string current_item;
};

template <typename ResultType, typename... Arguments>
ResultType invoke_chooser_value(const py::function& callback,
                                ResultType fallback,
                                Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<ResultType>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "Non-Python chooser callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return fallback;
}

template <typename... Arguments>
void invoke_chooser_void(const py::function& callback,
                         Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "Non-Python chooser callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
}

class PythonChooser final : public ida::ui::Chooser {
public:
    using ida::ui::Chooser::Chooser;

    std::size_t count() const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "count");
        if (!override)
            return 0;
        return invoke_chooser_value(override, std::size_t{0});
    }
    ida::ui::Row row(std::size_t index) const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "row");
        if (!override)
            return {};
        return invoke_chooser_value(override, ida::ui::Row{}, index);
    }
    ida::Address address_for(std::size_t index) const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "address_for");
        if (!override)
            return ida::ui::Chooser::address_for(index);
        return invoke_chooser_value(override, ida::BadAddress, index);
    }
    void on_insert(std::size_t index) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_insert");
        if (override)
            invoke_chooser_void(override, index);
    }
    void on_delete(std::size_t index) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_delete");
        if (override)
            invoke_chooser_void(override, index);
    }
    void on_edit(std::size_t index) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_edit");
        if (override)
            invoke_chooser_void(override, index);
    }
    void on_enter(std::size_t index) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_enter");
        if (override)
            invoke_chooser_void(override, index);
    }
    void on_refresh() override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_refresh");
        if (override)
            invoke_chooser_void(override);
    }
    void on_close() override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "on_close");
        if (override)
            invoke_chooser_void(override);
    }
};

std::unordered_map<std::string, py::object>& chooser_roots() {
    static std::unordered_map<std::string, py::object> roots;
    return roots;
}

} // namespace

void bind_ui(py::module_& module) {
    py::module_ ui = module.def_submodule(
        "ui", "Dialogs, forms, widgets, choosers, timers, and UI events.");

    py::native_enum<ida::ui::WidgetType>(ui, "WidgetType", "enum.Enum")
#define IDAX_PY_WIDGET_TYPE(name, python_name)                           \
        .value(python_name, ida::ui::WidgetType::name)
        IDAX_PY_WIDGET_TYPE(Unknown, "UNKNOWN")
        IDAX_PY_WIDGET_TYPE(Exports, "EXPORTS")
        IDAX_PY_WIDGET_TYPE(Imports, "IMPORTS")
        IDAX_PY_WIDGET_TYPE(Names, "NAMES")
        IDAX_PY_WIDGET_TYPE(Functions, "FUNCTIONS")
        IDAX_PY_WIDGET_TYPE(Strings, "STRINGS")
        IDAX_PY_WIDGET_TYPE(Segments, "SEGMENTS")
        IDAX_PY_WIDGET_TYPE(Segregs, "SEGREGS")
        IDAX_PY_WIDGET_TYPE(Selectors, "SELECTORS")
        IDAX_PY_WIDGET_TYPE(Signatures, "SIGNATURES")
        IDAX_PY_WIDGET_TYPE(TypeLibraries, "TYPE_LIBRARIES")
        IDAX_PY_WIDGET_TYPE(LocalTypes, "LOCAL_TYPES")
        IDAX_PY_WIDGET_TYPE(Problems, "PROBLEMS")
        IDAX_PY_WIDGET_TYPE(Breakpoints, "BREAKPOINTS")
        IDAX_PY_WIDGET_TYPE(Threads, "THREADS")
        IDAX_PY_WIDGET_TYPE(Modules, "MODULES")
        IDAX_PY_WIDGET_TYPE(TraceLog, "TRACE_LOG")
        IDAX_PY_WIDGET_TYPE(CallStack, "CALL_STACK")
        IDAX_PY_WIDGET_TYPE(CrossRefs, "CROSS_REFS")
        IDAX_PY_WIDGET_TYPE(SearchResults, "SEARCH_RESULTS")
        IDAX_PY_WIDGET_TYPE(StackFrame, "STACK_FRAME")
        IDAX_PY_WIDGET_TYPE(NavBand, "NAV_BAND")
        IDAX_PY_WIDGET_TYPE(Disassembly, "DISASSEMBLY")
        IDAX_PY_WIDGET_TYPE(HexView, "HEX_VIEW")
        IDAX_PY_WIDGET_TYPE(Notepad, "NOTEPAD")
        IDAX_PY_WIDGET_TYPE(Output, "OUTPUT")
        IDAX_PY_WIDGET_TYPE(CommandLine, "COMMAND_LINE")
        IDAX_PY_WIDGET_TYPE(Chooser, "CHOOSER")
        IDAX_PY_WIDGET_TYPE(Pseudocode, "PSEUDOCODE")
        IDAX_PY_WIDGET_TYPE(Microcode, "MICROCODE")
#undef IDAX_PY_WIDGET_TYPE
        .finalize();
    py::native_enum<ida::ui::DockPosition>(ui, "DockPosition", "enum.Enum")
        .value("LEFT", ida::ui::DockPosition::Left)
        .value("RIGHT", ida::ui::DockPosition::Right)
        .value("TOP", ida::ui::DockPosition::Top)
        .value("BOTTOM", ida::ui::DockPosition::Bottom)
        .value("FLOATING", ida::ui::DockPosition::Floating)
        .value("TAB", ida::ui::DockPosition::Tab)
        .finalize();
    py::native_enum<ida::ui::ColumnFormat>(ui, "ColumnFormat", "enum.Enum")
        .value("PLAIN", ida::ui::ColumnFormat::Plain)
        .value("PATH", ida::ui::ColumnFormat::Path)
        .value("HEX", ida::ui::ColumnFormat::Hex)
        .value("DECIMAL", ida::ui::ColumnFormat::Decimal)
        .value("ADDRESS", ida::ui::ColumnFormat::Address)
        .value("FUNCTION_NAME", ida::ui::ColumnFormat::FunctionName)
        .finalize();

    py::class_<PythonFormBinding>(ui, "FormBinding");
    py::class_<PythonFormSvalBinding, PythonFormBinding>(ui, "FormSvalBinding")
        .def(py::init<std::int64_t>(), py::arg("value") = 0)
        .def_readwrite("value", &PythonFormSvalBinding::value);
    py::class_<PythonFormIntBinding, PythonFormSvalBinding>(ui, "FormIntBinding")
        .def(py::init<std::int64_t>(), py::arg("value") = 0);
    py::class_<PythonFormU16Binding, PythonFormBinding>(ui, "FormU16Binding")
        .def(py::init<std::uint16_t>(), py::arg("value") = 0)
        .def_readwrite("value", &PythonFormU16Binding::value);
    py::class_<PythonFormAddressBinding, PythonFormBinding>(ui, "FormAddressBinding")
        .def(py::init<ida::Address>(), py::arg("value") = ida::BadAddress)
        .def_readwrite("value", &PythonFormAddressBinding::value);
    py::class_<PythonFormTextBinding, PythonFormBinding>(ui, "FormTextBinding")
        .def(py::init<std::string>(), py::arg("value") = "")
        .def_readwrite("value", &PythonFormTextBinding::value);
    py::class_<PythonFormPathBinding, PythonFormBinding>(ui, "FormPathBinding")
        .def(py::init<std::string, bool>(), py::arg("value") = "",
             py::arg("for_saving") = true)
        .def_readwrite("value", &PythonFormPathBinding::value)
        .def_readonly("for_saving", &PythonFormPathBinding::for_saving);
    py::class_<PythonFormBuilder>(ui, "FormBuilder")
        .def(py::init<std::string>(), py::arg("title"))
        .def_property_readonly("markup", &PythonFormBuilder::markup)
        .def_property_readonly("bindings", &PythonFormBuilder::bindings)
        .def("add_int", &PythonFormBuilder::add_int, py::arg("label"),
             py::arg("value") = 0, py::arg("width") = 10,
             py::arg("visible_width") = 10)
        .def("add_sval", &PythonFormBuilder::add_sval, py::arg("label"),
             py::arg("value") = 0, py::arg("width") = 10,
             py::arg("visible_width") = 10)
        .def("add_bitset", &PythonFormBuilder::add_bitset, py::arg("group_label"),
             py::arg("value") = 0, py::arg("choices") = std::vector<std::string>{})
        .def("add_radio", &PythonFormBuilder::add_radio, py::arg("group_label"),
             py::arg("value") = 0, py::arg("choices") = std::vector<std::string>{})
        .def("add_address", &PythonFormBuilder::add_address, py::arg("label"),
             py::arg("value") = ida::BadAddress, py::arg("width") = 16,
             py::arg("visible_width") = 16)
        .def("add_text", &PythonFormBuilder::add_text, py::arg("label"),
             py::arg("value") = "", py::arg("width") = 256,
             py::arg("visible_width") = 40)
        .def("add_path", &PythonFormBuilder::add_path, py::arg("label"),
             py::arg("value") = "", py::arg("for_saving") = true,
             py::arg("visible_width") = 64)
        .def("ask", &PythonFormBuilder::ask);

    py::class_<ida::ui::WaitBox>(ui, "WaitBox")
        .def(py::init<std::string_view>(), py::arg("message"))
        .def_property_readonly("active", &ida::ui::WaitBox::active)
        .def_property_readonly("cancelled", &ida::ui::WaitBox::cancelled)
        .def("update", [](ida::ui::WaitBox& self, std::string message) {
            runtime_status("ui.WaitBox.update", [&] { return self.update(message); });
        }, py::arg("message"))
        .def("dismiss", &ida::ui::WaitBox::dismiss)
        .def("close", &ida::ui::WaitBox::dismiss)
        .def("__enter__", [](ida::ui::WaitBox& self) -> ida::ui::WaitBox& {
            return self;
        }, py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::ui::WaitBox& self,
                              py::object, py::object, py::object) {
            self.dismiss();
            return false;
        });
    py::class_<PythonProgress>(ui, "Progress")
        .def(py::init<>())
        .def_readwrite("phase", &PythonProgress::phase)
        .def_readwrite("processed", &PythonProgress::processed)
        .def_readwrite("total", &PythonProgress::total)
        .def_readwrite("current_item", &PythonProgress::current_item);

#define IDAX_PY_UI_VALUE(type_name)                                      \
    py::class_<ida::ui::type_name>(ui, #type_name).def(py::init<>())
    IDAX_PY_UI_VALUE(ShowWidgetOptions)
        .def_readwrite("position", &ida::ui::ShowWidgetOptions::position)
        .def_readwrite("restore_previous", &ida::ui::ShowWidgetOptions::restore_previous);
    IDAX_PY_UI_VALUE(Column)
        .def_readwrite("name", &ida::ui::Column::name)
        .def_readwrite("width", &ida::ui::Column::width)
        .def_readwrite("format", &ida::ui::Column::format);
    IDAX_PY_UI_VALUE(RowStyle)
        .def_readwrite("bold", &ida::ui::RowStyle::bold)
        .def_readwrite("italic", &ida::ui::RowStyle::italic)
        .def_readwrite("strikethrough", &ida::ui::RowStyle::strikethrough)
        .def_readwrite("gray", &ida::ui::RowStyle::gray)
        .def_readwrite("background_color", &ida::ui::RowStyle::background_color);
    IDAX_PY_UI_VALUE(Row)
        .def_readwrite("columns", &ida::ui::Row::columns)
        .def_readwrite("icon", &ida::ui::Row::icon)
        .def_readwrite("style", &ida::ui::Row::style);
    IDAX_PY_UI_VALUE(ChooserOptions)
        .def_readwrite("title", &ida::ui::ChooserOptions::title)
        .def_readwrite("columns", &ida::ui::ChooserOptions::columns)
        .def_readwrite("modal", &ida::ui::ChooserOptions::modal)
        .def_readwrite("can_insert", &ida::ui::ChooserOptions::can_insert)
        .def_readwrite("can_delete", &ida::ui::ChooserOptions::can_delete)
        .def_readwrite("can_edit", &ida::ui::ChooserOptions::can_edit)
        .def_readwrite("can_refresh", &ida::ui::ChooserOptions::can_refresh);
#undef IDAX_PY_UI_VALUE

    py::class_<ida::ui::Widget>(ui, "Widget")
        .def(py::init<>())
        .def_property_readonly("valid", &ida::ui::Widget::valid)
        .def_property_readonly("title", &ida::ui::Widget::title)
        .def_property_readonly("id", &ida::ui::Widget::id)
        .def("__bool__", &ida::ui::Widget::valid)
        .def("__eq__", [](const ida::ui::Widget& self,
                             const ida::ui::Widget& other) {
            return self == other;
        });
    py::class_<ida::ui::Chooser, PythonChooser,
               std::shared_ptr<ida::ui::Chooser>>(ui, "Chooser")
        .def(py::init<ida::ui::ChooserOptions>(), py::arg("options"))
        .def("count", &ida::ui::Chooser::count)
        .def("row", &ida::ui::Chooser::row, py::arg("index"))
        .def("address_for", &ida::ui::Chooser::address_for, py::arg("index"))
        .def("on_insert", &ida::ui::Chooser::on_insert, py::arg("before_index"))
        .def("on_delete", &ida::ui::Chooser::on_delete, py::arg("index"))
        .def("on_edit", &ida::ui::Chooser::on_edit, py::arg("index"))
        .def("on_enter", &ida::ui::Chooser::on_enter, py::arg("index"))
        .def("on_refresh", &ida::ui::Chooser::on_refresh)
        .def("on_close", &ida::ui::Chooser::on_close)
        .def("show", [](py::object chooser_object, std::size_t selection) {
            auto& chooser = chooser_object.cast<ida::ui::Chooser&>();
            auto result = runtime_result("ui.Chooser.show", [&] {
                return chooser.show(selection);
            });
            if (!chooser.options().modal) {
                chooser_roots().insert_or_assign(
                    chooser.options().title, std::move(chooser_object));
            }
            return result;
        }, py::arg("default_selection") = 0)
        .def("refresh", [](ida::ui::Chooser& self) {
            runtime_status("ui.Chooser.refresh", [&] { return self.refresh(); });
        })
        .def("close", [](ida::ui::Chooser& self) {
            const std::string title = self.options().title;
            runtime_status("ui.Chooser.close", [&] { return self.close(); });
            chooser_roots().erase(title);
        })
        .def_property_readonly("options", &ida::ui::Chooser::options,
                               py::return_value_policy::reference_internal);

    ui.def("message", [](std::string text) {
        runtime_call("ui.message", [&] { ida::ui::message(text); });
    }, py::arg("text"));
    ui.def("warning", [](std::string text) {
        runtime_call("ui.warning", [&] { ida::ui::warning(text); });
    }, py::arg("text"));
    ui.def("info", [](std::string text) {
        runtime_call("ui.info", [&] { ida::ui::info(text); });
    }, py::arg("text"));
    ui.def("ask_yn", [](std::string question, bool default_yes) {
        return runtime_result("ui.ask_yn", [&] {
            return ida::ui::ask_yn(question, default_yes);
        });
    }, py::arg("question"), py::arg("default_yes") = true);
    ui.def("ask_string", [](std::string prompt, std::string default_value) {
        return runtime_result("ui.ask_string", [&] {
            return ida::ui::ask_string(prompt, default_value);
        });
    }, py::arg("prompt"), py::arg("default_value") = "");
    ui.def("ask_file", [](bool saving, std::string path, std::string prompt) {
        return runtime_result("ui.ask_file", [&] {
            return ida::ui::ask_file(saving, path, prompt);
        });
    }, py::arg("for_saving"), py::arg("default_path") = "",
       py::arg("prompt") = "");
    ui.def("ask_address", [](std::string prompt, ida::Address value) {
        return runtime_result("ui.ask_address", [&] {
            return ida::ui::ask_address(prompt, value);
        });
    }, py::arg("prompt"), py::arg("default_value") = ida::BadAddress);
    ui.def("ask_long", [](std::string prompt, std::int64_t value) {
        return runtime_result("ui.ask_long", [&] {
            return ida::ui::ask_long(prompt, value);
        });
    }, py::arg("prompt"), py::arg("default_value") = 0);
    ui.def("ask_text", [](std::string prompt, std::string value,
        std::size_t max_size, bool tabs, bool normal_font) {
        return runtime_result("ui.ask_text", [&] {
            return ida::ui::ask_text(prompt, value, max_size, tabs, normal_font);
        });
    }, py::arg("prompt"), py::arg("default_value") = "",
       py::arg("max_size") = 0, py::arg("accept_tabs") = false,
       py::arg("normal_font") = false);
    ui.def("ask_form", [](std::string markup, py::args arguments) {
        std::vector<py::object> objects;
        objects.reserve(arguments.size());
        for (const auto& argument : arguments)
            objects.emplace_back(py::reinterpret_borrow<py::object>(argument));
        return ask_form_bindings(markup, objects);
    }, py::arg("markup"));
    ui.def("copy_to_clipboard", [](std::string text) {
        runtime_status("ui.copy_to_clipboard", [&] {
            return ida::ui::copy_to_clipboard(text);
        });
    }, py::arg("text"));
    ui.def("read_clipboard", [] {
        return runtime_result("ui.read_clipboard", ida::ui::read_clipboard);
    });
    ui.def("clipboard_backend", [] {
        return std::string(ida::ui::clipboard_backend());
    });
    ui.def("form_sval", [](std::int64_t value) {
        return PythonFormSvalBinding(value);
    }, py::arg("value") = 0);
    ui.def("form_int", [](std::int64_t value) {
        return PythonFormIntBinding(value);
    }, py::arg("value") = 0);
    ui.def("form_bitset", [](std::uint16_t value) {
        return PythonFormU16Binding(value);
    }, py::arg("value") = 0);
    ui.def("form_radio", [](std::uint16_t value) {
        return PythonFormU16Binding(value);
    }, py::arg("value") = 0);
    ui.def("form_address", [](ida::Address value) {
        return PythonFormAddressBinding(value);
    }, py::arg("value") = ida::BadAddress);
    ui.def("form_text", [](std::string value) {
        return PythonFormTextBinding(std::move(value));
    }, py::arg("value") = "");
    ui.def("form_path", [](std::string value, bool saving) {
        return PythonFormPathBinding(std::move(value), saving);
    }, py::arg("value") = "", py::arg("for_saving") = true);
    ui.def("form_builder", [](std::string title) {
        return PythonFormBuilder(std::move(title));
    }, py::arg("title"));

    ui.def("jump_to", [](ida::Address address) {
        runtime_status("ui.jump_to", [=] { return ida::ui::jump_to(address); });
    }, py::arg("address"));
    ui.def("screen_address", [] {
        return runtime_result("ui.screen_address", ida::ui::screen_address);
    });
    ui.def("selection", [] {
        return runtime_result("ui.selection", ida::ui::selection);
    });
    ui.def("widget_type", [](py::object value) {
        if (py::isinstance<ida::ui::Widget>(value)) {
            return ida::ui::widget_type(value.cast<const ida::ui::Widget&>());
        }
        return ida::ui::widget_type(
            value.cast<const OpaqueHostHandle&>().get("ui.widget_type"));
    }, py::arg("widget"));
    ui.def("create_widget", [](std::string title) {
        return runtime_result("ui.create_widget", [&] {
            return ida::ui::create_widget(title);
        });
    }, py::arg("title"));
    ui.def("create_custom_viewer", [](std::string title,
        const std::vector<std::string>& lines) {
        return runtime_result("ui.create_custom_viewer", [&] {
            return ida::ui::create_custom_viewer(title, lines);
        });
    }, py::arg("title"), py::arg("lines"));
#define IDAX_PY_UI_VIEWER_STATUS(fn)                                     \
    ui.def(#fn, [](ida::ui::Widget& widget) {                            \
        runtime_status("ui." #fn, [&] { return ida::ui::fn(widget); });  \
    }, py::arg("viewer"))
    IDAX_PY_UI_VIEWER_STATUS(refresh_custom_viewer);
    IDAX_PY_UI_VIEWER_STATUS(close_custom_viewer);
#undef IDAX_PY_UI_VIEWER_STATUS
    ui.def("set_custom_viewer_lines", [](ida::ui::Widget& widget,
        const std::vector<std::string>& lines) {
        runtime_status("ui.set_custom_viewer_lines", [&] {
            return ida::ui::set_custom_viewer_lines(widget, lines);
        });
    }, py::arg("viewer"), py::arg("lines"));
    ui.def("custom_viewer_line_count", [](const ida::ui::Widget& widget) {
        return runtime_result("ui.custom_viewer_line_count", [&] {
            return ida::ui::custom_viewer_line_count(widget);
        });
    }, py::arg("viewer"));
    ui.def("custom_viewer_jump_to_line", [](ida::ui::Widget& widget,
        std::size_t line, int x, int y) {
        runtime_status("ui.custom_viewer_jump_to_line", [&] {
            return ida::ui::custom_viewer_jump_to_line(widget, line, x, y);
        });
    }, py::arg("viewer"), py::arg("line_index"), py::arg("x") = 0,
       py::arg("y") = 0);
    ui.def("custom_viewer_current_line", [](const ida::ui::Widget& widget,
        bool mouse) {
        return runtime_result("ui.custom_viewer_current_line", [&] {
            return ida::ui::custom_viewer_current_line(widget, mouse);
        });
    }, py::arg("viewer"), py::arg("mouse") = false);
    ui.def("show_widget", [](ida::ui::Widget& widget,
        const ida::ui::ShowWidgetOptions& options) {
        runtime_status("ui.show_widget", [&] {
            return ida::ui::show_widget(widget, options);
        });
    }, py::arg("widget"), py::arg("options") = ida::ui::ShowWidgetOptions{});
    ui.def("activate_widget", [](ida::ui::Widget& widget) {
        runtime_status("ui.activate_widget", [&] {
            return ida::ui::activate_widget(widget);
        });
    }, py::arg("widget"));
    ui.def("current_widget", [] {
        return runtime_call("ui.current_widget", ida::ui::current_widget);
    });
    ui.def("find_widget", [](std::string title) {
        return runtime_call("ui.find_widget", [&] {
            return ida::ui::find_widget(title);
        });
    }, py::arg("title"));
    ui.def("close_widget", [](ida::ui::Widget& widget) {
        runtime_status("ui.close_widget", [&] {
            return ida::ui::close_widget(widget);
        });
    }, py::arg("widget"));
    ui.def("is_widget_visible", [](const ida::ui::Widget& widget) {
        return runtime_call("ui.is_widget_visible", [&] {
            return ida::ui::is_widget_visible(widget);
        });
    }, py::arg("widget"));
    ui.def("widget_host", [](const ida::ui::Widget& widget) {
        auto pointer = runtime_result("ui.widget_host", [&] {
            return ida::ui::widget_host(widget);
        });
        return OpaqueHostHandle(
            pointer, "widget", std::make_shared<OpaqueHandleState>());
    }, py::arg("widget"));
    ui.def("with_widget_host", [](const ida::ui::Widget& widget,
                                     py::function callback) {
        ensure_runtime_thread("ui.with_widget_host");
        auto state = std::make_shared<OpaqueHandleState>();
        unwrap(ida::ui::with_widget_host(widget, [&](void* pointer) {
            try {
                callback(OpaqueHostHandle(pointer, "widget", state));
                state->valid = false;
                return ida::ok();
            } catch (py::error_already_set& error) {
                std::string detail = error.what();
                state->valid = false;
                error.discard_as_unraisable(callback);
                return ida::Status(std::unexpected(ida::Error::internal(
                    "Python widget-host callback failed", detail)));
            }
        }));
    }, py::arg("widget"), py::arg("callback"));
    ui.def("register_timer", [](int interval_ms, py::function callback) {
        return runtime_result("ui.register_timer", [&] {
            return ida::ui::register_timer(interval_ms,
                [callback = std::move(callback)] {
                    py::gil_scoped_acquire acquire;
                    try {
                        return callback().cast<int>();
                    } catch (py::error_already_set& error) {
                        error.discard_as_unraisable(callback);
                        return -1;
                    } catch (...) {
                        PyErr_SetString(
                            PyExc_RuntimeError,
                            "Python timer callback must return an integer");
                        PyErr_WriteUnraisable(callback.ptr());
                        return -1;
                    }
                });
        });
    }, py::arg("interval_ms"), py::arg("callback"));
    ui.def("unregister_timer", [](std::uint64_t token) {
        runtime_status("ui.unregister_timer", [=] {
            return ida::ui::unregister_timer(token);
        });
    }, py::arg("token"));
    ui.def("user_directory", [] {
        return runtime_result("ui.user_directory", ida::ui::user_directory);
    });
    ui.def("refresh_all_views", [] {
        runtime_call("ui.refresh_all_views", ida::ui::refresh_all_views);
    });

    bind_ui_events(ui);
}

} // namespace idax::python
