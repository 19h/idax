#include "common.hpp"

namespace idax::python {

void bind_lines(py::module_& module) {
    py::module_ lines = module.def_submodule(
        "lines", "Source mappings and IDA tagged-text manipulation.");

    py::class_<ida::lines::SourceFile>(lines, "SourceFile")
        .def(py::init<>())
        .def_readwrite("filename", &ida::lines::SourceFile::filename)
        .def_readwrite("range", &ida::lines::SourceFile::range);
    py::native_enum<ida::lines::Color>(lines, "Color", "enum.IntEnum")
        .value("DEFAULT", ida::lines::Color::Default)
        .value("REGULAR_COMMENT", ida::lines::Color::RegularComment)
        .value("REPEATABLE_COMMENT", ida::lines::Color::RepeatableComment)
        .value("AUTO_COMMENT", ida::lines::Color::AutoComment)
        .value("INSTRUCTION", ida::lines::Color::Instruction)
        .value("DATA_NAME", ida::lines::Color::DataName)
        .value("REGULAR_DATA_NAME", ida::lines::Color::RegularDataName)
        .value("DEMANGLED_NAME", ida::lines::Color::DemangledName)
        .value("SYMBOL", ida::lines::Color::Symbol)
        .value("CHAR_LITERAL", ida::lines::Color::CharLiteral)
        .value("STRING", ida::lines::Color::String)
        .value("NUMBER", ida::lines::Color::Number)
        .value("VOID", ida::lines::Color::Void)
        .value("CODE_REFERENCE", ida::lines::Color::CodeReference)
        .value("DATA_REFERENCE", ida::lines::Color::DataReference)
        .value("CODE_REF_TAIL", ida::lines::Color::CodeRefTail)
        .value("DATA_REF_TAIL", ida::lines::Color::DataRefTail)
        .value("ERROR", ida::lines::Color::Error)
        .value("PREFIX", ida::lines::Color::Prefix)
        .value("BINARY_PREFIX", ida::lines::Color::BinaryPrefix)
        .value("EXTRA", ida::lines::Color::Extra)
        .value("ALT_OPERAND", ida::lines::Color::AltOperand)
        .value("HIDDEN_NAME", ida::lines::Color::HiddenName)
        .value("LIBRARY_NAME", ida::lines::Color::LibraryName)
        .value("LOCAL_NAME", ida::lines::Color::LocalName)
        .value("DUMMY_CODE_NAME", ida::lines::Color::DummyCodeName)
        .value("ASM_DIRECTIVE", ida::lines::Color::AsmDirective)
        .value("MACRO", ida::lines::Color::Macro)
        .value("DATA_STRING", ida::lines::Color::DataString)
        .value("DATA_CHAR", ida::lines::Color::DataChar)
        .value("DATA_NUMBER", ida::lines::Color::DataNumber)
        .value("KEYWORD", ida::lines::Color::Keyword)
        .value("REGISTER", ida::lines::Color::Register)
        .value("IMPORTED_NAME", ida::lines::Color::ImportedName)
        .value("SEGMENT_NAME", ida::lines::Color::SegmentName)
        .value("UNKNOWN_NAME", ida::lines::Color::UnknownName)
        .value("CODE_NAME", ida::lines::Color::CodeName)
        .value("USER_NAME", ida::lines::Color::UserName)
        .value("COLLAPSED", ida::lines::Color::Collapsed)
        .finalize();

    lines.attr("COLOR_ON") = py::int_(static_cast<unsigned char>(ida::lines::kColorOn));
    lines.attr("COLOR_OFF") = py::int_(static_cast<unsigned char>(ida::lines::kColorOff));
    lines.attr("COLOR_ESC") = py::int_(static_cast<unsigned char>(ida::lines::kColorEsc));
    lines.attr("COLOR_INV") = py::int_(static_cast<unsigned char>(ida::lines::kColorInv));
    lines.attr("COLOR_ADDR") = py::int_(ida::lines::kColorAddr);
    lines.attr("COLOR_ADDR_SIZE") = py::int_(ida::lines::kColorAddrSize);

    lines.def("add_source_file", [](const ida::address::Range& range,
                                      std::string filename) {
        runtime_status("lines.add_source_file", [&] {
            return ida::lines::add_source_file(range, filename);
        });
    }, py::arg("range"), py::arg("filename"));
    lines.def("source_file_at", [](ida::Address address) {
        return runtime_result("lines.source_file_at", [=] {
            return ida::lines::source_file_at(address);
        });
    }, py::arg("address"));
    lines.def("remove_source_file", [](ida::Address address) {
        runtime_status("lines.remove_source_file", [=] {
            return ida::lines::remove_source_file(address);
        });
    }, py::arg("address"));
    lines.def("colstr", &ida::lines::colstr, py::arg("text"), py::arg("color"));
    lines.def("tag_remove", &ida::lines::tag_remove, py::arg("tagged_text"));
    lines.def("tag_advance", &ida::lines::tag_advance,
              py::arg("tagged_text"), py::arg("position"));
    lines.def("tag_strlen", &ida::lines::tag_strlen, py::arg("tagged_text"));
    lines.def("make_addr_tag", &ida::lines::make_addr_tag, py::arg("item_index"));
    lines.def("decode_addr_tag", &ida::lines::decode_addr_tag,
              py::arg("tagged_text"), py::arg("position"));
}

} // namespace idax::python
