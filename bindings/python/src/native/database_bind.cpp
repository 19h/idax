#include "common.hpp"

#include <array>

namespace idax::python {

namespace {

template <typename Function>
auto database_result(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    return unwrap(std::forward<Function>(function)());
}

template <typename Function>
void database_status(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    unwrap(std::forward<Function>(function)());
}

std::vector<std::string> parse_argv(const py::object& value) {
    if (value.is_none())
        return {"idax-python"};
    if (PyUnicode_Check(value.ptr()) || PyBytes_Check(value.ptr()))
        throw py::type_error("argv must be a sequence of strings, not a string");

    std::vector<std::string> result;
    for (py::handle item : py::reinterpret_borrow<py::iterable>(value)) {
        std::string text = py::cast<std::string>(item);
        if (text.find('\0') != std::string::npos)
            throw py::value_error("argv entries must not contain NUL bytes");
        result.push_back(std::move(text));
    }
    if (result.empty())
        result.emplace_back("idax-python");
    return result;
}

std::string optional_string_repr(const std::optional<std::string>& value) {
    if (!value)
        return "None";
    return py::repr(py::str(*value)).cast<std::string>();
}

} // namespace

void bind_database(py::module_& module) {
    py::module_ database = module.def_submodule(
        "database", "IDA runtime lifecycle, database metadata, and snapshots.");

    py::native_enum<ida::database::OpenMode>(
        database, "OpenMode", "enum.Enum")
        .value("ANALYZE", ida::database::OpenMode::Analyze)
        .value("SKIP_ANALYSIS", ida::database::OpenMode::SkipAnalysis)
        .export_values()
        .finalize();
    py::native_enum<ida::database::LoadIntent>(
        database, "LoadIntent", "enum.Enum")
        .value("AUTO_DETECT", ida::database::LoadIntent::AutoDetect)
        .value("BINARY", ida::database::LoadIntent::Binary)
        .value("NON_BINARY", ida::database::LoadIntent::NonBinary)
        .export_values()
        .finalize();

    auto processor_id = py::native_enum<ida::database::ProcessorId>(
        database, "ProcessorId", "enum.Enum");
    const std::array processor_ids{
        std::pair{"INTEL_X86", ida::database::ProcessorId::IntelX86},
        std::pair{"Z80", ida::database::ProcessorId::Z80},
        std::pair{"INTEL_I860", ida::database::ProcessorId::IntelI860},
        std::pair{"INTEL_8051", ida::database::ProcessorId::Intel8051},
        std::pair{"TMS320_C5X", ida::database::ProcessorId::Tms320C5x},
        std::pair{"MOS_6502", ida::database::ProcessorId::Mos6502},
        std::pair{"PDP11", ida::database::ProcessorId::Pdp11},
        std::pair{"MOTOROLA_68K", ida::database::ProcessorId::Motorola68k},
        std::pair{"JAVA_VM", ida::database::ProcessorId::JavaVm},
        std::pair{"MOTOROLA_6800", ida::database::ProcessorId::Motorola6800},
        std::pair{"ST7", ida::database::ProcessorId::St7},
        std::pair{"MOTOROLA_68HC12", ida::database::ProcessorId::Motorola68hc12},
        std::pair{"MIPS", ida::database::ProcessorId::Mips},
        std::pair{"ARM", ida::database::ProcessorId::Arm},
        std::pair{"TMS320_C6X", ida::database::ProcessorId::Tms320C6x},
        std::pair{"POWER_PC", ida::database::ProcessorId::PowerPc},
        std::pair{"INTEL_80196", ida::database::ProcessorId::Intel80196},
        std::pair{"Z8", ida::database::ProcessorId::Z8},
        std::pair{"SUPER_H", ida::database::ProcessorId::SuperH},
        std::pair{"DOT_NET", ida::database::ProcessorId::DotNet},
        std::pair{"AVR", ida::database::ProcessorId::Avr},
        std::pair{"H8", ida::database::ProcessorId::H8},
        std::pair{"PIC", ida::database::ProcessorId::Pic},
        std::pair{"SPARC", ida::database::ProcessorId::Sparc},
        std::pair{"ALPHA", ida::database::ProcessorId::Alpha},
        std::pair{"HPPA", ida::database::ProcessorId::Hppa},
        std::pair{"H8500", ida::database::ProcessorId::H8500},
        std::pair{"TRI_CORE", ida::database::ProcessorId::TriCore},
        std::pair{"DSP56K", ida::database::ProcessorId::Dsp56k},
        std::pair{"C166", ida::database::ProcessorId::C166},
        std::pair{"ST20", ida::database::ProcessorId::St20},
        std::pair{"IA64", ida::database::ProcessorId::Ia64},
        std::pair{"INTEL_I960", ida::database::ProcessorId::IntelI960},
        std::pair{"F2MC16", ida::database::ProcessorId::F2mc16},
        std::pair{"TMS320_C54X", ida::database::ProcessorId::Tms320C54x},
        std::pair{"TMS320_C55X", ida::database::ProcessorId::Tms320C55x},
        std::pair{"TRIMEDIA", ida::database::ProcessorId::Trimedia},
        std::pair{"M32R", ida::database::ProcessorId::M32r},
        std::pair{"NEC_78K0", ida::database::ProcessorId::Nec78k0},
        std::pair{"NEC_78K0S", ida::database::ProcessorId::Nec78k0s},
        std::pair{"MITSUBISHI_M740", ida::database::ProcessorId::MitsubishiM740},
        std::pair{"MITSUBISHI_M7700", ida::database::ProcessorId::MitsubishiM7700},
        std::pair{"ST9", ida::database::ProcessorId::St9},
        std::pair{"FUJITSU_FR", ida::database::ProcessorId::FujitsuFr},
        std::pair{"MOTOROLA_68HC16", ida::database::ProcessorId::Motorola68hc16},
        std::pair{"MITSUBISHI_M7900", ida::database::ProcessorId::MitsubishiM7900},
        std::pair{"TMS320_C3", ida::database::ProcessorId::Tms320C3},
        std::pair{"KR1878", ida::database::ProcessorId::Kr1878},
        std::pair{"ADSP_218X", ida::database::ProcessorId::Adsp218x},
        std::pair{"OAK_DSP", ida::database::ProcessorId::OakDsp},
        std::pair{"TLCS900", ida::database::ProcessorId::Tlcs900},
        std::pair{"ROCKWELL_C39", ida::database::ProcessorId::RockwellC39},
        std::pair{"CR16", ida::database::ProcessorId::Cr16},
        std::pair{"MN10200", ida::database::ProcessorId::Mn10200},
        std::pair{"TMS320_C1X", ida::database::ProcessorId::Tms320C1x},
        std::pair{"NEC_V850X", ida::database::ProcessorId::NecV850x},
        std::pair{"SCRIPT_ADAPTER", ida::database::ProcessorId::ScriptAdapter},
        std::pair{"EFI_BYTECODE", ida::database::ProcessorId::EfiBytecode},
        std::pair{"MSP430", ida::database::ProcessorId::Msp430},
        std::pair{"SPU", ida::database::ProcessorId::Spu},
        std::pair{"DALVIK", ida::database::ProcessorId::Dalvik},
        std::pair{"WDC_65C816", ida::database::ProcessorId::Wdc65c816},
        std::pair{"M16C", ida::database::ProcessorId::M16c},
        std::pair{"ARC", ida::database::ProcessorId::Arc},
        std::pair{"UNSP", ida::database::ProcessorId::Unsp},
        std::pair{"TMS320_C28X", ida::database::ProcessorId::Tms320C28x},
        std::pair{"DSP96000", ida::database::ProcessorId::Dsp96000},
        std::pair{"SPC700", ida::database::ProcessorId::Spc700},
        std::pair{"ADSP_2106X", ida::database::ProcessorId::Adsp2106x},
        std::pair{"PIC16", ida::database::ProcessorId::Pic16},
        std::pair{"S390", ida::database::ProcessorId::S390},
        std::pair{"XTENSA", ida::database::ProcessorId::Xtensa},
        std::pair{"RISC_V", ida::database::ProcessorId::RiscV},
        std::pair{"RL78", ida::database::ProcessorId::Rl78},
        std::pair{"RX", ida::database::ProcessorId::Rx},
        std::pair{"WASM", ida::database::ProcessorId::Wasm},
        std::pair{"NDS32", ida::database::ProcessorId::Nds32},
        std::pair{"MCORE", ida::database::ProcessorId::Mcore},
    };
    for (const auto& [name, value] : processor_ids)
        processor_id.value(name, value);
    processor_id.finalize();

    py::class_<ida::database::PluginLoadPolicy>(database, "PluginLoadPolicy")
        .def(py::init<>())
        .def(py::init([](bool disable_user_plugins,
                         std::vector<std::string> allowlist_patterns) {
            return ida::database::PluginLoadPolicy{
                disable_user_plugins, std::move(allowlist_patterns)};
        }), py::arg("disable_user_plugins") = false,
            py::arg("allowlist_patterns") = std::vector<std::string>{})
        .def_readwrite("disable_user_plugins",
                       &ida::database::PluginLoadPolicy::disable_user_plugins)
        .def_readwrite("allowlist_patterns",
                       &ida::database::PluginLoadPolicy::allowlist_patterns);

    py::class_<ida::database::RuntimeOptions>(database, "RuntimeOptions")
        .def(py::init<>())
        .def(py::init([](bool quiet,
                         ida::database::PluginLoadPolicy plugin_policy) {
            return ida::database::RuntimeOptions{quiet, std::move(plugin_policy)};
        }), py::arg("quiet") = false,
            py::arg("plugin_policy") = ida::database::PluginLoadPolicy{})
        .def_readwrite("quiet", &ida::database::RuntimeOptions::quiet)
        .def_readwrite("plugin_policy", &ida::database::RuntimeOptions::plugin_policy);

    py::class_<ida::database::CompilerInfo>(database, "CompilerInfo")
        .def(py::init<>())
        .def_readwrite("id", &ida::database::CompilerInfo::id)
        .def_readwrite("uncertain", &ida::database::CompilerInfo::uncertain)
        .def_readwrite("name", &ida::database::CompilerInfo::name)
        .def_readwrite("abbreviation", &ida::database::CompilerInfo::abbreviation)
        .def("__repr__", [](const ida::database::CompilerInfo& info) {
            return "CompilerInfo(id=" + std::to_string(info.id)
                + ", uncertain=" + std::string(info.uncertain ? "True" : "False")
                + ", name=" + py::repr(py::str(info.name)).cast<std::string>()
                + ", abbreviation="
                + py::repr(py::str(info.abbreviation)).cast<std::string>() + ")";
        });

    py::class_<ida::database::ImportSymbol>(database, "ImportSymbol")
        .def(py::init<>())
        .def_readwrite("address", &ida::database::ImportSymbol::address)
        .def_readwrite("name", &ida::database::ImportSymbol::name)
        .def_readwrite("ordinal", &ida::database::ImportSymbol::ordinal);
    py::class_<ida::database::ImportModule>(database, "ImportModule")
        .def(py::init<>())
        .def_readwrite("index", &ida::database::ImportModule::index)
        .def_readwrite("name", &ida::database::ImportModule::name)
        .def_readwrite("symbols", &ida::database::ImportModule::symbols);

    py::class_<ida::database::ProcessorProfile>(database, "ProcessorProfile")
        .def(py::init<>())
        .def_readwrite("raw_id", &ida::database::ProcessorProfile::raw_id)
        .def_readwrite("known_id", &ida::database::ProcessorProfile::known_id)
        .def_readwrite("name", &ida::database::ProcessorProfile::name)
        .def_readwrite("address_bitness",
                       &ida::database::ProcessorProfile::address_bitness)
        .def_readwrite("big_endian", &ida::database::ProcessorProfile::big_endian)
        .def_readwrite("abi_name", &ida::database::ProcessorProfile::abi_name)
        .def("__repr__", [](const ida::database::ProcessorProfile& profile) {
            return "ProcessorProfile(raw_id=" + std::to_string(profile.raw_id)
                + ", name=" + py::repr(py::str(profile.name)).cast<std::string>()
                + ", address_bitness=" + std::to_string(profile.address_bitness)
                + ", big_endian="
                + std::string(profile.big_endian ? "True" : "False")
                + ", abi_name=" + optional_string_repr(profile.abi_name) + ")";
        });

    py::class_<ida::database::Snapshot>(database, "Snapshot")
        .def(py::init<>())
        .def_readwrite("id", &ida::database::Snapshot::id)
        .def_readwrite("flags", &ida::database::Snapshot::flags)
        .def_readwrite("description", &ida::database::Snapshot::description)
        .def_readwrite("filename", &ida::database::Snapshot::filename)
        .def_readwrite("children", &ida::database::Snapshot::children);

    database.def("processor_id_from_raw", [](std::int32_t raw_id) {
        return ida::database::processor_id_from_raw(raw_id);
    }, py::arg("raw_id"));

    database.def("init", [](py::object argv, py::object options) {
        std::vector<std::string> arguments = parse_argv(argv);
        std::vector<char*> raw_arguments;
        raw_arguments.reserve(arguments.size());
        for (std::string& argument : arguments)
            raw_arguments.push_back(argument.data());

        ida::Status status;
        if (options.is_none()) {
            status = ida::database::init(
                static_cast<int>(raw_arguments.size()), raw_arguments.data());
        } else {
            status = ida::database::init(
                static_cast<int>(raw_arguments.size()), raw_arguments.data(),
                options.cast<const ida::database::RuntimeOptions&>());
        }
        unwrap(std::move(status));
        mark_runtime_thread();
    }, py::arg("argv") = py::none(), py::arg("options") = py::none());

    database.def("open", [](py::handle path_value, py::object mode_value,
                             ida::database::LoadIntent intent) {
        ensure_runtime_thread("database.open");
        std::string path = filesystem_path(path_value);
        if (py::isinstance<py::bool_>(mode_value)) {
            if (intent != ida::database::LoadIntent::AutoDetect)
                throw py::value_error("boolean analysis mode cannot be combined with intent");
            unwrap(ida::database::open(path, mode_value.cast<bool>()));
            return;
        }
        const auto mode = mode_value.cast<ida::database::OpenMode>();
        unwrap(ida::database::open(path, intent, mode));
    }, py::arg("path"), py::arg("mode") = ida::database::OpenMode::Analyze,
       py::arg("intent") = ida::database::LoadIntent::AutoDetect);
    database.def("open_binary", [](py::handle path_value,
                                    ida::database::OpenMode mode) {
        database_status("database.open_binary", [&] {
            return ida::database::open_binary(filesystem_path(path_value), mode);
        });
    }, py::arg("path"), py::arg("mode") = ida::database::OpenMode::Analyze);
    database.def("open_non_binary", [](py::handle path_value,
                                        ida::database::OpenMode mode) {
        database_status("database.open_non_binary", [&] {
            return ida::database::open_non_binary(filesystem_path(path_value), mode);
        });
    }, py::arg("path"), py::arg("mode") = ida::database::OpenMode::Analyze);
    database.def("save", [] {
        database_status("database.save", [] { return ida::database::save(); });
    });
    database.def("close", [](bool save) {
        database_status("database.close", [=] { return ida::database::close(save); });
    }, py::arg("save") = false);
    database.def("file_to_database", [](py::handle path_value,
                                         std::int64_t file_offset,
                                         ida::Address address,
                                         ida::AddressSize size,
                                         bool patchable,
                                         bool remote) {
        database_status("database.file_to_database", [&] {
            return ida::database::file_to_database(
                filesystem_path(path_value), file_offset, address, size,
                patchable, remote);
        });
    }, py::arg("file_path"), py::arg("file_offset"), py::arg("address"),
       py::arg("size"), py::arg("patchable") = true,
       py::arg("remote") = false);
    database.def("memory_to_database", [](py::handle data,
                                           ida::Address address,
                                           std::int64_t file_offset) {
        std::vector<std::uint8_t> bytes = buffer_bytes(data);
        database_status("database.memory_to_database", [&] {
            return ida::database::memory_to_database(bytes, address, file_offset);
        });
    }, py::arg("data"), py::arg("address"), py::arg("file_offset") = -1);

#define IDAX_PY_DATABASE_RESULT(name)                                      \
    database.def(#name, [] {                                               \
        return database_result("database." #name, [] {                    \
            return ida::database::name();                                  \
        });                                                                \
    })

    IDAX_PY_DATABASE_RESULT(input_file_path);
    IDAX_PY_DATABASE_RESULT(idb_path);
    IDAX_PY_DATABASE_RESULT(file_type_name);
    IDAX_PY_DATABASE_RESULT(loader_format_name);
    IDAX_PY_DATABASE_RESULT(input_md5);
    IDAX_PY_DATABASE_RESULT(compiler_info);
    IDAX_PY_DATABASE_RESULT(import_modules);
    IDAX_PY_DATABASE_RESULT(image_base);
    IDAX_PY_DATABASE_RESULT(min_address);
    IDAX_PY_DATABASE_RESULT(max_address);
    IDAX_PY_DATABASE_RESULT(address_bounds);
    IDAX_PY_DATABASE_RESULT(address_span);
    IDAX_PY_DATABASE_RESULT(processor_id);
    IDAX_PY_DATABASE_RESULT(processor);
    IDAX_PY_DATABASE_RESULT(processor_name);
    IDAX_PY_DATABASE_RESULT(address_bitness);
    IDAX_PY_DATABASE_RESULT(is_big_endian);
    IDAX_PY_DATABASE_RESULT(abi_name);
    IDAX_PY_DATABASE_RESULT(processor_profile);
    IDAX_PY_DATABASE_RESULT(snapshots);
    IDAX_PY_DATABASE_RESULT(is_snapshot_database);

#undef IDAX_PY_DATABASE_RESULT

    database.def("set_address_bitness", [](int bits) {
        database_status("database.set_address_bitness", [=] {
            return ida::database::set_address_bitness(bits);
        });
    }, py::arg("bits"));
    database.def("set_snapshot_description", [](std::string description) {
        database_status("database.set_snapshot_description", [&] {
            return ida::database::set_snapshot_description(description);
        });
    }, py::arg("description"));
}

} // namespace idax::python
