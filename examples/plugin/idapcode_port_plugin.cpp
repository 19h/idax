#include <ida/idax.hpp>

#include <sleigh/Support.h>
#include <sleigh/libsleigh.hh>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

template <typename... Args>
std::string format(const char* pattern, Args&&... args) {
    char buffer[4096];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return std::string(buffer);
}

std::string to_lower(std::string value) {
    std::transform(value.begin(),
                   value.end(),
                   value.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return value;
}

std::string error_text(const ida::Error& error) {
    if (error.context.empty())
        return error.message;
    return error.message + " (" + error.context + ")";
}

struct ProcessorContext {
    std::int32_t processor_id{0};
    std::string processor_name;
    int bitness{0};
    bool big_endian{false};
    std::string abi_name;
};

struct SpecChoice {
    std::string sla_file;
    std::optional<std::string> pspec_file;
};

constexpr std::string_view kSpecRootEnv = "IDAX_IDAPCODE_SPEC_ROOT";

std::string joined_paths(const std::vector<std::filesystem::path>& paths) {
    std::ostringstream out;
    for (std::size_t index = 0; index < paths.size(); ++index) {
        if (index != 0)
            out << ", ";
        out << paths[index].string();
    }
    return out.str();
}

std::vector<std::filesystem::path> spec_search_paths() {
    std::vector<std::filesystem::path> paths;
    if (const char* env = std::getenv(kSpecRootEnv.data()); env != nullptr && *env != '\0') {
        paths.emplace_back(env);
    }

    for (const auto& path : sleigh::gDefaultSearchPaths)
        paths.push_back(path);

    return paths;
}

ida::Result<ProcessorContext> build_processor_context(const ida::function::Function& function) {
    auto processor_id = ida::database::processor_id();
    if (!processor_id)
        return std::unexpected(processor_id.error());

    auto processor_name = ida::database::processor_name();
    if (!processor_name)
        return std::unexpected(processor_name.error());

    auto big_endian = ida::database::is_big_endian();
    if (!big_endian)
        return std::unexpected(big_endian.error());

    int bitness = function.bitness();
    if (bitness != 16 && bitness != 32 && bitness != 64) {
        auto database_bitness = ida::database::address_bitness();
        if (!database_bitness)
            return std::unexpected(database_bitness.error());
        bitness = *database_bitness;
    }

    std::string abi;
    if (auto abi_name = ida::database::abi_name(); abi_name) {
        abi = *abi_name;
    }

    ProcessorContext context;
    context.processor_id = *processor_id;
    context.processor_name = *processor_name;
    context.bitness = bitness;
    context.big_endian = *big_endian;
    context.abi_name = std::move(abi);
    return context;
}

ida::Result<SpecChoice> choose_spec(const ProcessorContext& context) {
    using ida::database::ProcessorId;

    const auto processor = static_cast<ProcessorId>(context.processor_id);
    const std::string abi_lower = to_lower(context.abi_name);

    switch (processor) {
        case ProcessorId::IntelX86:
            return SpecChoice{context.bitness == 64 ? "x86-64.sla" : "x86.sla", std::nullopt};
        case ProcessorId::Arm:
            if (context.bitness == 64) {
                return SpecChoice{context.big_endian ? "AARCH64BE.sla" : "AARCH64.sla", std::nullopt};
            }
            return SpecChoice{context.big_endian ? "ARM7_be.sla" : "ARM7_le.sla", std::nullopt};
        case ProcessorId::Mips:
            if (context.bitness == 64 || abi_lower.find("n32") != std::string::npos) {
                return SpecChoice{context.big_endian ? "mips64be.sla" : "mips64le.sla", std::nullopt};
            }
            return SpecChoice{context.big_endian ? "mips32be.sla" : "mips32le.sla", std::nullopt};
        case ProcessorId::PowerPc:
            if (context.bitness == 64) {
                if (abi_lower.find("xbox") != std::string::npos) {
                    return SpecChoice{context.big_endian ? "ppc_64_isa_altivec_be.sla"
                                                         : "ppc_64_isa_altivec_le.sla",
                                      std::nullopt};
                }
                return SpecChoice{context.big_endian ? "ppc_64_be.sla" : "ppc_64_le.sla", std::nullopt};
            }
            return SpecChoice{context.big_endian ? "ppc_32_be.sla" : "ppc_32_le.sla", std::nullopt};
        case ProcessorId::Sparc:
            return SpecChoice{context.bitness == 64 ? "SparcV9_64.sla" : "SparcV9_32.sla", std::nullopt};
        case ProcessorId::Mos6502:
            return SpecChoice{"6502.sla", std::nullopt};
        case ProcessorId::Motorola68k:
            return SpecChoice{"68020.sla", std::nullopt};
        case ProcessorId::Motorola6800:
            return SpecChoice{"6805.sla", std::nullopt};
        case ProcessorId::Intel8051:
            return SpecChoice{"8051.sla", std::nullopt};
        case ProcessorId::Avr:
            return SpecChoice{context.bitness == 32 ? "avr32a.sla" : "avr8.sla", std::nullopt};
        case ProcessorId::Cr16:
            return SpecChoice{"CR16B.sla", std::nullopt};
        case ProcessorId::Dalvik:
            return SpecChoice{"Dalvik_Base.sla", std::nullopt};
        case ProcessorId::JavaVm:
            return SpecChoice{"JVM.sla", std::nullopt};
        case ProcessorId::Hppa:
            return SpecChoice{"pa-risc32be.sla", std::nullopt};
        case ProcessorId::Pic:
            return SpecChoice{"pic16.sla", std::nullopt};
        case ProcessorId::Msp430:
            return SpecChoice{context.bitness > 16 ? "TI_MSP430X.sla" : "TI_MSP430.sla", std::nullopt};
        case ProcessorId::TriCore:
            return SpecChoice{"tricore.sla", std::nullopt};
        case ProcessorId::Z80:
            return SpecChoice{"z80.sla", std::nullopt};
        default:
            break;
    }

    return std::unexpected(ida::Error::unsupported(
        "No Sleigh mapping for active processor",
        format("id=%d name=%s bits=%d endian=%s abi=%s",
               context.processor_id,
               context.processor_name.c_str(),
               context.bitness,
               context.big_endian ? "BE" : "LE",
               context.abi_name.empty() ? "<none>" : context.abi_name.c_str())));
}

ida::Result<std::filesystem::path> resolve_spec_file(std::string_view file_name) {
    const auto search_paths = spec_search_paths();
    if (auto path = sleigh::FindSpecFile(file_name, search_paths); path.has_value()) {
        return *path;
    }

    return std::unexpected(ida::Error::not_found(
        "Sleigh spec file not found",
        std::string(file_name) + " (set " + std::string(kSpecRootEnv)
            + " or build specs; searched: " + joined_paths(search_paths) + ")"));
}

class InMemoryLoadImage final : public ghidra::LoadImage {
public:
    explicit InMemoryLoadImage(std::uint64_t base_address)
        : ghidra::LoadImage("idax-idapcode"), base_address_(base_address) {}

    void set_image(std::vector<std::uint8_t> bytes) {
        image_ = std::move(bytes);
    }

    void loadFill(unsigned char* out,
                  int size,
                  const ghidra::Address& address) override {
        const std::uint64_t start = address.getOffset();
        for (int index = 0; index < size; ++index) {
            const std::uint64_t absolute = start + static_cast<std::uint64_t>(index);
            if (absolute < base_address_) {
                out[index] = 0;
                continue;
            }

            const std::uint64_t relative = absolute - base_address_;
            if (relative >= image_.size()) {
                out[index] = 0;
                continue;
            }

            out[index] = image_[relative];
        }
    }

    std::string getArchType() const override {
        return "memory";
    }

    void adjustVma(long) override {}

private:
    std::uint64_t base_address_{0};
    std::vector<std::uint8_t> image_;
};

void append_varnode(std::ostringstream& out, const ghidra::VarnodeData& varnode) {
    out << '(' << varnode.space->getName() << ',';
    varnode.space->printOffset(out, varnode.offset);
    out << ',' << varnode.size << ')';
}

class PcodeCollector final : public ghidra::PcodeEmit {
public:
    void clear() { lines_.clear(); }

    const std::vector<std::string>& lines() const { return lines_; }

    void dump(const ghidra::Address&,
              ghidra::OpCode opcode,
              ghidra::VarnodeData* output,
              ghidra::VarnodeData* inputs,
              std::int32_t input_count) override {
        std::ostringstream line;

        if (output != nullptr) {
            append_varnode(line, *output);
            line << " = ";
        }

        line << get_opname(opcode);

        for (std::int32_t index = 0; index < input_count; ++index) {
            line << ' ';
            append_varnode(line, inputs[index]);
        }

        lines_.push_back(line.str());
    }

private:
    std::vector<std::string> lines_;
};

void initialize_tag_tables_once() {
    static bool initialized = false;
    if (initialized)
        return;
    ghidra::AttributeId::initialize();
    ghidra::ElementId::initialize();
    initialized = true;
}

void decode_processor_context(ghidra::Sleigh& engine,
                              ghidra::ContextInternal& context,
                              ghidra::DocumentStorage& storage) {
    const ghidra::Element* processor_spec = storage.getTag("processor_spec");
    if (processor_spec == nullptr)
        return;

    ghidra::XmlDecode decoder(&engine, processor_spec);
    ghidra::uint4 element_id = decoder.openElement(ghidra::ELEM_PROCESSOR_SPEC);

    for (;;) {
        ghidra::uint4 sub_id = decoder.peekElement();
        if (sub_id == 0)
            break;

        if (sub_id == ghidra::ELEM_CONTEXT_DATA) {
            context.decodeFromSpec(decoder);
            break;
        }

        decoder.openElement();
        decoder.closeElementSkipping(sub_id);
    }

    decoder.closeElement(element_id);
}

ida::Result<std::vector<std::string>> build_pcode_lines_for_function(const ida::function::Function& function) {
    auto processor_context = build_processor_context(function);
    if (!processor_context)
        return std::unexpected(processor_context.error());

    auto spec_choice = choose_spec(*processor_context);
    if (!spec_choice)
        return std::unexpected(spec_choice.error());

    auto sla_path = resolve_spec_file(spec_choice->sla_file);
    if (!sla_path)
        return std::unexpected(sla_path.error());

    std::optional<std::filesystem::path> pspec_path;
    if (spec_choice->pspec_file.has_value()) {
        auto resolved = resolve_spec_file(*spec_choice->pspec_file);
        if (resolved)
            pspec_path = *resolved;
    } else {
        auto candidate = *sla_path;
        candidate.replace_extension(".pspec");
        if (std::filesystem::exists(candidate))
            pspec_path = candidate;
    }

    auto function_bytes = ida::data::read_bytes(function.start(), function.size());
    if (!function_bytes)
        return std::unexpected(function_bytes.error());

    auto instruction_addresses = ida::function::code_addresses(function.start());
    if (!instruction_addresses)
        return std::unexpected(instruction_addresses.error());

    try {
        initialize_tag_tables_once();

        InMemoryLoadImage load_image(function.start());
        load_image.set_image(*function_bytes);

        ghidra::ContextInternal context;
        ghidra::Sleigh sleigh_engine(&load_image, &context);
        ghidra::DocumentStorage storage;

        std::istringstream sleigh_document("<sleigh>" + sla_path->string() + "</sleigh>");
        ghidra::Element* sleigh_root = storage.parseDocument(sleigh_document)->getRoot();
        storage.registerTag(sleigh_root);

        if (pspec_path.has_value()) {
            ghidra::Element* pspec_root = storage.openDocument(pspec_path->string())->getRoot();
            storage.registerTag(pspec_root);
        }

        sleigh_engine.initialize(storage);
        sleigh_engine.allowContextSet(false);
        decode_processor_context(sleigh_engine, context, storage);

        std::vector<std::string> lines;
        lines.reserve(instruction_addresses->size() * 2);

        PcodeCollector collector;

        for (ida::Address address : *instruction_addresses) {
            auto disassembly = ida::instruction::text(address);
            std::string disassembly_text = disassembly ? *disassembly : "<decode failed>";

            const std::string address_tag = ida::lines::colstr(
                format("%016llX", static_cast<unsigned long long>(address)),
                ida::lines::Color::Prefix);
            const std::string disassembly_tag = ida::lines::colstr(disassembly_text,
                                                                   ida::lines::Color::Instruction);
            lines.push_back(address_tag + "  " + disassembly_tag);

            collector.clear();
            try {
                ghidra::Address sleigh_address(sleigh_engine.getDefaultCodeSpace(), address);
                (void)sleigh_engine.oneInstruction(collector, sleigh_address);
                for (const auto& pcode_line : collector.lines()) {
                    lines.push_back("  " + pcode_line);
                }
            } catch (const ghidra::LowlevelError& error) {
                lines.push_back(ida::lines::colstr("  ; sleigh error: " + error.explain,
                                                   ida::lines::Color::Error));
            } catch (const std::exception& error) {
                lines.push_back(ida::lines::colstr("  ; exception: " + std::string(error.what()),
                                                   ida::lines::Color::Error));
            } catch (...) {
                lines.push_back(ida::lines::colstr("  ; unknown exception while lifting instruction",
                                                   ida::lines::Color::Error));
            }
        }

        if (lines.empty()) {
            lines.push_back("No p-code lines produced for this function.");
        }

        return lines;
    } catch (const ghidra::LowlevelError& error) {
        return std::unexpected(ida::Error::sdk("Sleigh initialization failed", error.explain));
    } catch (const std::exception& error) {
        return std::unexpected(ida::Error::internal("Sleigh setup failed", error.what()));
    }
}

ida::Status show_current_function_pcode() {
    auto screen = ida::ui::screen_address();
    if (!screen)
        return std::unexpected(screen.error());

    auto function = ida::function::at(*screen);
    if (!function)
        return std::unexpected(function.error());

    auto pcode_lines = build_pcode_lines_for_function(*function);
    if (!pcode_lines)
        return std::unexpected(pcode_lines.error());

    const std::string function_name = function->name();
    std::string title = "P-Code for " + function_name;
    if (function_name.empty()) {
        title = format("P-Code for sub_%llX", static_cast<unsigned long long>(function->start()));
    }

    auto existing = ida::ui::find_widget(title);
    if (existing) {
        auto update = ida::ui::set_custom_viewer_lines(existing, *pcode_lines);
        if (update) {
            (void)ida::ui::show_widget(existing);
            (void)ida::ui::activate_widget(existing);
            return ida::ok();
        }
        (void)ida::ui::close_widget(existing);
    }

    auto viewer = ida::ui::create_custom_viewer(title, *pcode_lines);
    if (!viewer)
        return std::unexpected(viewer.error());

    auto show = ida::ui::show_widget(*viewer);
    if (!show)
        return std::unexpected(show.error());

    auto activate = ida::ui::activate_widget(*viewer);
    if (!activate)
        return std::unexpected(activate.error());

    return ida::ok();
}

class IdaPcodePortPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {
            .name = "IDA P-Code (idax port)",
            .hotkey = "Ctrl-Alt-S",
            .comment = "Display Sleigh P-code for the current function",
            .help = "Port of idapcode.py to idax + sleigh",
        };
    }

    ida::Status run(std::size_t) override {
        auto status = show_current_function_pcode();
        if (!status) {
            ida::ui::warning("[idax-idapcode] " + error_text(status.error()));
            return std::unexpected(status.error());
        }
        return ida::ok();
    }
};

} // namespace

IDAX_PLUGIN(IdaPcodePortPlugin)
