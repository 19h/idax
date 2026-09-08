#ifndef IDAX_SWIFT_MODULE_HPP
#define IDAX_SWIFT_MODULE_HPP
#include <ida/loader.hpp>
#include <ida/plugin.hpp>
#include <ida/processor.hpp>
#include <memory>
namespace idax::swift {
struct ModuleState;
class PluginAdapter : public ida::plugin::Plugin {
    std::shared_ptr<ModuleState> state;

  public:
    explicit PluginAdapter(void (*bootstrap)());
    ida::plugin::Info info() const override;
    ida::plugin::ExportFlags export_flags() const;
    bool init() override;
    ida::Status run(std::size_t) override;
    void term() override;
};
ida::plugin::ExportFlags plugin_export_flags(void (*bootstrap)());
class LoaderAdapter : public ida::loader::Loader {
    std::shared_ptr<ModuleState> state;

  public:
    explicit LoaderAdapter(void (*bootstrap)());
    ida::loader::LoaderOptions options() const override;
    ida::Result<std::optional<ida::loader::AcceptResult>> accept(ida::loader::InputFile&) override;
    ida::Status load(ida::loader::InputFile&, std::string_view) override;
    ida::Status load_with_request(ida::loader::InputFile&,
                                  const ida::loader::LoadRequest&) override;
    ida::Result<std::optional<ida::loader::ArchiveMemberResult>>
    process_archive(ida::loader::InputFile&, const ida::loader::ArchiveMemberRequest&) override;
    ida::Result<bool> save(void*, std::string_view) override;
    ida::Result<bool> save_with_request(void*, const ida::loader::SaveRequest&) override;
    ida::Status move_segment(ida::Address, ida::Address, ida::AddressSize,
                             std::string_view) override;
    ida::Status move_segment_with_request(ida::Address, ida::Address, ida::AddressSize,
                                          const ida::loader::MoveSegmentRequest&) override;
};
class ProcessorAdapter : public ida::processor::Processor {
    std::shared_ptr<ModuleState> state;

  public:
    explicit ProcessorAdapter(void (*bootstrap)());
    ida::processor::ProcessorInfo info() const override;
    ida::Result<int> analyze(ida::Address) override;
    ida::Result<ida::processor::AnalyzeDetails> analyze_with_details(ida::Address) override;
    ida::processor::EmulateResult emulate(ida::Address) override;
    void output_instruction(ida::Address) override;
    ida::processor::OutputOperandResult output_operand(ida::Address, int) override;
    ida::processor::OutputInstructionResult
    output_mnemonic_with_context(ida::Address, ida::processor::OutputContext&) override;
    ida::processor::OutputInstructionResult
    output_instruction_with_context(ida::Address, ida::processor::OutputContext&) override;
    ida::processor::OutputOperandResult
    output_operand_with_context(ida::Address, int, ida::processor::OutputContext&) override;
    void on_new_file(std::string_view) override;
    void on_old_file(std::string_view) override;
    int is_call(ida::Address) override;
    int is_return(ida::Address) override;
    int may_be_function(ida::Address) override;
    int is_sane_instruction(ida::Address, bool) override;
    int is_indirect_jump(ida::Address) override;
    int is_basic_block_end(ida::Address, bool) override;
    bool create_function_frame(ida::Address) override;
    int adjust_function_bounds(ida::Address, ida::Address, int) override;
    int analyze_function_prolog(ida::Address) override;
    int calculate_stack_pointer_delta(ida::Address, std::int64_t&) override;
    int get_return_address_size(ida::Address) override;
    int detect_switch(ida::Address, ida::processor::SwitchDescription&) override;
    int calculate_switch_cases(ida::Address, const ida::processor::SwitchDescription&,
                               std::vector<ida::processor::SwitchCase>&) override;
    int create_switch_references(ida::Address, const ida::processor::SwitchDescription&) override;
};
} // namespace idax::swift
#endif
