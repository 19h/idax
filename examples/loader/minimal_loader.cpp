#include <ida/idax.hpp>

#include <optional>

class MinimalLoader final : public ida::loader::Loader {
public:
    ida::Result<std::optional<ida::loader::AcceptResult>>
    accept(ida::loader::InputFile& file) override {
        auto magic = file.read_bytes_at(0, 4);
        if (!magic || magic->size() < 4)
            return std::nullopt;

        // Accept ELF binaries for demonstration purposes.
        if ((*magic)[0] == 0x7F && (*magic)[1] == 'E' &&
            (*magic)[2] == 'L' && (*magic)[3] == 'F') {
            ida::loader::AcceptResult r;
            r.format_name = "idax minimal ELF";
            r.processor_name = "metapc";
            r.priority = 1;
            return r;
        }
        return std::nullopt;
    }

    ida::Status load(ida::loader::InputFile& file, std::string_view) override {
        auto processor = ida::loader::set_processor("metapc");
        if (!processor)
            return processor;

        // Load the first 0x1000 bytes at a sample base address.
        auto status = ida::loader::file_to_database(file.handle(), 0, 0x400000, 0x1000, true);
        if (!status)
            return status;

        return ida::loader::create_filename_comment();
    }
};

IDAX_LOADER(MinimalLoader)
