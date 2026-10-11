/// Full Diaphora application launcher using the opaque scripting boundary.
#include <ida/idax.hpp>

#include <string>

namespace {
class DiaphoraFullPlugin final : public ida::plugin::Plugin {
public:
    ida::plugin::Info info() const override {
        return {.name = "Diaphora Complete", .hotkey = "Ctrl-Alt-Shift-B",
                .comment = "Open native Diaphora matching and metadata results",
                .help = "Select a JSON configuration with upstream and results paths. "
                        "The shared complete application displays native result choosers."};
    }

    ida::Status run(std::size_t) override {
        auto configuration = ida::ui::ask_file(false, "*.json", "Diaphora result configuration");
        if (!configuration)
            return std::unexpected(configuration.error());
        if (configuration->empty())
            return ida::ok();
        std::string encoded;
        constexpr char digits[] = "0123456789abcdef";
        for (unsigned char byte : *configuration) {
            encoded += digits[byte >> 4];
            encoded += digits[byte & 15];
        }
        const std::string statement =
            "__import__('examples.diaphora.gui', fromlist=['launch']).launch("
            "bytes.fromhex('" + encoded + "').decode('utf-8'))";
        auto result = ida::script::call("exec_python", {ida::script::Value(statement)});
        if (!result)
            return std::unexpected(result.error());
        if (!result->succeeded)
            return std::unexpected(ida::Error::sdk(result->error));
        if (auto error = result->value.as_string(); error)
            return std::unexpected(ida::Error::sdk(*error));
        auto code = result->value.as_integer();
        if (!code || *code != 0)
            return std::unexpected(ida::Error::sdk("Python application did not complete"));
        return ida::ok();
    }
};
}

IDAX_PLUGIN_WITH_FLAGS(DiaphoraFullPlugin,
                      ida::plugin::ExportFlags{.modifies_database = true})
