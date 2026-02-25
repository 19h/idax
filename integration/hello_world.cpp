#include <ida/idax.hpp>

#include <cstdint>
#include <string>

struct HelloWorldPlugin : ida::plugin::Plugin {
    HelloWorldPlugin() {
        ida::ui::message("HelloWorldPlugin loaded.\n");
    }

    ida::plugin::Info info() const override {
        return {
            .name    = "Hello World Plugin",
            .hotkey  = "Ctrl-Shift-H",
            .comment = "Prints hello world when shortcut is pressed",
            .help    = "Press Ctrl-Shift-H to print hello world",
        };
    }

    ida::Status run(std::size_t) override {
        ida::ui::message("hello world\n");
        return ida::ok();
    }
};

IDAX_PLUGIN(HelloWorldPlugin)
