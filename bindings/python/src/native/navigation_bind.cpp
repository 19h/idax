#include "common.hpp"

namespace idax::python {

void bind_navigation(py::module_& module) {
    py::module_ navigation = module.def_submodule(
        "navigation", "Opaque persistent address navigation history.");

    py::class_<ida::navigation::Entry>(navigation, "Entry")
        .def(py::init<>())
        .def_readwrite("address", &ida::navigation::Entry::address)
        .def_readwrite("channel", &ida::navigation::Entry::channel)
        .def_readwrite("metadata", &ida::navigation::Entry::metadata)
        .def("__eq__",
             [](const ida::navigation::Entry& left,
                const ida::navigation::Entry& right) { return left == right; })
        .def("__repr__", [](const ida::navigation::Entry& value) {
            return "Entry(address=" + std::to_string(value.address) +
                   ", channel=" +
                   py::repr(py::str(value.channel)).cast<std::string>() +
                   ", metadata=" +
                   py::repr(py::str(value.metadata)).cast<std::string>() + ")";
        });

    py::class_<ida::navigation::History>(navigation, "History")
        .def_property_readonly("name", &ida::navigation::History::name)
        .def_property_readonly("created", &ida::navigation::History::created)
        .def_property_readonly("entries",
             [](const ida::navigation::History& history) {
                 return runtime_result("navigation.History.entries", [&] {
                     return history.entries();
                 });
             })
        .def_property_readonly("size",
             [](const ida::navigation::History& history) {
                 return runtime_result("navigation.History.size", [&] {
                     return history.size();
                 });
             })
        .def_property_readonly("index",
             [](const ida::navigation::History& history) {
                 return runtime_result("navigation.History.index", [&] {
                     return history.index();
                 });
             })
        .def_property_readonly("current",
             [](const ida::navigation::History& history) {
                 return runtime_result("navigation.History.current", [&] {
                     return history.current();
                 });
             })
        .def("current_for",
             [](const ida::navigation::History& history,
                const std::string& channel) {
                 return runtime_result("navigation.History.current_for", [&] {
                     return history.current_for(channel);
                 });
             }, py::arg("channel"))
        .def_property_readonly("all_current",
             [](const ida::navigation::History& history) {
                 return runtime_result("navigation.History.all_current", [&] {
                     return history.all_current();
                 });
             })
        .def("set_current",
             [](const ida::navigation::History& history,
                const ida::navigation::Entry& entry,
                bool record_in_history) {
                 runtime_status("navigation.History.set_current", [&] {
                     return history.set_current(entry, record_in_history);
                 });
             }, py::arg("entry"), py::arg("record_in_history") = false)
        .def("push",
             [](const ida::navigation::History& history,
                const ida::navigation::Entry& entry) {
                 return runtime_result("navigation.History.push", [&] {
                     return history.push(entry);
                 });
             }, py::arg("entry"))
        .def("seek",
             [](const ida::navigation::History& history, std::size_t index) {
                 return runtime_result("navigation.History.seek", [&] {
                     return history.seek(index);
                 });
             }, py::arg("index"))
        .def("back",
             [](const ida::navigation::History& history, std::size_t count) {
                 return runtime_result("navigation.History.back", [&] {
                     return history.back(count);
                 });
             }, py::arg("count") = 1)
        .def("forward",
             [](const ida::navigation::History& history, std::size_t count) {
                 return runtime_result("navigation.History.forward", [&] {
                     return history.forward(count);
                 });
             }, py::arg("count") = 1)
        .def("replace",
             [](const ida::navigation::History& history, std::size_t index,
                const ida::navigation::Entry& entry) {
                 runtime_status("navigation.History.replace", [&] {
                     return history.replace(index, entry);
                 });
             }, py::arg("index"), py::arg("entry"))
        .def("clear",
             [](const ida::navigation::History& history,
                const ida::navigation::Entry& new_tip) {
                 runtime_status("navigation.History.clear", [&] {
                     return history.clear(new_tip);
                 });
             }, py::arg("new_tip"))
        .def("transfer_channel_to",
             [](const ida::navigation::History& history,
                const ida::navigation::History& destination,
                const std::string& channel, bool retain_history) {
                 runtime_status("navigation.History.transfer_channel_to", [&] {
                     return history.transfer_channel_to(destination, channel,
                                                        retain_history);
                 });
             }, py::arg("destination"), py::arg("channel"),
             py::arg("retain_history") = true);

    navigation.def(
        "open",
        [](const std::string& name, const ida::navigation::Entry& initial) {
            return runtime_result("navigation.open", [&] {
                return ida::navigation::History::open(name, initial);
            });
        },
        py::arg("name"), py::arg("initial"));
}

} // namespace idax::python
