#include "common.hpp"

namespace idax::python {

namespace {

template <typename Function>
bool runtime_predicate(std::string_view operation, Function&& function) {
    ensure_runtime_thread(operation);
    return std::forward<Function>(function)();
}

} // namespace

void bind_address(py::module_& module) {
    py::module_ address = module.def_submodule(
        "address", "Address navigation, predicates, searches, and lazy ranges.");

    py::class_<ida::address::Range>(address, "Range")
        .def(py::init<ida::Address, ida::Address>(),
             py::arg("start") = ida::BadAddress,
             py::arg("end") = ida::BadAddress)
        .def_readwrite("start", &ida::address::Range::start)
        .def_readwrite("end", &ida::address::Range::end)
        .def_property_readonly("size", &ida::address::Range::size)
        .def("contains", &ida::address::Range::contains, py::arg("address"))
        .def_property_readonly("empty", &ida::address::Range::empty)
        .def("__contains__", &ida::address::Range::contains)
        .def("__len__", &ida::address::Range::size)
        .def("__bool__", [](const ida::address::Range& range) {
            return !range.empty();
        })
        .def("__repr__", [](const ida::address::Range& range) {
            return "Range(start=" + std::to_string(range.start)
                + ", end=" + std::to_string(range.end) + ")";
        })
        .def("__eq__", [](const ida::address::Range& left,
                          const ida::address::Range& right) {
            return left.start == right.start && left.end == right.end;
        });

    py::native_enum<ida::address::Predicate>(
        address, "Predicate", "enum.Enum")
        .value("MAPPED", ida::address::Predicate::Mapped)
        .value("LOADED", ida::address::Predicate::Loaded)
        .value("CODE", ida::address::Predicate::Code)
        .value("DATA", ida::address::Predicate::Data)
        .value("UNKNOWN", ida::address::Predicate::Unknown)
        .value("HEAD", ida::address::Predicate::Head)
        .value("TAIL", ida::address::Predicate::Tail)
        .export_values()
        .finalize();

    py::class_<ida::address::ItemRange>(address, "ItemRange")
        .def("__iter__", [](const ida::address::ItemRange& range) {
            ensure_runtime_thread("address.ItemRange.__iter__");
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>());

    py::class_<ida::address::PredicateRange>(address, "PredicateRange")
        .def("__iter__", [](const ida::address::PredicateRange& range) {
            ensure_runtime_thread("address.PredicateRange.__iter__");
            return py::make_iterator(range.begin(), range.end());
        }, py::keep_alive<0, 1>());

    address.def("item_start", [](ida::Address value) {
        return runtime_result("address.item_start", [=] {
            return ida::address::item_start(value);
        });
    }, py::arg("address"));
    address.def("item_end", [](ida::Address value) {
        return runtime_result("address.item_end", [=] {
            return ida::address::item_end(value);
        });
    }, py::arg("address"));
    address.def("item_size", [](ida::Address value) {
        return runtime_result("address.item_size", [=] {
            return ida::address::item_size(value);
        });
    }, py::arg("address"));
    address.def("next_head", [](ida::Address value, ida::Address limit) {
        return runtime_result("address.next_head", [=] {
            return ida::address::next_head(value, limit);
        });
    }, py::arg("address"), py::arg("limit") = ida::BadAddress);
    address.def("prev_head", [](ida::Address value, ida::Address limit) {
        return runtime_result("address.prev_head", [=] {
            return ida::address::prev_head(value, limit);
        });
    }, py::arg("address"), py::arg("limit") = 0);
    address.def("next_defined", [](ida::Address value, ida::Address limit) {
        return runtime_result("address.next_defined", [=] {
            return ida::address::next_defined(value, limit);
        });
    }, py::arg("address"), py::arg("limit") = ida::BadAddress);
    address.def("prev_defined", [](ida::Address value, ida::Address limit) {
        return runtime_result("address.prev_defined", [=] {
            return ida::address::prev_defined(value, limit);
        });
    }, py::arg("address"), py::arg("limit") = 0);
    address.def("next_not_tail", [](ida::Address value) {
        return runtime_result("address.next_not_tail", [=] {
            return ida::address::next_not_tail(value);
        });
    }, py::arg("address"));
    address.def("prev_not_tail", [](ida::Address value) {
        return runtime_result("address.prev_not_tail", [=] {
            return ida::address::prev_not_tail(value);
        });
    }, py::arg("address"));
    address.def("next_mapped", [](ida::Address value) {
        return runtime_result("address.next_mapped", [=] {
            return ida::address::next_mapped(value);
        });
    }, py::arg("address"));
    address.def("prev_mapped", [](ida::Address value) {
        return runtime_result("address.prev_mapped", [=] {
            return ida::address::prev_mapped(value);
        });
    }, py::arg("address"));

    address.def("is_mapped", [](ida::Address value) {
        return runtime_predicate("address.is_mapped", [=] {
            return ida::address::is_mapped(value);
        });
    }, py::arg("address"));
    address.def("is_loaded", [](ida::Address value) {
        return runtime_predicate("address.is_loaded", [=] {
            return ida::address::is_loaded(value);
        });
    }, py::arg("address"));
    address.def("is_code", [](ida::Address value) {
        return runtime_predicate("address.is_code", [=] {
            return ida::address::is_code(value);
        });
    }, py::arg("address"));
    address.def("is_data", [](ida::Address value) {
        return runtime_predicate("address.is_data", [=] {
            return ida::address::is_data(value);
        });
    }, py::arg("address"));
    address.def("is_unknown", [](ida::Address value) {
        return runtime_predicate("address.is_unknown", [=] {
            return ida::address::is_unknown(value);
        });
    }, py::arg("address"));
    address.def("is_head", [](ida::Address value) {
        return runtime_predicate("address.is_head", [=] {
            return ida::address::is_head(value);
        });
    }, py::arg("address"));
    address.def("is_tail", [](ida::Address value) {
        return runtime_predicate("address.is_tail", [=] {
            return ida::address::is_tail(value);
        });
    }, py::arg("address"));

    address.def("find_first", [](ida::Address start, ida::Address end,
                                  ida::address::Predicate predicate) {
        return runtime_result("address.find_first", [=] {
            return ida::address::find_first(start, end, predicate);
        });
    }, py::arg("start"), py::arg("end"), py::arg("predicate"));
    address.def("find_next", [](ida::Address value,
                                 ida::address::Predicate predicate,
                                 ida::Address end) {
        return runtime_result("address.find_next", [=] {
            return ida::address::find_next(value, predicate, end);
        });
    }, py::arg("address"), py::arg("predicate"),
       py::arg("end") = ida::BadAddress);

    address.def("items", [](ida::Address start, ida::Address end) {
        ensure_runtime_thread("address.items");
        return ida::address::items(start, end);
    }, py::arg("start"), py::arg("end"));
    address.def("code_items", [](ida::Address start, ida::Address end) {
        ensure_runtime_thread("address.code_items");
        return ida::address::code_items(start, end);
    }, py::arg("start"), py::arg("end"));
    address.def("data_items", [](ida::Address start, ida::Address end) {
        ensure_runtime_thread("address.data_items");
        return ida::address::data_items(start, end);
    }, py::arg("start"), py::arg("end"));
    address.def("unknown_bytes", [](ida::Address start, ida::Address end) {
        ensure_runtime_thread("address.unknown_bytes");
        return ida::address::unknown_bytes(start, end);
    }, py::arg("start"), py::arg("end"));
}

} // namespace idax::python
