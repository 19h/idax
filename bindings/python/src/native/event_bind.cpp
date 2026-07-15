#include "common.hpp"

namespace idax::python {

namespace {

template <typename... Arguments>
void invoke_callback(const py::function& callback, Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python event callback failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
}

template <typename... Arguments>
bool invoke_filter(const py::function& callback, Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...).template cast<bool>();
    } catch (py::error_already_set& error) {
        error.discard_as_unraisable(callback);
    } catch (...) {
        PyErr_SetString(PyExc_RuntimeError, "non-Python event filter failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return false;
}

} // namespace

void bind_event(py::module_& module) {
    py::module_ event = module.def_submodule(
        "event", "Typed IDB event subscriptions and deterministic guards.");

    py::native_enum<ida::event::EventKind>(event, "EventKind", "enum.Enum")
        .value("SEGMENT_ADDED", ida::event::EventKind::SegmentAdded)
        .value("SEGMENT_DELETED", ida::event::EventKind::SegmentDeleted)
        .value("FUNCTION_ADDED", ida::event::EventKind::FunctionAdded)
        .value("FUNCTION_DELETED", ida::event::EventKind::FunctionDeleted)
        .value("RENAMED", ida::event::EventKind::Renamed)
        .value("BYTE_PATCHED", ida::event::EventKind::BytePatched)
        .value("COMMENT_CHANGED", ida::event::EventKind::CommentChanged)
        .value("SEGMENT_MOVED", ida::event::EventKind::SegmentMoved)
        .value("FUNCTION_UPDATED", ida::event::EventKind::FunctionUpdated)
        .value("ITEM_TYPE_CHANGED", ida::event::EventKind::ItemTypeChanged)
        .value("OPERAND_TYPE_CHANGED", ida::event::EventKind::OperandTypeChanged)
        .value("CODE_CREATED", ida::event::EventKind::CodeCreated)
        .value("DATA_CREATED", ida::event::EventKind::DataCreated)
        .value("ITEMS_DESTROYED", ida::event::EventKind::ItemsDestroyed)
        .value("EXTRA_COMMENT_CHANGED", ida::event::EventKind::ExtraCommentChanged)
        .value("LOCAL_TYPES_CHANGED", ida::event::EventKind::LocalTypesChanged)
        .finalize();
    py::native_enum<ida::event::ExtraCommentPlacement>(
        event, "ExtraCommentPlacement", "enum.Enum")
        .value("UNKNOWN", ida::event::ExtraCommentPlacement::Unknown)
        .value("ANTERIOR", ida::event::ExtraCommentPlacement::Anterior)
        .value("POSTERIOR", ida::event::ExtraCommentPlacement::Posterior)
        .finalize();
    py::native_enum<ida::event::LocalTypeChangeKind>(
        event, "LocalTypeChangeKind", "enum.Enum")
        .value("NONE", ida::event::LocalTypeChangeKind::None)
        .value("ADDED", ida::event::LocalTypeChangeKind::Added)
        .value("DELETED", ida::event::LocalTypeChangeKind::Deleted)
        .value("EDITED", ida::event::LocalTypeChangeKind::Edited)
        .value("ALIASED", ida::event::LocalTypeChangeKind::Aliased)
        .value("COMPILER_CHANGED", ida::event::LocalTypeChangeKind::CompilerChanged)
        .value("LIBRARY_LOADED", ida::event::LocalTypeChangeKind::LibraryLoaded)
        .value("LIBRARY_UNLOADED", ida::event::LocalTypeChangeKind::LibraryUnloaded)
        .value("ORDINALS_COMPACTED", ida::event::LocalTypeChangeKind::OrdinalsCompacted)
        .finalize();

#define IDAX_PY_EVENT_VALUE(type_name)                                   \
    py::class_<ida::event::type_name>(event, #type_name).def(py::init<>())
    IDAX_PY_EVENT_VALUE(SegmentMovedEvent)
        .def_readwrite("from_address", &ida::event::SegmentMovedEvent::from)
        .def_readwrite("to_address", &ida::event::SegmentMovedEvent::to)
        .def_readwrite("size", &ida::event::SegmentMovedEvent::size)
        .def_readwrite("address_mapping_changed",
                       &ida::event::SegmentMovedEvent::address_mapping_changed);
    IDAX_PY_EVENT_VALUE(ItemCreatedEvent)
        .def_readwrite("address", &ida::event::ItemCreatedEvent::address)
        .def_readwrite("size", &ida::event::ItemCreatedEvent::size);
    IDAX_PY_EVENT_VALUE(ItemsDestroyedEvent)
        .def_readwrite("start", &ida::event::ItemsDestroyedEvent::start)
        .def_readwrite("end", &ida::event::ItemsDestroyedEvent::end)
        .def_readwrite("will_disable_range",
                       &ida::event::ItemsDestroyedEvent::will_disable_range);
    IDAX_PY_EVENT_VALUE(ExtraCommentChangedEvent)
        .def_readwrite("address", &ida::event::ExtraCommentChangedEvent::address)
        .def_readwrite("placement",
                       &ida::event::ExtraCommentChangedEvent::placement)
        .def_readwrite("line_index", &ida::event::ExtraCommentChangedEvent::line_index)
        .def_readwrite("text", &ida::event::ExtraCommentChangedEvent::text);
    IDAX_PY_EVENT_VALUE(LocalTypesChangedEvent)
        .def_readwrite("change", &ida::event::LocalTypesChangedEvent::change)
        .def_readwrite("ordinal", &ida::event::LocalTypesChangedEvent::ordinal)
        .def_readwrite("name", &ida::event::LocalTypesChangedEvent::name);
    IDAX_PY_EVENT_VALUE(Event)
        .def_readwrite("kind", &ida::event::Event::kind)
        .def_readwrite("address", &ida::event::Event::address)
        .def_readwrite("secondary_address", &ida::event::Event::secondary_address)
        .def_readwrite("new_name", &ida::event::Event::new_name)
        .def_readwrite("old_name", &ida::event::Event::old_name)
        .def_readwrite("old_value", &ida::event::Event::old_value)
        .def_readwrite("repeatable", &ida::event::Event::repeatable)
        .def_readwrite("size", &ida::event::Event::size)
        .def_readwrite("operand_index", &ida::event::Event::operand_index)
        .def_readwrite("line_index", &ida::event::Event::line_index)
        .def_readwrite("text", &ida::event::Event::text)
        .def_readwrite("will_disable_range", &ida::event::Event::will_disable_range)
        .def_readwrite("address_mapping_changed",
                       &ida::event::Event::address_mapping_changed)
        .def_readwrite("extra_comment_placement",
                       &ida::event::Event::extra_comment_placement)
        .def_readwrite("local_type_change", &ida::event::Event::local_type_change)
        .def_readwrite("type_ordinal", &ida::event::Event::type_ordinal)
        .def_readwrite("type_name", &ida::event::Event::type_name);
#undef IDAX_PY_EVENT_VALUE

    py::class_<ida::event::ScopedSubscription>(event, "ScopedSubscription")
        .def(py::init<ida::event::Token>(), py::arg("token"))
        .def_property_readonly("token", &ida::event::ScopedSubscription::token)
        .def("close", [](ida::event::ScopedSubscription& self) {
            self = ida::event::ScopedSubscription{};
        })
        .def("__enter__", [](ida::event::ScopedSubscription& self)
             -> ida::event::ScopedSubscription& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](ida::event::ScopedSubscription& self,
                             py::object, py::object, py::object) {
            self = ida::event::ScopedSubscription{};
            return false;
        });

    event.def("unsubscribe", [](ida::event::Token token) {
        runtime_status("event.unsubscribe", [=] { return ida::event::unsubscribe(token); });
    }, py::arg("token"));

    event.def("on_segment_added", [](py::function callback) {
        return runtime_result("event.on_segment_added", [&] {
            return ida::event::on_segment_added(
                [callback = std::move(callback)](ida::Address start) {
                    invoke_callback(callback, start);
                });
        });
    }, py::arg("callback"));
    event.def("on_segment_deleted", [](py::function callback) {
        return runtime_result("event.on_segment_deleted", [&] {
            return ida::event::on_segment_deleted(
                [callback = std::move(callback)](ida::Address start, ida::Address end) {
                    invoke_callback(callback, start, end);
                });
        });
    }, py::arg("callback"));
    event.def("on_function_added", [](py::function callback) {
        return runtime_result("event.on_function_added", [&] {
            return ida::event::on_function_added(
                [callback = std::move(callback)](ida::Address address) {
                    invoke_callback(callback, address);
                });
        });
    }, py::arg("callback"));
    event.def("on_function_deleted", [](py::function callback) {
        return runtime_result("event.on_function_deleted", [&] {
            return ida::event::on_function_deleted(
                [callback = std::move(callback)](ida::Address address) {
                    invoke_callback(callback, address);
                });
        });
    }, py::arg("callback"));
    event.def("on_renamed", [](py::function callback) {
        return runtime_result("event.on_renamed", [&] {
            return ida::event::on_renamed(
                [callback = std::move(callback)](
                    ida::Address address, std::string new_name, std::string old_name) {
                    invoke_callback(callback, address, new_name, old_name);
                });
        });
    }, py::arg("callback"));
    event.def("on_byte_patched", [](py::function callback) {
        return runtime_result("event.on_byte_patched", [&] {
            return ida::event::on_byte_patched(
                [callback = std::move(callback)](
                    ida::Address address, std::uint32_t old_value) {
                    invoke_callback(callback, address, old_value);
                });
        });
    }, py::arg("callback"));
    event.def("on_comment_changed", [](py::function callback) {
        return runtime_result("event.on_comment_changed", [&] {
            return ida::event::on_comment_changed(
                [callback = std::move(callback)](
                    ida::Address address, bool repeatable) {
                    invoke_callback(callback, address, repeatable);
                });
        });
    }, py::arg("callback"));

#define IDAX_PY_EVENT_STRUCT_CALLBACK(fn, type_name)                     \
    event.def(#fn, [](py::function callback) {                           \
        return runtime_result("event." #fn, [&] {                        \
            return ida::event::fn([callback = std::move(callback)](      \
                const ida::event::type_name& value) {                    \
                invoke_callback(callback, value);                        \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_segment_moved, SegmentMovedEvent);
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_code_created, ItemCreatedEvent);
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_data_created, ItemCreatedEvent);
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_items_destroyed, ItemsDestroyedEvent);
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_extra_comment_changed, ExtraCommentChangedEvent);
    IDAX_PY_EVENT_STRUCT_CALLBACK(on_local_types_changed, LocalTypesChangedEvent);
#undef IDAX_PY_EVENT_STRUCT_CALLBACK

#define IDAX_PY_EVENT_ADDRESS_CALLBACK(fn)                               \
    event.def(#fn, [](py::function callback) {                           \
        return runtime_result("event." #fn, [&] {                        \
            return ida::event::fn([callback = std::move(callback)](ida::Address address) { \
                invoke_callback(callback, address);                      \
            });                                                           \
        });                                                               \
    }, py::arg("callback"))
    IDAX_PY_EVENT_ADDRESS_CALLBACK(on_function_updated);
    IDAX_PY_EVENT_ADDRESS_CALLBACK(on_item_type_changed);
#undef IDAX_PY_EVENT_ADDRESS_CALLBACK

    event.def("on_operand_type_changed", [](py::function callback) {
        return runtime_result("event.on_operand_type_changed", [&] {
            return ida::event::on_operand_type_changed(
                [callback = std::move(callback)](ida::Address address, int index) {
                    invoke_callback(callback, address, index);
                });
        });
    }, py::arg("callback"));
    event.def("on_event", [](py::function callback) {
        return runtime_result("event.on_event", [&] {
            return ida::event::on_event(
                [callback = std::move(callback)](const ida::event::Event& value) {
                    invoke_callback(callback, value);
                });
        });
    }, py::arg("callback"));
    event.def("on_event_filtered", [](py::function filter,
                                       py::function callback) {
        return runtime_result("event.on_event_filtered", [&] {
            return ida::event::on_event_filtered(
                [filter = std::move(filter)](const ida::event::Event& value) {
                    return invoke_filter(filter, value);
                },
                [callback = std::move(callback)](const ida::event::Event& value) {
                    invoke_callback(callback, value);
                });
        });
    }, py::arg("filter"), py::arg("callback"));
}

} // namespace idax::python
