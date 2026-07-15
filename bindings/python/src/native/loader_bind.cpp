#include "opaque_handle.hpp"

#include <cstdio>
#include <memory>

namespace idax::python {

namespace {

class PythonInputFile {
public:
    PythonInputFile(ida::loader::InputFile& input,
                    std::shared_ptr<OpaqueHandleState> state)
        : input_(&input), state_(std::move(state)) {}

    ida::loader::InputFile& get(std::string_view operation) const {
        if (input_ == nullptr || !state_ || !state_->valid) {
            throw_error(ida::Error::conflict(
                "InputFile is only valid during a loader callback",
                std::string(operation)));
        }
        return *input_;
    }

private:
    ida::loader::InputFile* input_{nullptr};
    std::shared_ptr<OpaqueHandleState> state_;
};

class PythonOutputFile {
public:
    PythonOutputFile(std::FILE* output,
                     std::shared_ptr<OpaqueHandleState> state)
        : output_(output), state_(std::move(state)) {}

    std::FILE* get(std::string_view operation) const {
        if (output_ == nullptr || !state_ || !state_->valid) {
            throw_error(ida::Error::conflict(
                "OutputFile is only valid during a loader save callback",
                std::string(operation)));
        }
        return output_;
    }

    std::size_t write(py::handle buffer) const {
        const auto bytes = buffer_bytes(buffer);
        if (bytes.empty())
            return 0;
        auto* output = get("loader.OutputFile.write");
        const auto written = std::fwrite(bytes.data(), 1, bytes.size(), output);
        if (written != bytes.size()) {
            throw_error(ida::Error::sdk(
                "Failed to write complete loader output buffer"));
        }
        return written;
    }

    void flush() const {
        if (std::fflush(get("loader.OutputFile.flush")) != 0)
            throw_error(ida::Error::sdk("Failed to flush loader output"));
    }

    std::int64_t tell() const {
        const long position = std::ftell(get("loader.OutputFile.tell"));
        if (position < 0)
            throw_error(ida::Error::sdk("Failed to query loader output position"));
        return static_cast<std::int64_t>(position);
    }

private:
    std::FILE* output_{nullptr};
    std::shared_ptr<OpaqueHandleState> state_;
};

template <typename ResultType, typename... Arguments>
ida::Result<ResultType> invoke_loader_result(
    const py::function& callback,
    std::string_view operation,
    Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        return callback(std::forward<Arguments>(arguments)...)
            .template cast<ResultType>();
    } catch (py::error_already_set& error) {
        std::string detail = error.what();
        error.discard_as_unraisable(callback);
        return std::unexpected(ida::Error::internal(
            "Python loader callback failed",
            std::string(operation) + ":" + detail));
    } catch (...) {
        return std::unexpected(ida::Error::internal(
            "Non-Python loader callback failure", std::string(operation)));
    }
}

template <typename... Arguments>
ida::Status invoke_loader_status(
    const py::function& callback,
    std::string_view operation,
    Arguments&&... arguments) noexcept {
    py::gil_scoped_acquire acquire;
    try {
        callback(std::forward<Arguments>(arguments)...);
        return ida::ok();
    } catch (py::error_already_set& error) {
        std::string detail = error.what();
        error.discard_as_unraisable(callback);
        return std::unexpected(ida::Error::internal(
            "Python loader callback failed",
            std::string(operation) + ":" + detail));
    } catch (...) {
        return std::unexpected(ida::Error::internal(
            "Non-Python loader callback failure", std::string(operation)));
    }
}

template <typename Function>
auto with_input_adapter(ida::loader::InputFile& input, Function&& function) {
    auto state = std::make_shared<OpaqueHandleState>();
    PythonInputFile adapter(input, state);
    auto result = std::forward<Function>(function)(adapter);
    state->valid = false;
    return result;
}

class PythonLoader final : public ida::loader::Loader {
public:
    using ida::loader::Loader::Loader;

    ida::loader::LoaderOptions options() const override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "options");
        if (!override)
            return ida::loader::Loader::options();
        try {
            return override().cast<ida::loader::LoaderOptions>();
        } catch (py::error_already_set& error) {
            error.discard_as_unraisable(override);
            return {};
        } catch (...) {
            PyErr_SetString(PyExc_RuntimeError,
                            "Python Loader.options must return LoaderOptions");
            PyErr_WriteUnraisable(override.ptr());
            return {};
        }
    }

    ida::Result<std::optional<ida::loader::AcceptResult>> accept(
        ida::loader::InputFile& input) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "accept");
        if (!override) {
            return std::unexpected(ida::Error::unsupported(
                "Python Loader.accept override is required"));
        }
        return with_input_adapter(input, [&](PythonInputFile& adapter) {
            return invoke_loader_result<std::optional<ida::loader::AcceptResult>>(
                override, "loader.Loader.accept", adapter);
        });
    }

    ida::Status load(ida::loader::InputFile& input,
                     std::string_view format_name) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "load");
        if (!override) {
            return std::unexpected(ida::Error::unsupported(
                "Python Loader.load override is required"));
        }
        return with_input_adapter(input, [&](PythonInputFile& adapter) {
            return invoke_loader_status(
                override, "loader.Loader.load", adapter,
                std::string(format_name));
        });
    }

    ida::Status load_with_request(
        ida::loader::InputFile& input,
        const ida::loader::LoadRequest& request) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "load_with_request");
        if (!override)
            return ida::loader::Loader::load_with_request(input, request);
        return with_input_adapter(input, [&](PythonInputFile& adapter) {
            return invoke_loader_status(
                override, "loader.Loader.load_with_request", adapter, request);
        });
    }

    ida::Result<std::optional<ida::loader::ArchiveMemberResult>> process_archive(
        ida::loader::InputFile& input,
        const ida::loader::ArchiveMemberRequest& request) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "process_archive");
        if (!override)
            return ida::loader::Loader::process_archive(input, request);
        return with_input_adapter(input, [&](PythonInputFile& adapter) {
            return invoke_loader_result<
                std::optional<ida::loader::ArchiveMemberResult>>(
                override, "loader.Loader.process_archive", adapter, request);
        });
    }

    ida::Result<bool> save(void* output, std::string_view format_name) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "save");
        if (!override)
            return ida::loader::Loader::save(output, format_name);
        auto state = std::make_shared<OpaqueHandleState>();
        py::object target = py::none();
        if (output != nullptr) {
            target = py::cast(PythonOutputFile(
                static_cast<std::FILE*>(output), state));
        }
        auto result = invoke_loader_result<bool>(
            override, "loader.Loader.save", target, std::string(format_name));
        state->valid = false;
        return result;
    }

    ida::Result<bool> save_with_request(
        void* output, const ida::loader::SaveRequest& request) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "save_with_request");
        if (!override)
            return ida::loader::Loader::save_with_request(output, request);
        auto state = std::make_shared<OpaqueHandleState>();
        py::object target = py::none();
        if (output != nullptr) {
            target = py::cast(PythonOutputFile(
                static_cast<std::FILE*>(output), state));
        }
        auto result = invoke_loader_result<bool>(
            override, "loader.Loader.save_with_request", target, request);
        state->valid = false;
        return result;
    }

    ida::Status move_segment(ida::Address from, ida::Address to,
                             ida::AddressSize size,
                             std::string_view format_name) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "move_segment");
        if (!override)
            return ida::loader::Loader::move_segment(from, to, size, format_name);
        return invoke_loader_status(
            override, "loader.Loader.move_segment", from, to, size,
            std::string(format_name));
    }

    ida::Status move_segment_with_request(
        ida::Address from, ida::Address to, ida::AddressSize size,
        const ida::loader::MoveSegmentRequest& request) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "move_segment_with_request");
        if (!override) {
            return ida::loader::Loader::move_segment_with_request(
                from, to, size, request);
        }
        return invoke_loader_status(
            override, "loader.Loader.move_segment_with_request",
            from, to, size, request);
    }
};

} // namespace

void bind_loader(py::module_& module) {
    py::module_ loader = module.def_submodule(
        "loader", "Custom loader extension interfaces and database ingestion.");

    py::class_<PythonInputFile>(loader, "InputFile")
        .def("size", [](const PythonInputFile& self) {
            return unwrap(self.get("loader.InputFile.size").size());
        })
        .def("tell", [](const PythonInputFile& self) {
            return unwrap(self.get("loader.InputFile.tell").tell());
        })
        .def("seek", [](const PythonInputFile& self, std::int64_t offset) {
            return unwrap(self.get("loader.InputFile.seek").seek(offset));
        }, py::arg("offset"))
        .def("read_bytes", [](const PythonInputFile& self, std::size_t count) {
            return python_bytes(unwrap(
                self.get("loader.InputFile.read_bytes").read_bytes(count)));
        }, py::arg("count"))
        .def("read_bytes_at", [](const PythonInputFile& self,
                                    std::int64_t offset, std::size_t count) {
            return python_bytes(unwrap(
                self.get("loader.InputFile.read_bytes_at")
                    .read_bytes_at(offset, count)));
        }, py::arg("offset"), py::arg("count"))
        .def("read_string", [](const PythonInputFile& self,
                                  std::int64_t offset, std::size_t max_length) {
            return unwrap(self.get("loader.InputFile.read_string")
                              .read_string(offset, max_length));
        }, py::arg("offset"), py::arg("max_length") = 1024)
        .def("filename", [](const PythonInputFile& self) {
            return unwrap(self.get("loader.InputFile.filename").filename());
        });
    py::class_<PythonOutputFile>(loader, "OutputFile")
        .def("write", &PythonOutputFile::write, py::arg("data"))
        .def("flush", &PythonOutputFile::flush)
        .def("tell", &PythonOutputFile::tell);

#define IDAX_PY_LOADER_VALUE(type_name)                                  \
    py::class_<ida::loader::type_name>(loader, #type_name).def(py::init<>())
    IDAX_PY_LOADER_VALUE(AcceptResult)
        .def_readwrite("format_name", &ida::loader::AcceptResult::format_name)
        .def_readwrite("processor_name", &ida::loader::AcceptResult::processor_name)
        .def_readwrite("priority", &ida::loader::AcceptResult::priority)
        .def_readwrite("archive_loader", &ida::loader::AcceptResult::archive_loader)
        .def_readwrite("continue_probe", &ida::loader::AcceptResult::continue_probe)
        .def_readwrite("prefer_first", &ida::loader::AcceptResult::prefer_first);
    IDAX_PY_LOADER_VALUE(LoaderOptions)
        .def_readwrite("supports_reload", &ida::loader::LoaderOptions::supports_reload)
        .def_readwrite("requires_processor", &ida::loader::LoaderOptions::requires_processor);
    IDAX_PY_LOADER_VALUE(LoadFlags)
        .def_readwrite("create_segments", &ida::loader::LoadFlags::create_segments)
        .def_readwrite("load_resources", &ida::loader::LoadFlags::load_resources)
        .def_readwrite("rename_entries", &ida::loader::LoadFlags::rename_entries)
        .def_readwrite("manual_load", &ida::loader::LoadFlags::manual_load)
        .def_readwrite("fill_gaps", &ida::loader::LoadFlags::fill_gaps)
        .def_readwrite("create_import_segment", &ida::loader::LoadFlags::create_import_segment)
        .def_readwrite("first_file", &ida::loader::LoadFlags::first_file)
        .def_readwrite("binary_code_segment", &ida::loader::LoadFlags::binary_code_segment)
        .def_readwrite("reload", &ida::loader::LoadFlags::reload)
        .def_readwrite("auto_flat_group", &ida::loader::LoadFlags::auto_flat_group)
        .def_readwrite("mini_database", &ida::loader::LoadFlags::mini_database)
        .def_readwrite("loader_options_dialog", &ida::loader::LoadFlags::loader_options_dialog)
        .def_readwrite("load_all_segments", &ida::loader::LoadFlags::load_all_segments);
    IDAX_PY_LOADER_VALUE(LoadRequest)
        .def_readwrite("format_name", &ida::loader::LoadRequest::format_name)
        .def_readwrite("input_name", &ida::loader::LoadRequest::input_name)
        .def_readwrite("archive_name", &ida::loader::LoadRequest::archive_name)
        .def_readwrite("archive_member_name", &ida::loader::LoadRequest::archive_member_name)
        .def_readwrite("flags", &ida::loader::LoadRequest::flags)
        .def_readwrite("is_remote", &ida::loader::LoadRequest::is_remote);
    IDAX_PY_LOADER_VALUE(SaveRequest)
        .def_readwrite("format_name", &ida::loader::SaveRequest::format_name)
        .def_readwrite("capability_query", &ida::loader::SaveRequest::capability_query)
        .def_readwrite("is_remote", &ida::loader::SaveRequest::is_remote);
    IDAX_PY_LOADER_VALUE(MoveSegmentRequest)
        .def_readwrite("format_name", &ida::loader::MoveSegmentRequest::format_name)
        .def_readwrite("whole_program_rebase", &ida::loader::MoveSegmentRequest::whole_program_rebase)
        .def_readwrite("reload", &ida::loader::MoveSegmentRequest::reload);
    IDAX_PY_LOADER_VALUE(ArchiveMemberRequest)
        .def_readwrite("archive_name", &ida::loader::ArchiveMemberRequest::archive_name)
        .def_readwrite("default_member", &ida::loader::ArchiveMemberRequest::default_member)
        .def_readwrite("flags", &ida::loader::ArchiveMemberRequest::flags);
    IDAX_PY_LOADER_VALUE(ArchiveMemberResult)
        .def_readwrite("extracted_file", &ida::loader::ArchiveMemberResult::extracted_file)
        .def_readwrite("member_name", &ida::loader::ArchiveMemberResult::member_name)
        .def_readwrite("flags", &ida::loader::ArchiveMemberResult::flags);
#undef IDAX_PY_LOADER_VALUE

    py::class_<ida::loader::Loader, PythonLoader,
               std::shared_ptr<ida::loader::Loader>>(loader, "Loader")
        .def(py::init<>())
        .def("options", &ida::loader::Loader::options)
        .def("accept", [](ida::loader::Loader& self, PythonInputFile& input) {
            return unwrap(self.accept(input.get("loader.Loader.accept")));
        }, py::arg("input"))
        .def("load", [](ida::loader::Loader& self, PythonInputFile& input,
            std::string format_name) {
            unwrap(self.load(input.get("loader.Loader.load"), format_name));
        }, py::arg("input"), py::arg("format_name"))
        .def("load_with_request", [](ida::loader::Loader& self,
            PythonInputFile& input, const ida::loader::LoadRequest& request) {
            unwrap(self.load_with_request(
                input.get("loader.Loader.load_with_request"), request));
        }, py::arg("input"), py::arg("request"))
        .def("process_archive", [](ida::loader::Loader& self,
            PythonInputFile& input,
            const ida::loader::ArchiveMemberRequest& request) {
            return unwrap(self.process_archive(
                input.get("loader.Loader.process_archive"), request));
        }, py::arg("input"), py::arg("request"))
        .def("save", [](ida::loader::Loader& self, py::object output,
            std::string format_name) {
            void* pointer = nullptr;
            if (!output.is_none()) {
                pointer = output.cast<const PythonOutputFile&>().get(
                    "loader.Loader.save");
            }
            return unwrap(self.save(pointer, format_name));
        }, py::arg("output") = py::none(), py::arg("format_name") = "")
        .def("save_with_request", [](ida::loader::Loader& self,
            py::object output, const ida::loader::SaveRequest& request) {
            void* pointer = nullptr;
            if (!output.is_none()) {
                pointer = output.cast<const PythonOutputFile&>().get(
                    "loader.Loader.save_with_request");
            }
            return unwrap(self.save_with_request(pointer, request));
        }, py::arg("output"), py::arg("request"))
        .def("move_segment", [](ida::loader::Loader& self,
            ida::Address from, ida::Address to, ida::AddressSize size,
            std::string format_name) {
            unwrap(self.move_segment(from, to, size, format_name));
        }, py::arg("from_address"), py::arg("to_address"), py::arg("size"),
           py::arg("format_name") = "")
        .def("move_segment_with_request", [](ida::loader::Loader& self,
            ida::Address from, ida::Address to, ida::AddressSize size,
            const ida::loader::MoveSegmentRequest& request) {
            unwrap(self.move_segment_with_request(from, to, size, request));
        }, py::arg("from_address"), py::arg("to_address"), py::arg("size"),
           py::arg("request"));

    loader.def("decode_load_flags", &ida::loader::decode_load_flags,
               py::arg("raw_flags"));
    loader.def("encode_load_flags", &ida::loader::encode_load_flags,
               py::arg("flags"));
    loader.def("file_to_database", [](const PythonInputFile& input,
        std::int64_t file_offset, ida::Address address, ida::AddressSize size,
        bool patchable) {
        runtime_status("loader.file_to_database", [&] {
            return ida::loader::file_to_database(
                input.get("loader.file_to_database").handle(), file_offset,
                address, size, patchable);
        });
    }, py::arg("input"), py::arg("file_offset"), py::arg("address"),
       py::arg("size"), py::arg("patchable") = true);
    loader.def("memory_to_database", [](py::handle buffer,
        ida::Address address, std::optional<ida::AddressSize> requested_size) {
        auto bytes = buffer_bytes(buffer);
        const auto size = requested_size.value_or(bytes.size());
        if (size > bytes.size()) {
            throw_error(ida::Error::validation(
                "Requested database copy size exceeds input buffer"));
        }
        runtime_status("loader.memory_to_database", [&] {
            return ida::loader::memory_to_database(bytes.data(), address, size);
        });
    }, py::arg("data"), py::arg("address"), py::arg("size") = py::none());
    loader.def("set_processor", [](std::string name) {
        runtime_status("loader.set_processor", [&] {
            return ida::loader::set_processor(name);
        });
    }, py::arg("processor_name"));
    loader.def("create_filename_comment", [] {
        runtime_status("loader.create_filename_comment",
                       ida::loader::create_filename_comment);
    });
    loader.def("abort_load", [](std::string message) {
        ensure_runtime_thread("loader.abort_load");
        ida::loader::abort_load(message);
    }, py::arg("message"));
}

} // namespace idax::python
