/// \file directory_bind.cpp
/// \brief NAN bindings for opaque standard database directory trees.

#include "helpers.hpp"

#include <ida/directory.hpp>

#include <cmath>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace idax_node {
namespace {

std::string exact_string(v8::Local<v8::Value> value) {
    Nan::Utf8String text(value);
    return *text == nullptr
        ? std::string{}
        : std::string(*text, static_cast<std::size_t>(text.length()));
}

bool string_argument(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                     std::string& output) {
    if (index >= info.Length() || !info[index]->IsString()) {
        Nan::ThrowTypeError("Expected string argument");
        return false;
    }
    output = exact_string(info[index]);
    return true;
}

bool kind_from_value(v8::Local<v8::Value> value,
                     ida::directory::Kind& output) {
    if (!value->IsString()) {
        Nan::ThrowTypeError("Directory kind must be a string");
        return false;
    }
    const std::string kind = exact_string(value);
    if (kind == "localTypes") output = ida::directory::Kind::LocalTypes;
    else if (kind == "functions") output = ida::directory::Kind::Functions;
    else if (kind == "names") output = ida::directory::Kind::Names;
    else if (kind == "imports") output = ida::directory::Kind::Imports;
    else if (kind == "idaPlaceBookmarks") output = ida::directory::Kind::IdaPlaceBookmarks;
    else if (kind == "breakpoints") output = ida::directory::Kind::Breakpoints;
    else if (kind == "localTypeBookmarks") output = ida::directory::Kind::LocalTypeBookmarks;
    else if (kind == "snippets") output = ida::directory::Kind::Snippets;
    else {
        Nan::ThrowRangeError("Unknown standard directory-tree kind");
        return false;
    }
    return true;
}

const char* kind_name(ida::directory::Kind kind) {
    switch (kind) {
        case ida::directory::Kind::LocalTypes: return "localTypes";
        case ida::directory::Kind::Functions: return "functions";
        case ida::directory::Kind::Names: return "names";
        case ida::directory::Kind::Imports: return "imports";
        case ida::directory::Kind::IdaPlaceBookmarks: return "idaPlaceBookmarks";
        case ida::directory::Kind::Breakpoints: return "breakpoints";
        case ida::directory::Kind::LocalTypeBookmarks: return "localTypeBookmarks";
        case ida::directory::Kind::Snippets: return "snippets";
    }
    return "unknown";
}

const char* operation_error_name(ida::directory::OperationError error) {
    switch (error) {
        case ida::directory::OperationError::AlreadyExists: return "alreadyExists";
        case ida::directory::OperationError::NotFound: return "notFound";
        case ida::directory::OperationError::NotDirectory: return "notDirectory";
        case ida::directory::OperationError::NotEmpty: return "notEmpty";
        case ida::directory::OperationError::BadPath: return "badPath";
        case ida::directory::OperationError::CannotRename: return "cannotRename";
        case ida::directory::OperationError::OwnChild: return "ownChild";
        case ida::directory::OperationError::DirectoryLimit: return "directoryLimit";
        case ida::directory::OperationError::NotOrderable: return "notOrderable";
        case ida::directory::OperationError::SdkFailure: return "sdkFailure";
    }
    return "sdkFailure";
}

v8::Local<v8::Object> entry_to_object(const ida::directory::Entry& entry) {
    return ObjectBuilder()
        .setStr("path", entry.path)
        .setStr("name", entry.name)
        .setStr("displayName", entry.display_name)
        .setStr("attributes", entry.attributes)
        .set("kind", FromString(entry.is_directory() ? "directory" : "item"))
        .build();
}

v8::Local<v8::Array> entries_to_array(
    const std::vector<ida::directory::Entry>& entries) {
    auto output = Nan::New<v8::Array>(static_cast<int>(entries.size()));
    for (std::size_t index = 0; index < entries.size(); ++index) {
        Nan::Set(output, static_cast<std::uint32_t>(index),
                 entry_to_object(entries[index]));
    }
    return output;
}

v8::Local<v8::Object> bulk_report_to_object(
    const ida::directory::BulkReport& report) {
    auto failures = Nan::New<v8::Array>(static_cast<int>(report.failures.size()));
    for (std::size_t index = 0; index < report.failures.size(); ++index) {
        const auto& failure = report.failures[index];
        auto object = ObjectBuilder()
            .setSize("inputIndex", failure.input_index)
            .setStr("path", failure.path)
            .set("error", FromString(operation_error_name(failure.error)))
            .setStr("message", failure.message)
            .build();
        Nan::Set(failures, static_cast<std::uint32_t>(index), object);
    }
    return ObjectBuilder()
        .set("affectedPaths", StringVectorToArray(report.affected_paths))
        .set("failures", failures)
        .setBool("ok", report.ok())
        .build();
}

bool path_array(v8::Local<v8::Value> value,
                std::vector<std::string>& output) {
    if (!value->IsArray()) {
        Nan::ThrowTypeError("Directory paths must be an array of strings");
        return false;
    }
    const auto array = value.As<v8::Array>();
    output.reserve(array->Length());
    for (std::uint32_t index = 0; index < array->Length(); ++index) {
        const auto element = Nan::Get(array, index).ToLocalChecked();
        if (!element->IsString()) {
            Nan::ThrowTypeError("Directory paths must be an array of strings");
            return false;
        }
        output.push_back(exact_string(element));
    }
    return true;
}

bool signed_delta(v8::Local<v8::Value> value, std::ptrdiff_t& output) {
    if (!value->IsNumber()) {
        Nan::ThrowTypeError("Directory rank delta must be a safe integer");
        return false;
    }
    const double number = Nan::To<double>(value).FromJust();
    constexpr double safe_limit = 9007199254740991.0;
    if (!std::isfinite(number) || std::trunc(number) != number
        || number < -safe_limit || number > safe_limit
        || number < static_cast<double>(std::numeric_limits<std::ptrdiff_t>::min())
        || number > static_cast<double>(std::numeric_limits<std::ptrdiff_t>::max())) {
        Nan::ThrowRangeError("Directory rank delta must be a safe integer");
        return false;
    }
    output = static_cast<std::ptrdiff_t>(number);
    return true;
}

bool optional_rank(Nan::NAN_METHOD_ARGS_TYPE info, int index,
                   std::optional<std::size_t>& output) {
    if (index >= info.Length() || info[index]->IsNull()
        || info[index]->IsUndefined()) {
        output.reset();
        return true;
    }
    if (!info[index]->IsNumber()) {
        Nan::ThrowTypeError("Destination rank must be a non-negative safe integer");
        return false;
    }
    const double number = Nan::To<double>(info[index]).FromJust();
    if (!std::isfinite(number) || std::trunc(number) != number || number < 0
        || number > 9007199254740991.0
        || number > static_cast<double>(std::numeric_limits<std::size_t>::max())) {
        Nan::ThrowRangeError("Destination rank must be a non-negative safe integer");
        return false;
    }
    output = static_cast<std::size_t>(number);
    return true;
}

class TreeWrapper final : public Nan::ObjectWrap {
public:
    static NAN_MODULE_INIT(Init);
    static NAN_METHOD(Open);

private:
    TreeWrapper() = default;
    ~TreeWrapper() override = default;

    ida::directory::Tree& tree() { return *tree_; }
    static TreeWrapper* unwrap(Nan::NAN_METHOD_ARGS_TYPE info) {
        return Nan::ObjectWrap::Unwrap<TreeWrapper>(info.Holder());
    }

    static Nan::Persistent<v8::Function> constructor_;
    std::optional<ida::directory::Tree> tree_;

    static NAN_METHOD(Kind);
    static NAN_METHOD(IsOrderable);
    static NAN_METHOD(CurrentDirectory);
    static NAN_METHOD(ChangeDirectory);
    static NAN_METHOD(AbsolutePath);
    static NAN_METHOD(Contains);
    static NAN_METHOD(Entry);
    static NAN_METHOD(Children);
    static NAN_METHOD(Snapshot);
    static NAN_METHOD(FindItems);
    static NAN_METHOD(CreateDirectory);
    static NAN_METHOD(RemoveDirectory);
    static NAN_METHOD(Link);
    static NAN_METHOD(Unlink);
    static NAN_METHOD(Rename);
    static NAN_METHOD(FoldCommonPrefix);
    static NAN_METHOD(HasNaturalOrder);
    static NAN_METHOD(SetNaturalOrder);
    static NAN_METHOD(Rank);
    static NAN_METHOD(ChangeRank);
    static NAN_METHOD(Move);
    static NAN_METHOD(Remove);
};

Nan::Persistent<v8::Function> TreeWrapper::constructor_;

NAN_MODULE_INIT(TreeWrapper::Init) {
    (void)target;
    auto tpl = Nan::New<v8::FunctionTemplate>(
        [](const Nan::FunctionCallbackInfo<v8::Value>& info) {
            if (!info.IsConstructCall()) {
                Nan::ThrowError("Use directory.open() to acquire a standard tree");
                return;
            }
            auto* wrapper = new TreeWrapper();
            wrapper->Wrap(info.This());
            info.GetReturnValue().Set(info.This());
        });
    tpl->SetClassName(FromString("DirectoryTree"));
    tpl->InstanceTemplate()->SetInternalFieldCount(1);
    Nan::SetPrototypeMethod(tpl, "kind", Kind);
    Nan::SetPrototypeMethod(tpl, "isOrderable", IsOrderable);
    Nan::SetPrototypeMethod(tpl, "currentDirectory", CurrentDirectory);
    Nan::SetPrototypeMethod(tpl, "changeDirectory", ChangeDirectory);
    Nan::SetPrototypeMethod(tpl, "absolutePath", AbsolutePath);
    Nan::SetPrototypeMethod(tpl, "contains", Contains);
    Nan::SetPrototypeMethod(tpl, "entry", Entry);
    Nan::SetPrototypeMethod(tpl, "children", Children);
    Nan::SetPrototypeMethod(tpl, "snapshot", Snapshot);
    Nan::SetPrototypeMethod(tpl, "findItems", FindItems);
    Nan::SetPrototypeMethod(tpl, "createDirectory", CreateDirectory);
    Nan::SetPrototypeMethod(tpl, "removeDirectory", RemoveDirectory);
    Nan::SetPrototypeMethod(tpl, "link", Link);
    Nan::SetPrototypeMethod(tpl, "unlink", Unlink);
    Nan::SetPrototypeMethod(tpl, "rename", Rename);
    Nan::SetPrototypeMethod(tpl, "foldCommonPrefix", FoldCommonPrefix);
    Nan::SetPrototypeMethod(tpl, "hasNaturalOrder", HasNaturalOrder);
    Nan::SetPrototypeMethod(tpl, "setNaturalOrder", SetNaturalOrder);
    Nan::SetPrototypeMethod(tpl, "rank", Rank);
    Nan::SetPrototypeMethod(tpl, "changeRank", ChangeRank);
    Nan::SetPrototypeMethod(tpl, "move", Move);
    Nan::SetPrototypeMethod(tpl, "remove", Remove);
    constructor_.Reset(Nan::GetFunction(tpl).ToLocalChecked());
}

NAN_METHOD(TreeWrapper::Open) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing standard directory-tree kind");
        return;
    }
    ida::directory::Kind kind;
    if (!kind_from_value(info[0], kind)) return;
    IDAX_UNWRAP(auto tree, ida::directory::Tree::open(kind));
    auto instance = Nan::NewInstance(Nan::New(constructor_), 0, nullptr)
                        .ToLocalChecked();
    auto* wrapper = Nan::ObjectWrap::Unwrap<TreeWrapper>(instance);
    wrapper->tree_ = std::move(tree);
    info.GetReturnValue().Set(instance);
}

NAN_METHOD(TreeWrapper::Kind) {
    info.GetReturnValue().Set(FromString(kind_name(unwrap(info)->tree().kind())));
}

NAN_METHOD(TreeWrapper::IsOrderable) {
    IDAX_UNWRAP(auto value, unwrap(info)->tree().is_orderable());
    info.GetReturnValue().Set(Nan::New(value));
}

NAN_METHOD(TreeWrapper::CurrentDirectory) {
    IDAX_UNWRAP(auto value, unwrap(info)->tree().current_directory());
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(TreeWrapper::ChangeDirectory) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_CHECK_STATUS(unwrap(info)->tree().change_directory(path));
}

NAN_METHOD(TreeWrapper::AbsolutePath) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().absolute_path(path));
    info.GetReturnValue().Set(FromString(value));
}

NAN_METHOD(TreeWrapper::Contains) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().contains(path));
    info.GetReturnValue().Set(Nan::New(value));
}

NAN_METHOD(TreeWrapper::Entry) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().entry(path));
    info.GetReturnValue().Set(entry_to_object(value));
}

NAN_METHOD(TreeWrapper::Children) {
    std::string path = "/";
    if (info.Length() > 0 && !info[0]->IsUndefined()
        && !string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().children(path));
    info.GetReturnValue().Set(entries_to_array(value));
}

NAN_METHOD(TreeWrapper::Snapshot) {
    std::string path = "/";
    if (info.Length() > 0 && !info[0]->IsUndefined()
        && !string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().snapshot(path));
    info.GetReturnValue().Set(entries_to_array(value));
}

NAN_METHOD(TreeWrapper::FindItems) {
    std::string pattern;
    if (!string_argument(info, 0, pattern)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().find_items(pattern));
    info.GetReturnValue().Set(entries_to_array(value));
}

#define IDAX_DIRECTORY_PATH_STATUS(method_name, cpp_name)                  \
    NAN_METHOD(TreeWrapper::method_name) {                                 \
        std::string path;                                                  \
        if (!string_argument(info, 0, path)) return;                       \
        IDAX_CHECK_STATUS(unwrap(info)->tree().cpp_name(path));            \
    }

IDAX_DIRECTORY_PATH_STATUS(CreateDirectory, create_directory)
IDAX_DIRECTORY_PATH_STATUS(RemoveDirectory, remove_directory)
IDAX_DIRECTORY_PATH_STATUS(Link, link)
IDAX_DIRECTORY_PATH_STATUS(Unlink, unlink)

#undef IDAX_DIRECTORY_PATH_STATUS

NAN_METHOD(TreeWrapper::FoldCommonPrefix) {
    std::string path = "/";
    if (info.Length() > 0 && !info[0]->IsUndefined()
        && !string_argument(info, 0, path)) return;
    IDAX_CHECK_STATUS(unwrap(info)->tree().fold_common_prefix(path));
}

NAN_METHOD(TreeWrapper::Rename) {
    std::string from;
    std::string to;
    if (!string_argument(info, 0, from) || !string_argument(info, 1, to)) return;
    IDAX_CHECK_STATUS(unwrap(info)->tree().rename(from, to));
}

NAN_METHOD(TreeWrapper::HasNaturalOrder) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().has_natural_order(path));
    info.GetReturnValue().Set(Nan::New(value));
}

NAN_METHOD(TreeWrapper::SetNaturalOrder) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    if (info.Length() < 2 || !info[1]->IsBoolean()) {
        Nan::ThrowTypeError("Natural-order state must be a boolean");
        return;
    }
    IDAX_CHECK_STATUS(unwrap(info)->tree().set_natural_order(
        path, Nan::To<bool>(info[1]).FromJust()));
}

NAN_METHOD(TreeWrapper::Rank) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    IDAX_UNWRAP(auto value, unwrap(info)->tree().rank(path));
    info.GetReturnValue().Set(Nan::New(static_cast<double>(value)));
}

NAN_METHOD(TreeWrapper::ChangeRank) {
    std::string path;
    if (!string_argument(info, 0, path)) return;
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing directory rank delta");
        return;
    }
    std::ptrdiff_t delta;
    if (!signed_delta(info[1], delta)) return;
    IDAX_CHECK_STATUS(unwrap(info)->tree().change_rank(path, delta));
}

NAN_METHOD(TreeWrapper::Move) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing directory paths array");
        return;
    }
    std::vector<std::string> paths;
    if (!path_array(info[0], paths)) return;
    std::string destination;
    if (!string_argument(info, 1, destination)) return;
    std::optional<std::size_t> rank;
    if (!optional_rank(info, 2, rank)) return;
    IDAX_UNWRAP(auto report,
                unwrap(info)->tree().move(paths, destination, rank));
    info.GetReturnValue().Set(bulk_report_to_object(report));
}

NAN_METHOD(TreeWrapper::Remove) {
    if (info.Length() < 1) {
        Nan::ThrowTypeError("Missing directory paths array");
        return;
    }
    std::vector<std::string> paths;
    if (!path_array(info[0], paths)) return;
    IDAX_UNWRAP(auto report, unwrap(info)->tree().remove(paths));
    info.GetReturnValue().Set(bulk_report_to_object(report));
}

} // namespace

void InitDirectory(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "directory");
    TreeWrapper::Init(ns);
    SetMethod(ns, "open", TreeWrapper::Open);
}

} // namespace idax_node
