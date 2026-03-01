/// \file database_bind.cpp
/// \brief NAN bindings for ida::database — lifecycle, metadata, and snapshots.

#include "helpers.hpp"
#include <ida/database.hpp>

namespace idax_node {
namespace {

// ── Lifecycle ───────────────────────────────────────────────────────────

NAN_METHOD(Init) {
    // init() or init(options)
    // options: { quiet?: bool, pluginPolicy?: { disableUserPlugins?: bool, allowlistPatterns?: string[] } }
    if (info.Length() > 0 && info[0]->IsObject()) {
        auto isolate = v8::Isolate::GetCurrent();
        auto context = isolate->GetCurrentContext();
        auto opts = info[0].As<v8::Object>();

        ida::database::RuntimeOptions rt;

        // quiet
        auto quietKey = FromString("quiet");
        auto quietVal = Nan::Get(opts, quietKey).ToLocalChecked();
        if (quietVal->IsBoolean()) {
            rt.quiet = Nan::To<bool>(quietVal).FromJust();
        }

        // pluginPolicy
        auto ppKey = FromString("pluginPolicy");
        auto ppVal = Nan::Get(opts, ppKey).ToLocalChecked();
        if (ppVal->IsObject()) {
            auto ppObj = ppVal.As<v8::Object>();

            auto dupKey = FromString("disableUserPlugins");
            auto dupVal = Nan::Get(ppObj, dupKey).ToLocalChecked();
            if (dupVal->IsBoolean()) {
                rt.plugin_policy.disable_user_plugins = Nan::To<bool>(dupVal).FromJust();
            }

            auto apKey = FromString("allowlistPatterns");
            auto apVal = Nan::Get(ppObj, apKey).ToLocalChecked();
            if (apVal->IsArray()) {
                auto arr = apVal.As<v8::Array>();
                uint32_t len = arr->Length();
                rt.plugin_policy.allowlist_patterns.reserve(len);
                for (uint32_t i = 0; i < len; ++i) {
                    auto elem = Nan::Get(arr, i).ToLocalChecked();
                    if (elem->IsString()) {
                        rt.plugin_policy.allowlist_patterns.push_back(ToString(elem));
                    }
                }
            }
        }

        IDAX_CHECK_STATUS(ida::database::init(rt));
    } else {
        IDAX_CHECK_STATUS(ida::database::init());
    }
}

NAN_METHOD(Open) {
    // open(path)
    // open(path, autoAnalysis: bool)
    // open(path, mode: string)             — "analyze" | "skipAnalysis"
    // open(path, intent: string, mode?: string) — intent: "autoDetect"|"binary"|"nonBinary"
    std::string path;
    if (!GetStringArg(info, 0, path)) return;

    if (info.Length() <= 1) {
        // open(path) — default auto analysis
        IDAX_CHECK_STATUS(ida::database::open(path));
        return;
    }

    // Second arg could be bool, or string
    if (info[1]->IsBoolean()) {
        bool autoAnalysis = Nan::To<bool>(info[1]).FromJust();
        IDAX_CHECK_STATUS(ida::database::open(path, autoAnalysis));
        return;
    }

    if (info[1]->IsString()) {
        std::string arg1 = ToString(info[1]);

        // Check if arg1 is a mode
        if (arg1 == "analyze" || arg1 == "skipAnalysis") {
            auto mode = (arg1 == "analyze")
                ? ida::database::OpenMode::Analyze
                : ida::database::OpenMode::SkipAnalysis;
            IDAX_CHECK_STATUS(ida::database::open(path, mode));
            return;
        }

        // arg1 is an intent
        ida::database::LoadIntent intent = ida::database::LoadIntent::AutoDetect;
        if (arg1 == "binary") {
            intent = ida::database::LoadIntent::Binary;
        } else if (arg1 == "nonBinary") {
            intent = ida::database::LoadIntent::NonBinary;
        } else if (arg1 != "autoDetect") {
            Nan::ThrowTypeError("Invalid intent: expected 'autoDetect', 'binary', or 'nonBinary'");
            return;
        }

        // Optional third arg: mode
        ida::database::OpenMode mode = ida::database::OpenMode::Analyze;
        if (info.Length() > 2 && info[2]->IsString()) {
            std::string modeStr = ToString(info[2]);
            if (modeStr == "skipAnalysis") {
                mode = ida::database::OpenMode::SkipAnalysis;
            } else if (modeStr != "analyze") {
                Nan::ThrowTypeError("Invalid mode: expected 'analyze' or 'skipAnalysis'");
                return;
            }
        }

        IDAX_CHECK_STATUS(ida::database::open(path, intent, mode));
        return;
    }

    Nan::ThrowTypeError("Invalid second argument: expected boolean, mode string, or intent string");
}

NAN_METHOD(OpenBinary) {
    std::string path;
    if (!GetStringArg(info, 0, path)) return;

    ida::database::OpenMode mode = ida::database::OpenMode::Analyze;
    if (info.Length() > 1 && info[1]->IsString()) {
        std::string modeStr = ToString(info[1]);
        if (modeStr == "skipAnalysis") {
            mode = ida::database::OpenMode::SkipAnalysis;
        } else if (modeStr != "analyze") {
            Nan::ThrowTypeError("Invalid mode: expected 'analyze' or 'skipAnalysis'");
            return;
        }
    }

    IDAX_CHECK_STATUS(ida::database::open_binary(path, mode));
}

NAN_METHOD(OpenNonBinary) {
    std::string path;
    if (!GetStringArg(info, 0, path)) return;

    ida::database::OpenMode mode = ida::database::OpenMode::Analyze;
    if (info.Length() > 1 && info[1]->IsString()) {
        std::string modeStr = ToString(info[1]);
        if (modeStr == "skipAnalysis") {
            mode = ida::database::OpenMode::SkipAnalysis;
        } else if (modeStr != "analyze") {
            Nan::ThrowTypeError("Invalid mode: expected 'analyze' or 'skipAnalysis'");
            return;
        }
    }

    IDAX_CHECK_STATUS(ida::database::open_non_binary(path, mode));
}

NAN_METHOD(Save) {
    IDAX_CHECK_STATUS(ida::database::save());
}

NAN_METHOD(Close) {
    bool saveBefore = GetOptionalBool(info, 0, false);
    DisposeAllDecompilerFunctions();
    IDAX_CHECK_STATUS(ida::database::close(saveBefore));
}

NAN_METHOD(FileToDatabase) {
    // fileToDatabase(filePath, fileOffset, ea, size, patchable?, remote?)
    std::string filePath;
    if (!GetStringArg(info, 0, filePath)) return;

    int64_t fileOffset = GetOptionalInt64(info, 1, 0);

    ida::Address ea;
    if (!GetAddressArg(info, 2, ea)) return;

    // size as address (uint64)
    ida::AddressSize size;
    if (info.Length() <= 3) {
        Nan::ThrowTypeError("Missing size argument");
        return;
    }
    ida::Address sizeVal;
    if (!ToAddress(info[3], sizeVal)) {
        Nan::ThrowTypeError("Invalid size argument");
        return;
    }
    size = sizeVal;

    bool patchable = GetOptionalBool(info, 4, true);
    bool remote = GetOptionalBool(info, 5, false);

    IDAX_CHECK_STATUS(ida::database::file_to_database(filePath, fileOffset, ea, size, patchable, remote));
}

NAN_METHOD(MemoryToDatabase) {
    // memoryToDatabase(buffer, ea, fileOffset?)
    if (info.Length() < 2) {
        Nan::ThrowTypeError("Expected (buffer, address) arguments");
        return;
    }

    std::vector<std::uint8_t> bytes;
    if (!BufferToByteVector(info[0], bytes)) {
        Nan::ThrowTypeError("First argument must be a Buffer or Uint8Array");
        return;
    }

    ida::Address ea;
    if (!GetAddressArg(info, 1, ea)) return;

    int64_t fileOffset = GetOptionalInt64(info, 2, -1);

    IDAX_CHECK_STATUS(ida::database::memory_to_database(
        std::span<const std::uint8_t>(bytes.data(), bytes.size()),
        ea, fileOffset));
}

// ── Metadata ────────────────────────────────────────────────────────────

NAN_METHOD(InputFilePath) {
    IDAX_UNWRAP(auto path, ida::database::input_file_path());
    info.GetReturnValue().Set(FromString(path));
}

NAN_METHOD(FileTypeName) {
    IDAX_UNWRAP(auto name, ida::database::file_type_name());
    info.GetReturnValue().Set(FromString(name));
}

NAN_METHOD(LoaderFormatName) {
    IDAX_UNWRAP(auto name, ida::database::loader_format_name());
    info.GetReturnValue().Set(FromString(name));
}

NAN_METHOD(InputMd5) {
    IDAX_UNWRAP(auto md5, ida::database::input_md5());
    info.GetReturnValue().Set(FromString(md5));
}

NAN_METHOD(CompilerInfoFn) {
    IDAX_UNWRAP(auto ci, ida::database::compiler_info());

    auto obj = ObjectBuilder()
        .setUint("id", ci.id)
        .setBool("uncertain", ci.uncertain)
        .setStr("name", ci.name)
        .setStr("abbreviation", ci.abbreviation)
        .build();

    info.GetReturnValue().Set(obj);
}

NAN_METHOD(ImportModules) {
    IDAX_UNWRAP(auto modules, ida::database::import_modules());

    auto arr = Nan::New<v8::Array>(static_cast<int>(modules.size()));
    for (size_t i = 0; i < modules.size(); ++i) {
        const auto& mod = modules[i];

        // Build symbols array
        auto symsArr = Nan::New<v8::Array>(static_cast<int>(mod.symbols.size()));
        for (size_t j = 0; j < mod.symbols.size(); ++j) {
            const auto& sym = mod.symbols[j];
            auto symObj = ObjectBuilder()
                .setAddr("address", sym.address)
                .setStr("name", sym.name)
                .set("ordinal", v8::BigInt::NewFromUnsigned(
                    v8::Isolate::GetCurrent(), sym.ordinal))
                .build();
            Nan::Set(symsArr, static_cast<uint32_t>(j), symObj);
        }

        auto modObj = ObjectBuilder()
            .setSize("index", mod.index)
            .setStr("name", mod.name)
            .set("symbols", symsArr)
            .build();

        Nan::Set(arr, static_cast<uint32_t>(i), modObj);
    }

    info.GetReturnValue().Set(arr);
}

NAN_METHOD(ImageBase) {
    IDAX_UNWRAP(auto addr, ida::database::image_base());
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(MinAddress) {
    IDAX_UNWRAP(auto addr, ida::database::min_address());
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(MaxAddress) {
    IDAX_UNWRAP(auto addr, ida::database::max_address());
    info.GetReturnValue().Set(FromAddress(addr));
}

NAN_METHOD(AddressBounds) {
    IDAX_UNWRAP(auto range, ida::database::address_bounds());

    auto obj = ObjectBuilder()
        .setAddr("start", range.start)
        .setAddr("end", range.end)
        .build();

    info.GetReturnValue().Set(obj);
}

NAN_METHOD(AddressSpan) {
    IDAX_UNWRAP(auto span, ida::database::address_span());
    info.GetReturnValue().Set(FromAddressSize(span));
}

NAN_METHOD(ProcessorIdFn) {
    IDAX_UNWRAP(auto id, ida::database::processor_id());
    info.GetReturnValue().Set(Nan::New(id));
}

NAN_METHOD(Processor) {
    IDAX_UNWRAP(auto proc, ida::database::processor());
    info.GetReturnValue().Set(Nan::New(static_cast<int32_t>(proc)));
}

NAN_METHOD(ProcessorName) {
    IDAX_UNWRAP(auto name, ida::database::processor_name());
    info.GetReturnValue().Set(FromString(name));
}

NAN_METHOD(AddressBitness) {
    IDAX_UNWRAP(auto bits, ida::database::address_bitness());
    info.GetReturnValue().Set(Nan::New(bits));
}

NAN_METHOD(SetAddressBitness) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric bitness argument");
        return;
    }

    int bits = Nan::To<int>(info[0]).FromJust();
    IDAX_CHECK_STATUS(ida::database::set_address_bitness(bits));
}

NAN_METHOD(IsBigEndian) {
    IDAX_UNWRAP(auto big, ida::database::is_big_endian());
    info.GetReturnValue().Set(Nan::New(big));
}

NAN_METHOD(AbiName) {
    IDAX_UNWRAP(auto name, ida::database::abi_name());
    info.GetReturnValue().Set(FromString(name));
}

// ── Snapshots ───────────────────────────────────────────────────────────

/// Recursively convert a Snapshot tree to a JS object.
static v8::Local<v8::Object> SnapshotToObject(const ida::database::Snapshot& snap) {
    auto childArr = Nan::New<v8::Array>(static_cast<int>(snap.children.size()));
    for (size_t i = 0; i < snap.children.size(); ++i) {
        Nan::Set(childArr, static_cast<uint32_t>(i),
                 SnapshotToObject(snap.children[i]));
    }

    return ObjectBuilder()
        .set("id", v8::BigInt::New(v8::Isolate::GetCurrent(), snap.id))
        .setUint("flags", snap.flags)
        .setStr("description", snap.description)
        .setStr("filename", snap.filename)
        .set("children", childArr)
        .build();
}

NAN_METHOD(Snapshots) {
    IDAX_UNWRAP(auto snaps, ida::database::snapshots());

    auto arr = Nan::New<v8::Array>(static_cast<int>(snaps.size()));
    for (size_t i = 0; i < snaps.size(); ++i) {
        Nan::Set(arr, static_cast<uint32_t>(i), SnapshotToObject(snaps[i]));
    }

    info.GetReturnValue().Set(arr);
}

NAN_METHOD(SetSnapshotDescription) {
    std::string desc;
    if (!GetStringArg(info, 0, desc)) return;
    IDAX_CHECK_STATUS(ida::database::set_snapshot_description(desc));
}

NAN_METHOD(IsSnapshotDatabase) {
    IDAX_UNWRAP(auto is, ida::database::is_snapshot_database());
    info.GetReturnValue().Set(Nan::New(is));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitDatabase(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "database");

    // Lifecycle
    SetMethod(ns, "init",             Init);
    SetMethod(ns, "open",             Open);
    SetMethod(ns, "openBinary",       OpenBinary);
    SetMethod(ns, "openNonBinary",    OpenNonBinary);
    SetMethod(ns, "save",             Save);
    SetMethod(ns, "close",            Close);
    SetMethod(ns, "fileToDatabase",   FileToDatabase);
    SetMethod(ns, "memoryToDatabase", MemoryToDatabase);

    // Metadata
    SetMethod(ns, "inputFilePath",    InputFilePath);
    SetMethod(ns, "fileTypeName",     FileTypeName);
    SetMethod(ns, "loaderFormatName", LoaderFormatName);
    SetMethod(ns, "inputMd5",        InputMd5);
    SetMethod(ns, "compilerInfo",     CompilerInfoFn);
    SetMethod(ns, "importModules",    ImportModules);
    SetMethod(ns, "imageBase",        ImageBase);
    SetMethod(ns, "minAddress",       MinAddress);
    SetMethod(ns, "maxAddress",       MaxAddress);
    SetMethod(ns, "addressBounds",    AddressBounds);
    SetMethod(ns, "addressSpan",      AddressSpan);
    SetMethod(ns, "processorId",      ProcessorIdFn);
    SetMethod(ns, "processor",        Processor);
    SetMethod(ns, "processorName",    ProcessorName);
    SetMethod(ns, "addressBitness",   AddressBitness);
    SetMethod(ns, "setAddressBitness", SetAddressBitness);
    SetMethod(ns, "isBigEndian",      IsBigEndian);
    SetMethod(ns, "abiName",          AbiName);

    // Snapshots
    SetMethod(ns, "snapshots",               Snapshots);
    SetMethod(ns, "setSnapshotDescription",  SetSnapshotDescription);
    SetMethod(ns, "isSnapshotDatabase",      IsSnapshotDatabase);
}

} // namespace idax_node
