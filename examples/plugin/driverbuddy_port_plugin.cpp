/// \file driverbuddy_port_plugin.cpp
/// \brief idax-first C++ port of `/Users/int/Downloads/plo/DriverBuddy-master`.

#include <ida/idax.hpp>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using namespace ida;

template <typename... Args>
std::string fmt(const char* pattern, Args&&... args) {
    char buffer[2048];
    std::snprintf(buffer, sizeof(buffer), pattern, std::forward<Args>(args)...);
    return std::string(buffer);
}

std::string to_lower_ascii(std::string_view text) {
    std::string out(text);
    std::transform(out.begin(),
                   out.end(),
                   out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

bool starts_with_ignore_case(std::string_view text, std::string_view prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        const auto left = static_cast<unsigned char>(text[i]);
        const auto right = static_cast<unsigned char>(prefix[i]);
        if (std::tolower(left) != std::tolower(right)) {
            return false;
        }
    }
    return true;
}

bool contains_ignore_case(std::string_view haystack, std::string_view needle) {
    const std::string lowered_haystack = to_lower_ascii(haystack);
    const std::string lowered_needle = to_lower_ascii(needle);
    return lowered_haystack.find(lowered_needle) != std::string::npos;
}

std::string error_text(const Error& error) {
    if (error.context.empty()) {
        return error.message;
    }
    return error.message + " (" + error.context + ")";
}

const std::vector<std::string_view> kDangerousCFunctions = {
    "sprintf",
    "strcpy",
    "strcat",
    "memcpy",
    "RtlCopyMemory",
    "gets",
    "scanf",
};

const std::vector<std::string_view> kInterestingWinApiPrefixes = {
    "SeAccessCheck",
    "ProbeFor",
    "SeQueryAuthenticationIdToken",
    "IoRegisterDeviceInterface",
    "Ob",
    "Zw",
    "IofCallDriver",
    "PsCreateSystemThread",
};

const std::vector<std::string_view> kDriverSpecificFunctions = {
    // Add target-specific driver routines here while auditing a concrete sample.
};

const std::vector<std::string_view> kAccessNames = {
    "FILE_ANY_ACCESS",
    "FILE_READ_ACCESS",
    "FILE_WRITE_ACCESS",
    "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
};

const std::vector<std::string_view> kMethodNames = {
    "METHOD_BUFFERED",
    "METHOD_IN_DIRECT",
    "METHOD_OUT_DIRECT",
    "METHOD_NEITHER",
};

const std::vector<std::string_view> kDeviceNames = {
    "<UNKNOWN>",
    "FILE_DEVICE_BEEP",
    "FILE_DEVICE_CD_ROM",
    "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
    "FILE_DEVICE_CONTROLLER",
    "FILE_DEVICE_DATALINK",
    "FILE_DEVICE_DFS",
    "FILE_DEVICE_DISK",
    "FILE_DEVICE_DISK_FILE_SYSTEM",
    "FILE_DEVICE_FILE_SYSTEM",
    "FILE_DEVICE_INPORT_PORT",
    "FILE_DEVICE_KEYBOARD",
    "FILE_DEVICE_MAILSLOT",
    "FILE_DEVICE_MIDI_IN",
    "FILE_DEVICE_MIDI_OUT",
    "FILE_DEVICE_MOUSE",
    "FILE_DEVICE_MULTI_UNC_PROVIDER",
    "FILE_DEVICE_NAMED_PIPE",
    "FILE_DEVICE_NETWORK",
    "FILE_DEVICE_NETWORK_BROWSER",
    "FILE_DEVICE_NETWORK_FILE_SYSTEM",
    "FILE_DEVICE_NULL",
    "FILE_DEVICE_PARALLEL_PORT",
    "FILE_DEVICE_PHYSICAL_NETCARD",
    "FILE_DEVICE_PRINTER",
    "FILE_DEVICE_SCANNER",
    "FILE_DEVICE_SERIAL_MOUSE_PORT",
    "FILE_DEVICE_SERIAL_PORT",
    "FILE_DEVICE_SCREEN",
    "FILE_DEVICE_SOUND",
    "FILE_DEVICE_STREAMS",
    "FILE_DEVICE_TAPE",
    "FILE_DEVICE_TAPE_FILE_SYSTEM",
    "FILE_DEVICE_TRANSPORT",
    "FILE_DEVICE_UNKNOWN",
    "FILE_DEVICE_VIDEO",
    "FILE_DEVICE_VIRTUAL_DISK",
    "FILE_DEVICE_WAVE_IN",
    "FILE_DEVICE_WAVE_OUT",
    "FILE_DEVICE_8042_PORT",
    "FILE_DEVICE_NETWORK_REDIRECTOR",
    "FILE_DEVICE_BATTERY",
    "FILE_DEVICE_BUS_EXTENDER",
    "FILE_DEVICE_MODEM",
    "FILE_DEVICE_VDM",
    "FILE_DEVICE_MASS_STORAGE",
    "FILE_DEVICE_SMB",
    "FILE_DEVICE_KS",
    "FILE_DEVICE_CHANGER",
    "FILE_DEVICE_SMARTCARD",
    "FILE_DEVICE_ACPI",
    "FILE_DEVICE_DVD",
    "FILE_DEVICE_FULLSCREEN_VIDEO",
    "FILE_DEVICE_DFS_FILE_SYSTEM",
    "FILE_DEVICE_DFS_VOLUME",
    "FILE_DEVICE_SERENUM",
    "FILE_DEVICE_TERMSRV",
    "FILE_DEVICE_KSEC",
    "FILE_DEVICE_FIPS",
    "FILE_DEVICE_INFINIBAND",
    "<UNKNOWN>",
    "<UNKNOWN>",
    "FILE_DEVICE_VMBUS",
    "FILE_DEVICE_CRYPT_PROVIDER",
    "FILE_DEVICE_WPD",
    "FILE_DEVICE_BLUETOOTH",
    "FILE_DEVICE_MT_COMPOSITE",
    "FILE_DEVICE_MT_TRANSPORT",
    "FILE_DEVICE_BIOMETRIC",
    "FILE_DEVICE_PMI",
};

struct CustomIoctlDevice {
    std::uint16_t code;
    std::string_view name;
};

const std::vector<CustomIoctlDevice> kCustomIoctlDevices = {
    {0x6D, "MOUNTMGRCONTROLTYPE"},
};

const std::vector<std::string_view> kWdfFunctionSlots = {
    "pfnWdfChildListCreate",
    "pfnWdfChildListGetDevice",
    "pfnWdfChildListRetrievePdo",
    "pfnWdfChildListRetrieveAddressDescription",
    "pfnWdfChildListBeginScan",
    "pfnWdfChildListEndScan",
    "pfnWdfChildListBeginIteration",
    "pfnWdfChildListRetrieveNextDevice",
    "pfnWdfChildListEndIteration",
    "pfnWdfChildListAddOrUpdateChildDescriptionAsPresent",
    "pfnWdfChildListUpdateChildDescriptionAsMissing",
    "pfnWdfChildListUpdateAllChildDescriptionsAsPresent",
    "pfnWdfChildListRequestChildEject",
    "pfnWdfCollectionCreate",
    "pfnWdfCollectionGetCount",
    "pfnWdfCollectionAdd",
    "pfnWdfCollectionRemove",
    "pfnWdfCollectionRemoveItem",
    "pfnWdfCollectionGetItem",
    "pfnWdfCollectionGetFirstItem",
    "pfnWdfCollectionGetLastItem",
    "pfnWdfCommonBufferCreate",
    "pfnWdfCommonBufferGetAlignedVirtualAddress",
    "pfnWdfCommonBufferGetAlignedLogicalAddress",
    "pfnWdfCommonBufferGetLength",
    "pfnWdfControlDeviceInitAllocate",
    "pfnWdfControlDeviceInitSetShutdownNotification",
    "pfnWdfControlFinishInitializing",
    "pfnWdfDeviceGetDeviceState",
    "pfnWdfDeviceSetDeviceState",
    "pfnWdfWdmDeviceGetWdfDeviceHandle",
    "pfnWdfDeviceWdmGetDeviceObject",
    "pfnWdfDeviceWdmGetAttachedDevice",
    "pfnWdfDeviceWdmGetPhysicalDevice",
    "pfnWdfDeviceWdmDispatchPreprocessedIrp",
    "pfnWdfDeviceAddDependentUsageDeviceObject",
    "pfnWdfDeviceAddRemovalRelationsPhysicalDevice",
    "pfnWdfDeviceRemoveRemovalRelationsPhysicalDevice",
    "pfnWdfDeviceClearRemovalRelationsDevices",
    "pfnWdfDeviceGetDriver",
    "pfnWdfDeviceRetrieveDeviceName",
    "pfnWdfDeviceAssignMofResourceName",
    "pfnWdfDeviceGetIoTarget",
    "pfnWdfDeviceGetDevicePnpState",
    "pfnWdfDeviceGetDevicePowerState",
    "pfnWdfDeviceGetDevicePowerPolicyState",
    "pfnWdfDeviceAssignS0IdleSettings",
    "pfnWdfDeviceAssignSxWakeSettings",
    "pfnWdfDeviceOpenRegistryKey",
    "pfnWdfDeviceSetSpecialFileSupport",
    "pfnWdfDeviceSetCharacteristics",
    "pfnWdfDeviceGetCharacteristics",
    "pfnWdfDeviceGetAlignmentRequirement",
    "pfnWdfDeviceSetAlignmentRequirement",
    "pfnWdfDeviceInitFree",
    "pfnWdfDeviceInitSetPnpPowerEventCallbacks",
    "pfnWdfDeviceInitSetPowerPolicyEventCallbacks",
    "pfnWdfDeviceInitSetPowerPolicyOwnership",
    "pfnWdfDeviceInitRegisterPnpStateChangeCallback",
    "pfnWdfDeviceInitRegisterPowerStateChangeCallback",
    "pfnWdfDeviceInitRegisterPowerPolicyStateChangeCallback",
    "pfnWdfDeviceInitSetIoType",
    "pfnWdfDeviceInitSetExclusive",
    "pfnWdfDeviceInitSetPowerNotPageable",
    "pfnWdfDeviceInitSetPowerPageable",
    "pfnWdfDeviceInitSetPowerInrush",
    "pfnWdfDeviceInitSetDeviceType",
    "pfnWdfDeviceInitAssignName",
    "pfnWdfDeviceInitAssignSDDLString",
    "pfnWdfDeviceInitSetDeviceClass",
    "pfnWdfDeviceInitSetCharacteristics",
    "pfnWdfDeviceInitSetFileObjectConfig",
    "pfnWdfDeviceInitSetRequestAttributes",
    "pfnWdfDeviceInitAssignWdmIrpPreprocessCallback",
    "pfnWdfDeviceInitSetIoInCallerContextCallback",
    "pfnWdfDeviceCreate",
    "pfnWdfDeviceSetStaticStopRemove",
    "pfnWdfDeviceCreateDeviceInterface",
    "pfnWdfDeviceSetDeviceInterfaceState",
    "pfnWdfDeviceRetrieveDeviceInterfaceString",
    "pfnWdfDeviceCreateSymbolicLink",
    "pfnWdfDeviceQueryProperty",
    "pfnWdfDeviceAllocAndQueryProperty",
    "pfnWdfDeviceSetPnpCapabilities",
    "pfnWdfDeviceSetPowerCapabilities",
    "pfnWdfDeviceSetBusInformationForChildren",
    "pfnWdfDeviceIndicateWakeStatus",
    "pfnWdfDeviceSetFailed",
    "pfnWdfDeviceStopIdle",
    "pfnWdfDeviceResumeIdle",
    "pfnWdfDeviceGetFileObject",
    "pfnWdfDeviceEnqueueRequest",
    "pfnWdfDeviceGetDefaultQueue",
    "pfnWdfDeviceConfigureRequestDispatching",
    "pfnWdfDmaEnablerCreate",
    "pfnWdfDmaEnablerGetMaximumLength",
    "pfnWdfDmaEnablerGetMaximumScatterGatherElements",
    "pfnWdfDmaEnablerSetMaximumScatterGatherElements",
    "pfnWdfDmaTransactionCreate",
    "pfnWdfDmaTransactionInitialize",
    "pfnWdfDmaTransactionInitializeUsingRequest",
    "pfnWdfDmaTransactionExecute",
    "pfnWdfDmaTransactionRelease",
    "pfnWdfDmaTransactionDmaCompleted",
    "pfnWdfDmaTransactionDmaCompletedWithLength",
    "pfnWdfDmaTransactionDmaCompletedFinal",
    "pfnWdfDmaTransactionGetBytesTransferred",
    "pfnWdfDmaTransactionSetMaximumLength",
    "pfnWdfDmaTransactionGetRequest",
    "pfnWdfDmaTransactionGetCurrentDmaTransferLength",
    "pfnWdfDmaTransactionGetDevice",
    "pfnWdfDpcCreate",
    "pfnWdfDpcEnqueue",
    "pfnWdfDpcCancel",
    "pfnWdfDpcGetParentObject",
    "pfnWdfDpcWdmGetDpc",
    "pfnWdfDriverCreate",
    "pfnWdfDriverGetRegistryPath",
    "pfnWdfDriverWdmGetDriverObject",
    "pfnWdfDriverOpenParametersRegistryKey",
    "pfnWdfWdmDriverGetWdfDriverHandle",
    "pfnWdfDriverRegisterTraceInfo",
    "pfnWdfDriverRetrieveVersionString",
    "pfnWdfDriverIsVersionAvailable",
    "pfnWdfFdoInitWdmGetPhysicalDevice",
    "pfnWdfFdoInitOpenRegistryKey",
    "pfnWdfFdoInitQueryProperty",
    "pfnWdfFdoInitAllocAndQueryProperty",
    "pfnWdfFdoInitSetEventCallbacks",
    "pfnWdfFdoInitSetFilter",
    "pfnWdfFdoInitSetDefaultChildListConfig",
    "pfnWdfFdoQueryForInterface",
    "pfnWdfFdoGetDefaultChildList",
    "pfnWdfFdoAddStaticChild",
    "pfnWdfFdoLockStaticChildListForIteration",
    "pfnWdfFdoRetrieveNextStaticChild",
    "pfnWdfFdoUnlockStaticChildListFromIteration",
    "pfnWdfFileObjectGetFileName",
    "pfnWdfFileObjectGetFlags",
    "pfnWdfFileObjectGetDevice",
    "pfnWdfFileObjectWdmGetFileObject",
    "pfnWdfInterruptCreate",
    "pfnWdfInterruptQueueDpcForIsr",
    "pfnWdfInterruptSynchronize",
    "pfnWdfInterruptAcquireLock",
    "pfnWdfInterruptReleaseLock",
    "pfnWdfInterruptEnable",
    "pfnWdfInterruptDisable",
    "pfnWdfInterruptWdmGetInterrupt",
    "pfnWdfInterruptGetInfo",
    "pfnWdfInterruptSetPolicy",
    "pfnWdfInterruptGetDevice",
    "pfnWdfIoQueueCreate",
    "pfnWdfIoQueueGetState",
    "pfnWdfIoQueueStart",
    "pfnWdfIoQueueStop",
    "pfnWdfIoQueueStopSynchronously",
    "pfnWdfIoQueueGetDevice",
    "pfnWdfIoQueueRetrieveNextRequest",
    "pfnWdfIoQueueRetrieveRequestByFileObject",
    "pfnWdfIoQueueFindRequest",
    "pfnWdfIoQueueRetrieveFoundRequest",
    "pfnWdfIoQueueDrainSynchronously",
    "pfnWdfIoQueueDrain",
    "pfnWdfIoQueuePurgeSynchronously",
    "pfnWdfIoQueuePurge",
    "pfnWdfIoQueueReadyNotify",
    "pfnWdfIoTargetCreate",
    "pfnWdfIoTargetOpen",
    "pfnWdfIoTargetCloseForQueryRemove",
    "pfnWdfIoTargetClose",
    "pfnWdfIoTargetStart",
    "pfnWdfIoTargetStop",
    "pfnWdfIoTargetGetState",
    "pfnWdfIoTargetGetDevice",
    "pfnWdfIoTargetQueryTargetProperty",
    "pfnWdfIoTargetAllocAndQueryTargetProperty",
    "pfnWdfIoTargetQueryForInterface",
    "pfnWdfIoTargetWdmGetTargetDeviceObject",
    "pfnWdfIoTargetWdmGetTargetPhysicalDevice",
};

struct FunctionInventory {
    std::unordered_map<std::string, Address> functions;
    std::unordered_map<std::string, Address> imports;
};

enum class DriverType {
    MiniFilter,
    Wdf,
    StreamMiniDriver,
    AvStream,
    PortCls,
    Wdm,
};

struct DispatchTargets {
    std::optional<Address> device_control;
    std::optional<Address> internal_device_control;
    std::vector<Address> possible_device_controls;
};

std::string_view driver_type_name(DriverType type) {
    switch (type) {
        case DriverType::MiniFilter: return "Mini-Filter";
        case DriverType::Wdf: return "WDF";
        case DriverType::StreamMiniDriver: return "Stream Minidriver";
        case DriverType::AvStream: return "AVStream";
        case DriverType::PortCls: return "PortCls";
        case DriverType::Wdm: return "WDM";
    }
    return "WDM";
}

std::string sanitize_symbol_token(std::string text) {
    auto trim = [](std::string& value) {
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
            value.erase(value.begin());
        }
        while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
            value.pop_back();
        }
    };

    trim(text);

    const std::vector<std::string_view> prefixes = {
        "offset ",
        "cs:",
        "ds:",
        "ss:",
        "qword ptr ",
        "dword ptr ",
        "word ptr ",
        "byte ptr ",
        "ptr ",
    };
    for (const auto prefix : prefixes) {
        if (starts_with_ignore_case(text, prefix)) {
            text.erase(0, prefix.size());
            trim(text);
        }
    }

    if (!text.empty() && text.front() == '[') {
        text.erase(text.begin());
    }
    if (!text.empty() && text.back() == ']') {
        text.pop_back();
    }

    const auto cut = text.find_first_of("+-* ");
    if (cut != std::string::npos) {
        text.resize(cut);
    }

    while (!text.empty() && (text.back() == ',' || text.back() == ';')) {
        text.pop_back();
    }

    trim(text);
    return text;
}

std::optional<Address> maybe_operand_address(const instruction::Operand& operand) {
    const Address target = operand.target_address();
    if (target != BadAddress && address::is_mapped(target)) {
        return target;
    }
    if (operand.is_immediate()) {
        const Address value_address = static_cast<Address>(operand.value());
        if (value_address != BadAddress && address::is_mapped(value_address)) {
            return value_address;
        }
    }
    return std::nullopt;
}

std::optional<Address> resolve_operand_target(Address instruction_address,
                                              int operand_index) {
    const auto decoded = instruction::decode(instruction_address);
    if (!decoded) {
        return std::nullopt;
    }
    const auto operand = decoded->operand(static_cast<std::size_t>(operand_index));
    if (!operand) {
        return std::nullopt;
    }

    if (const auto maybe_address = maybe_operand_address(*operand); maybe_address.has_value()) {
        return maybe_address;
    }

    const auto operand_text = instruction::operand_text(instruction_address, operand_index);
    if (!operand_text) {
        return std::nullopt;
    }

    const std::string token = sanitize_symbol_token(*operand_text);
    if (token.empty()) {
        return std::nullopt;
    }

    const auto resolved = name::resolve(token);
    if (!resolved) {
        return std::nullopt;
    }
    return *resolved;
}

std::optional<std::uint32_t> first_immediate_operand(const instruction::Instruction& insn) {
    for (std::size_t index = 0; index < insn.operand_count(); ++index) {
        const auto operand = insn.operand(index);
        if (!operand || !operand->is_immediate()) {
            continue;
        }
        return static_cast<std::uint32_t>(operand->value() & 0xFFFFFFFFU);
    }
    return std::nullopt;
}

std::string ioctl_device_name(std::uint16_t device_code) {
    if (device_code < kDeviceNames.size()) {
        return std::string(kDeviceNames[device_code]);
    }
    for (const auto& custom : kCustomIoctlDevices) {
        if (custom.code == device_code) {
            return std::string(custom.name);
        }
    }
    return "<UNKNOWN>";
}

void decode_and_print_ioctl(std::uint32_t ioctl_code) {
    const auto device = static_cast<std::uint16_t>((ioctl_code >> 16) & 0xFFFFU);
    const auto access = static_cast<std::uint16_t>((ioctl_code >> 14) & 0x3U);
    const auto function_code = static_cast<std::uint16_t>((ioctl_code >> 2) & 0xFFFU);
    const auto method = static_cast<std::uint16_t>(ioctl_code & 0x3U);

    const std::string device_name = ioctl_device_name(device);

    ui::message(fmt("[+] IOCTL: 0x%08X\n", ioctl_code));
    ui::message(fmt("[+] Device   : %s (0x%X)\n", device_name.c_str(), device));
    ui::message(fmt("[+] Function : 0x%X\n", function_code));
    ui::message(fmt("[+] Method   : %s (%u)\n",
                    kMethodNames[method].data(),
                    method));
    ui::message(fmt("[+] Access   : %s (%u)\n",
                    kAccessNames[access].data(),
                    access));
}

FunctionInventory build_inventory() {
    FunctionInventory inventory;

    for (auto function_entry : function::all()) {
        inventory.functions[function_entry.name()] = function_entry.start();
    }

    const auto import_modules = database::import_modules();
    if (!import_modules) {
        ui::message(fmt("[-] Failed to enumerate import modules: %s\n",
                        error_text(import_modules.error()).c_str()));
        return inventory;
    }

    for (const auto& module : *import_modules) {
        for (const auto& symbol : module.symbols) {
            if (symbol.name.empty()) {
                continue;
            }
            inventory.imports[symbol.name] = symbol.address;
            inventory.functions[symbol.name] = symbol.address;
        }
    }

    return inventory;
}

std::vector<std::pair<std::string, Address>> collect_exact_matches(
    const std::unordered_map<std::string, Address>& functions,
    const std::vector<std::string_view>& needles) {
    std::vector<std::pair<std::string, Address>> hits;
    for (const auto name : needles) {
        const auto it = functions.find(std::string(name));
        if (it != functions.end()) {
            hits.emplace_back(it->first, it->second);
        }
    }
    return hits;
}

std::vector<std::pair<std::string, Address>> collect_prefix_matches(
    const std::unordered_map<std::string, Address>& functions,
    const std::vector<std::string_view>& prefixes) {
    std::vector<std::pair<std::string, Address>> hits;
    std::set<std::string> seen;
    for (const auto& [name, address] : functions) {
        for (const auto prefix : prefixes) {
            if (!starts_with_ignore_case(name, prefix)) {
                continue;
            }
            if (seen.insert(name).second) {
                hits.emplace_back(name, address);
            }
            break;
        }
    }
    std::sort(hits.begin(),
              hits.end(),
              [](const auto& left, const auto& right) { return left.first < right.first; });
    return hits;
}

void print_function_xrefs(const std::vector<std::pair<std::string, Address>>& candidates) {
    for (const auto& [name, address] : candidates) {
        const auto refs = xref::code_refs_to(address);
        if (!refs) {
            continue;
        }
        for (const auto& ref : *refs) {
            ui::message(fmt("[+] Found 0x%08llX xref to %s\n",
                            static_cast<unsigned long long>(ref.from),
                            name.c_str()));
        }
    }
}

std::optional<Address> find_driver_entry() {
    const auto resolved = name::resolve("DriverEntry");
    if (resolved && address::is_mapped(*resolved)) {
        return *resolved;
    }

    for (auto function_entry : function::all()) {
        if (function_entry.name() == "DriverEntry") {
            return function_entry.start();
        }
    }
    return std::nullopt;
}

DriverType detect_driver_type(const FunctionInventory& inventory) {
    if (inventory.imports.contains("FltRegisterFilter")) {
        return DriverType::MiniFilter;
    }
    if (inventory.imports.contains("WdfVersionBind")) {
        return DriverType::Wdf;
    }
    if (inventory.imports.contains("StreamClassRegisterMinidriver")) {
        return DriverType::StreamMiniDriver;
    }
    if (inventory.imports.contains("KsCreateFilterFactory")) {
        return DriverType::AvStream;
    }
    if (inventory.imports.contains("PcRegisterSubdevice")) {
        return DriverType::PortCls;
    }
    return DriverType::Wdm;
}

std::size_t pointer_size_for_function(Address function_address) {
    const auto function_entry = function::at(function_address);
    if (function_entry && function_entry->bitness() == 64) {
        return 8;
    }
    return 4;
}

Status ensure_wdf_struct_type(std::size_t pointer_size) {
    const auto existing = type::TypeInfo::by_name("WDFFUNCTIONS");
    if (existing) {
        return ida::ok();
    }

    auto wdf_struct = type::TypeInfo::create_struct();
    const auto pointer_type = type::TypeInfo::pointer_to(type::TypeInfo::void_type());

    std::size_t member_offset = 0;
    for (const auto member_name : kWdfFunctionSlots) {
        const auto add = wdf_struct.add_member(member_name, pointer_type, member_offset);
        if (!add) {
            return std::unexpected(add.error());
        }
        member_offset += pointer_size;
    }

    const auto save = wdf_struct.save_as("WDFFUNCTIONS");
    if (!save) {
        return std::unexpected(save.error());
    }
    return ida::ok();
}

void annotate_wdf_functions(Address driver_entry) {
    ui::message("[+] Attempting WDF function-table annotation...\n");

    const auto min_address = database::min_address();
    const auto max_address = database::max_address();
    if (!min_address || !max_address) {
        ui::message("[-] Unable to get database address bounds for WDF annotation\n");
        return;
    }

    constexpr auto kKmdfLibraryUtf16Pattern =
        "4B 00 6D 00 64 00 66 00 4C 00 69 00 62 00 72 00 61 00 72 00 79 00";

    const auto marker = data::find_binary_pattern(*min_address,
                                                   *max_address,
                                                   kKmdfLibraryUtf16Pattern);
    if (!marker) {
        ui::message("[-] KmdfLibrary marker not found; skipping WDF table annotation\n");
        return;
    }

    const auto refs = xref::data_refs_to(*marker);
    if (!refs || refs->empty()) {
        ui::message("[-] No data references to KmdfLibrary marker\n");
        return;
    }

    const std::size_t pointer_size = pointer_size_for_function(driver_entry);

    for (const auto& ref : *refs) {
        const Address metadata_address = ref.from;

        const auto minor_version = data::read_dword(metadata_address + pointer_size + 0x4);

        Address table_address = BadAddress;
        if (pointer_size == 8) {
            const auto qword_value = data::read_qword(metadata_address + pointer_size + 0x10);
            if (qword_value) {
                table_address = static_cast<Address>(*qword_value);
            }
        } else {
            const auto dword_value = data::read_dword(metadata_address + pointer_size + 0x10);
            if (dword_value) {
                table_address = static_cast<Address>(*dword_value);
            }
        }

        if (table_address == BadAddress || !address::is_mapped(table_address)) {
            continue;
        }

        const auto ensure = ensure_wdf_struct_type(pointer_size);
        if (!ensure) {
            ui::message(fmt("[-] Failed to materialize WDFFUNCTIONS type: %s\n",
                            error_text(ensure.error()).c_str()));
            return;
        }

        const auto apply = type::apply_named_type(table_address, "WDFFUNCTIONS");
        if (!apply) {
            ui::message(fmt("[-] Failed to apply WDFFUNCTIONS type at 0x%llX: %s\n",
                            static_cast<unsigned long long>(table_address),
                            error_text(apply.error()).c_str()));
            return;
        }

        (void)name::force_set(table_address, "WdfFunctions");
        ui::message(fmt("[+] Annotated WdfFunctions at 0x%08llX (KMDF 1.%u, %zu slots)\n",
                        static_cast<unsigned long long>(table_address),
                        minor_version ? *minor_version : 0U,
                        kWdfFunctionSlots.size()));
        return;
    }

    ui::message("[-] Unable to resolve a valid WDF dispatch table from marker refs\n");
}

std::optional<Address> find_real_driver_entry(Address driver_entry) {
    const auto code_addresses = function::code_addresses(driver_entry);
    if (!code_addresses) {
        return std::nullopt;
    }

    for (auto it = code_addresses->rbegin(); it != code_addresses->rend(); ++it) {
        const auto insn = instruction::decode(*it);
        if (!insn) {
            continue;
        }

        const std::string mnemonic = to_lower_ascii(insn->mnemonic());
        if (mnemonic != "jmp" && mnemonic != "call") {
            continue;
        }

        const auto target = resolve_operand_target(*it, 0);
        if (!target || *target == driver_entry) {
            continue;
        }
        return target;
    }

    return std::nullopt;
}

std::vector<Address> locate_possible_dispatches(Address driver_entry) {
    std::vector<Address> candidates;
    std::set<Address> seen;

    for (auto fn : function::all()) {
        const auto function_items = function::code_addresses(fn.start());
        if (!function_items) {
            continue;
        }

        std::string io_stack_register;
        bool matched = false;

        for (const auto item : *function_items) {
            const auto disasm = instruction::text(item);
            if (!disasm) {
                continue;
            }

            const auto operand_1 = instruction::operand_text(item, 1);
            if (operand_1 && contains_ignore_case(*operand_1, "[rdx+0b8h]")) {
                const auto operand_0 = instruction::operand_text(item, 0);
                if (operand_0) {
                    io_stack_register = sanitize_symbol_token(*operand_0);
                }
            }

            if (!io_stack_register.empty()) {
                const std::string iocode = "[" + to_lower_ascii(io_stack_register) + "+18h]";
                if (contains_ignore_case(*disasm, iocode)) {
                    matched = true;
                    break;
                }
            }
        }

        if (!matched) {
            continue;
        }

        const auto refs = xref::code_refs_to(fn.start());
        if (!refs) {
            continue;
        }

        for (const auto& ref : *refs) {
            const auto caller = function::at(ref.from);
            if (!caller) {
                continue;
            }
            if (caller->start() == driver_entry && seen.insert(fn.start()).second) {
                candidates.push_back(fn.start());
                break;
            }
        }
    }

    return candidates;
}

DispatchTargets locate_dispatch_targets(Address driver_entry) {
    DispatchTargets targets;
    const auto function_items = function::code_addresses(driver_entry);
    if (!function_items) {
        return targets;
    }

    Address previous = BadAddress;
    for (const auto item : *function_items) {
        if (previous == BadAddress) {
            previous = item;
            continue;
        }

        const auto current_operand_0 = instruction::operand_text(item, 0);
        const auto previous_insn = instruction::decode(previous);
        if (!current_operand_0 || !previous_insn) {
            previous = item;
            continue;
        }

        const std::string previous_mnemonic = to_lower_ascii(previous_insn->mnemonic());
        if (previous_mnemonic != "lea") {
            previous = item;
            continue;
        }

        const auto maybe_target = resolve_operand_target(previous, 1);
        if (!maybe_target) {
            previous = item;
            continue;
        }

        if (contains_ignore_case(*current_operand_0, "+0e0h]")) {
            targets.device_control = *maybe_target;
        }
        if (contains_ignore_case(*current_operand_0, "+0e8h]")) {
            targets.internal_device_control = *maybe_target;
        }

        previous = item;
    }

    if (!targets.device_control.has_value()) {
        targets.possible_device_controls = locate_possible_dispatches(driver_entry);
    }

    return targets;
}

bool apply_struct_offset_if_matches(Address instruction_address,
                                    std::string_view pattern,
                                    std::string_view struct_name,
                                    std::string_view message_label) {
    bool applied = false;
    for (int operand_index = 0; operand_index < 2; ++operand_index) {
        const auto operand_text = instruction::operand_text(instruction_address, operand_index);
        if (!operand_text || !contains_ignore_case(*operand_text, pattern)) {
            continue;
        }

        const auto set_status = instruction::set_operand_struct_offset(
            instruction_address,
            operand_index,
            struct_name,
            0);
        if (set_status) {
            ui::message(fmt("[+] Labeled %s at 0x%08llX operand %d\n",
                            std::string(message_label).c_str(),
                            static_cast<unsigned long long>(instruction_address),
                            operand_index));
            applied = true;
        }
    }
    return applied;
}

void annotate_dispatch_structs(Address dispatch_address) {
    ui::message("[+] Annotating DispatchDeviceControl with known WDM structs...\n");

    (void)type::import_type("", "IRP");
    (void)type::import_type("", "IO_STACK_LOCATION");
    (void)type::import_type("", "DEVICE_OBJECT");

    const auto function_items = function::code_addresses(dispatch_address);
    if (!function_items) {
        return;
    }

    for (const auto item : *function_items) {
        (void)apply_struct_offset_if_matches(item,
                                             "+0b8h",
                                             "IRP",
                                             "IRP.CurrentStackLocation reference");
        (void)apply_struct_offset_if_matches(item,
                                             "+18h",
                                             "IRP",
                                             "IRP/SystemBuffer or DeviceIoControlCode reference");
        (void)apply_struct_offset_if_matches(item,
                                             "+38h",
                                             "IRP",
                                             "IRP.IoStatus.Information reference");
        (void)apply_struct_offset_if_matches(item,
                                             "+40h",
                                             "DEVICE_OBJECT",
                                             "DEVICE_OBJECT.DeviceExtension reference");
    }
}

void analyze_wdm_path(Address driver_entry) {
    Address effective_driver_entry = driver_entry;

    if (const auto real_entry = find_real_driver_entry(driver_entry); real_entry.has_value()) {
        effective_driver_entry = *real_entry;
        ui::message(fmt("[+] Found real DriverEntry address of %08llX\n",
                        static_cast<unsigned long long>(*real_entry)));
        (void)name::force_set(*real_entry, "Real_Driver_Entry");
    }

    const auto dispatch_targets = locate_dispatch_targets(effective_driver_entry);

    if (dispatch_targets.device_control.has_value()) {
        ui::message(fmt("[+] Found DispatchDeviceControl 0x%08llX\n",
                        static_cast<unsigned long long>(*dispatch_targets.device_control)));
        (void)name::force_set(*dispatch_targets.device_control, "DispatchDeviceControl");
        annotate_dispatch_structs(*dispatch_targets.device_control);
    }

    if (dispatch_targets.internal_device_control.has_value()) {
        ui::message(fmt("[+] Found DispatchInternalDeviceControl 0x%08llX\n",
                        static_cast<unsigned long long>(*dispatch_targets.internal_device_control)));
        (void)name::force_set(*dispatch_targets.internal_device_control,
                              "DispatchInternalDeviceControl");
    }

    if (!dispatch_targets.device_control.has_value()) {
        if (dispatch_targets.possible_device_controls.empty()) {
            ui::message("[-] Unable to automatically locate DispatchDeviceControl\n");
        } else {
            int index = 0;
            for (const auto candidate : dispatch_targets.possible_device_controls) {
                ui::message(fmt("[+] Possible DispatchDeviceControl 0x%08llX\n",
                                static_cast<unsigned long long>(candidate)));
                (void)name::force_set(candidate,
                                      "Possible_DispatchDeviceControl"
                                          + std::to_string(index++));
            }
        }
    }
}

void find_ioctls_via_listing_search() {
    const auto min_address = database::min_address();
    const auto max_address = database::max_address();
    if (!min_address || !max_address) {
        return;
    }

    ui::message("[+] Searching for IOCTLs found by IDA...\n");

    search::TextOptions options;
    options.direction = search::Direction::Forward;
    options.case_sensitive = false;

    Address cursor = *min_address;
    bool first = true;
    bool found_any = false;

    while (cursor < *max_address) {
        options.skip_start = !first;

        const auto hit = search::text("IoControlCode", cursor, options);
        if (!hit) {
            if (hit.error().category != ErrorCategory::NotFound) {
                ui::message(fmt("[-] IOCTL text search failed: %s\n",
                                error_text(hit.error()).c_str()));
            }
            break;
        }

        first = false;
        cursor = *hit;

        const auto insn = instruction::decode(cursor);
        if (!insn) {
            continue;
        }

        bool decoded = false;
        for (std::size_t index = 0; index < insn->operand_count(); ++index) {
            const auto operand = insn->operand(index);
            if (!operand || !operand->is_immediate()) {
                continue;
            }

            (void)instruction::set_operand_decimal(cursor, static_cast<int>(index));
            decode_and_print_ioctl(static_cast<std::uint32_t>(operand->value() & 0xFFFFFFFFU));
            found_any = true;
            decoded = true;
            break;
        }

        if (!decoded) {
            const auto line = instruction::text(cursor);
            ui::message(fmt("[-] Couldn't get IOCTL from %s at address %s\n",
                            line ? line->c_str() : "<unknown>",
                            fmt("0x%08llX", static_cast<unsigned long long>(cursor)).c_str()));
        }
    }

    if (!found_any) {
        ui::message("[-] Unable to automatically find any IOCTLs\n");
    }
}

class DriverBuddyPortPlugin final : public plugin::Plugin {
public:
    plugin::Info info() const override {
        return {
            .name = "Driver Buddy (idax port)",
            .hotkey = "Ctrl-Alt-D",
            .comment = "Windows driver analysis helper: driver type, dispatch IOCTL paths, and IOCTL decoding",
            .help = "Port of DriverBuddy IDAPython plugin with idax-first APIs",
        };
    }

    bool init() override {
        const auto action_status = register_decode_action();
        if (!action_status) {
            ui::message(fmt("[-] Failed to register decode action: %s\n",
                            error_text(action_status.error()).c_str()));
            return false;
        }

        action_registered_ = true;
        return true;
    }

    Status run(std::size_t) override {
        ui::message("[+] Welcome to Driver Buddy (idax)\n");

        const auto waited = analysis::wait();
        if (!waited) {
            ui::message(fmt("[-] auto-analysis wait failed: %s\n",
                            error_text(waited.error()).c_str()));
        }

        const auto driver_entry = find_driver_entry();
        if (!driver_entry.has_value()) {
            ui::message("[-] No DriverEntry stub found\n");
            ui::message("[-] Exiting...\n");
            return ida::ok();
        }
        ui::message("[+] DriverEntry found\n");

        const FunctionInventory inventory = build_inventory();

        ui::message("[+] Searching for interesting C functions....\n");
        const auto c_hits = collect_exact_matches(inventory.functions, kDangerousCFunctions);
        if (c_hits.empty()) {
            ui::message("[-] No interesting C functions detected\n");
        } else {
            ui::message("[+] interesting C functions detected\n");
            print_function_xrefs(c_hits);
        }

        ui::message("[+] Searching for interesting Windows functions....\n");
        const auto win_hits = collect_prefix_matches(inventory.functions, kInterestingWinApiPrefixes);
        if (win_hits.empty()) {
            ui::message("[-] No interesting winapi functions detected\n");
        } else {
            ui::message("[+] interesting winapi functions detected\n");
            print_function_xrefs(win_hits);
        }

        ui::message("[+] Searching for interesting driver functions....\n");
        const auto driver_hits = collect_exact_matches(inventory.functions, kDriverSpecificFunctions);
        if (driver_hits.empty()) {
            ui::message("[-] No interesting specific driver functions detected\n");
        } else {
            ui::message("[+] interesting driver functions detected\n");
            print_function_xrefs(driver_hits);
        }

        const DriverType type = detect_driver_type(inventory);
        ui::message(fmt("[+] Driver type detected: %s\n", std::string(driver_type_name(type)).c_str()));

        if (type == DriverType::Wdf) {
            annotate_wdf_functions(*driver_entry);
        } else if (type == DriverType::Wdm) {
            analyze_wdm_path(*driver_entry);
        }

        find_ioctls_via_listing_search();

        return ida::ok();
    }

    void term() override {
        if (!action_registered_) {
            return;
        }
        unregister_decode_action();
        action_registered_ = false;
    }

private:
    static constexpr std::string_view kDecodeActionId = "driverbuddy:decode-ioctl";
    static constexpr std::string_view kPluginMenuPath = "Edit/Plugins/";

    Status decode_ioctl_under_cursor() {
        const auto cursor = ui::screen_address();
        if (!cursor) {
            ui::message("[-] Unable to resolve current cursor address\n");
            return ida::ok();
        }

        const auto insn = instruction::decode(*cursor);
        if (!insn) {
            ui::message("[-] Current location is not a decodable instruction\n");
            return ida::ok();
        }

        const auto immediate = first_immediate_operand(*insn);
        if (!immediate.has_value()) {
            ui::message("[-] Highlight an instruction with an immediate IOCTL operand\n");
            return ida::ok();
        }

        decode_and_print_ioctl(*immediate);
        return ida::ok();
    }

    Status register_decode_action() {
        plugin::Action action;
        action.id = std::string(kDecodeActionId);
        action.label = "DriverBuddy: Decode IOCTL at cursor";
        action.hotkey = "Ctrl-Alt-I";
        action.tooltip = "Decode immediate DeviceIoControl value under the cursor";
        action.handler = [this]() { return decode_ioctl_under_cursor(); };
        action.enabled = []() { return true; };

        const auto register_status = plugin::register_action(action);
        if (!register_status) {
            return std::unexpected(register_status.error());
        }

        const auto attach_status = plugin::attach_to_menu(kPluginMenuPath, kDecodeActionId);
        if (!attach_status) {
            (void)plugin::unregister_action(kDecodeActionId);
            return std::unexpected(attach_status.error());
        }

        return ida::ok();
    }

    void unregister_decode_action() {
        (void)plugin::detach_from_menu(kPluginMenuPath, kDecodeActionId);
        (void)plugin::unregister_action(kDecodeActionId);
    }

    bool action_registered_{false};
};

} // namespace

IDAX_PLUGIN(DriverBuddyPortPlugin)
