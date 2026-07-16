/// \file exception.cpp
/// \brief Architecture-independent exception-region implementation.

#include "detail/sdk_bridge.hpp"

#include <ida/exception.hpp>

#include <tryblks.hpp>

#include <string>

namespace ida::exception {

namespace {

constexpr std::uint32_t kAllowedLocationBits =
    static_cast<std::uint32_t>(Location::Any)
    | static_cast<std::uint32_t>(Location::UnwindFallthrough);

static_assert(static_cast<std::uint32_t>(Location::CppTry) == TBEA_TRY);
static_assert(static_cast<std::uint32_t>(Location::CppHandler) == TBEA_CATCH);
static_assert(static_cast<std::uint32_t>(Location::SehTry) == TBEA_SEHTRY);
static_assert(static_cast<std::uint32_t>(Location::SehHandler) == TBEA_SEHLPAD);
static_assert(static_cast<std::uint32_t>(Location::SehFilter) == TBEA_SEHFILT);
static_assert(static_cast<std::uint32_t>(Location::Any) == TBEA_ANY);
static_assert(static_cast<std::uint32_t>(Location::UnwindFallthrough)
              == TBEA_FALLTHRU);
static_assert(static_cast<std::int8_t>(SehDisposition::ContinueExecution) == -1);
static_assert(static_cast<std::int8_t>(SehDisposition::ContinueSearch) == 0);
static_assert(static_cast<std::int8_t>(SehDisposition::ExecuteHandler) == 1);

Error with_code(Error error, int code) {
    error.code = code;
    return error;
}

Status validate_range(address::Range range, const char* context) {
    if (range.start == BadAddress) {
        return std::unexpected(Error::validation(
            "Exception range start cannot be BadAddress", context));
    }
    if (range.end <= range.start) {
        return std::unexpected(Error::validation(
            "Exception range must be non-empty and ordered", context));
    }
    return ok();
}

Status validate_ranges(const std::vector<address::Range>& ranges,
                       const char* context,
                       bool require_nonempty = true) {
    if (require_nonempty && ranges.empty()) {
        return std::unexpected(Error::validation(
            "Exception range collection cannot be empty", context));
    }
    Address previous_end = 0;
    bool first = true;
    for (const auto& range : ranges) {
        if (auto status = validate_range(range, context); !status)
            return status;
        if (!first && range.start < previous_end) {
            return std::unexpected(Error::validation(
                "Exception ranges must be sorted and non-overlapping", context));
        }
        first = false;
        previous_end = range.end;
    }
    return ok();
}

Status validate_metadata(const HandlerMetadata& metadata,
                         const char* context) {
    if (auto status = validate_ranges(metadata.regions, context); !status)
        return status;
    if (metadata.stack_displacement && *metadata.stack_displacement == -1) {
        return std::unexpected(Error::validation(
            "Use absence for an unknown handler stack displacement", context));
    }
    if (metadata.frame_register && *metadata.frame_register < 0) {
        return std::unexpected(Error::validation(
            "Handler frame register must be non-negative", context));
    }
    return ok();
}

Status validate_definition(const BlockDefinition& block) {
    if (auto status = validate_ranges(
            block.protected_regions, "protected regions"); !status)
        return status;

    if (const auto* cpp = std::get_if<CppHandlers>(&block.handlers)) {
        if (cpp->catches.empty()) {
            return std::unexpected(Error::validation(
                "C++ exception block requires at least one catch handler"));
        }
        for (std::size_t index = 0; index < cpp->catches.size(); ++index) {
            const auto& handler = cpp->catches[index];
            const std::string context = "C++ catch " + std::to_string(index);
            if (auto status = validate_metadata(
                    handler.metadata, context.c_str()); !status)
                return status;
            if (handler.object_displacement
                && *handler.object_displacement == -1) {
                return std::unexpected(Error::validation(
                    "Use absence for an unknown exception-object displacement",
                    context));
            }
            if (handler.selector.kind == CatchSelectorKind::Typed) {
                if (handler.selector.type_identifier < 0) {
                    return std::unexpected(Error::validation(
                        "Typed catch identifier must be non-negative", context));
                }
            } else if (handler.selector.type_identifier != 0) {
                return std::unexpected(Error::validation(
                    "Catch-all and cleanup selectors cannot carry a type identifier",
                    context));
            }
        }
        return ok();
    }

    const auto& seh = std::get<SehHandler>(block.handlers);
    if (auto status = validate_metadata(seh.metadata, "SEH handler"); !status)
        return status;
    if (auto status = validate_ranges(
            seh.filter_regions, "SEH filter regions", false); !status)
        return status;
    if (seh.filter_regions.empty() != seh.disposition.has_value()) {
        return std::unexpected(Error::validation(
            "SEH disposition is required exactly when filter regions are absent"));
    }
    if (seh.disposition) {
        switch (*seh.disposition) {
        case SehDisposition::ContinueExecution:
        case SehDisposition::ContinueSearch:
        case SehDisposition::ExecuteHandler:
            break;
        default:
            return std::unexpected(Error::validation(
                "Unknown SEH disposition"));
        }
    }
    return ok();
}

range_t to_native_range(address::Range range) {
    return {static_cast<ea_t>(range.start), static_cast<ea_t>(range.end)};
}

address::Range from_native_range(const range_t& range) {
    return {static_cast<Address>(range.start_ea),
            static_cast<Address>(range.end_ea)};
}

template <typename NativeRanges>
std::vector<address::Range> copy_ranges(const NativeRanges& ranges) {
    std::vector<address::Range> result;
    result.reserve(ranges.size());
    for (const auto& range : ranges)
        result.push_back(from_native_range(range));
    return result;
}

template <typename NativeRanges>
void append_ranges(NativeRanges& output,
                   const std::vector<address::Range>& ranges) {
    for (const auto& range : ranges)
        output.push_back(to_native_range(range));
}

template <typename NativeHandler>
HandlerMetadata copy_metadata(const NativeHandler& handler) {
    HandlerMetadata result;
    result.regions = copy_ranges(handler);
    if (handler.disp != -1)
        result.stack_displacement = static_cast<AddressDelta>(handler.disp);
    if (handler.fpreg != -1)
        result.frame_register = handler.fpreg;
    return result;
}

template <typename NativeHandler>
void fill_metadata(NativeHandler& output, const HandlerMetadata& metadata) {
    append_ranges(output, metadata.regions);
    output.disp = metadata.stack_displacement
        ? static_cast<sval_t>(*metadata.stack_displacement) : sval_t(-1);
    output.fpreg = metadata.frame_register.value_or(-1);
}

Result<CatchHandler> copy_catch(const catch_t& input) {
    CatchHandler output;
    output.metadata = copy_metadata(input);
    if (input.obj != -1)
        output.object_displacement = static_cast<AddressDelta>(input.obj);
    if (input.type_id == CATCH_ID_ALL) {
        output.selector.kind = CatchSelectorKind::CatchAll;
    } else if (input.type_id == CATCH_ID_CLEANUP) {
        output.selector.kind = CatchSelectorKind::Cleanup;
    } else if (input.type_id >= 0) {
        output.selector.kind = CatchSelectorKind::Typed;
        output.selector.type_identifier = static_cast<std::int64_t>(input.type_id);
    } else {
        return std::unexpected(Error::sdk(
            "IDA returned an unknown C++ catch selector",
            std::to_string(input.type_id)));
    }
    return output;
}

Result<SehHandler> copy_seh(const seh_t& input) {
    SehHandler output;
    output.metadata = copy_metadata(input);
    output.filter_regions = copy_ranges(input.filter);
    if (!output.filter_regions.empty())
        return output;
    if (input.seh_code == SEH_CONTINUE) {
        output.disposition = SehDisposition::ContinueExecution;
    } else if (input.seh_code == SEH_SEARCH) {
        output.disposition = SehDisposition::ContinueSearch;
    } else if (input.seh_code == SEH_HANDLE) {
        output.disposition = SehDisposition::ExecuteHandler;
    } else {
        return std::unexpected(Error::sdk(
            "IDA returned an unknown SEH disposition",
            std::to_string(input.seh_code)));
    }
    return output;
}

Result<Block> copy_block(const tryblk_t& input) {
    Block output;
    output.definition.protected_regions = copy_ranges(input);
    output.nesting_level = input.level;
    if (input.is_cpp()) {
        CppHandlers handlers;
        handlers.catches.reserve(input.cpp().size());
        for (const auto& native_catch : input.cpp()) {
            auto handler = copy_catch(native_catch);
            if (!handler)
                return std::unexpected(handler.error());
            handlers.catches.push_back(std::move(*handler));
        }
        output.definition.handlers = std::move(handlers);
    } else if (input.is_seh()) {
        auto handler = copy_seh(input.seh());
        if (!handler)
            return std::unexpected(handler.error());
        output.definition.handlers = std::move(*handler);
    } else {
        return std::unexpected(Error::sdk(
            "IDA returned an exception block with an unknown kind"));
    }
    return output;
}

void fill_catch(catch_t& output, const CatchHandler& input) {
    fill_metadata(output, input.metadata);
    output.obj = input.object_displacement
        ? static_cast<sval_t>(*input.object_displacement) : sval_t(-1);
    switch (input.selector.kind) {
    case CatchSelectorKind::Typed:
        output.type_id = static_cast<sval_t>(input.selector.type_identifier);
        break;
    case CatchSelectorKind::CatchAll:
        output.type_id = CATCH_ID_ALL;
        break;
    case CatchSelectorKind::Cleanup:
        output.type_id = CATCH_ID_CLEANUP;
        break;
    }
}

void fill_seh(seh_t& output, const SehHandler& input) {
    output.clear();
    fill_metadata(output, input.metadata);
    append_ranges(output.filter, input.filter_regions);
    if (!input.filter_regions.empty())
        return;
    switch (*input.disposition) {
    case SehDisposition::ContinueExecution:
        output.seh_code = SEH_CONTINUE;
        break;
    case SehDisposition::ContinueSearch:
        output.seh_code = SEH_SEARCH;
        break;
    case SehDisposition::ExecuteHandler:
        output.seh_code = SEH_HANDLE;
        break;
    }
}

Error add_error(int code) {
    switch (code) {
    case TBERR_START:
        return with_code(Error::validation(
            "IDA rejected an exception-region start address"), code);
    case TBERR_END:
        return with_code(Error::validation(
            "IDA rejected an exception-region end address"), code);
    case TBERR_ORDER:
        return with_code(Error::validation(
            "IDA rejected exception-region ordering"), code);
    case TBERR_EMPTY:
        return with_code(Error::validation(
            "IDA rejected an empty exception region"), code);
    case TBERR_KIND:
        return with_code(Error::validation(
            "IDA rejected the exception-region kind"), code);
    case TBERR_NO_CATCHES:
        return with_code(Error::validation(
            "IDA requires at least one exception handler"), code);
    case TBERR_INTERSECT:
        return with_code(Error::conflict(
            "Exception region intersects incompatible existing metadata"), code);
    default:
        return with_code(Error::sdk(
            "IDA failed to add exception-region metadata"), code);
    }
}

} // namespace

Result<std::vector<Block>> list(address::Range range) {
    if (auto status = validate_range(range, "query range"); !status)
        return std::unexpected(status.error());

    tryblks_t native_blocks;
    ::get_tryblks(&native_blocks, to_native_range(range));
    std::vector<Block> blocks;
    blocks.reserve(native_blocks.size());
    for (const auto& native_block : native_blocks) {
        auto block = copy_block(native_block);
        if (!block)
            return std::unexpected(block.error());
        blocks.push_back(std::move(*block));
    }
    return blocks;
}

Status remove(address::Range range) {
    if (auto status = validate_range(range, "removal range"); !status)
        return status;
    ::del_tryblks(to_native_range(range));
    return ok();
}

Status add(const BlockDefinition& block) {
    if (auto status = validate_definition(block); !status)
        return status;

    tryblk_t native_block;
    append_ranges(native_block, block.protected_regions);
    if (const auto* cpp = std::get_if<CppHandlers>(&block.handlers)) {
        auto& native_catches = native_block.set_cpp();
        native_catches.reserve(cpp->catches.size());
        for (const auto& input : cpp->catches) {
            catch_t output;
            fill_catch(output, input);
            native_catches.push_back(std::move(output));
        }
    } else {
        fill_seh(native_block.set_seh(), std::get<SehHandler>(block.handlers));
    }

    const int code = ::add_tryblk(native_block);
    if (code != TBERR_OK)
        return std::unexpected(add_error(code));
    return ok();
}

Result<std::optional<Address>> system_region_start(Address address) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "Exception lookup address cannot be BadAddress"));
    }
    const ea_t result = ::find_syseh(static_cast<ea_t>(address));
    if (result == BADADDR)
        return std::optional<Address>{};
    return std::optional<Address>{static_cast<Address>(result)};
}

Result<bool> contains(Address address, Location locations) {
    if (address == BadAddress) {
        return std::unexpected(Error::validation(
            "Exception membership address cannot be BadAddress"));
    }
    const auto bits = static_cast<std::uint32_t>(locations);
    if (bits == 0 || (bits & ~kAllowedLocationBits) != 0) {
        return std::unexpected(Error::validation(
            "Exception location mask is empty or contains unknown classes",
            std::to_string(bits)));
    }
    return ::is_ea_tryblks(static_cast<ea_t>(address), bits);
}

} // namespace ida::exception
