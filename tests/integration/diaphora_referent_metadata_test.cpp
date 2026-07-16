#define IDAX_DIAPHORA_EXACT_CORE_TEST
#include "../../examples/plugin/diaphora_exact_port_plugin.cpp"

#include <filesystem>
#include <iostream>
#include <string>

namespace {

bool fail(std::string_view message) {
    std::cerr << "FAIL: " << message << "\n";
    return false;
}

template <typename T>
bool require_result(const ida::Result<T>& result, std::string_view operation) {
    if (result)
        return true;
    std::cerr << "FAIL: " << operation << ": " << result.error().message << "\n";
    return false;
}

bool require_status(const ida::Status& status, std::string_view operation) {
    if (status)
        return true;
    std::cerr << "FAIL: " << operation << ": " << status.error().message << "\n";
    return false;
}

const EligibleReferentMetadata* find_eligible(
    const ReferentMetadataManifest& manifest,
    const ReferentMetadataComparison& comparison,
    bool require_name,
    bool require_type,
    ida::Address excluded = ida::BadAddress) {
    for (const auto& eligible : comparison.eligible) {
        const auto& source = manifest.referents[eligible.metadata_index];
        if (eligible.referent_address != excluded
            && (!require_name || !source.name.empty())
            && (!require_type || !source.declaration.empty())) {
            return &eligible;
        }
    }
    return nullptr;
}

bool remove_name_if_present(ida::Address address) {
    auto existing = ida::name::get(address);
    if (existing)
        return require_status(ida::name::remove(address), "remove source referent name");
    return existing.error().category == ida::ErrorCategory::NotFound
        || fail("unexpected source referent name lookup failure");
}

bool remove_type_if_present(ida::Address address) {
    auto existing = ida::type::retrieve(address);
    if (existing)
        return require_status(ida::type::remove_type(address), "remove source referent type");
    return existing.error().category == ida::ErrorCategory::NotFound
        || fail("unexpected source referent type lookup failure");
}

bool verify_name(ida::Address address, std::string_view expected) {
    auto actual = ida::name::get(address);
    return require_result(actual, "read referent name")
        && (*actual == expected || fail("referent name mismatch"));
}

bool verify_type(ida::Address address, std::string_view expected) {
    auto actual = ida::type::retrieve(address);
    if (!require_result(actual, "read referent type"))
        return false;
    auto expected_type = ida::type::TypeInfo::from_declaration(expected);
    if (!require_result(expected_type, "parse expected referent type"))
        return false;
    auto actual_text = actual->to_string();
    auto expected_text = expected_type->to_string();
    return require_result(actual_text, "render actual referent type")
        && require_result(expected_text, "render expected referent type")
        && (*actual_text == *expected_text || fail("referent type mismatch"));
}

} // namespace

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <fixture>\n";
        return 2;
    }
    if (!std::filesystem::exists(argv[1]))
        return fail("fixture does not exist") ? 0 : 1;

    std::cerr << "[diaphora-referent] init\n";
    char* ida_argv[] = {argv[0]};
    if (!require_status(ida::database::init(1, ida_argv), "database init")
        || !require_status(ida::database::open(argv[1], true), "database open")
        || !require_status(ida::analysis::wait(), "analysis wait")) {
        return 1;
    }
    std::cerr << "[diaphora-referent] opened\n";

    bool ok = true;
    auto baseline = extract_referent_metadata_manifest();
    auto current = extract_manifest();
    std::cerr << "[diaphora-referent] extracted\n";
    if (!require_result(baseline, "extract referent metadata")
        || !require_result(current, "extract current functions")) {
        ok = false;
    }
    if (!ok) {
        (void)ida::database::close(false);
        return 1;
    }

    const std::string encoded = format_referent_metadata_manifest(*baseline);
    auto parsed = parse_referent_metadata_manifest(encoded);
    if (!require_result(parsed, "parse emitted referent metadata")
        || format_referent_metadata_manifest(*parsed) != encoded) {
        ok = fail("real-IDA manifest is not byte-stable");
    }

    auto initial = compare_referent_metadata(*baseline, *current);
    if (!require_result(initial, "compare referent metadata")) {
        ok = false;
    } else if (initial->eligible.empty()
               || initial->instruction_guard_failures != 0
               || initial->reference_guard_failures != 0) {
        ok = fail("fixture did not provide clean eligible referent metadata");
    }

    if (ok) {
        auto tampered = *baseline;
        const std::size_t index = initial->eligible.front().metadata_index;
        tampered.referents[index].relocation_md5[0] =
            tampered.referents[index].relocation_md5[0] == '0' ? '1' : '0';
        auto rejected = compare_referent_metadata(tampered, *current);
        if (!require_result(rejected, "compare tampered instruction guard")
            || rejected->eligible.size() + 1 != initial->eligible.size()
            || rejected->instruction_guard_failures != 1
            || rejected->reference_guard_failures != 0) {
            ok = fail("relocation-hash guard did not reject exactly one record");
        }
    }

    const EligibleReferentMetadata* ambiguous = nullptr;
    if (ok) {
        for (const auto& eligible : initial->eligible) {
            if (baseline->referents[eligible.metadata_index].kind == ReferentKind::Data) {
                ambiguous = &eligible;
                break;
            }
        }
        if (ambiguous == nullptr) {
            ok = fail("fixture has no eligible data referent for ambiguity probe");
        } else {
            const ida::Address alternate = ambiguous->referent_address + 1;
            if (!require_status(ida::xref::add_data(
                    ambiguous->instruction_address, alternate,
                    ida::xref::DataType::Informational),
                                "add ambiguous data reference")) {
                ok = false;
            } else {
                auto rejected = compare_referent_metadata(*baseline, *current);
                if (!require_result(rejected, "compare ambiguous data reference")
                    || rejected->eligible.size() + 1 != initial->eligible.size()
                    || rejected->reference_guard_failures != 1
                    || rejected->instruction_guard_failures != 0) {
                    ok = fail("multi-referent guard did not reject exactly one record");
                }
                if (!require_status(ida::xref::remove_data(
                        ambiguous->instruction_address, alternate),
                                    "remove ambiguous data reference")) {
                    ok = false;
                }
            }
        }
    }

    const EligibleReferentMetadata* absent_name = nullptr;
    const EligibleReferentMetadata* preserved_name = nullptr;
    const EligibleReferentMetadata* absent_type = nullptr;
    const EligibleReferentMetadata* preserved_type = nullptr;
    if (ok) {
        absent_name = find_eligible(*baseline, *initial, true, false);
        preserved_name = absent_name == nullptr
            ? nullptr
            : find_eligible(*baseline, *initial, true, false,
                            absent_name->referent_address);
        absent_type = find_eligible(*baseline, *initial, false, true);
        preserved_type = absent_type == nullptr
            ? nullptr
            : find_eligible(*baseline, *initial, false, true,
                            absent_type->referent_address);
        if (absent_name == nullptr || preserved_name == nullptr
            || absent_type == nullptr || preserved_type == nullptr) {
            ok = fail("fixture lacks distinct apply/preserve referent candidates");
        }
    }

    constexpr std::string_view kPreservedName = "idax_phase53_target_owned";
    constexpr std::string_view kPreservedDeclaration =
        "unsigned char __idax_diaphora_referent;";
    if (ok) {
        ok = remove_name_if_present(absent_name->referent_address)
          && remove_type_if_present(absent_type->referent_address)
          && require_status(ida::name::set(
                 preserved_name->referent_address, kPreservedName),
                            "seed target-owned referent name");
        auto preserved = ida::type::TypeInfo::from_declaration(kPreservedDeclaration);
        ok = ok && require_result(preserved, "parse target-owned referent type")
          && require_status(preserved->apply(preserved_type->referent_address),
                            "seed target-owned referent type");
    }

    if (ok) {
        auto eligible = compare_referent_metadata(*baseline, *current);
        if (!require_result(eligible, "compare after metadata removal")) {
            ok = false;
        } else {
            const auto applied = apply_referent_metadata(*baseline, *eligible);
            if (applied.names == 0 || applied.types == 0
                || applied.preserved < 2 || applied.failures != 0) {
                ok = fail("conservative apply counts do not cover apply/preserve paths");
            }
        }
    }

    if (ok) {
        const auto& absent_name_source =
            baseline->referents[absent_name->metadata_index];
        const auto& absent_type_source =
            baseline->referents[absent_type->metadata_index];
        ok = verify_name(absent_name->referent_address, absent_name_source.name)
          && verify_type(absent_type->referent_address,
                         absent_type_source.declaration)
          && verify_name(preserved_name->referent_address, kPreservedName)
          && verify_type(preserved_type->referent_address,
                         kPreservedDeclaration);
    }

    if (ok && !require_status(ida::database::close(true), "save and close database"))
        ok = false;
    else if (!ok)
        (void)ida::database::close(false);

    if (ok) {
        if (!require_status(ida::database::open(argv[1], true), "reopen database")
            || !require_status(ida::analysis::wait(), "reopen analysis wait")) {
            ok = false;
        } else {
            const auto& absent_name_source =
                baseline->referents[absent_name->metadata_index];
            const auto& absent_type_source =
                baseline->referents[absent_type->metadata_index];
            ok = verify_name(absent_name->referent_address, absent_name_source.name)
              && verify_type(absent_type->referent_address,
                             absent_type_source.declaration)
              && verify_name(preserved_name->referent_address, kPreservedName)
              && verify_type(preserved_type->referent_address,
                             kPreservedDeclaration);
            auto reopened_current = extract_manifest();
            auto reopened = require_result(reopened_current, "extract reopened functions")
                ? compare_referent_metadata(*baseline, *reopened_current)
                : ida::Result<ReferentMetadataComparison>{
                    std::unexpected(ida::Error::internal("reopen extraction failed"))};
            if (!require_result(reopened, "compare reopened referent metadata")) {
                ok = false;
            } else {
                const auto reapplied = apply_referent_metadata(*baseline, *reopened);
                if (reapplied.names != 0 || reapplied.types != 0
                    || reapplied.failures != 0) {
                    ok = fail("reopened apply is not idempotent");
                }
            }
        }
        (void)ida::database::close(false);
    }

    if (!ok)
        return 1;
    std::cout << "Diaphora referent metadata runtime evidence: PASS\n";
    return 0;
}
