/// \file addon.cpp
/// \brief Main NAN module entry point for idax Node.js bindings.
///
/// Registers all namespace sub-modules under a single native addon.

#include "helpers.hpp"

NAN_MODULE_INIT(InitAll) {
    using namespace idax_node;

    // Each Init* creates a namespace object on `target`
    InitDatabase(target);
    InitAddress(target);
    InitSegment(target);
    InitFunction(target);
    InitInstruction(target);
    InitName(target);
    InitXref(target);
    InitComment(target);
    InitData(target);
    InitSearch(target);
    InitAnalysis(target);
    InitType(target);
    InitEntry(target);
    InitFixup(target);
    InitEvent(target);
    InitStorage(target);
    InitDiagnostics(target);
    InitLumina(target);
    InitLines(target);
    InitDecompiler(target);
}

NODE_MODULE(idax_native, InitAll)
