/// \file idax.hpp
/// \brief Master include for the idax intuitive IDA SDK wrapper.
///
/// Including this single header brings in every idax namespace.
/// For finer-grained control, include the individual domain headers instead.

#ifndef IDAX_IDAX_HPP
#define IDAX_IDAX_HPP

#include <ida/error.hpp>
#include <ida/core.hpp>
#include <ida/diagnostics.hpp>
#include <ida/address.hpp>
#include <ida/data.hpp>
#include <ida/database.hpp>
#include <ida/segment.hpp>
#include <ida/function.hpp>
#include <ida/instruction.hpp>
#include <ida/name.hpp>
#include <ida/xref.hpp>
#include <ida/comment.hpp>
#include <ida/search.hpp>
#include <ida/analysis.hpp>
#include <ida/lumina.hpp>
#include <ida/type.hpp>
#include <ida/entry.hpp>
#include <ida/fixup.hpp>
#include <ida/event.hpp>
#include <ida/plugin.hpp>
#include <ida/loader.hpp>
#include <ida/processor.hpp>
#include <ida/debugger.hpp>
#include <ida/decompiler.hpp>
#include <ida/storage.hpp>
#include <ida/graph.hpp>
#include <ida/ui.hpp>
#include <ida/lines.hpp>

#endif // IDAX_IDAX_HPP
