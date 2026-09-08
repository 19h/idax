#ifndef IDAX_SWIFT_CIDAX_H
#define IDAX_SWIFT_CIDAX_H

// Keep the canonical C transport shared with Rust. It remains private to the
// Swift implementation; public Swift values contain no SDK pointers.
#include "../../../../rust/idax-sys/shim/idax_shim.h"
#include "../../../bridge/bridge.h"
#include "../../../bridge/data_custom.h"
#include "../../../bridge/data_values.h"
#include "../../../bridge/decompiler.h"
#include "../../../bridge/decompiler_events.h"
#include "../../../bridge/values.h"
#include "../../../bridge/values_extra.h"
#include "../../../bridge/lifecycle.h"
#include "../../../bridge/forms.h"
#include "../../../bridge/microcode.h"
#include "../../../bridge/type_extra.h"

#endif
