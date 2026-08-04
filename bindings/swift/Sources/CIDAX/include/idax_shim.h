/* SPM publicHeaders shim — the C ABI's single source lives at
 * `bindings/c/include/idax_shim.h`. This file only exists because SPM
 * requires every public-header path to be under the target's source
 * directory; consumers (Swift `import CIDAX`, the XCFramework Headers/)
 * see exactly the same declarations as the central header.
 *
 * Do NOT add declarations here. Edit `bindings/c/include/idax_shim.h`.
 *
 * The Rust binding and the XCFramework packaging step both reference
 * the central header directly — they do not go through this shim.
 */
#include "../../../../c/include/idax_shim.h"
