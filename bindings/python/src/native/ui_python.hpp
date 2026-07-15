#ifndef IDAX_PYTHON_UI_PYTHON_HPP
#define IDAX_PYTHON_UI_PYTHON_HPP

#include "opaque_handle.hpp"

namespace idax::python {

void bind_ui_events(py::module_& ui);

} // namespace idax::python

#endif // IDAX_PYTHON_UI_PYTHON_HPP
