/// \file qtform_renderer_bridge.hpp
/// \brief Non-Qt bridge used by the ida-qtform plugin glue.

#ifndef IDAX_EXAMPLES_QTFORM_RENDERER_BRIDGE_HPP
#define IDAX_EXAMPLES_QTFORM_RENDERER_BRIDGE_HPP

#include <functional>
#include <string>

bool mount_form_renderer_widget(
    void* host_widget,
    std::function<void(const std::string&)> test_callback,
    std::string* error);

#endif // IDAX_EXAMPLES_QTFORM_RENDERER_BRIDGE_HPP
