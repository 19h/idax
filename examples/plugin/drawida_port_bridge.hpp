/// \file drawida_port_bridge.hpp
/// \brief Non-Qt bridge used by the DrawIDA plugin glue.

#ifndef IDAX_EXAMPLES_DRAWIDA_PORT_BRIDGE_HPP
#define IDAX_EXAMPLES_DRAWIDA_PORT_BRIDGE_HPP

#include <string>

bool mount_drawida_panel(void* host_widget, std::string* error);

#endif // IDAX_EXAMPLES_DRAWIDA_PORT_BRIDGE_HPP
