/// \file ida_names_port_bridge.hpp
/// \brief Non-Qt bridge used by the IDA-names plugin glue.

#ifndef IDAX_EXAMPLES_IDA_NAMES_PORT_BRIDGE_HPP
#define IDAX_EXAMPLES_IDA_NAMES_PORT_BRIDGE_HPP

#include <string>
#include <string_view>

bool set_ida_names_widget_title(void* host_widget,
                                std::string_view title,
                                std::string* error);

#endif // IDAX_EXAMPLES_IDA_NAMES_PORT_BRIDGE_HPP
