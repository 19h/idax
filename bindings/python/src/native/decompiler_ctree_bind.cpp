#include "decompiler_python.hpp"

namespace idax::python {

namespace {

struct CtreeCallbackState {
    bool valid{true};
};

class PythonDecompiledFunction {
public:
    explicit PythonDecompiledFunction(ida::decompiler::DecompiledFunction function)
        : function_(std::move(function)) {}

    ida::decompiler::DecompiledFunction& get(std::string_view operation) {
        if (!function_) {
            throw_error(ida::Error::conflict(
                "DecompiledFunction is closed", std::string(operation)));
        }
        return *function_;
    }

    const ida::decompiler::DecompiledFunction& get(
        std::string_view operation) const {
        if (!function_) {
            throw_error(ida::Error::conflict(
                "DecompiledFunction is closed", std::string(operation)));
        }
        return *function_;
    }

    bool valid() const noexcept { return function_.has_value(); }
    void close() { function_.reset(); }

private:
    std::optional<ida::decompiler::DecompiledFunction> function_;
};

class PythonExpressionView {
public:
    PythonExpressionView(
        ida::decompiler::ExpressionView view,
        std::shared_ptr<CtreeCallbackState> state)
        : view_(std::move(view)), state_(std::move(state)) {}

    const ida::decompiler::ExpressionView& get(std::string_view operation) const {
        if (!state_->valid) {
            throw_error(ida::Error::conflict(
                "ExpressionView is only valid during ctree callback execution",
                std::string(operation)));
        }
        return view_;
    }

    PythonExpressionView child(
        ida::Result<ida::decompiler::ExpressionView> result,
        std::string_view operation) const {
        if (!state_->valid)
            (void)get(operation);
        return PythonExpressionView(unwrap(std::move(result)), state_);
    }

private:
    ida::decompiler::ExpressionView view_;
    std::shared_ptr<CtreeCallbackState> state_;
};

class PythonStatementView {
public:
    PythonStatementView(
        ida::decompiler::StatementView view,
        std::shared_ptr<CtreeCallbackState> state)
        : view_(std::move(view)), state_(std::move(state)) {}

    const ida::decompiler::StatementView& get(std::string_view operation) const {
        if (!state_->valid) {
            throw_error(ida::Error::conflict(
                "StatementView is only valid during ctree callback execution",
                std::string(operation)));
        }
        return view_;
    }

private:
    ida::decompiler::StatementView view_;
    std::shared_ptr<CtreeCallbackState> state_;
};

template <typename Adapter, typename Native>
ida::decompiler::VisitAction invoke_ctree_method(
    const py::function& callback, Native native) noexcept {
    py::gil_scoped_acquire acquire;
    auto state = std::make_shared<CtreeCallbackState>();
    Adapter adapter(std::move(native), state);
    try {
        auto action = callback(adapter)
            .template cast<ida::decompiler::VisitAction>();
        state->valid = false;
        return action;
    } catch (py::error_already_set& error) {
        state->valid = false;
        error.discard_as_unraisable(callback);
    } catch (...) {
        state->valid = false;
        PyErr_SetString(PyExc_RuntimeError, "non-Python ctree visitor failure");
        PyErr_WriteUnraisable(callback.ptr());
    }
    return ida::decompiler::VisitAction::Stop;
}

class PythonCtreeVisitor final : public ida::decompiler::CtreeVisitor {
public:
    using ida::decompiler::CtreeVisitor::CtreeVisitor;

    ida::decompiler::VisitAction visit_expression(
        ida::decompiler::ExpressionView expression) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "visit_expression");
        if (!override)
            return ida::decompiler::CtreeVisitor::visit_expression(expression);
        return invoke_ctree_method<PythonExpressionView>(override, expression);
    }

    ida::decompiler::VisitAction visit_statement(
        ida::decompiler::StatementView statement) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "visit_statement");
        if (!override)
            return ida::decompiler::CtreeVisitor::visit_statement(statement);
        return invoke_ctree_method<PythonStatementView>(override, statement);
    }

    ida::decompiler::VisitAction leave_expression(
        ida::decompiler::ExpressionView expression) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "leave_expression");
        if (!override)
            return ida::decompiler::CtreeVisitor::leave_expression(expression);
        return invoke_ctree_method<PythonExpressionView>(override, expression);
    }

    ida::decompiler::VisitAction leave_statement(
        ida::decompiler::StatementView statement) override {
        py::gil_scoped_acquire acquire;
        py::function override = py::get_override(this, "leave_statement");
        if (!override)
            return ida::decompiler::CtreeVisitor::leave_statement(statement);
        return invoke_ctree_method<PythonStatementView>(override, statement);
    }
};

ida::decompiler::DecompilerView view_from_event(py::handle source) {
    if (py::isinstance<PythonCursorPositionEvent>(source)) {
        const auto& event = source.cast<const PythonCursorPositionEvent&>();
        return unwrap(ida::decompiler::view_from_host(
            event.view->get("view_from_host")));
    }
    if (py::isinstance<PythonHintRequestEvent>(source)) {
        const auto& event = source.cast<const PythonHintRequestEvent&>();
        return unwrap(ida::decompiler::view_from_host(
            event.view->get("view_from_host")));
    }
    if (py::isinstance<PythonPopulatingPopupEvent>(source)) {
        const auto& event = source.cast<const PythonPopulatingPopupEvent&>();
        return unwrap(ida::decompiler::view_from_host(
            event.view->get("view_from_host")));
    }
    throw_error(ida::Error::validation(
        "view_from_host expects a callback-scoped decompiler event"));
}

const PythonPseudocodeEvent& pseudocode_event(py::handle source,
                                               std::string_view operation) {
    if (!py::isinstance<PythonPseudocodeEvent>(source)) {
        throw_error(ida::Error::validation(
            "Operation expects a callback-scoped PseudocodeEvent",
            std::string(operation)));
    }
    return source.cast<const PythonPseudocodeEvent&>();
}

} // namespace

void bind_decompiler_ctree(py::module_& decompiler) {
    py::native_enum<ida::decompiler::VariableStorage>(
        decompiler, "VariableStorage", "enum.Enum")
        .value("UNKNOWN", ida::decompiler::VariableStorage::Unknown)
        .value("REGISTER", ida::decompiler::VariableStorage::Register)
        .value("STACK", ida::decompiler::VariableStorage::Stack)
        .finalize();
    py::native_enum<ida::decompiler::LocalVariableLocationKind>(
        decompiler, "LocalVariableLocationKind", "enum.Enum")
        .value("NONE", ida::decompiler::LocalVariableLocationKind::None)
        .value("REGISTER", ida::decompiler::LocalVariableLocationKind::Register)
        .value("STACK", ida::decompiler::LocalVariableLocationKind::Stack)
        .finalize();
    py::native_enum<ida::decompiler::VisitAction>(
        decompiler, "VisitAction", "enum.Enum")
        .value("CONTINUE", ida::decompiler::VisitAction::Continue)
        .value("STOP", ida::decompiler::VisitAction::Stop)
        .value("SKIP_CHILDREN", ida::decompiler::VisitAction::SkipChildren)
        .finalize();
    py::native_enum<ida::decompiler::CommentPositionKind>(
        decompiler, "CommentPositionKind", "enum.Enum")
        .value("DEFAULT", ida::decompiler::CommentPositionKind::Default)
        .value("ARGUMENT", ida::decompiler::CommentPositionKind::Argument)
        .value("PARENTHESIS_OPEN", ida::decompiler::CommentPositionKind::ParenthesisOpen)
        .value("ASSEMBLY", ida::decompiler::CommentPositionKind::Assembly)
        .value("ELSE_LINE", ida::decompiler::CommentPositionKind::ElseLine)
        .value("DO_LINE", ida::decompiler::CommentPositionKind::DoLine)
        .value("SEMICOLON", ida::decompiler::CommentPositionKind::Semicolon)
        .value("OPEN_BRACE", ida::decompiler::CommentPositionKind::OpenBrace)
        .value("CLOSE_BRACE", ida::decompiler::CommentPositionKind::CloseBrace)
        .value("PARENTHESIS_CLOSE", ida::decompiler::CommentPositionKind::ParenthesisClose)
        .value("LABEL_COLON", ida::decompiler::CommentPositionKind::LabelColon)
        .value("BLOCK_BEFORE", ida::decompiler::CommentPositionKind::BlockBefore)
        .value("BLOCK_AFTER", ida::decompiler::CommentPositionKind::BlockAfter)
        .value("TRY_LINE", ida::decompiler::CommentPositionKind::TryLine)
        .value("SWITCH_CASE", ida::decompiler::CommentPositionKind::SwitchCase)
        .finalize();

    auto item_type = py::native_enum<ida::decompiler::ItemType>(
        decompiler, "ItemType", "enum.Enum");
#define IDAX_PY_ITEM(name, python_name) item_type.value(python_name, ida::decompiler::ItemType::name)
    IDAX_PY_ITEM(ExprEmpty, "EXPR_EMPTY");
    IDAX_PY_ITEM(ExprComma, "EXPR_COMMA");
    IDAX_PY_ITEM(ExprAssign, "EXPR_ASSIGN");
    IDAX_PY_ITEM(ExprAssignBitOr, "EXPR_ASSIGN_BIT_OR");
    IDAX_PY_ITEM(ExprAssignXor, "EXPR_ASSIGN_XOR");
    IDAX_PY_ITEM(ExprAssignBitAnd, "EXPR_ASSIGN_BIT_AND");
    IDAX_PY_ITEM(ExprAssignAdd, "EXPR_ASSIGN_ADD");
    IDAX_PY_ITEM(ExprAssignSub, "EXPR_ASSIGN_SUB");
    IDAX_PY_ITEM(ExprAssignMul, "EXPR_ASSIGN_MUL");
    IDAX_PY_ITEM(ExprAssignShiftRightSigned, "EXPR_ASSIGN_SHIFT_RIGHT_SIGNED");
    IDAX_PY_ITEM(ExprAssignShiftRightUnsigned, "EXPR_ASSIGN_SHIFT_RIGHT_UNSIGNED");
    IDAX_PY_ITEM(ExprAssignShiftLeft, "EXPR_ASSIGN_SHIFT_LEFT");
    IDAX_PY_ITEM(ExprAssignDivSigned, "EXPR_ASSIGN_DIV_SIGNED");
    IDAX_PY_ITEM(ExprAssignDivUnsigned, "EXPR_ASSIGN_DIV_UNSIGNED");
    IDAX_PY_ITEM(ExprAssignModSigned, "EXPR_ASSIGN_MOD_SIGNED");
    IDAX_PY_ITEM(ExprAssignModUnsigned, "EXPR_ASSIGN_MOD_UNSIGNED");
    IDAX_PY_ITEM(ExprTernary, "EXPR_TERNARY");
    IDAX_PY_ITEM(ExprLogicalOr, "EXPR_LOGICAL_OR");
    IDAX_PY_ITEM(ExprLogicalAnd, "EXPR_LOGICAL_AND");
    IDAX_PY_ITEM(ExprBitOr, "EXPR_BIT_OR");
    IDAX_PY_ITEM(ExprXor, "EXPR_XOR");
    IDAX_PY_ITEM(ExprBitAnd, "EXPR_BIT_AND");
    IDAX_PY_ITEM(ExprEqual, "EXPR_EQUAL");
    IDAX_PY_ITEM(ExprNotEqual, "EXPR_NOT_EQUAL");
    IDAX_PY_ITEM(ExprSignedGE, "EXPR_SIGNED_GE");
    IDAX_PY_ITEM(ExprUnsignedGE, "EXPR_UNSIGNED_GE");
    IDAX_PY_ITEM(ExprSignedLE, "EXPR_SIGNED_LE");
    IDAX_PY_ITEM(ExprUnsignedLE, "EXPR_UNSIGNED_LE");
    IDAX_PY_ITEM(ExprSignedGT, "EXPR_SIGNED_GT");
    IDAX_PY_ITEM(ExprUnsignedGT, "EXPR_UNSIGNED_GT");
    IDAX_PY_ITEM(ExprSignedLT, "EXPR_SIGNED_LT");
    IDAX_PY_ITEM(ExprUnsignedLT, "EXPR_UNSIGNED_LT");
    IDAX_PY_ITEM(ExprShiftRightSigned, "EXPR_SHIFT_RIGHT_SIGNED");
    IDAX_PY_ITEM(ExprShiftRightUnsigned, "EXPR_SHIFT_RIGHT_UNSIGNED");
    IDAX_PY_ITEM(ExprShiftLeft, "EXPR_SHIFT_LEFT");
    IDAX_PY_ITEM(ExprAdd, "EXPR_ADD");
    IDAX_PY_ITEM(ExprSub, "EXPR_SUB");
    IDAX_PY_ITEM(ExprMul, "EXPR_MUL");
    IDAX_PY_ITEM(ExprDivSigned, "EXPR_DIV_SIGNED");
    IDAX_PY_ITEM(ExprDivUnsigned, "EXPR_DIV_UNSIGNED");
    IDAX_PY_ITEM(ExprModSigned, "EXPR_MOD_SIGNED");
    IDAX_PY_ITEM(ExprModUnsigned, "EXPR_MOD_UNSIGNED");
    IDAX_PY_ITEM(ExprFloatAdd, "EXPR_FLOAT_ADD");
    IDAX_PY_ITEM(ExprFloatSub, "EXPR_FLOAT_SUB");
    IDAX_PY_ITEM(ExprFloatMul, "EXPR_FLOAT_MUL");
    IDAX_PY_ITEM(ExprFloatDiv, "EXPR_FLOAT_DIV");
    IDAX_PY_ITEM(ExprFloatNeg, "EXPR_FLOAT_NEG");
    IDAX_PY_ITEM(ExprNeg, "EXPR_NEG");
    IDAX_PY_ITEM(ExprCast, "EXPR_CAST");
    IDAX_PY_ITEM(ExprLogicalNot, "EXPR_LOGICAL_NOT");
    IDAX_PY_ITEM(ExprBitNot, "EXPR_BIT_NOT");
    IDAX_PY_ITEM(ExprDeref, "EXPR_DEREF");
    IDAX_PY_ITEM(ExprRef, "EXPR_REF");
    IDAX_PY_ITEM(ExprPostInc, "EXPR_POST_INC");
    IDAX_PY_ITEM(ExprPostDec, "EXPR_POST_DEC");
    IDAX_PY_ITEM(ExprPreInc, "EXPR_PRE_INC");
    IDAX_PY_ITEM(ExprPreDec, "EXPR_PRE_DEC");
    IDAX_PY_ITEM(ExprCall, "EXPR_CALL");
    IDAX_PY_ITEM(ExprIndex, "EXPR_INDEX");
    IDAX_PY_ITEM(ExprMemberRef, "EXPR_MEMBER_REF");
    IDAX_PY_ITEM(ExprMemberPtr, "EXPR_MEMBER_PTR");
    IDAX_PY_ITEM(ExprNumber, "EXPR_NUMBER");
    IDAX_PY_ITEM(ExprFloatNumber, "EXPR_FLOAT_NUMBER");
    IDAX_PY_ITEM(ExprString, "EXPR_STRING");
    IDAX_PY_ITEM(ExprObject, "EXPR_OBJECT");
    IDAX_PY_ITEM(ExprVariable, "EXPR_VARIABLE");
    IDAX_PY_ITEM(ExprInsn, "EXPR_INSN");
    IDAX_PY_ITEM(ExprSizeof, "EXPR_SIZEOF");
    IDAX_PY_ITEM(ExprHelper, "EXPR_HELPER");
    IDAX_PY_ITEM(ExprType, "EXPR_TYPE");
    IDAX_PY_ITEM(StmtEmpty, "STMT_EMPTY");
    IDAX_PY_ITEM(StmtBlock, "STMT_BLOCK");
    IDAX_PY_ITEM(StmtExpr, "STMT_EXPR");
    IDAX_PY_ITEM(StmtIf, "STMT_IF");
    IDAX_PY_ITEM(StmtFor, "STMT_FOR");
    IDAX_PY_ITEM(StmtWhile, "STMT_WHILE");
    IDAX_PY_ITEM(StmtDo, "STMT_DO");
    IDAX_PY_ITEM(StmtSwitch, "STMT_SWITCH");
    IDAX_PY_ITEM(StmtBreak, "STMT_BREAK");
    IDAX_PY_ITEM(StmtContinue, "STMT_CONTINUE");
    IDAX_PY_ITEM(StmtReturn, "STMT_RETURN");
    IDAX_PY_ITEM(StmtGoto, "STMT_GOTO");
    IDAX_PY_ITEM(StmtAsm, "STMT_ASM");
    IDAX_PY_ITEM(StmtTry, "STMT_TRY");
    IDAX_PY_ITEM(StmtThrow, "STMT_THROW");
#undef IDAX_PY_ITEM
    item_type.finalize();

#define IDAX_PY_DECOMPILER_CTREE_VALUE(type_name)                        \
    py::class_<ida::decompiler::type_name>(decompiler, #type_name).def(py::init<>())
    IDAX_PY_DECOMPILER_CTREE_VALUE(DecompileFailure)
        .def_readwrite("request_address", &ida::decompiler::DecompileFailure::request_address)
        .def_readwrite("failure_address", &ida::decompiler::DecompileFailure::failure_address)
        .def_readwrite("description", &ida::decompiler::DecompileFailure::description);
    IDAX_PY_DECOMPILER_CTREE_VALUE(LocalVariableLocator)
        .def_readwrite("kind", &ida::decompiler::LocalVariableLocator::kind)
        .def_readwrite("register_id", &ida::decompiler::LocalVariableLocator::register_id)
        .def_readwrite("stack_offset", &ida::decompiler::LocalVariableLocator::stack_offset)
        .def_readwrite("definition_address", &ida::decompiler::LocalVariableLocator::definition_address);
    IDAX_PY_DECOMPILER_CTREE_VALUE(LocalVariable)
        .def_readwrite("index", &ida::decompiler::LocalVariable::index)
        .def_readwrite("name", &ida::decompiler::LocalVariable::name)
        .def_readwrite("type_name", &ida::decompiler::LocalVariable::type_name)
        .def_readwrite("is_argument", &ida::decompiler::LocalVariable::is_argument)
        .def_readwrite("width", &ida::decompiler::LocalVariable::width)
        .def_readwrite("has_user_name", &ida::decompiler::LocalVariable::has_user_name)
        .def_readwrite("has_nice_name", &ida::decompiler::LocalVariable::has_nice_name)
        .def_readwrite("storage", &ida::decompiler::LocalVariable::storage)
        .def_readwrite("comment", &ida::decompiler::LocalVariable::comment);
    IDAX_PY_DECOMPILER_CTREE_VALUE(LocalVariableUserSetting)
        .def_readwrite("locator", &ida::decompiler::LocalVariableUserSetting::locator)
        .def_readwrite("name", &ida::decompiler::LocalVariableUserSetting::name)
        .def_readwrite("type_declaration", &ida::decompiler::LocalVariableUserSetting::type_declaration)
        .def_readwrite("comment", &ida::decompiler::LocalVariableUserSetting::comment);
    IDAX_PY_DECOMPILER_CTREE_VALUE(ReferencedTypeCollection)
        .def_readwrite("ordinals", &ida::decompiler::ReferencedTypeCollection::ordinals)
        .def_readwrite("used_offsets", &ida::decompiler::ReferencedTypeCollection::used_offsets);
    IDAX_PY_DECOMPILER_CTREE_VALUE(CtreeItemView)
        .def_readwrite("type", &ida::decompiler::CtreeItemView::type)
        .def_readwrite("address", &ida::decompiler::CtreeItemView::address)
        .def_readwrite("is_expression", &ida::decompiler::CtreeItemView::is_expression);
    IDAX_PY_DECOMPILER_CTREE_VALUE(VisitOptions)
        .def_readwrite("post_order", &ida::decompiler::VisitOptions::post_order)
        .def_readwrite("track_parents", &ida::decompiler::VisitOptions::track_parents)
        .def_readwrite("expressions_only", &ida::decompiler::VisitOptions::expressions_only);
    IDAX_PY_DECOMPILER_CTREE_VALUE(PseudocodeComment)
        .def_readwrite("address", &ida::decompiler::PseudocodeComment::address)
        .def_readwrite("position", &ida::decompiler::PseudocodeComment::position)
        .def_readwrite("text", &ida::decompiler::PseudocodeComment::text);
    IDAX_PY_DECOMPILER_CTREE_VALUE(AddressMapping)
        .def_readwrite("address", &ida::decompiler::AddressMapping::address)
        .def_readwrite("line_number", &ida::decompiler::AddressMapping::line_number);
    IDAX_PY_DECOMPILER_CTREE_VALUE(ItemAtPosition)
        .def_readwrite("type", &ida::decompiler::ItemAtPosition::type)
        .def_readwrite("address", &ida::decompiler::ItemAtPosition::address)
        .def_readwrite("item_index", &ida::decompiler::ItemAtPosition::item_index)
        .def_readwrite("is_expression", &ida::decompiler::ItemAtPosition::is_expression);
#undef IDAX_PY_DECOMPILER_CTREE_VALUE

    py::class_<ida::decompiler::LvarSnapshot>(decompiler, "LvarSnapshot")
        .def(py::init<>())
        .def_property_readonly("empty", &ida::decompiler::LvarSnapshot::empty)
        .def_property_readonly("saved_variable_count",
                               &ida::decompiler::LvarSnapshot::saved_variable_count)
        .def("__bool__", [](const ida::decompiler::LvarSnapshot& self) {
            return !self.empty();
        });
    auto comment_position = py::class_<ida::decompiler::CommentPosition>(
        decompiler, "CommentPosition")
        .def(py::init<>())
        .def_static("argument", [](std::size_t index) {
            return unwrap(ida::decompiler::CommentPosition::argument(index));
        }, py::arg("zero_based_index"))
        .def_static("switch_case", [](std::int64_t value) {
            return unwrap(ida::decompiler::CommentPosition::switch_case(value));
        }, py::arg("value"))
        .def_property_readonly("kind", &ida::decompiler::CommentPosition::kind)
        .def_property_readonly("argument_index",
                               &ida::decompiler::CommentPosition::argument_index)
        .def_property_readonly("switch_case_value",
                               &ida::decompiler::CommentPosition::switch_case_value)
        .def("__eq__", [](const ida::decompiler::CommentPosition& left,
                            const ida::decompiler::CommentPosition& right) {
            return left == right;
        });
    comment_position.attr("DEFAULT") = ida::decompiler::CommentPosition::Default;
    comment_position.attr("PARENTHESIS_OPEN") = ida::decompiler::CommentPosition::ParenthesisOpen;
    comment_position.attr("ASSEMBLY") = ida::decompiler::CommentPosition::Assembly;
    comment_position.attr("ELSE_LINE") = ida::decompiler::CommentPosition::ElseLine;
    comment_position.attr("DO_LINE") = ida::decompiler::CommentPosition::DoLine;
    comment_position.attr("SEMICOLON") = ida::decompiler::CommentPosition::Semicolon;
    comment_position.attr("OPEN_BRACE") = ida::decompiler::CommentPosition::OpenBrace;
    comment_position.attr("CLOSE_BRACE") = ida::decompiler::CommentPosition::CloseBrace;
    comment_position.attr("PARENTHESIS_CLOSE") = ida::decompiler::CommentPosition::ParenthesisClose;
    comment_position.attr("LABEL_COLON") = ida::decompiler::CommentPosition::LabelColon;
    comment_position.attr("BLOCK_BEFORE") = ida::decompiler::CommentPosition::BlockBefore;
    comment_position.attr("BLOCK_AFTER") = ida::decompiler::CommentPosition::BlockAfter;
    comment_position.attr("TRY_LINE") = ida::decompiler::CommentPosition::TryLine;

    py::class_<PythonExpressionView>(decompiler, "ExpressionView")
        .def_property_readonly("type", [](const PythonExpressionView& self) {
            return self.get("type").type();
        })
        .def_property_readonly("address", [](const PythonExpressionView& self) {
            return self.get("address").address();
        })
#define IDAX_PY_EXPR_RESULT(fn)                                          \
        .def(#fn, [](const PythonExpressionView& self) {                 \
            return unwrap(self.get(#fn).fn());                           \
        })
        IDAX_PY_EXPR_RESULT(number_value)
        IDAX_PY_EXPR_RESULT(object_address)
        IDAX_PY_EXPR_RESULT(variable_index)
        IDAX_PY_EXPR_RESULT(helper_name)
        IDAX_PY_EXPR_RESULT(type_declaration)
        IDAX_PY_EXPR_RESULT(type_byte_width)
        IDAX_PY_EXPR_RESULT(pointed_type_byte_width)
        IDAX_PY_EXPR_RESULT(string_value)
        IDAX_PY_EXPR_RESULT(call_argument_count)
        IDAX_PY_EXPR_RESULT(member_offset)
        IDAX_PY_EXPR_RESULT(member_name)
        IDAX_PY_EXPR_RESULT(to_string)
        IDAX_PY_EXPR_RESULT(parent)
        IDAX_PY_EXPR_RESULT(parents)
#undef IDAX_PY_EXPR_RESULT
        .def("call_callee", [](const PythonExpressionView& self) {
            return self.child(self.get("call_callee").call_callee(), "call_callee");
        })
        .def("call_argument", [](const PythonExpressionView& self, std::size_t index) {
            return self.child(self.get("call_argument").call_argument(index), "call_argument");
        }, py::arg("index"))
        .def("left", [](const PythonExpressionView& self) {
            return self.child(self.get("left").left(), "left");
        })
        .def("right", [](const PythonExpressionView& self) {
            return self.child(self.get("right").right(), "right");
        })
        .def("third", [](const PythonExpressionView& self) {
            return self.child(self.get("third").third(), "third");
        })
        .def_property_readonly("is_assignment_lhs", [](const PythonExpressionView& self) {
            return self.get("is_assignment_lhs").is_assignment_lhs();
        })
        .def_property_readonly("operand_count", [](const PythonExpressionView& self) {
            return self.get("operand_count").operand_count();
        });
    py::class_<PythonStatementView>(decompiler, "StatementView")
        .def_property_readonly("type", [](const PythonStatementView& self) {
            return self.get("type").type();
        })
        .def_property_readonly("address", [](const PythonStatementView& self) {
            return self.get("address").address();
        })
        .def("goto_target_label", [](const PythonStatementView& self) {
            return unwrap(self.get("goto_target_label").goto_target_label());
        })
        .def("parent", [](const PythonStatementView& self) {
            return unwrap(self.get("parent").parent());
        })
        .def("parents", [](const PythonStatementView& self) {
            return unwrap(self.get("parents").parents());
        });
    py::class_<ida::decompiler::CtreeVisitor, PythonCtreeVisitor>(
        decompiler, "CtreeVisitor")
        .def(py::init<>())
        .def("visit_expression", [](ida::decompiler::CtreeVisitor& self,
                                      const PythonExpressionView& expression) {
            return self.visit_expression(expression.get("visit_expression"));
        })
        .def("visit_statement", [](ida::decompiler::CtreeVisitor& self,
                                     const PythonStatementView& statement) {
            return self.visit_statement(statement.get("visit_statement"));
        })
        .def("leave_expression", [](ida::decompiler::CtreeVisitor& self,
                                      const PythonExpressionView& expression) {
            return self.leave_expression(expression.get("leave_expression"));
        })
        .def("leave_statement", [](ida::decompiler::CtreeVisitor& self,
                                     const PythonStatementView& statement) {
            return self.leave_statement(statement.get("leave_statement"));
        });

    py::class_<PythonDecompiledFunction>(decompiler, "DecompiledFunction")
#define IDAX_PY_DF_RESULT(fn)                                            \
        .def(#fn, [](const PythonDecompiledFunction& self) {             \
            return runtime_result("decompiler.DecompiledFunction." #fn, \
                [&] { return self.get(#fn).fn(); });                     \
        })
        IDAX_PY_DF_RESULT(pseudocode)
        IDAX_PY_DF_RESULT(microcode)
        IDAX_PY_DF_RESULT(lines)
        IDAX_PY_DF_RESULT(raw_lines)
        IDAX_PY_DF_RESULT(header_line_count)
        IDAX_PY_DF_RESULT(microcode_lines)
        IDAX_PY_DF_RESULT(declaration)
        IDAX_PY_DF_RESULT(variable_count)
        IDAX_PY_DF_RESULT(variables)
        IDAX_PY_DF_RESULT(capture_user_lvar_settings)
        IDAX_PY_DF_RESULT(comments)
        IDAX_PY_DF_RESULT(has_orphan_comments)
        IDAX_PY_DF_RESULT(address_map)
#undef IDAX_PY_DF_RESULT
        .def_property_readonly("valid", &PythonDecompiledFunction::valid)
        .def("close", &PythonDecompiledFunction::close)
        .def("__enter__", [](PythonDecompiledFunction& self)
             -> PythonDecompiledFunction& { return self; },
             py::return_value_policy::reference_internal)
        .def("__exit__", [](PythonDecompiledFunction& self,
                             py::object, py::object, py::object) {
            self.close();
            return false;
        })
        .def("set_raw_line", [](PythonDecompiledFunction& self,
                                  std::size_t index, std::string text) {
            runtime_status("decompiler.DecompiledFunction.set_raw_line", [&] {
                return self.get("set_raw_line").set_raw_line(index, text);
            });
        }, py::arg("line_index"), py::arg("tagged_text"))
        .def("variable", [](const PythonDecompiledFunction& self,
                              std::size_t index) {
            return runtime_result("decompiler.DecompiledFunction.variable", [&] {
                return self.get("variable").variable(index);
            });
        }, py::arg("variable_index"))
        .def("rename_variable", [](PythonDecompiledFunction& self,
                                     std::string old_name, std::string new_name) {
            runtime_status("decompiler.DecompiledFunction.rename_variable", [&] {
                return self.get("rename_variable").rename_variable(old_name, new_name);
            });
        }, py::arg("old_name"), py::arg("new_name"))
        .def("retype_variable", [](PythonDecompiledFunction& self,
            py::object variable, const ida::type::TypeInfo& new_type) {
            runtime_status("decompiler.DecompiledFunction.retype_variable", [&] {
                auto& function = self.get("retype_variable");
                if (py::isinstance<py::str>(variable))
                    return function.retype_variable(variable.cast<std::string>(), new_type);
                return function.retype_variable(variable.cast<std::size_t>(), new_type);
            });
        }, py::arg("variable"), py::arg("new_type"))
        .def("restore_user_lvar_settings", [](
            PythonDecompiledFunction& self,
            const ida::decompiler::LvarSnapshot& snapshot) {
            runtime_status("decompiler.DecompiledFunction.restore_user_lvar_settings", [&] {
                return self.get("restore_user_lvar_settings")
                    .restore_user_lvar_settings(snapshot);
            });
        }, py::arg("snapshot"))
        .def("set_variable_comment", [](PythonDecompiledFunction& self,
            py::object variable, std::string comment) {
            runtime_status("decompiler.DecompiledFunction.set_variable_comment", [&] {
                auto& function = self.get("set_variable_comment");
                if (py::isinstance<py::str>(variable))
                    return function.set_variable_comment(variable.cast<std::string>(), comment);
                return function.set_variable_comment(variable.cast<std::size_t>(), comment);
            });
        }, py::arg("variable"), py::arg("comment"))
        .def("visit", [](const PythonDecompiledFunction& self,
                           ida::decompiler::CtreeVisitor& visitor,
                           const ida::decompiler::VisitOptions& options) {
            return runtime_result("decompiler.DecompiledFunction.visit", [&] {
                return self.get("visit").visit(visitor, options);
            });
        }, py::arg("visitor"), py::arg("options") = ida::decompiler::VisitOptions{})
        .def("visit_expressions", [](const PythonDecompiledFunction& self,
            ida::decompiler::CtreeVisitor& visitor, bool post_order) {
            return runtime_result("decompiler.DecompiledFunction.visit_expressions", [&] {
                return self.get("visit_expressions")
                    .visit_expressions(visitor, post_order);
            });
        }, py::arg("visitor"), py::arg("post_order") = false)
        .def("set_comment", [](PythonDecompiledFunction& self,
            ida::Address address, std::string text,
            ida::decompiler::CommentPosition position) {
            runtime_status("decompiler.DecompiledFunction.set_comment", [&] {
                return self.get("set_comment").set_comment(address, text, position);
            });
        }, py::arg("address"), py::arg("text"),
           py::arg("position") = ida::decompiler::CommentPosition::Default)
        .def("get_comment", [](const PythonDecompiledFunction& self,
            ida::Address address, ida::decompiler::CommentPosition position) {
            return runtime_result("decompiler.DecompiledFunction.get_comment", [&] {
                return self.get("get_comment").get_comment(address, position);
            });
        }, py::arg("address"),
           py::arg("position") = ida::decompiler::CommentPosition::Default)
        .def("save_comments", [](const PythonDecompiledFunction& self) {
            runtime_status("decompiler.DecompiledFunction.save_comments", [&] {
                return self.get("save_comments").save_comments();
            });
        })
        .def("remove_orphan_comments", [](PythonDecompiledFunction& self) {
            return runtime_result("decompiler.DecompiledFunction.remove_orphan_comments", [&] {
                return self.get("remove_orphan_comments").remove_orphan_comments();
            });
        })
        .def("refresh", [](const PythonDecompiledFunction& self) {
            runtime_status("decompiler.DecompiledFunction.refresh", [&] {
                return self.get("refresh").refresh();
            });
        })
        .def_property_readonly("entry_address", [](
            const PythonDecompiledFunction& self) {
            return self.get("entry_address").entry_address();
        })
        .def("line_to_address", [](const PythonDecompiledFunction& self,
                                     int line_number) {
            return runtime_result("decompiler.DecompiledFunction.line_to_address", [&] {
                return self.get("line_to_address").line_to_address(line_number);
            });
        }, py::arg("line_number"));

    py::class_<ida::decompiler::DecompilerView>(decompiler, "DecompilerView")
        .def_property_readonly("function_address",
                               &ida::decompiler::DecompilerView::function_address)
        .def("function_name", [](const ida::decompiler::DecompilerView& self) {
            return runtime_result("decompiler.DecompilerView.function_name", [&] {
                return self.function_name();
            });
        })
        .def("decompiled_function", [](const ida::decompiler::DecompilerView& self) {
            auto function = runtime_result(
                "decompiler.DecompilerView.decompiled_function", [&] {
                return self.decompiled_function();
            });
            return PythonDecompiledFunction(std::move(function));
        })
        .def("rename_variable", [](const ida::decompiler::DecompilerView& self,
            std::string old_name, std::string new_name) {
            runtime_status("decompiler.DecompilerView.rename_variable", [&] {
                return self.rename_variable(old_name, new_name);
            });
        }, py::arg("old_name"), py::arg("new_name"))
        .def("retype_variable", [](const ida::decompiler::DecompilerView& self,
            py::object variable, const ida::type::TypeInfo& new_type) {
            runtime_status("decompiler.DecompilerView.retype_variable", [&] {
                if (py::isinstance<py::str>(variable))
                    return self.retype_variable(variable.cast<std::string>(), new_type);
                return self.retype_variable(variable.cast<std::size_t>(), new_type);
            });
        }, py::arg("variable"), py::arg("new_type"))
        .def("capture_user_lvar_settings", [](const ida::decompiler::DecompilerView& self) {
            return runtime_result("decompiler.DecompilerView.capture_user_lvar_settings", [&] {
                return self.capture_user_lvar_settings();
            });
        })
        .def("restore_user_lvar_settings", [](const ida::decompiler::DecompilerView& self,
            const ida::decompiler::LvarSnapshot& snapshot) {
            runtime_status("decompiler.DecompilerView.restore_user_lvar_settings", [&] {
                return self.restore_user_lvar_settings(snapshot);
            });
        }, py::arg("snapshot"))
        .def("set_variable_comment", [](const ida::decompiler::DecompilerView& self,
            py::object variable, std::string comment) {
            runtime_status("decompiler.DecompilerView.set_variable_comment", [&] {
                if (py::isinstance<py::str>(variable))
                    return self.set_variable_comment(variable.cast<std::string>(), comment);
                return self.set_variable_comment(variable.cast<std::size_t>(), comment);
            });
        }, py::arg("variable"), py::arg("comment"))
        .def("set_comment", [](const ida::decompiler::DecompilerView& self,
            ida::Address address, std::string text,
            ida::decompiler::CommentPosition position) {
            runtime_status("decompiler.DecompilerView.set_comment", [&] {
                return self.set_comment(address, text, position);
            });
        }, py::arg("address"), py::arg("text"),
           py::arg("position") = ida::decompiler::CommentPosition::Default)
        .def("get_comment", [](const ida::decompiler::DecompilerView& self,
            ida::Address address, ida::decompiler::CommentPosition position) {
            return runtime_result("decompiler.DecompilerView.get_comment", [&] {
                return self.get_comment(address, position);
            });
        }, py::arg("address"),
           py::arg("position") = ida::decompiler::CommentPosition::Default)
        .def("comments", [](const ida::decompiler::DecompilerView& self) {
            return runtime_result("decompiler.DecompilerView.comments", [&] {
                return self.comments();
            });
        })
        .def("save_comments", [](const ida::decompiler::DecompilerView& self) {
            runtime_status("decompiler.DecompilerView.save_comments", [&] {
                return self.save_comments();
            });
        })
        .def("refresh", [](const ida::decompiler::DecompilerView& self) {
            runtime_status("decompiler.DecompilerView.refresh", [&] {
                return self.refresh();
            });
        });

    decompiler.def("saved_user_lvar_settings", [](ida::Address address) {
        return runtime_result("decompiler.saved_user_lvar_settings", [=] {
            return ida::decompiler::saved_user_lvar_settings(address);
        });
    }, py::arg("function_address"));
    decompiler.def("apply_user_lvar_setting", [](ida::Address address,
        const ida::decompiler::LocalVariableUserSetting& setting) {
        runtime_status("decompiler.apply_user_lvar_setting", [&] {
            return ida::decompiler::apply_user_lvar_setting(address, setting);
        });
    }, py::arg("function_address"), py::arg("setting"));
    decompiler.def("apply_user_lvar_settings", [](ida::Address address,
        const std::vector<ida::decompiler::LocalVariableUserSetting>& settings) {
        runtime_status("decompiler.apply_user_lvar_settings", [&] {
            return ida::decompiler::apply_user_lvar_settings(address, settings);
        });
    }, py::arg("function_address"), py::arg("settings"));
    decompiler.def("collect_referenced_types", [](ida::Address address) {
        return runtime_result("decompiler.collect_referenced_types", [=] {
            return ida::decompiler::collect_referenced_types(address);
        });
    }, py::arg("function_address"));
    decompiler.def("is_expression", &ida::decompiler::is_expression, py::arg("type"));
    decompiler.def("is_statement", &ida::decompiler::is_statement, py::arg("type"));
    decompiler.def("view_from_host", [](py::object event) {
        ensure_runtime_thread("decompiler.view_from_host");
        return view_from_event(event);
    }, py::arg("event"));
    decompiler.def("view_for_function", [](ida::Address address) {
        return runtime_result("decompiler.view_for_function", [=] {
            return ida::decompiler::view_for_function(address);
        });
    }, py::arg("address"));
    decompiler.def("current_view", [] {
        return runtime_result("decompiler.current_view", ida::decompiler::current_view);
    });
    decompiler.def("decompile", [](ida::Address address) {
        ensure_runtime_thread("decompiler.decompile");
        ida::decompiler::DecompileFailure failure;
        auto result = ida::decompiler::decompile(address, &failure);
        if (!result) {
            auto error = std::move(result.error());
            std::string detail = failure.description;
            if (failure.failure_address != ida::BadAddress)
                detail += "@" + std::to_string(failure.failure_address);
            if (!detail.empty()) {
                if (!error.context.empty())
                    error.context += ":";
                error.context += detail;
            }
            throw_error(std::move(error));
        }
        return PythonDecompiledFunction(std::move(*result));
    }, py::arg("address"));
    decompiler.def("raw_pseudocode_lines", [](py::object event) {
        const auto& value = pseudocode_event(event, "raw_pseudocode_lines");
        return runtime_result("decompiler.raw_pseudocode_lines", [&] {
            return ida::decompiler::raw_pseudocode_lines(
                value.cfunc->get("raw_pseudocode_lines"));
        });
    }, py::arg("event"));
    decompiler.def("set_pseudocode_line", [](py::object event,
        std::size_t line_index, std::string text) {
        const auto& value = pseudocode_event(event, "set_pseudocode_line");
        runtime_status("decompiler.set_pseudocode_line", [&] {
            return ida::decompiler::set_pseudocode_line(
                value.cfunc->get("set_pseudocode_line"), line_index, text);
        });
    }, py::arg("event"), py::arg("line_index"), py::arg("tagged_text"));
    decompiler.def("pseudocode_header_line_count", [](py::object event) {
        const auto& value = pseudocode_event(event, "pseudocode_header_line_count");
        return runtime_result("decompiler.pseudocode_header_line_count", [&] {
            return ida::decompiler::pseudocode_header_line_count(
                value.cfunc->get("pseudocode_header_line_count"));
        });
    }, py::arg("event"));
    decompiler.def("item_at_position", [](py::object event,
        std::string line, int char_index) {
        const auto& value = pseudocode_event(event, "item_at_position");
        return runtime_result("decompiler.item_at_position", [&] {
            return ida::decompiler::item_at_position(
                value.cfunc->get("item_at_position"), line, char_index);
        });
    }, py::arg("event"), py::arg("tagged_line"), py::arg("char_index"));
    decompiler.def("item_type_name", &ida::decompiler::item_type_name,
                   py::arg("type"));
    decompiler.def("for_each_expression", [](
        const PythonDecompiledFunction& function,
        py::function callback) {
        return runtime_result("decompiler.for_each_expression", [&] {
            return ida::decompiler::for_each_expression(
                function.get("for_each_expression"),
                [callback = std::move(callback)](
                    ida::decompiler::ExpressionView expression) {
                    return invoke_ctree_method<PythonExpressionView>(
                        callback, expression);
                });
        });
    }, py::arg("function"), py::arg("callback"));
    decompiler.def("for_each_item", [](
        const PythonDecompiledFunction& function,
        py::function expression_callback, py::function statement_callback) {
        return runtime_result("decompiler.for_each_item", [&] {
            return ida::decompiler::for_each_item(
                function.get("for_each_item"),
                [expression_callback](ida::decompiler::ExpressionView expression) {
                    return invoke_ctree_method<PythonExpressionView>(
                        expression_callback, expression);
                },
                [statement_callback](ida::decompiler::StatementView statement) {
                    return invoke_ctree_method<PythonStatementView>(
                        statement_callback, statement);
                });
        });
    }, py::arg("function"), py::arg("on_expression"),
       py::arg("on_statement"));
}

} // namespace idax::python
