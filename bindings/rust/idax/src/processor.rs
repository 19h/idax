//! Processor module development helpers.
//!
//! Mirrors C++ `ida::processor` data models and callback contracts.

use crate::address::{Address, BAD_ADDRESS};
use crate::error::Result;

#[derive(Debug, Clone)]
pub struct RegisterInfo {
    pub name: String,
    pub read_only: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum InstructionFeature {
    None = 0,
    Stop = 0x00001,
    Call = 0x00002,
    Change1 = 0x00004,
    Change2 = 0x00008,
    Change3 = 0x00010,
    Change4 = 0x00020,
    Change5 = 0x00040,
    Change6 = 0x00080,
    Use1 = 0x00100,
    Use2 = 0x00200,
    Use3 = 0x00400,
    Use4 = 0x00800,
    Use5 = 0x01000,
    Use6 = 0x02000,
    Jump = 0x04000,
    Shift = 0x08000,
    HighLevel = 0x10000,
}

#[derive(Debug, Clone)]
pub struct InstructionDescriptor {
    pub mnemonic: String,
    pub feature_flags: u32,
    pub operand_count: u8,
    pub description: String,
    pub privileged: bool,
}

#[derive(Debug, Clone)]
pub struct AssemblerInfo {
    pub name: String,
    pub comment_prefix: String,
    pub origin: String,
    pub end_directive: String,
    pub string_delim: char,
    pub char_delim: char,
    pub byte_directive: String,
    pub word_directive: String,
    pub dword_directive: String,
    pub qword_directive: String,
    pub oword_directive: String,
    pub float_directive: String,
    pub double_directive: String,
    pub tbyte_directive: String,
    pub align_directive: String,
    pub include_directive: String,
    pub public_directive: String,
    pub weak_directive: String,
    pub external_directive: String,
    pub current_ip_symbol: String,
    pub uppercase_mnemonics: bool,
    pub uppercase_registers: bool,
    pub requires_colon_after_labels: bool,
    pub supports_quoted_names: bool,
}

impl Default for AssemblerInfo {
    fn default() -> Self {
        Self {
            name: String::new(),
            comment_prefix: String::new(),
            origin: String::new(),
            end_directive: String::new(),
            string_delim: '"',
            char_delim: '\'',
            byte_directive: String::new(),
            word_directive: String::new(),
            dword_directive: String::new(),
            qword_directive: String::new(),
            oword_directive: String::new(),
            float_directive: String::new(),
            double_directive: String::new(),
            tbyte_directive: String::new(),
            align_directive: String::new(),
            include_directive: String::new(),
            public_directive: String::new(),
            weak_directive: String::new(),
            external_directive: String::new(),
            current_ip_symbol: String::new(),
            uppercase_mnemonics: false,
            uppercase_registers: false,
            requires_colon_after_labels: false,
            supports_quoted_names: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ProcessorFlag {
    None = 0,
    Segments = 0x000001,
    Use32 = 0x000002,
    Use64 = 0x000004,
    DefaultSeg32 = 0x000008,
    DefaultSeg64 = 0x000010,
    TypeInfo = 0x000020,
    UseArgTypes = 0x000040,
    ConditionalInsns = 0x000080,
    NoSegMove = 0x000100,
    HexNumbers = 0x000200,
    DecimalNumbers = 0x000400,
    OctalNumbers = 0x000800,
}

#[derive(Debug, Clone)]
pub struct ProcessorInfo {
    pub id: i32,
    pub short_names: Vec<String>,
    pub long_names: Vec<String>,
    pub flags: u32,
    pub flags2: u32,
    pub code_bits_per_byte: i32,
    pub data_bits_per_byte: i32,
    pub registers: Vec<RegisterInfo>,
    pub code_segment_register: i32,
    pub data_segment_register: i32,
    pub first_segment_register: i32,
    pub last_segment_register: i32,
    pub segment_register_size: i32,
    pub instructions: Vec<InstructionDescriptor>,
    pub return_icode: i32,
    pub assemblers: Vec<AssemblerInfo>,
    pub default_bitness: i32,
}

impl Default for ProcessorInfo {
    fn default() -> Self {
        Self {
            id: 0,
            short_names: Vec::new(),
            long_names: Vec::new(),
            flags: 0,
            flags2: 0,
            code_bits_per_byte: 8,
            data_bits_per_byte: 8,
            registers: Vec::new(),
            code_segment_register: 0,
            data_segment_register: 1,
            first_segment_register: 0,
            last_segment_register: 1,
            segment_register_size: 0,
            instructions: Vec::new(),
            return_icode: 0,
            assemblers: Vec::new(),
            default_bitness: 32,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SwitchTableKind {
    Dense,
    Sparse,
    Indirect,
    Custom,
}

#[derive(Debug, Clone)]
pub struct SwitchDescription {
    pub kind: SwitchTableKind,
    pub jump_table: Address,
    pub values_table: Address,
    pub default_target: Address,
    pub idiom_start: Address,
    pub element_base: Address,
    pub low_case_value: i64,
    pub indirect_low_case_value: i64,
    pub case_count: u32,
    pub jump_table_entry_count: u32,
    pub jump_element_size: u8,
    pub value_element_size: u8,
    pub shift: u8,
    pub expression_register: i32,
    pub expression_data_type: u8,
    pub has_default: bool,
    pub default_in_table: bool,
    pub values_signed: bool,
    pub subtract_values: bool,
    pub self_relative: bool,
    pub inverted: bool,
    pub user_defined: bool,
}

impl Default for SwitchDescription {
    fn default() -> Self {
        Self {
            kind: SwitchTableKind::Dense,
            jump_table: BAD_ADDRESS,
            values_table: BAD_ADDRESS,
            default_target: BAD_ADDRESS,
            idiom_start: BAD_ADDRESS,
            element_base: 0,
            low_case_value: 0,
            indirect_low_case_value: 0,
            case_count: 0,
            jump_table_entry_count: 0,
            jump_element_size: 0,
            value_element_size: 0,
            shift: 0,
            expression_register: -1,
            expression_data_type: 0,
            has_default: false,
            default_in_table: false,
            values_signed: false,
            subtract_values: false,
            self_relative: false,
            inverted: false,
            user_defined: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SwitchCase {
    pub values: Vec<i64>,
    pub target: Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum EmulateResult {
    NotImplemented = 0,
    Success = 1,
    DeleteInsn = -1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OutputOperandResult {
    NotImplemented = 0,
    Success = 1,
    Hidden = -1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum OutputInstructionResult {
    NotImplemented = 0,
    Success = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnalyzeOperandKind {
    None,
    Register,
    Immediate,
    NearAddress,
    FarAddress,
    DirectMemory,
    IndirectMemory,
    Displacement,
    ProcessorSpecific0,
    ProcessorSpecific1,
    ProcessorSpecific2,
    ProcessorSpecific3,
    ProcessorSpecific4,
    ProcessorSpecific5,
}

#[derive(Debug, Clone)]
pub struct AnalyzeOperand {
    pub index: usize,
    pub kind: AnalyzeOperandKind,
    pub has_register: bool,
    pub register_index: i32,
    pub has_immediate: bool,
    pub immediate_value: u64,
    pub has_target_address: bool,
    pub target_address: Address,
    pub has_displacement: bool,
    pub displacement: i64,
    pub data_type_code: u32,
    pub processor_flags: u32,
}

impl Default for AnalyzeOperand {
    fn default() -> Self {
        Self {
            index: 0,
            kind: AnalyzeOperandKind::None,
            has_register: false,
            register_index: -1,
            has_immediate: false,
            immediate_value: 0,
            has_target_address: false,
            target_address: BAD_ADDRESS,
            has_displacement: false,
            displacement: 0,
            data_type_code: 0,
            processor_flags: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AnalyzeDetails {
    pub size: i32,
    pub operands: Vec<AnalyzeOperand>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputTokenKind {
    PlainText,
    Mnemonic,
    Register,
    Immediate,
    Address,
    Symbol,
    Comment,
    Keyword,
    StringLiteral,
    Number,
    OperatorSymbol,
    Punctuation,
    Whitespace,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputToken {
    pub kind: OutputTokenKind,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct OutputContext {
    buffer: String,
    tokens: Vec<OutputToken>,
}

impl OutputContext {
    pub fn token(&mut self, kind: OutputTokenKind, text: impl AsRef<str>) -> &mut Self {
        let t = text.as_ref();
        if t.is_empty() {
            return self;
        }
        self.buffer.push_str(t);
        self.tokens.push(OutputToken {
            kind,
            text: t.to_string(),
        });
        self
    }

    pub fn append(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::PlainText, text)
    }

    pub fn mnemonic(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Mnemonic, text)
    }

    pub fn register_name(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Register, text)
    }

    pub fn symbol(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Symbol, text)
    }

    pub fn keyword(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Keyword, text)
    }

    pub fn comment(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Comment, text)
    }

    pub fn number(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Number, text)
    }

    pub fn operator_symbol(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::OperatorSymbol, text)
    }

    pub fn punctuation(&mut self, text: impl AsRef<str>) -> &mut Self {
        self.token(OutputTokenKind::Punctuation, text)
    }

    pub fn whitespace(&mut self, text: Option<&str>) -> &mut Self {
        self.token(OutputTokenKind::Whitespace, text.unwrap_or(" "))
    }

    pub fn string_literal(&mut self, text: impl AsRef<str>, quote: Option<char>) -> &mut Self {
        let q = quote.unwrap_or('"');
        self.punctuation(q.to_string());
        self.token(OutputTokenKind::StringLiteral, text);
        self.punctuation(q.to_string())
    }

    pub fn immediate(&mut self, value: i64, radix: i32) -> &mut Self {
        let rendered = match radix {
            10 => format!("{value}"),
            8 => format!("0{:o}", value as u64),
            2 => format!("0b{:b}", value as u64),
            _ => format!("0x{:x}", value as u64),
        };
        self.token(OutputTokenKind::Immediate, rendered)
    }

    pub fn address(&mut self, address: Address) -> &mut Self {
        self.token(OutputTokenKind::Address, format!("0x{address:x}"))
    }

    pub fn character(&mut self, ch: char) -> &mut Self {
        if ch.is_whitespace() {
            return self.token(OutputTokenKind::Whitespace, ch.to_string());
        }
        if ",:;()[]{}".contains(ch) {
            return self.token(OutputTokenKind::Punctuation, ch.to_string());
        }
        self.token(OutputTokenKind::PlainText, ch.to_string())
    }

    pub fn space(&mut self) -> &mut Self {
        self.whitespace(Some(" "))
    }

    pub fn comma(&mut self) -> &mut Self {
        self.punctuation(",")
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.tokens.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn text(&self) -> &str {
        &self.buffer
    }

    pub fn tokens(&self) -> &[OutputToken] {
        &self.tokens
    }

    pub fn take(&mut self) -> String {
        self.tokens.clear();
        std::mem::take(&mut self.buffer)
    }

    pub fn take_tokens(&mut self) -> Vec<OutputToken> {
        self.buffer.clear();
        std::mem::take(&mut self.tokens)
    }
}

pub trait Processor {
    fn info(&self) -> ProcessorInfo;
    fn analyze(&mut self, address: Address) -> Result<i32>;
    fn emulate(&mut self, address: Address) -> EmulateResult;
    fn output_instruction(&mut self, address: Address);
    fn output_operand(&mut self, address: Address, operand_index: i32) -> OutputOperandResult;

    fn analyze_with_details(&mut self, address: Address) -> Result<AnalyzeDetails> {
        let size = self.analyze(address)?;
        Ok(AnalyzeDetails {
            size,
            operands: Vec::new(),
        })
    }

    fn output_mnemonic_with_context(
        &mut self,
        _address: Address,
        _output: &mut OutputContext,
    ) -> OutputInstructionResult {
        OutputInstructionResult::NotImplemented
    }

    fn output_instruction_with_context(
        &mut self,
        address: Address,
        output: &mut OutputContext,
    ) -> OutputInstructionResult {
        if self.output_mnemonic_with_context(address, output) == OutputInstructionResult::Success {
            return OutputInstructionResult::Success;
        }
        self.output_instruction(address);
        OutputInstructionResult::NotImplemented
    }

    fn output_operand_with_context(
        &mut self,
        address: Address,
        operand_index: i32,
        _output: &mut OutputContext,
    ) -> OutputOperandResult {
        self.output_operand(address, operand_index)
    }

    fn on_new_file(&mut self, _filename: &str) {}
    fn on_old_file(&mut self, _filename: &str) {}
    fn is_call(&mut self, _address: Address) -> i32 {
        0
    }
    fn is_return(&mut self, _address: Address) -> i32 {
        0
    }
    fn may_be_function(&mut self, _address: Address) -> i32 {
        0
    }
    fn is_sane_instruction(&mut self, _address: Address, _no_code_references: bool) -> i32 {
        0
    }
    fn is_indirect_jump(&mut self, _address: Address) -> i32 {
        0
    }
    fn is_basic_block_end(&mut self, _address: Address, _call_stops: bool) -> i32 {
        0
    }
    fn create_function_frame(&mut self, _function_start: Address) -> bool {
        false
    }
    fn adjust_function_bounds(
        &mut self,
        _function_start: Address,
        _max_function_end: Address,
        suggested_result: i32,
    ) -> i32 {
        suggested_result
    }
    fn analyze_function_prolog(&mut self, _function_start: Address) -> i32 {
        0
    }
    fn calculate_stack_pointer_delta(&mut self, _address: Address, out_delta: &mut i64) -> i32 {
        *out_delta = 0;
        0
    }
    fn get_return_address_size(&mut self, _function_start: Address) -> i32 {
        0
    }
    fn detect_switch(&mut self, _address: Address, _out_switch: &mut SwitchDescription) -> i32 {
        0
    }
    fn calculate_switch_cases(
        &mut self,
        _address: Address,
        _switch_description: &SwitchDescription,
        _out_cases: &mut Vec<SwitchCase>,
    ) -> i32 {
        0
    }
    fn create_switch_references(
        &mut self,
        _address: Address,
        _switch_description: &SwitchDescription,
    ) -> i32 {
        0
    }
}
