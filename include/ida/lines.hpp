/// \file lines.hpp
/// \brief Color tag manipulation for IDA's tagged text format.
///
/// IDA uses embedded color tags in text output (pseudocode, disassembly,
/// listing lines). This namespace provides utilities for creating, parsing,
/// and stripping these tags without exposing the raw SDK constants.
///
/// The tag format is IDA-proprietary and encodes colors, addresses, and
/// item references inline within text strings.

#ifndef IDAX_LINES_HPP
#define IDAX_LINES_HPP

#include <cstdint>
#include <string>
#include <string_view>

namespace ida::lines {

// ── Color constants ─────────────────────────────────────────────────────
//
// These correspond to the SDK's COLOR_* / SCOLOR_* constants (color_t).
// Values match the SDK exactly so they can be used directly in tag bytes.

enum class Color : std::uint8_t {
    Default          = 0x01,  ///< COLOR_DEFAULT
    RegularComment   = 0x02,  ///< COLOR_REGCMT
    RepeatableComment= 0x03,  ///< COLOR_RPTCMT
    AutoComment      = 0x04,  ///< COLOR_AUTOCMT
    Instruction      = 0x05,  ///< COLOR_INSN
    DataName         = 0x06,  ///< COLOR_DATNAME (dummy data name)
    RegularDataName  = 0x07,  ///< COLOR_DNAME (regular data name)
    DemangledName    = 0x08,  ///< COLOR_DEMNAME
    Symbol           = 0x09,  ///< COLOR_SYMBOL (punctuation)
    CharLiteral      = 0x0A,  ///< COLOR_CHAR
    String           = 0x0B,  ///< COLOR_STRING
    Number           = 0x0C,  ///< COLOR_NUMBER
    Void             = 0x0D,  ///< COLOR_VOIDOP
    CodeReference    = 0x0E,  ///< COLOR_CREF
    DataReference    = 0x0F,  ///< COLOR_DREF
    CodeRefTail      = 0x10,  ///< COLOR_CREFTAIL
    DataRefTail      = 0x11,  ///< COLOR_DREFTAIL
    Error            = 0x12,  ///< COLOR_ERROR
    Prefix           = 0x13,  ///< COLOR_PREFIX
    BinaryPrefix     = 0x14,  ///< COLOR_BINPREF
    Extra            = 0x15,  ///< COLOR_EXTRA
    AltOperand       = 0x16,  ///< COLOR_ALTOP
    HiddenName       = 0x17,  ///< COLOR_HIDNAME
    LibraryName      = 0x18,  ///< COLOR_LIBNAME
    LocalName        = 0x19,  ///< COLOR_LOCNAME
    DummyCodeName    = 0x1A,  ///< COLOR_CODNAME
    AsmDirective     = 0x1B,  ///< COLOR_ASMDIR
    Macro            = 0x1C,  ///< COLOR_MACRO
    DataString       = 0x1D,  ///< COLOR_DSTR
    DataChar         = 0x1E,  ///< COLOR_DCHAR
    DataNumber       = 0x1F,  ///< COLOR_DNUM
    Keyword          = 0x20,  ///< COLOR_KEYWORD
    Register         = 0x21,  ///< COLOR_REG
    ImportedName     = 0x22,  ///< COLOR_IMPNAME
    SegmentName      = 0x23,  ///< COLOR_SEGNAME
    UnknownName      = 0x24,  ///< COLOR_UNKNAME
    CodeName         = 0x25,  ///< COLOR_CNAME
    UserName         = 0x26,  ///< COLOR_UNAME
    Collapsed        = 0x27,  ///< COLOR_COLLAPSED
};

// ── Tag control bytes ───────────────────────────────────────────────────

/// COLOR_ON escape byte — begins a color span.
constexpr char kColorOn  = '\x01';

/// COLOR_OFF escape byte — ends a color span.
constexpr char kColorOff = '\x02';

/// COLOR_ESC escape byte — quotes the next character.
constexpr char kColorEsc = '\x03';

/// COLOR_INV escape byte — toggles inverse video (no OFF pair).
constexpr char kColorInv = '\x04';

/// COLOR_ADDR tag byte value — marks an address/anchor tag.
constexpr std::uint8_t kColorAddr = 0x28;

// ── Color tag manipulation ──────────────────────────────────────────────

/// Wrap a string in color tags. Equivalent to IDA's COLSTR() macro.
///
/// The returned string has the form: COLOR_ON + color + text + COLOR_OFF + color.
/// This can be inserted into raw pseudocode/listing lines.
std::string colstr(std::string_view text, Color color);

/// Remove all color tags from a tagged string, returning plain text.
///
/// This is useful for getting the visible text length or display text.
std::string tag_remove(std::string_view tagged_text);

/// Advance past a color tag at the given position.
///
/// Returns the number of bytes to skip past the tag at `tagged_text[pos]`.
/// If there is no tag at position `pos`, returns 1 (advance one character).
/// This is essential for iterating through tagged text character-by-character.
int tag_advance(std::string_view tagged_text, int pos);

/// Get the visible (non-tag) character length of a tagged string.
///
/// Equivalent to tag_remove(s).size() but avoids allocating a new string.
std::size_t tag_strlen(std::string_view tagged_text);

// ── Color address tag constants ─────────────────────────────────────────

/// The size (in hex characters) of a COLOR_ADDR encoded item reference.
/// COLOR_ADDR tags encode ctree item indices within pseudocode lines.
constexpr int kColorAddrSize = 16;

/// Build a COLOR_ADDR item reference tag.
///
/// This creates the encoded tag string that references a ctree item by
/// its index. Used by filters that insert annotations at specific items.
std::string make_addr_tag(int item_index);

/// Decode a COLOR_ADDR tag at the given position in a tagged string.
///
/// Returns the decoded item index, or -1 if no valid tag at that position.
int decode_addr_tag(std::string_view tagged_text, std::size_t pos);

} // namespace ida::lines

#endif // IDAX_LINES_HPP
