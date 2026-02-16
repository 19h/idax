/// \file lines_bind.cpp
/// \brief NAN bindings for ida::lines — color tag manipulation and constants.

#include "helpers.hpp"
#include <ida/lines.hpp>

namespace idax_node {
namespace {

// ── Color string <-> enum conversion ────────────────────────────────────

static bool StringToColor(const std::string& s, ida::lines::Color& out) {
    if (s == "default")           { out = ida::lines::Color::Default;           return true; }
    if (s == "regularComment")    { out = ida::lines::Color::RegularComment;    return true; }
    if (s == "repeatableComment") { out = ida::lines::Color::RepeatableComment; return true; }
    if (s == "autoComment")       { out = ida::lines::Color::AutoComment;       return true; }
    if (s == "instruction")       { out = ida::lines::Color::Instruction;       return true; }
    if (s == "dataName")          { out = ida::lines::Color::DataName;          return true; }
    if (s == "regularDataName")   { out = ida::lines::Color::RegularDataName;   return true; }
    if (s == "demangledName")     { out = ida::lines::Color::DemangledName;     return true; }
    if (s == "symbol")            { out = ida::lines::Color::Symbol;            return true; }
    if (s == "charLiteral")       { out = ida::lines::Color::CharLiteral;       return true; }
    if (s == "string")            { out = ida::lines::Color::String;            return true; }
    if (s == "number")            { out = ida::lines::Color::Number;            return true; }
    if (s == "void")              { out = ida::lines::Color::Void;              return true; }
    if (s == "codeReference")     { out = ida::lines::Color::CodeReference;     return true; }
    if (s == "dataReference")     { out = ida::lines::Color::DataReference;     return true; }
    if (s == "codeRefTail")       { out = ida::lines::Color::CodeRefTail;       return true; }
    if (s == "dataRefTail")       { out = ida::lines::Color::DataRefTail;       return true; }
    if (s == "error")             { out = ida::lines::Color::Error;             return true; }
    if (s == "prefix")            { out = ida::lines::Color::Prefix;            return true; }
    if (s == "binaryPrefix")      { out = ida::lines::Color::BinaryPrefix;      return true; }
    if (s == "extra")             { out = ida::lines::Color::Extra;             return true; }
    if (s == "altOperand")        { out = ida::lines::Color::AltOperand;        return true; }
    if (s == "hiddenName")        { out = ida::lines::Color::HiddenName;        return true; }
    if (s == "libraryName")       { out = ida::lines::Color::LibraryName;       return true; }
    if (s == "localName")         { out = ida::lines::Color::LocalName;         return true; }
    if (s == "dummyCodeName")     { out = ida::lines::Color::DummyCodeName;     return true; }
    if (s == "asmDirective")      { out = ida::lines::Color::AsmDirective;      return true; }
    if (s == "macro")             { out = ida::lines::Color::Macro;             return true; }
    if (s == "dataString")        { out = ida::lines::Color::DataString;        return true; }
    if (s == "dataChar")          { out = ida::lines::Color::DataChar;          return true; }
    if (s == "dataNumber")        { out = ida::lines::Color::DataNumber;        return true; }
    if (s == "keyword")           { out = ida::lines::Color::Keyword;           return true; }
    if (s == "register")          { out = ida::lines::Color::Register;          return true; }
    if (s == "importedName")      { out = ida::lines::Color::ImportedName;      return true; }
    if (s == "segmentName")       { out = ida::lines::Color::SegmentName;       return true; }
    if (s == "unknownName")       { out = ida::lines::Color::UnknownName;       return true; }
    if (s == "codeName")          { out = ida::lines::Color::CodeName;          return true; }
    if (s == "userName")          { out = ida::lines::Color::UserName;          return true; }
    if (s == "collapsed")         { out = ida::lines::Color::Collapsed;         return true; }
    return false;
}

// ── NAN methods ─────────────────────────────────────────────────────────

// colstr(text: string, color: number|string) -> string
NAN_METHOD(Colstr) {
    std::string text;
    if (!GetStringArg(info, 0, text)) return;

    if (info.Length() < 2) {
        Nan::ThrowTypeError("Missing color argument");
        return;
    }

    ida::lines::Color color;

    if (info[1]->IsNumber()) {
        // Accept raw numeric color value
        int val = Nan::To<int>(info[1]).FromJust();
        color = static_cast<ida::lines::Color>(static_cast<std::uint8_t>(val));
    } else if (info[1]->IsString()) {
        std::string colorStr = ToString(info[1]);
        if (!StringToColor(colorStr, color)) {
            Nan::ThrowTypeError("Invalid color name");
            return;
        }
    } else {
        Nan::ThrowTypeError("Expected number or string for color argument");
        return;
    }

    auto result = ida::lines::colstr(text, color);
    info.GetReturnValue().Set(FromString(result));
}

// tagRemove(taggedText: string) -> string
NAN_METHOD(TagRemove) {
    std::string taggedText;
    if (!GetStringArg(info, 0, taggedText)) return;

    auto result = ida::lines::tag_remove(taggedText);
    info.GetReturnValue().Set(FromString(result));
}

// tagAdvance(taggedText: string, pos: number) -> number
NAN_METHOD(TagAdvance) {
    std::string taggedText;
    if (!GetStringArg(info, 0, taggedText)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric position argument");
        return;
    }
    int pos = Nan::To<int>(info[1]).FromJust();

    int result = ida::lines::tag_advance(taggedText, pos);
    info.GetReturnValue().Set(Nan::New(result));
}

// tagStrlen(taggedText: string) -> number
NAN_METHOD(TagStrlen) {
    std::string taggedText;
    if (!GetStringArg(info, 0, taggedText)) return;

    auto result = ida::lines::tag_strlen(taggedText);
    info.GetReturnValue().Set(Nan::New(static_cast<double>(result)));
}

// makeAddrTag(itemIndex: number) -> string
NAN_METHOD(MakeAddrTag) {
    if (info.Length() < 1 || !info[0]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric item index argument");
        return;
    }
    int itemIndex = Nan::To<int>(info[0]).FromJust();

    auto result = ida::lines::make_addr_tag(itemIndex);
    info.GetReturnValue().Set(FromString(result));
}

// decodeAddrTag(taggedText: string, pos: number) -> number
NAN_METHOD(DecodeAddrTag) {
    std::string taggedText;
    if (!GetStringArg(info, 0, taggedText)) return;

    if (info.Length() < 2 || !info[1]->IsNumber()) {
        Nan::ThrowTypeError("Expected numeric position argument");
        return;
    }
    auto pos = static_cast<std::size_t>(Nan::To<uint32_t>(info[1]).FromJust());

    int result = ida::lines::decode_addr_tag(taggedText, pos);
    info.GetReturnValue().Set(Nan::New(result));
}

} // anonymous namespace

// ── Module registration ─────────────────────────────────────────────────

void InitLines(v8::Local<v8::Object> target) {
    auto ns = CreateNamespace(target, "lines");

    // Functions
    SetMethod(ns, "colstr",        Colstr);
    SetMethod(ns, "tagRemove",     TagRemove);
    SetMethod(ns, "tagAdvance",    TagAdvance);
    SetMethod(ns, "tagStrlen",     TagStrlen);
    SetMethod(ns, "makeAddrTag",   MakeAddrTag);
    SetMethod(ns, "decodeAddrTag", DecodeAddrTag);

    // ── Tag control byte constants ──────────────────────────────────────

    Nan::Set(ns, FromString("colorOn"),
             Nan::New(static_cast<int>(ida::lines::kColorOn)));
    Nan::Set(ns, FromString("colorOff"),
             Nan::New(static_cast<int>(ida::lines::kColorOff)));
    Nan::Set(ns, FromString("colorEsc"),
             Nan::New(static_cast<int>(ida::lines::kColorEsc)));
    Nan::Set(ns, FromString("colorInv"),
             Nan::New(static_cast<int>(ida::lines::kColorInv)));
    Nan::Set(ns, FromString("colorAddr"),
             Nan::New(static_cast<int>(ida::lines::kColorAddr)));
    Nan::Set(ns, FromString("colorAddrSize"),
             Nan::New(ida::lines::kColorAddrSize));

    // ── Color enum values ───────────────────────────────────────────────

    auto colorObj = Nan::New<v8::Object>();

    Nan::Set(colorObj, FromString("Default"),           Nan::New(static_cast<int>(ida::lines::Color::Default)));
    Nan::Set(colorObj, FromString("RegularComment"),    Nan::New(static_cast<int>(ida::lines::Color::RegularComment)));
    Nan::Set(colorObj, FromString("RepeatableComment"), Nan::New(static_cast<int>(ida::lines::Color::RepeatableComment)));
    Nan::Set(colorObj, FromString("AutoComment"),       Nan::New(static_cast<int>(ida::lines::Color::AutoComment)));
    Nan::Set(colorObj, FromString("Instruction"),       Nan::New(static_cast<int>(ida::lines::Color::Instruction)));
    Nan::Set(colorObj, FromString("DataName"),          Nan::New(static_cast<int>(ida::lines::Color::DataName)));
    Nan::Set(colorObj, FromString("RegularDataName"),   Nan::New(static_cast<int>(ida::lines::Color::RegularDataName)));
    Nan::Set(colorObj, FromString("DemangledName"),     Nan::New(static_cast<int>(ida::lines::Color::DemangledName)));
    Nan::Set(colorObj, FromString("Symbol"),            Nan::New(static_cast<int>(ida::lines::Color::Symbol)));
    Nan::Set(colorObj, FromString("CharLiteral"),       Nan::New(static_cast<int>(ida::lines::Color::CharLiteral)));
    Nan::Set(colorObj, FromString("String"),            Nan::New(static_cast<int>(ida::lines::Color::String)));
    Nan::Set(colorObj, FromString("Number"),            Nan::New(static_cast<int>(ida::lines::Color::Number)));
    Nan::Set(colorObj, FromString("Void"),              Nan::New(static_cast<int>(ida::lines::Color::Void)));
    Nan::Set(colorObj, FromString("CodeReference"),     Nan::New(static_cast<int>(ida::lines::Color::CodeReference)));
    Nan::Set(colorObj, FromString("DataReference"),     Nan::New(static_cast<int>(ida::lines::Color::DataReference)));
    Nan::Set(colorObj, FromString("CodeRefTail"),       Nan::New(static_cast<int>(ida::lines::Color::CodeRefTail)));
    Nan::Set(colorObj, FromString("DataRefTail"),       Nan::New(static_cast<int>(ida::lines::Color::DataRefTail)));
    Nan::Set(colorObj, FromString("Error"),             Nan::New(static_cast<int>(ida::lines::Color::Error)));
    Nan::Set(colorObj, FromString("Prefix"),            Nan::New(static_cast<int>(ida::lines::Color::Prefix)));
    Nan::Set(colorObj, FromString("BinaryPrefix"),      Nan::New(static_cast<int>(ida::lines::Color::BinaryPrefix)));
    Nan::Set(colorObj, FromString("Extra"),             Nan::New(static_cast<int>(ida::lines::Color::Extra)));
    Nan::Set(colorObj, FromString("AltOperand"),        Nan::New(static_cast<int>(ida::lines::Color::AltOperand)));
    Nan::Set(colorObj, FromString("HiddenName"),        Nan::New(static_cast<int>(ida::lines::Color::HiddenName)));
    Nan::Set(colorObj, FromString("LibraryName"),       Nan::New(static_cast<int>(ida::lines::Color::LibraryName)));
    Nan::Set(colorObj, FromString("LocalName"),         Nan::New(static_cast<int>(ida::lines::Color::LocalName)));
    Nan::Set(colorObj, FromString("DummyCodeName"),     Nan::New(static_cast<int>(ida::lines::Color::DummyCodeName)));
    Nan::Set(colorObj, FromString("AsmDirective"),      Nan::New(static_cast<int>(ida::lines::Color::AsmDirective)));
    Nan::Set(colorObj, FromString("Macro"),             Nan::New(static_cast<int>(ida::lines::Color::Macro)));
    Nan::Set(colorObj, FromString("DataString"),        Nan::New(static_cast<int>(ida::lines::Color::DataString)));
    Nan::Set(colorObj, FromString("DataChar"),          Nan::New(static_cast<int>(ida::lines::Color::DataChar)));
    Nan::Set(colorObj, FromString("DataNumber"),        Nan::New(static_cast<int>(ida::lines::Color::DataNumber)));
    Nan::Set(colorObj, FromString("Keyword"),           Nan::New(static_cast<int>(ida::lines::Color::Keyword)));
    Nan::Set(colorObj, FromString("Register"),          Nan::New(static_cast<int>(ida::lines::Color::Register)));
    Nan::Set(colorObj, FromString("ImportedName"),      Nan::New(static_cast<int>(ida::lines::Color::ImportedName)));
    Nan::Set(colorObj, FromString("SegmentName"),       Nan::New(static_cast<int>(ida::lines::Color::SegmentName)));
    Nan::Set(colorObj, FromString("UnknownName"),       Nan::New(static_cast<int>(ida::lines::Color::UnknownName)));
    Nan::Set(colorObj, FromString("CodeName"),          Nan::New(static_cast<int>(ida::lines::Color::CodeName)));
    Nan::Set(colorObj, FromString("UserName"),          Nan::New(static_cast<int>(ida::lines::Color::UserName)));
    Nan::Set(colorObj, FromString("Collapsed"),         Nan::New(static_cast<int>(ida::lines::Color::Collapsed)));

    Nan::Set(ns, FromString("Color"), colorObj);
}

} // namespace idax_node
