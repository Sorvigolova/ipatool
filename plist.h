#pragma once
// Minimal Apple plist (XML) encoder/decoder using tinyxml2 (header-only usage)
// and a small hand-rolled parser for the simple structures ipatool needs.
//
// For encoding we produce Apple XML plist v1.0.
// For decoding we parse <key>/<string>/<integer>/<data>/<array>/<dict> nodes.

#include <string>
#include <map>
#include <vector>
#include <variant>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <cctype>
#include <algorithm>

// ── PlistValue ───────────────────────────────────────────────────────────────

struct PlistValue;
using PlistDict  = std::map<std::string, PlistValue>;
using PlistArray = std::vector<PlistValue>;

struct PlistValue {
    enum class Type { String, Integer, Real, Bool, Data, Dict, Array, Date, Null };
    Type type = Type::Null;

    std::string              strVal;
    int64_t                  intVal  = 0;
    double                   realVal = 0.0;
    bool                     boolVal = false;
    std::vector<uint8_t>     dataVal;
    PlistDict                dictVal;
    PlistArray               arrayVal;

    static PlistValue makeString (const std::string& s)       { PlistValue v; v.type=Type::String;  v.strVal=s;    return v; }
    static PlistValue makeInt    (int64_t i)                   { PlistValue v; v.type=Type::Integer; v.intVal=i;    return v; }
    static PlistValue makeReal   (double d)                    { PlistValue v; v.type=Type::Real;    v.realVal=d;   return v; }
    static PlistValue makeBool   (bool b)                      { PlistValue v; v.type=Type::Bool;    v.boolVal=b;   return v; }
    static PlistValue makeData   (const std::vector<uint8_t>& d){ PlistValue v; v.type=Type::Data;   v.dataVal=d;   return v; }
    static PlistValue makeDate   (const std::string& s)         { PlistValue v; v.type=Type::Date;   v.strVal=s;    return v; }
    static PlistValue makeDict   (const PlistDict& d)          { PlistValue v; v.type=Type::Dict;    v.dictVal=d;   return v; }
    static PlistValue makeArray  (const PlistArray& a)         { PlistValue v; v.type=Type::Array;   v.arrayVal=a;  return v; }

    bool isNull()    const { return type == Type::Null;    }
    bool isString()  const { return type == Type::String;  }
    bool isInt()     const { return type == Type::Integer; }
    bool isBool()    const { return type == Type::Bool;    }
    bool isDict()    const { return type == Type::Dict;    }
    bool isArray()   const { return type == Type::Array;   }
    bool isData()    const { return type == Type::Data;    }
    bool isDate()    const { return type == Type::Date;    }
    bool isReal()    const { return type == Type::Real;    }

    const std::string& str()   const { return strVal;  }
    int64_t            i64()   const { return intVal;  }
    double             real()  const { return realVal; }
    const PlistDict&   dict()  const { return dictVal; }
    const PlistArray&  arr()   const { return arrayVal;}
    const std::vector<uint8_t>& data() const { return dataVal; }
};

// ── XML escape / unescape ────────────────────────────────────────────────────

static std::string xml_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch(c) {
            case '<': out += "&lt;";  break;
            case '>': out += "&gt;";  break;
            case '&': out += "&amp;"; break;
            case '"': out += "&quot;";break;
            default:  out += c;
        }
    }
    return out;
}

static std::string xml_unescape(const std::string& s) {
    std::string out = s;
    auto replace_all = [&](const std::string& from, const std::string& to){
        size_t pos = 0;
        while ((pos = out.find(from, pos)) != std::string::npos) {
            out.replace(pos, from.size(), to);
            pos += to.size();
        }
    };
    replace_all("&lt;",   "<");
    replace_all("&gt;",   ">");
    replace_all("&quot;", "\"");
    replace_all("&apos;", "'");
    // Decode numeric character references &#DDD; and &#xHHH; → UTF-8
    {
        std::string res;
        res.reserve(out.size());
        size_t i = 0;
        while (i < out.size()) {
            if (out[i] == '&' && i+2 < out.size() && out[i+1] == '#') {
                size_t semi = out.find(';', i+2);
                if (semi != std::string::npos) {
                    uint32_t cp = 0;
                    bool ok = false;
                    if (out[i+2] == 'x' || out[i+2] == 'X') {
                        try { cp = (uint32_t)std::stoul(out.substr(i+3, semi-i-3), nullptr, 16); ok = true; } catch(...) {}
                    } else {
                        try { cp = (uint32_t)std::stoul(out.substr(i+2, semi-i-2)); ok = true; } catch(...) {}
                    }
                    if (ok) {
                        // encode codepoint as UTF-8
                        if (cp < 0x80) {
                            res += (char)cp;
                        } else if (cp < 0x800) {
                            res += (char)(0xC0 | (cp >> 6));
                            res += (char)(0x80 | (cp & 0x3F));
                        } else if (cp < 0x10000) {
                            res += (char)(0xE0 | (cp >> 12));
                            res += (char)(0x80 | ((cp >> 6) & 0x3F));
                            res += (char)(0x80 | (cp & 0x3F));
                        } else {
                            res += (char)(0xF0 | (cp >> 18));
                            res += (char)(0x80 | ((cp >> 12) & 0x3F));
                            res += (char)(0x80 | ((cp >> 6) & 0x3F));
                            res += (char)(0x80 | (cp & 0x3F));
                        }
                        i = semi + 1;
                        continue;
                    }
                }
            }
            res += out[i++];
        }
        out = res;
    }
    replace_all("&amp;",  "&");
    return out;
}

// ── Base64 (needed for <data> nodes) ─────────────────────────────────────────

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string base64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t n = (uint32_t)data[i] << 16;
        if (i+1 < len) n |= (uint32_t)data[i+1] << 8;
        if (i+2 < len) n |= (uint32_t)data[i+2];
        out += B64_CHARS[(n >> 18) & 63];
        out += B64_CHARS[(n >> 12) & 63];
        out += (i+1 < len) ? B64_CHARS[(n >> 6) & 63] : '=';
        out += (i+2 < len) ? B64_CHARS[ n       & 63] : '=';
    }
    return out;
}

static std::vector<uint8_t> base64_decode(const std::string& s) {
    static const int8_t idx[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    };
    std::vector<uint8_t> out;
    uint32_t bits = 0; int nbits = 0;
    for (unsigned char c : s) {
        if (c == '=') break;
        int8_t v = idx[c & 0xFF];
        if (v < 0) continue;
        bits = (bits << 6) | (uint8_t)v;
        nbits += 6;
        if (nbits >= 8) {
            nbits -= 8;
            out.push_back((uint8_t)(bits >> nbits));
            bits &= (1u << nbits) - 1;
        }
    }
    return out;
}

// ── Plist XML encoder ─────────────────────────────────────────────────────────

static void plist_encode_value(const PlistValue& v, std::ostringstream& os, int indent);

static std::string plist_indent(int n) { return std::string((size_t)n, '\t'); }

static void plist_encode_value(const PlistValue& v, std::ostringstream& os, int indent) {
    switch(v.type) {
        case PlistValue::Type::String:
            os << "<string>" << xml_escape(v.strVal) << "</string>";
            break;
        case PlistValue::Type::Integer:
            os << "<integer>" << v.intVal << "</integer>";
            break;
        case PlistValue::Type::Real:
            os << "<real>" << v.realVal << "</real>";
            break;
        case PlistValue::Type::Bool:
            os << (v.boolVal ? "<true/>" : "<false/>");
            break;
        case PlistValue::Type::Data:
            os << "<data>" << base64_encode(v.dataVal.data(), v.dataVal.size()) << "</data>";
            break;
        case PlistValue::Type::Date:
            os << "<date>" << xml_escape(v.strVal) << "</date>";
            break;
        case PlistValue::Type::Dict:
            os << "<dict>\n";
            for (auto& [k, val] : v.dictVal) {
                os << plist_indent(indent+1) << "<key>" << xml_escape(k) << "</key>\n";
                os << plist_indent(indent+1);
                plist_encode_value(val, os, indent+1);
                os << "\n";
            }
            os << plist_indent(indent) << "</dict>";
            break;
        case PlistValue::Type::Array:
            os << "<array>\n";
            for (auto& item : v.arrayVal) {
                os << plist_indent(indent+1);
                plist_encode_value(item, os, indent+1);
                os << "\n";
            }
            os << plist_indent(indent) << "</array>";
            break;
        default:
            os << "<string/>";
    }
}

// Encode a map<string,anything> to a plist XML body
// Values can be: string, int64_t, double, bool, or recursive PlistValue
static std::string encode_plist_xml(const PlistDict& root) {
    std::ostringstream os;
    os << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    os << "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" "
          "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n";
    os << "<plist version=\"1.0\">\n";
    plist_encode_value(PlistValue::makeDict(root), os, 0);
    os << "\n</plist>\n";
    return os.str();
}

// ── Plist XML decoder (minimal, recursive-descent on raw string) ──────────────

struct XmlTokenizer {
    const std::string& src;
    size_t pos = 0;

    XmlTokenizer(const std::string& s) : src(s) {}

    void skip_whitespace() {
        while (pos < src.size() && std::isspace((unsigned char)src[pos])) pos++;
    }

    // Returns tag name and whether it's closing (</...>), self-closing (<.../>), or opening
    // Returns empty string at EOF
    std::string peek_tag() {
        skip_whitespace();
        if (pos >= src.size() || src[pos] != '<') return "";
        size_t end = src.find('>', pos);
        if (end == std::string::npos) return "";
        return src.substr(pos, end - pos + 1);
    }

    std::string read_tag() {
        skip_whitespace();
        if (pos >= src.size()) return "";
        size_t start = pos;
        size_t end = src.find('>', pos);
        if (end == std::string::npos) return "";
        pos = end + 1;
        return src.substr(start, end - start + 1);
    }

    std::string read_text_until(const std::string& endTag) {
        size_t end = src.find(endTag, pos);
        if (end == std::string::npos) return "";
        std::string text = src.substr(pos, end - pos);
        pos = end;
        return text;
    }

    bool at_end() { skip_whitespace(); return pos >= src.size(); }

    static std::string tag_name(const std::string& tag) {
        // strip <, /, >, and attributes
        size_t start = 0;
        while (start < tag.size() && (tag[start] == '<' || tag[start] == '/')) start++;
        size_t end = start;
        while (end < tag.size() && tag[end] != '>' && tag[end] != '/' && !std::isspace((unsigned char)tag[end])) end++;
        return tag.substr(start, end - start);
    }
};

static PlistValue parse_value(XmlTokenizer& tok);

static PlistDict parse_dict(XmlTokenizer& tok) {
    PlistDict d;
    while (!tok.at_end()) {
        std::string tag = tok.peek_tag();
        if (tag.find("</dict>") != std::string::npos) { tok.read_tag(); break; }
        if (tag.find("<key") == std::string::npos) { tok.read_tag(); continue; }
        tok.read_tag(); // consume <key>
        std::string key = tok.read_text_until("</key>");
        tok.read_tag(); // consume </key>
        key = xml_unescape(key);
        d[key] = parse_value(tok);
    }
    return d;
}

static PlistArray parse_array(XmlTokenizer& tok) {
    PlistArray arr;
    while (!tok.at_end()) {
        std::string tag = tok.peek_tag();
        if (tag.find("</array>") != std::string::npos) { tok.read_tag(); break; }
        arr.push_back(parse_value(tok));
    }
    return arr;
}

static PlistValue parse_value(XmlTokenizer& tok) {
    tok.skip_whitespace();
    std::string tag = tok.peek_tag();
    if (tag.empty()) return {};

    std::string name = XmlTokenizer::tag_name(tag);

    if (name == "dict") {
        tok.read_tag();
        return PlistValue::makeDict(parse_dict(tok));
    }
    if (name == "array") {
        tok.read_tag();
        return PlistValue::makeArray(parse_array(tok));
    }
    if (name == "string") {
        tok.read_tag();
        std::string text = tok.read_text_until("</string>");
        tok.read_tag();
        return PlistValue::makeString(xml_unescape(text));
    }
    if (name == "integer") {
        tok.read_tag();
        std::string text = tok.read_text_until("</integer>");
        tok.read_tag();
        return PlistValue::makeInt(std::stoll(text));
    }
    if (name == "real") {
        tok.read_tag();
        std::string text = tok.read_text_until("</real>");
        tok.read_tag();
        return PlistValue::makeReal(std::stod(text));
    }
    if (name == "true") {
        tok.read_tag();
        return PlistValue::makeBool(true);
    }
    if (name == "false") {
        tok.read_tag();
        return PlistValue::makeBool(false);
    }
    if (name == "data") {
        tok.read_tag();
        std::string text = tok.read_text_until("</data>");
        tok.read_tag();
        return PlistValue::makeData(base64_decode(text));
    }
    if (name == "date") {
        tok.read_tag();
        std::string text = tok.read_text_until("</date>");
        tok.read_tag();
        return PlistValue::makeDate(text);
    }
    // skip unknown tag
    tok.read_tag();
    return {};
}

// ── Case-insensitive substring search helper ──────────────────────────────────

static size_t istr_find(const std::string& haystack, const std::string& needle,
                         size_t pos = 0)
{
    if (needle.empty()) return pos;
    auto it = std::search(
        haystack.begin() + (std::ptrdiff_t)pos, haystack.end(),
        needle.begin(), needle.end(),
        [](unsigned char a, unsigned char b){
            return std::tolower(a) == std::tolower(b);
        });
    return (it == haystack.end()) ? std::string::npos
                                  : (size_t)(it - haystack.begin());
}

// Extract the inner content of <TAG ...>...</TAG> (case-insensitive tag name).
// Returns empty string if not found.
static std::string extract_inner(const std::string& body, const std::string& tag) {
    // Find opening tag  <tag  or <tag>
    std::string open_pat = "<" + tag;
    size_t open_start = istr_find(body, open_pat);
    if (open_start == std::string::npos) return "";
    // Skip to end of opening tag (find '>')
    size_t open_end = body.find('>', open_start);
    if (open_end == std::string::npos) return "";
    // Find closing tag </tag>
    std::string close_pat = "</" + tag + ">";
    size_t close_start = istr_find(body, close_pat, open_end);
    if (close_start == std::string::npos) return "";
    return body.substr(open_end + 1, close_start - open_end - 1);
}

// Extract the full <TAG ...>...</TAG> span (case-insensitive).
// Uses rfind for the closing tag so nested tags of the same name are handled
// correctly — e.g. <dict>...<dict>...</dict>...</dict> returns the full outer span.
static std::string extract_full(const std::string& body, const std::string& tag) {
    std::string open_pat = "<" + tag;
    size_t open_start = istr_find(body, open_pat);
    if (open_start == std::string::npos) return "";

    // Build a lower-cased copy once for rfind
    std::string body_lower = body;
    for (char& c : body_lower) c = (char)tolower((unsigned char)c);

    std::string close_pat = "</" + tag + ">";
    std::string close_pat_lower = close_pat;
    for (char& c : close_pat_lower) c = (char)tolower((unsigned char)c);

    // rfind gives us the LAST (outermost) closing tag
    size_t close_pos = body_lower.rfind(close_pat_lower);
    if (close_pos == std::string::npos || close_pos < open_start) return "";
    return body.substr(open_start, close_pos + close_pat.size() - open_start);
}

// Normalize XML plist: mirror Go normalizeXMLPlistBody logic
// Pure string operations — no <regex> needed, compiles on all platforms.
static std::string normalize_plist_body(const std::string& raw) {
    auto trim = [](const std::string& s) -> std::string {
        size_t s1 = s.find_first_not_of(" \t\r\n");
        if (s1 == std::string::npos) return {};
        size_t s2 = s.find_last_not_of(" \t\r\n");
        return s.substr(s1, s2 - s1 + 1);
    };

    std::string body = trim(raw);
    if (body.empty()) return body;

    // Unwrap <Document><Protocol>...<plist>...</plist>...</Protocol></Document>
    // Apple bag.xml wraps the plist inside these two extra tags.
    // We strip them layer by layer until we reach the raw plist/dict.
    for (auto& wrapper : {"Document", "Protocol"}) {
        std::string inner = extract_inner(body, wrapper);
        if (!inner.empty()) body = trim(inner);
    }

    // Extract embedded <plist>...</plist>  (may span multiple lines / be minified)
    {
        std::string full = extract_full(body, "plist");
        if (!full.empty()) body = trim(full);
    }
    // Extract embedded <dict>...</dict>
    {
        std::string full = extract_full(body, "dict");
        if (!full.empty()) return trim(full);
    }
    // Wrap bare key-value content
    if (body.find("<key>") != std::string::npos) {
        return "<dict>" + body + "</dict>";
    }
    return body;
}

// Top-level decoder: returns the root PlistDict
static PlistDict decode_plist_xml(const std::string& raw) {
    std::string body = normalize_plist_body(raw);

    // If wrapped in <plist>, descend into it
    if (body.rfind("<plist", 0) == 0 || body.find("<plist") != std::string::npos) {
        size_t ds = body.find("<dict");
        if (ds != std::string::npos) body = body.substr(ds);
    }

    XmlTokenizer tok(body);
    PlistValue root = parse_value(tok);

    if (root.isDict()) return root.dictVal;
    return {};
}
// ── Binary plist decoder (bplist00) ──────────────────────────────────────────

class BplistDecoder {
    const uint8_t* data_;
    size_t         size_;
    int            refSize_  = 1;
    int            offSize_  = 1;
    uint64_t       numObjs_  = 0;
    uint64_t       topObj_   = 0;
    uint64_t       offTable_ = 0;

    uint64_t read_be(size_t pos, int n) const {
        uint64_t v = 0;
        for (int i = 0; i < n; i++)
            v = (v << 8) | data_[pos + i];
        return v;
    }

    uint64_t obj_offset(uint64_t ref) const {
        return read_be((size_t)(offTable_ + ref * offSize_), offSize_);
    }

    PlistValue read_obj(uint64_t ref) const {
        size_t pos = (size_t)obj_offset(ref);
        uint8_t marker = data_[pos++];
        uint8_t hi = (marker >> 4) & 0xF;
        uint8_t lo = marker & 0xF;

        // null / bool / fill
        if (marker == 0x00) return {};
        if (marker == 0x08) return PlistValue::makeBool(false);
        if (marker == 0x09) return PlistValue::makeBool(true);

        // int
        if (hi == 0x1) {
            int bytes = 1 << lo;
            uint64_t v = read_be(pos, bytes);
            // handle signed 64-bit
            if (bytes == 8 && (v >> 63)) {
                return PlistValue::makeInt((int64_t)v);
            }
            return PlistValue::makeInt((int64_t)v);
        }

        // real
        if (hi == 0x2) {
            int bytes = 1 << lo;
            uint64_t bits = read_be(pos, bytes);
            double d = 0;
            memcpy(&d, &bits, bytes < 8 ? bytes : 8);
            return PlistValue::makeReal(d);
        }

        // date (64-bit float, seconds since 2001-01-01)
        if (marker == 0x33) {
            uint64_t bits = read_be(pos, 8);
            double ts; memcpy(&ts, &bits, 8);
            // Convert Apple epoch to ISO8601 string
            time_t unix_ts = (time_t)((int64_t)ts + 978307200LL);
            struct tm t;
#ifdef _WIN32
            gmtime_s(&t, &unix_ts);
#else
            gmtime_r(&unix_ts, &t);
#endif
            char buf[64];
            snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                     t.tm_year+1900, t.tm_mon+1, t.tm_mday,
                     t.tm_hour, t.tm_min, t.tm_sec);
            return PlistValue::makeDate(std::string(buf));
        }

        // data
        if (hi == 0x4) {
            size_t n = lo;
            if (lo == 0xF) n = (size_t)read_int_at(pos, pos);
            std::vector<uint8_t> bytes(data_ + pos, data_ + pos + n);
            return PlistValue::makeData(bytes);
        }

        // ASCII string
        if (hi == 0x5) {
            size_t n = lo;
            if (lo == 0xF) n = (size_t)read_int_at(pos, pos);
            return PlistValue::makeString(std::string((const char*)data_ + pos, n));
        }

        // UTF-16 string
        if (hi == 0x6) {
            size_t n = lo;
            if (lo == 0xF) n = (size_t)read_int_at(pos, pos);
            // Convert UTF-16BE to UTF-8
            std::string s;
            for (size_t i = 0; i < n; i++) {
                uint16_t cp = (uint16_t)((data_[pos + i*2] << 8) | data_[pos + i*2 + 1]);
                if (cp < 0x80) {
                    s += (char)cp;
                } else if (cp < 0x800) {
                    s += (char)(0xC0 | (cp >> 6));
                    s += (char)(0x80 | (cp & 0x3F));
                } else {
                    s += (char)(0xE0 | (cp >> 12));
                    s += (char)(0x80 | ((cp >> 6) & 0x3F));
                    s += (char)(0x80 | (cp & 0x3F));
                }
            }
            return PlistValue::makeString(s);
        }

        // array
        if (hi == 0xA) {
            size_t n = lo;
            if (lo == 0xF) n = (size_t)read_int_at(pos, pos);
            PlistArray arr;
            for (size_t i = 0; i < n; i++) {
                uint64_t ref = read_be(pos + i * refSize_, refSize_);
                arr.push_back(read_obj(ref));
            }
            return PlistValue::makeArray(arr);
        }

        // dict
        if (hi == 0xD) {
            size_t n = lo;
            if (lo == 0xF) n = (size_t)read_int_at(pos, pos);
            PlistDict d;
            for (size_t i = 0; i < n; i++) {
                uint64_t kref = read_be(pos + i * refSize_, refSize_);
                uint64_t vref = read_be(pos + (n + i) * refSize_, refSize_);
                PlistValue kv = read_obj(kref);
                PlistValue vv = read_obj(vref);
                d[kv.isString() ? kv.str() : ""] = std::move(vv);
            }
            return PlistValue::makeDict(d);
        }

        return {};
    }

    // Read a bplist int object at pos, advance pos past it, return value
    uint64_t read_int_at(size_t& pos, size_t startPos) const {
        // pos points right after a count marker byte that had lo==0xF
        // the next byte is an int marker
        uint8_t intMarker = data_[pos++];
        int bytes = 1 << (intMarker & 0xF);
        uint64_t v = read_be(pos, bytes);
        pos += bytes;
        return v;
    }

public:
    PlistValue decode(const uint8_t* data, size_t size) {
        data_ = data; size_ = size;
        if (size < 8 || memcmp(data, "bplist00", 8) != 0)
            return {};
        // Read trailer (last 32 bytes)
        if (size < 32) return {};
        size_t t = size - 32;
        offSize_  = data[t + 6];
        refSize_  = data[t + 7];
        numObjs_  = read_be(t + 8,  8);
        topObj_   = read_be(t + 16, 8);
        offTable_ = read_be(t + 24, 8);
        if (!offSize_ || !refSize_ || !numObjs_) return {};
        return read_obj(topObj_);
    }
};

static PlistDict decode_plist(const std::string& src) {
    const uint8_t* data = (const uint8_t*)src.data();
    size_t size = src.size();
    // Auto-detect binary vs XML
    if (size >= 8 && memcmp(data, "bplist00", 8) == 0) {
        BplistDecoder dec;
        PlistValue v = dec.decode(data, size);
        if (v.isDict()) return v.dictVal;
        return {};
    }
    // Fall back to XML
    return decode_plist_xml(src);
}

;


// ── Helpers ───────────────────────────────────────────────────────────────────

static std::string dict_str(const PlistDict& d, const std::string& key) {
    auto it = d.find(key);
    if (it == d.end()) return "";
    if (it->second.isString()) return it->second.str();
    if (it->second.isInt())    return std::to_string(it->second.i64());
    return "";
}

static int64_t dict_int(const PlistDict& d, const std::string& key) {
    auto it = d.find(key);
    if (it == d.end()) return 0;
    if (it->second.isInt())    return it->second.i64();
    if (it->second.isString()) {
        try { return std::stoll(it->second.str()); } catch(...) {}
    }
    return 0;
}

static PlistDict dict_dict(const PlistDict& d, const std::string& key) {
    auto it = d.find(key);
    if (it == d.end()) return {};
    if (it->second.isDict()) return it->second.dictVal;
    return {};
}

static PlistArray dict_arr(const PlistDict& d, const std::string& key) {
    auto it = d.find(key);
    if (it == d.end()) return {};
    if (it->second.isArray()) return it->second.arrayVal;
    return {};
}

