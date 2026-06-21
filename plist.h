#pragma once
// Minimal Apple plist (XML + binary) encoder/decoder, hand-rolled — no
// external XML library dependency.
//
// For encoding we produce Apple XML plist v1.0.
// For decoding we auto-detect XML vs binary (bplist00) and parse either.
//
// This header exposes only the public API: the PlistValue/PlistDict/PlistArray
// data types and the handful of functions other files actually call.
// Everything else (the XML tokenizer, the recursive-descent parser, the
// binary plist decoder, body normalization) is an implementation detail
// that lives entirely in plist.cpp — nothing outside this module needs it.

#include <string>
#include <map>
#include <vector>
#include <cstdint>

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

    static PlistValue makeString (const std::string& s)        { PlistValue v; v.type=Type::String;  v.strVal=s;    return v; }
    static PlistValue makeInt    (int64_t i)                   { PlistValue v; v.type=Type::Integer; v.intVal=i;    return v; }
    static PlistValue makeReal   (double d)                    { PlistValue v; v.type=Type::Real;    v.realVal=d;   return v; }
    static PlistValue makeBool   (bool b)                       { PlistValue v; v.type=Type::Bool;    v.boolVal=b;   return v; }
    static PlistValue makeData   (const std::vector<uint8_t>& d){ PlistValue v; v.type=Type::Data;    v.dataVal=d;   return v; }
    static PlistValue makeDate   (const std::string& s)        { PlistValue v; v.type=Type::Date;    v.strVal=s;    return v; }
    static PlistValue makeDict   (const PlistDict& d)           { PlistValue v; v.type=Type::Dict;    v.dictVal=d;   return v; }
    static PlistValue makeArray  (const PlistArray& a)          { PlistValue v; v.type=Type::Array;   v.arrayVal=a;  return v; }

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

// ── Base64 (needed for <data> nodes, also used by GSA for token encoding) ────

std::string          base64_encode(const uint8_t* data, size_t len);
std::vector<uint8_t> base64_decode(const std::string& s);

// ── Encode ───────────────────────────────────────────────────────────────────

// Encode a PlistDict to a full Apple XML plist document (with header/DOCTYPE).
std::string encode_plist_xml(const PlistDict& root);

// ── Decode ───────────────────────────────────────────────────────────────────

// Auto-detects XML vs binary (bplist00) and parses either, returning the
// root dict. Returns an empty dict on any parse failure rather than throwing
// — callers check for missing/empty fields instead of catching exceptions.
PlistDict decode_plist(const std::string& src);

// ── Dict access helpers ───────────────────────────────────────────────────────
// All return a zero-value (empty string / 0 / empty dict / empty array) if
// the key is missing or has the wrong type, rather than throwing.

std::string dict_str (const PlistDict& d, const std::string& key);
int64_t     dict_int (const PlistDict& d, const std::string& key);
PlistDict   dict_dict(const PlistDict& d, const std::string& key);
PlistArray  dict_arr (const PlistDict& d, const std::string& key);
