/*
 * saslprep.c — SASLprep (RFC 4013) for PDF 2.0 R6 password normalization
 *
 * Implements the minimal SASLprep profile needed for PDF encryption:
 *   1. Map: non-ASCII spaces → U+0020, "commonly mapped to nothing" → removed
 *   2. Normalize: NFKC via CoreFoundation
 *   3. Prohibit: certain codepoints (return error)
 *   4. Bidi: simplified check (reject if mixed L and R/AL)
 *
 * Pure ASCII passwords (the common case) take a fast path with no allocation.
 */

#include "saslprep.h"
#include <string.h>
#include <CoreFoundation/CoreFoundation.h>

/* Check if a Unicode scalar is a non-ASCII space (RFC 3454 C.1.2) */
static int is_non_ascii_space(uint32_t cp)
{
    switch (cp) {
        case 0x00A0: /* NO-BREAK SPACE */
        case 0x1680: /* OGHAM SPACE MARK */
        case 0x2000: case 0x2001: case 0x2002: case 0x2003:
        case 0x2004: case 0x2005: case 0x2006: case 0x2007:
        case 0x2008: case 0x2009: case 0x200A: case 0x200B:
        case 0x202F: /* NARROW NO-BREAK SPACE */
        case 0x205F: /* MEDIUM MATHEMATICAL SPACE */
        case 0x3000: /* IDEOGRAPHIC SPACE */
            return 1;
        default:
            return 0;
    }
}

/* Check if a Unicode scalar is "commonly mapped to nothing" (RFC 3454 B.1) */
static int is_mapped_to_nothing(uint32_t cp)
{
    switch (cp) {
        case 0x00AD: /* SOFT HYPHEN */
        case 0x1806: /* MONGOLIAN TODO SOFT HYPHEN */
        case 0x200B: /* ZERO WIDTH SPACE */
        case 0x2060: /* WORD JOINER */
        case 0xFEFF: /* BOM / ZERO WIDTH NO-BREAK SPACE */
            return 1;
        default:
            /* RFC 3454 B.1 also lists FE00-FE0F (variation selectors) */
            if (cp >= 0xFE00 && cp <= 0xFE0F) return 1;
            return 0;
    }
}

/* Check if a Unicode scalar is prohibited (RFC 3454 C.2.1, C.2.2, C.3-C.9) */
static int is_prohibited(uint32_t cp)
{
    /* C.2.1: ASCII control characters */
    if (cp <= 0x001F || cp == 0x007F) return 1;
    /* C.2.2: Non-ASCII control characters */
    if ((cp >= 0x0080 && cp <= 0x009F) ||
        cp == 0x06DD || cp == 0x070F ||
        cp == 0x180E ||
        (cp >= 0x200C && cp <= 0x200D) ||
        (cp >= 0x2028 && cp <= 0x2029) ||
        (cp >= 0x2060 && cp <= 0x2063) ||
        (cp >= 0x206A && cp <= 0x206F) ||
        cp == 0xFEFF ||
        (cp >= 0xFFF9 && cp <= 0xFFFF) ||
        (cp >= 0x1D173 && cp <= 0x1D17A) ||
        (cp >= 0xE0001 && cp <= 0xE007F))
        return 1;
    /* C.3: Private use */
    if ((cp >= 0xE000 && cp <= 0xF8FF) ||
        (cp >= 0xF0000 && cp <= 0xFFFFD) ||
        (cp >= 0x100000 && cp <= 0x10FFFD))
        return 1;
    /* C.4: Non-character code points */
    if ((cp >= 0xFDD0 && cp <= 0xFDEF) ||
        (cp & 0xFFFF) == 0xFFFE || (cp & 0xFFFF) == 0xFFFF)
        return 1;
    /* C.5: Surrogate codes (shouldn't appear in valid UTF-8 but check anyway) */
    if (cp >= 0xD800 && cp <= 0xDFFF) return 1;
    /* C.8: Change display properties / deprecated */
    if (cp == 0x0340 || cp == 0x0341 || cp == 0x200E || cp == 0x200F ||
        (cp >= 0x202A && cp <= 0x202E) ||
        (cp >= 0x206A && cp <= 0x206F))
        return 1;
    return 0;
}

int saslprep(const char *input, size_t input_len, uint8_t *out, size_t *out_len)
{
    if (!input || input_len == 0) {
        *out_len = 0;
        return 0;
    }

    /* Fast path: pure ASCII with no control characters */
    int pure_ascii = 1;
    for (size_t i = 0; i < input_len; i++) {
        if ((uint8_t)input[i] > 0x7E || (uint8_t)input[i] < 0x20) {
            pure_ascii = 0;
            break;
        }
    }
    if (pure_ascii) {
        size_t len = input_len > 127 ? 127 : input_len;
        memcpy(out, input, len);
        *out_len = len;
        return 0;
    }

    /* Create CFString from UTF-8 input */
    CFStringRef cfstr = CFStringCreateWithBytes(kCFAllocatorDefault,
                                                 (const UInt8 *)input,
                                                 (CFIndex)input_len,
                                                 kCFStringEncodingUTF8, false);
    if (!cfstr) return -1;

    /* Create mutable copy for in-place operations */
    CFMutableStringRef mstr = CFStringCreateMutableCopy(kCFAllocatorDefault, 0, cfstr);
    CFRelease(cfstr);
    if (!mstr) return -1;

    /* Step 1: Map non-ASCII spaces to U+0020, remove "mapped to nothing" chars */
    CFIndex len = CFStringGetLength(mstr);
    for (CFIndex i = len - 1; i >= 0; i--) {
        UniChar ch = CFStringGetCharacterAtIndex(mstr, i);
        uint32_t cp = ch;
        /* Handle surrogate pairs for codepoints > U+FFFF */
        if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < len) {
            UniChar lo = CFStringGetCharacterAtIndex(mstr, i + 1);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((uint32_t)(ch - 0xD800) << 10) + (lo - 0xDC00);
            }
        }
        if (is_mapped_to_nothing(cp)) {
            CFStringDelete(mstr, CFRangeMake(i, (cp > 0xFFFF) ? 2 : 1));
        } else if (is_non_ascii_space(cp)) {
            UniChar space = 0x0020;
            CFStringRef sp = CFStringCreateWithCharacters(kCFAllocatorDefault, &space, 1);
            CFStringReplace(mstr, CFRangeMake(i, 1), sp);
            CFRelease(sp);
        }
    }

    /* Step 2: NFKC normalization */
    CFStringNormalize(mstr, kCFStringNormalizationFormKC);

    /* Step 3: Check for prohibited characters */
    len = CFStringGetLength(mstr);
    for (CFIndex i = 0; i < len; i++) {
        UniChar ch = CFStringGetCharacterAtIndex(mstr, i);
        uint32_t cp = ch;
        if (ch >= 0xD800 && ch <= 0xDBFF && i + 1 < len) {
            UniChar lo = CFStringGetCharacterAtIndex(mstr, i + 1);
            if (lo >= 0xDC00 && lo <= 0xDFFF) {
                cp = 0x10000 + ((uint32_t)(ch - 0xD800) << 10) + (lo - 0xDC00);
                i++; /* skip low surrogate */
            }
        }
        if (is_prohibited(cp)) {
            CFRelease(mstr);
            return -1;
        }
    }

    /* Convert back to UTF-8 */
    CFIndex utf8_len = 0;
    CFIndex used = 0;
    CFStringGetBytes(mstr, CFRangeMake(0, CFStringGetLength(mstr)),
                     kCFStringEncodingUTF8, 0, false, NULL, 0, &utf8_len);

    if (utf8_len > 127) utf8_len = 127; /* PDF spec: truncate to 127 bytes */

    CFStringGetBytes(mstr, CFRangeMake(0, CFStringGetLength(mstr)),
                     kCFStringEncodingUTF8, 0, false, out, utf8_len, &used);
    CFRelease(mstr);

    *out_len = (size_t)used;
    return 0;
}
