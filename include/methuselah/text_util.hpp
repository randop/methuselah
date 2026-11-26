#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

namespace methuselah::strutil {

// Strips leading and trailing whitespace (the C locale's isspace).
[[nodiscard]] inline std::string_view trim(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front()))) {
    text.remove_prefix(1);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back()))) {
    text.remove_suffix(1);
  }
  return text;
}

// Splits the first line off `text` and returns it without its newline. The
// remainder (possibly empty) stays in `text`, so
//   while (!text.empty()) { auto line = next_line(text); ... }
// visits every line, including a last one without a trailing newline.
[[nodiscard]] inline std::string_view next_line(std::string_view &text) {
  const std::size_t newline = text.find('\n');
  const std::string_view line = text.substr(0, newline);
  text.remove_prefix(newline == std::string_view::npos ? text.size()
                                                       : newline + 1);
  return line;
}

[[nodiscard]] inline bool is_hex(std::string_view text) {
  return std::all_of(text.begin(), text.end(),
                     [](unsigned char c) { return std::isxdigit(c) != 0; });
}

// ASCII case conversion that never depends on the locale. The result is built
// element by element into a string of exactly the right size, which keeps GCC's
// string-overread diagnostics quiet where a copy plus transform would not.
[[nodiscard]] inline std::string ascii_upper(std::string_view text) {
  std::string out(text.size(), '\0');
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    out[i] = c >= 'a' && c <= 'z' ? static_cast<char>(c - 'a' + 'A') : c;
  }
  return out;
}

[[nodiscard]] inline std::string ascii_lower(std::string_view text) {
  std::string out(text.size(), '\0');
  for (std::size_t i = 0; i < text.size(); ++i) {
    const char c = text[i];
    out[i] = c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c;
  }
  return out;
}

[[nodiscard]] inline bool ascii_iequals(std::string_view a,
                                        std::string_view b) {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    const char x =
        a[i] >= 'A' && a[i] <= 'Z' ? static_cast<char>(a[i] - 'A' + 'a') : a[i];
    const char y =
        b[i] >= 'A' && b[i] <= 'Z' ? static_cast<char>(b[i] - 'A' + 'a') : b[i];
    if (x != y) {
      return false;
    }
  }
  return true;
}

} // namespace methuselah::strutil
