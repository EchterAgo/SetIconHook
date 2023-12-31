// bwprint.h by Bill Weinman <http://bw.org/>
// Copyright (c) 2021 BHG LLC
// This code is free and open source without restriction
// updated 2021-08-12
//
// This code requires either the C++20 <format> library,
// or the libfmt library from <https://fmt.dev/>
//
// Once C++23 is released, along with std::print(), this code
// will become obsolete.

// NOTE BENE: It's generally considered extremely bad practice to add user code
// to the std namespace. In this case I chose to violate that rule with the
// knowledge that this code will be obsoleted by an equivalent function in C++23.
// At that time the user may simply drop this #include file and leave the rest of
// their code alone. I think that's a good reason to violate the rule. If you
// disagree, simply change the _BWP_NAMESPACE macro to whatever name you prefer.

#ifndef BW_PRINT
#define BW_PRINT

#include <cstdio>
#include <iostream>
#include <string_view>

// namespace for print() is std or bw
// make this std if you dare

#define BWP_NAMESPACE bw
// #define BWP_NAMESPACE std

#ifdef __cpp_lib_format
#include <format>
#define BWP_FMT_LIB "std"
#define BWP_FMTNS std
#else
#include <fmt/core.h>
#define BWP_FMT_LIB "libfmt"
#define BWP_FMTNS fmt
#endif  // __cpp_lib_format

// print function is missing from c++20 format library

namespace BWP_NAMESPACE {

constexpr const char* bwp_version = "0.4b";

// default to stdout
template <typename... Args>
constexpr void print(const std::string_view str_fmt, Args&&... args)
{
  fputs(BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_format_args(args...)).c_str(), stdout);
}

// send to FILE*
template <typename... Args>
constexpr void print(FILE* fdest, const std::string_view str_fmt, Args&&... args)
{
  fputs(BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_format_args(args...)).c_str(), fdest);
}

// send to ostream
template <typename... Args>
constexpr void print(std::ostream& ostream_dest, const std::string_view str_fmt, Args&&... args)
{
  ostream_dest << BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_format_args(args...));
}

// default to stdout
template <typename... Args>
constexpr void print(const std::wstring_view str_fmt, Args&&... args)
{
  fputws(BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_wformat_args(args...)).c_str(), stdout);
}

// send to FILE*
template <typename... Args>
constexpr void print(FILE* fdest, const std::wstring_view str_fmt, Args&&... args)
{
  fputws(BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_wformat_args(args...)).c_str(), fdest);
}

// send to ostream
template <typename... Args>
constexpr void print(std::ostream& ostream_dest, const std::wstring_view str_fmt, Args&&... args)
{
  ostream_dest << BWP_FMTNS::vformat(str_fmt, BWP_FMTNS::make_wformat_args(args...));
}

}  // namespace BWP_NAMESPACE

// using std::print;

#endif  // BWPRINT
