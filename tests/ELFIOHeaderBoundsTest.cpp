/*
Copyright (C) 2001-present by Serge Lamikhov-Center

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <cstdint>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include <elfio/elfio.hpp>

using namespace ELFIO;

namespace {

template <class T> class test_section : public section_impl<T>
{
  public:
    using section_impl<T>::section_impl;
    using section_impl<T>::load;
};

template <class T> class test_segment : public segment_impl<T>
{
  public:
    using segment_impl<T>::segment_impl;
    using segment_impl<T>::load;
};

std::shared_ptr<endianness_convertor> make_convertor()
{
    auto                convertor = std::make_shared<endianness_convertor>();
    const std::uint16_t value     = 1;
    convertor->setup( *reinterpret_cast<const unsigned char*>( &value ) == 1
                          ? ELFDATA2LSB
                          : ELFDATA2MSB );
    return convertor;
}

template <class T> std::string bytes_for( const T& value, std::size_t size )
{
    std::string bytes( size, '\0' );
    std::memcpy( bytes.data(), &value, size );
    return bytes;
}

template <class T>
void expect_truncated_section_rejected( bool is_lazy, bool translated )
{
    auto        translator      = std::make_shared<address_translator>();
    std::size_t physical_offset = translated ? 8 : 0;
    if ( translated ) {
        std::vector<address_translation> translations = {
            { 0, sizeof( T ), physical_offset } };
        translator->set_address_translation( translations );
    }
    test_section<T> section( make_convertor(), translator, nullptr );
    T               header{};
    header.sh_type   = SHT_PROGBITS;
    header.sh_offset = 0;
    header.sh_size   = 1;
    {
        std::string bytes( physical_offset, '\0' );
        bytes += bytes_for( header, sizeof( T ) - 1 );
        std::istringstream input( bytes );
        EXPECT_FALSE( section.load( input, 0, is_lazy ) );
    }
    EXPECT_EQ( section.get_type(), SHT_NULL );
    EXPECT_EQ( section.get_size(), 0U );
    EXPECT_EQ( section.get_data(), nullptr );
}

template <class T>
void expect_truncated_segment_rejected( bool is_lazy, bool translated )
{
    auto        translator      = std::make_shared<address_translator>();
    std::size_t physical_offset = translated ? 8 : 0;
    if ( translated ) {
        std::vector<address_translation> translations = {
            { 0, sizeof( T ), physical_offset } };
        translator->set_address_translation( translations );
    }
    test_segment<T> segment( make_convertor(), translator );
    T               header{};
    header.p_type   = PT_LOAD;
    header.p_offset = 0;
    header.p_filesz = 1;
    {
        std::string bytes( physical_offset, '\0' );
        bytes += bytes_for( header, sizeof( T ) - 1 );
        std::istringstream input( bytes );
        EXPECT_FALSE( segment.load( input, 0, is_lazy ) );
    }
    EXPECT_EQ( segment.get_type(), PT_NULL );
    EXPECT_EQ( segment.get_file_size(), 0U );
    EXPECT_EQ( segment.get_data(), nullptr );
}

template <class T> void expect_complete_section_header_accepted()
{
    auto               translator = std::make_shared<address_translator>();
    test_section<T>    section( make_convertor(), translator, nullptr );
    std::istringstream section_input( std::string( sizeof( T ), '\0' ) );
    EXPECT_TRUE( section.load( section_input, 0, true ) );
}

template <class T> void expect_complete_segment_header_accepted()
{
    auto               translator = std::make_shared<address_translator>();
    test_segment<T>    segment( make_convertor(), translator );
    std::istringstream segment_input( std::string( sizeof( T ), '\0' ) );
    EXPECT_TRUE( segment.load( segment_input, 0, false ) );
}

template <class T> void expect_section_recovers_after_failed_load()
{
    auto            translator = std::make_shared<address_translator>();
    test_section<T> section( make_convertor(), translator, nullptr );
    {
        std::istringstream truncated( std::string( sizeof( T ) - 1, '\0' ) );
        EXPECT_FALSE( section.load( truncated, 0, false ) );
    }

    T header{};
    header.sh_type    = SHT_PROGBITS;
    header.sh_offset  = sizeof( T );
    header.sh_size    = 1;
    std::string bytes = bytes_for( header, sizeof( header ) );
    bytes.push_back( 'x' );
    {
        std::istringstream complete( bytes );
        ASSERT_TRUE( section.load( complete, 0, false ) );
    }
    ASSERT_NE( section.get_data(), nullptr );
    EXPECT_EQ( section.get_data()[0], 'x' );
}

template <class T> void expect_segment_recovers_after_failed_load()
{
    auto            translator = std::make_shared<address_translator>();
    test_segment<T> segment( make_convertor(), translator );
    {
        std::istringstream truncated( std::string( sizeof( T ) - 1, '\0' ) );
        EXPECT_FALSE( segment.load( truncated, 0, false ) );
    }

    T header{};
    header.p_type     = PT_LOAD;
    header.p_offset   = sizeof( T );
    header.p_filesz   = 1;
    std::string bytes = bytes_for( header, sizeof( header ) );
    bytes.push_back( 'x' );
    {
        std::istringstream complete( bytes );
        ASSERT_TRUE( segment.load( complete, 0, false ) );
    }
    ASSERT_NE( segment.get_data(), nullptr );
    EXPECT_EQ( segment.get_data()[0], 'x' );
}

unsigned char host_encoding()
{
    const std::uint16_t value = 1;
    return *reinterpret_cast<const unsigned char*>( &value ) == 1 ? ELFDATA2LSB
                                                                  : ELFDATA2MSB;
}

template <class ElfHeader, class TableHeader>
void expect_public_load_result( bool          section_table,
                                unsigned char file_class,
                                bool          is_lazy )
{
    ElfHeader header{};
    header.e_ident[EI_MAG0]    = ELFMAG0;
    header.e_ident[EI_MAG1]    = ELFMAG1;
    header.e_ident[EI_MAG2]    = ELFMAG2;
    header.e_ident[EI_MAG3]    = ELFMAG3;
    header.e_ident[EI_CLASS]   = file_class;
    header.e_ident[EI_DATA]    = host_encoding();
    header.e_ident[EI_VERSION] = EV_CURRENT;
    header.e_version           = EV_CURRENT;
    header.e_ehsize            = sizeof( ElfHeader );
    if ( section_table ) {
        header.e_shoff     = sizeof( ElfHeader );
        header.e_shentsize = sizeof( TableHeader );
        header.e_shnum     = 1;
        header.e_shstrndx  = SHN_UNDEF;
    }
    else {
        header.e_phoff     = sizeof( ElfHeader );
        header.e_phentsize = sizeof( TableHeader );
        header.e_phnum     = 1;
    }

    elfio reader;
    bool  result = false;
    {
        std::string bytes( sizeof( ElfHeader ) + sizeof( TableHeader ) - 1,
                           '\0' );
        std::memcpy( bytes.data(), &header, sizeof( header ) );
        std::istringstream input( bytes );
        result = reader.load( input, is_lazy );
    }

    if ( section_table ) {
        EXPECT_TRUE( result );
        ASSERT_EQ( reader.sections.size(), 1U );
        EXPECT_EQ( reader.sections[0]->get_type(), SHT_NULL );
        EXPECT_EQ( reader.sections[0]->get_data(), nullptr );
    }
    else {
        EXPECT_FALSE( result );
        EXPECT_EQ( reader.segments.size(), 0U );
    }
}

} // namespace

TEST( ELFIOHeaderBoundsTest, RejectsTruncatedSectionHeaders )
{
    for ( bool is_lazy : { false, true } ) {
        for ( bool translated : { false, true } ) {
            expect_truncated_section_rejected<Elf32_Shdr>( is_lazy,
                                                           translated );
            expect_truncated_section_rejected<Elf64_Shdr>( is_lazy,
                                                           translated );
        }
    }
}

TEST( ELFIOHeaderBoundsTest, RejectsTruncatedProgramHeaders )
{
    for ( bool is_lazy : { false, true } ) {
        for ( bool translated : { false, true } ) {
            expect_truncated_segment_rejected<Elf32_Phdr>( is_lazy,
                                                           translated );
            expect_truncated_segment_rejected<Elf64_Phdr>( is_lazy,
                                                           translated );
        }
    }
}

TEST( ELFIOHeaderBoundsTest, AcceptsCompleteHeadersAtExactBoundary )
{
    expect_complete_section_header_accepted<Elf32_Shdr>();
    expect_complete_section_header_accepted<Elf64_Shdr>();
    expect_complete_segment_header_accepted<Elf32_Phdr>();
    expect_complete_segment_header_accepted<Elf64_Phdr>();
}

TEST( ELFIOHeaderBoundsTest, RecoversAfterSubsequentCompleteHeader )
{
    expect_section_recovers_after_failed_load<Elf32_Shdr>();
    expect_section_recovers_after_failed_load<Elf64_Shdr>();
    expect_segment_recovers_after_failed_load<Elf32_Phdr>();
    expect_segment_recovers_after_failed_load<Elf64_Phdr>();
}

TEST( ELFIOHeaderBoundsTest, PreservesPublicCorruptedSectionRecovery )
{
    for ( bool is_lazy : { false, true } ) {
        expect_public_load_result<Elf32_Ehdr, Elf32_Shdr>( true, ELFCLASS32,
                                                           is_lazy );
        expect_public_load_result<Elf64_Ehdr, Elf64_Shdr>( true, ELFCLASS64,
                                                           is_lazy );
    }
}

TEST( ELFIOHeaderBoundsTest, PublicLoadRejectsTruncatedProgramTable )
{
    for ( bool is_lazy : { false, true } ) {
        expect_public_load_result<Elf32_Ehdr, Elf32_Phdr>( false, ELFCLASS32,
                                                           is_lazy );
        expect_public_load_result<Elf64_Ehdr, Elf64_Phdr>( false, ELFCLASS64,
                                                           is_lazy );
    }
}
