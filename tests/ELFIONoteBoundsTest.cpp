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
#include <string>

#include <gtest/gtest.h>
#include <elfio/elfio.hpp>

using namespace ELFIO;

TEST( ELFIONoteBoundsTest, RejectsOutOfRangeIndex )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* notes = file.sections.add( ".note.test" );
    notes->set_type( SHT_NOTE );

    note_section_accessor accessor( file, notes );
    std::uint32_t         payload = 0x12345678;
    accessor.add_note( 1, "test", reinterpret_cast<const char*>( &payload ),
                       sizeof( payload ) );
    ASSERT_EQ( accessor.get_notes_num(), 1U );

    Elf_Word    type     = 0;
    std::string name     = "unchanged";
    char*       desc     = nullptr;
    Elf_Word    descSize = 0;
    EXPECT_FALSE( accessor.get_note( 1, type, name, desc, descSize ) );
    EXPECT_EQ( name, "unchanged" );
}

TEST( ELFIONoteBoundsTest, RejectsTruncatedPayload )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* notes = file.sections.add( ".note.test" );
    notes->set_type( SHT_NOTE );

    const std::uint32_t header[] = { 12, 0, 1 };
    notes->set_data( reinterpret_cast<const char*>( header ),
                     sizeof( header ) );

    note_section_accessor accessor( file, notes );
    EXPECT_EQ( accessor.get_notes_num(), 0U );
}

TEST( ELFIONoteBoundsTest, AcceptsNamelessNoteAndContinuesParsing )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* notes = file.sections.add( ".note.test" );
    notes->set_type( SHT_NOTE );

    std::string data;
    const auto& convertor   = file.get_convertor();
    auto        append_word = [&]( Elf_Word value ) {
        value = ( *convertor )( value );
        data.append( reinterpret_cast<const char*>( &value ), sizeof( value ) );
    };

    append_word( 0 );
    append_word( 0 );
    append_word( 1 );
    append_word( 4 );
    append_word( 0 );
    append_word( 2 );
    data.append( "GNU\0", 4 );
    notes->set_data( data );

    note_section_accessor accessor( file, notes );
    ASSERT_EQ( accessor.get_notes_num(), 2U );

    Elf_Word    type     = 0;
    std::string name     = "not empty";
    char        marker   = 0;
    char*       desc     = &marker;
    Elf_Word    descSize = 1;
    ASSERT_TRUE( accessor.get_note( 0, type, name, desc, descSize ) );
    EXPECT_EQ( type, 1U );
    EXPECT_TRUE( name.empty() );
    EXPECT_EQ( desc, nullptr );
    EXPECT_EQ( descSize, 0U );

    ASSERT_TRUE( accessor.get_note( 1, type, name, desc, descSize ) );
    EXPECT_EQ( type, 2U );
    EXPECT_EQ( name, "GNU" );
}
