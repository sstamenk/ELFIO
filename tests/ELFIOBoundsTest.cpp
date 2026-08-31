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
#include <initializer_list>
#include <string>

#include <gtest/gtest.h>
#include <elfio/elfio.hpp>

using namespace ELFIO;

namespace {

template <class T>
void append_value( std::string& data, const elfio& file, T value )
{
    T converted = ( *file.get_convertor() )( value );
    data.append( reinterpret_cast<const char*>( &converted ),
                 sizeof( converted ) );
}

class symbol_lookup_fixture
{
  public:
    symbol_lookup_fixture( unsigned char file_class,
                           unsigned char encoding,
                           Elf_Word      hash_type )
    {
        file.create( file_class, encoding );

        section* strings = file.sections.add( ".strtab.test" );
        strings->set_type( SHT_STRTAB );
        const char string_data[] = { '\0', 'f', 'o', 'o', '\0' };
        strings->set_data( string_data, sizeof( string_data ) );

        symbols = file.sections.add( ".symtab.test" );
        symbols->set_type( SHT_SYMTAB );
        symbols->set_entry_size( file.get_default_entry_size( SHT_SYMTAB ) );
        symbols->set_link( strings->get_index() );
        symbol_section_accessor symbol_writer( file, symbols );
        symbol_writer.add_symbol( 1, 0, 0, STB_GLOBAL, STT_NOTYPE, 0,
                                  SHN_UNDEF );

        hash = file.sections.add( ".hash.test" );
        hash->set_type( hash_type );
        hash->set_link( symbols->get_index() );
    }

    void set_words( std::initializer_list<std::uint32_t> words )
    {
        std::string data;
        for ( std::uint32_t word : words ) {
            append_value( data, file, word );
        }
        hash->set_data( data );
    }

    void set_valid_gnu_hash( const std::string& name, bool terminated )
    {
        constexpr std::uint32_t bloom_shift = 5;
        std::uint32_t           hash_value =
            elf_gnu_hash( (const unsigned char*)name.c_str() );
        std::string data;
        append_value<std::uint32_t>( data, file, 1 );
        append_value<std::uint32_t>( data, file, 1 );
        append_value<std::uint32_t>( data, file, 1 );
        append_value<std::uint32_t>( data, file, bloom_shift );
        if ( file.get_class() == ELFCLASS32 ) {
            std::uint32_t bloom =
                ( (std::uint32_t)1 << ( hash_value % 32 ) ) |
                ( (std::uint32_t)1 << ( ( hash_value >> bloom_shift ) % 32 ) );
            append_value( data, file, bloom );
        }
        else {
            std::uint64_t bloom =
                ( (std::uint64_t)1 << ( hash_value % 64 ) ) |
                ( (std::uint64_t)1 << ( ( hash_value >> bloom_shift ) % 64 ) );
            append_value( data, file, bloom );
        }
        append_value<std::uint32_t>( data, file, 1 );
        append_value<std::uint32_t>(
            data, file, terminated ? hash_value | 1U : hash_value & ~1U );
        hash->set_data( data );
    }

    bool find( const std::string& name ) const
    {
        const_symbol_section_accessor reader( file, symbols );
        Elf64_Addr                    value         = 0;
        Elf_Xword                     size          = 0;
        unsigned char                 bind          = 0;
        unsigned char                 type          = 0;
        Elf_Half                      section_index = 0;
        unsigned char                 other         = 0;
        return reader.get_symbol( name, value, size, bind, type, section_index,
                                  other );
    }

  private:
    elfio    file;
    section* symbols = nullptr;
    section* hash    = nullptr;
};

} // namespace

TEST( ELFIOBoundsTest, RejectsOutOfRangeNoteIndex )
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

TEST( ELFIOBoundsTest, RejectsTruncatedNotePayload )
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

TEST( ELFIOBoundsTest, AcceptsNamelessNoteAndContinuesParsing )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* notes = file.sections.add( ".note.test" );
    notes->set_type( SHT_NOTE );

    std::string data;
    append_value<Elf_Word>( data, file, 0 );
    append_value<Elf_Word>( data, file, 0 );
    append_value<Elf_Word>( data, file, 1 );
    append_value<Elf_Word>( data, file, 4 );
    append_value<Elf_Word>( data, file, 0 );
    append_value<Elf_Word>( data, file, 2 );
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

TEST( ELFIOBoundsTest, RejectsMalformedSysvHashTables )
{
    symbol_lookup_fixture fixture( ELFCLASS64, ELFDATA2LSB, SHT_HASH );

    fixture.set_words( { 0, 0 } );
    EXPECT_FALSE( fixture.find( "missing" ) );
    EXPECT_TRUE( fixture.find( "foo" ) );

    fixture.set_words( { 1, 1 } );
    EXPECT_FALSE( fixture.find( "missing" ) );

    fixture.set_words( { 1 } );
    EXPECT_FALSE( fixture.find( "missing" ) );

    fixture.set_words( { UINT32_MAX, UINT32_MAX } );
    EXPECT_FALSE( fixture.find( "missing" ) );

    fixture.set_words( { 1, 2, 1, 0, 1 } );
    EXPECT_FALSE( fixture.find( "missing" ) );
}

TEST( ELFIOBoundsTest, PreservesValidSysvHashLookups )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( unsigned char encoding : { ELFDATA2LSB, ELFDATA2MSB } ) {
            symbol_lookup_fixture fixture( file_class, encoding, SHT_HASH );
            fixture.set_words( { 1, 2, 1, 0, 0 } );
            EXPECT_TRUE( fixture.find( "foo" ) );
            EXPECT_FALSE( fixture.find( "missing" ) );
        }
    }
}

TEST( ELFIOBoundsTest, RejectsMalformedGnuHashTables )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        symbol_lookup_fixture fixture( file_class, ELFDATA2LSB, SHT_GNU_HASH );

        fixture.set_words( { 0, 0, 0, 0 } );
        EXPECT_FALSE( fixture.find( "missing" ) );
        EXPECT_TRUE( fixture.find( "foo" ) );

        fixture.set_words( { 1, 1, 1, 0 } );
        EXPECT_FALSE( fixture.find( "missing" ) );

        fixture.set_words( { 1, 1, 1 } );
        EXPECT_FALSE( fixture.find( "missing" ) );

        fixture.set_words( { UINT32_MAX, 1, UINT32_MAX, 0 } );
        EXPECT_FALSE( fixture.find( "missing" ) );

        fixture.set_words( { 1, 1, 1, 32 } );
        EXPECT_FALSE( fixture.find( "missing" ) );

        fixture.set_valid_gnu_hash( "missing", false );
        EXPECT_FALSE( fixture.find( "missing" ) );
    }
}

TEST( ELFIOBoundsTest, PreservesValidGnuHashLookups )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( unsigned char encoding : { ELFDATA2LSB, ELFDATA2MSB } ) {
            symbol_lookup_fixture fixture( file_class, encoding, SHT_GNU_HASH );
            fixture.set_valid_gnu_hash( "foo", true );
            EXPECT_TRUE( fixture.find( "foo" ) );
            EXPECT_FALSE( fixture.find( "missing" ) );
        }
    }
}
