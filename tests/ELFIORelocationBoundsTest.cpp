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

#include <sstream>
#include <string>

#include <gtest/gtest.h>
#include <elfio/elfio.hpp>

using namespace ELFIO;

TEST( ELFIORelocationBoundsTest, RejectsMissingSectionData )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( unsigned char encoding : { ELFDATA2LSB, ELFDATA2MSB } ) {
            for ( Elf_Word section_type : { SHT_REL, SHT_RELA } ) {
                elfio file;
                file.create( file_class, encoding );

                section* relocations = file.sections.add( ".rel.test" );
                relocations->set_type( section_type );
                relocations->set_entry_size(
                    file.get_default_entry_size( section_type ) );
                relocations->set_size( relocations->get_entry_size() );
                relocations->set_stream_size( 0 );
                relocations->set_link( 0xffff );

                relocation_section_accessor accessor( file, relocations );
                ASSERT_EQ( accessor.get_entries_num(), 1U );

                Elf64_Addr offset = 11;
                Elf_Word   symbol = 12;
                unsigned   type   = 13;
                Elf_Sxword addend = 14;
                EXPECT_FALSE(
                    accessor.get_entry( 0, offset, symbol, type, addend ) );
                EXPECT_EQ( offset, 11U );
                EXPECT_EQ( symbol, 12U );
                EXPECT_EQ( type, 13U );
                EXPECT_EQ( addend, 14 );
                EXPECT_FALSE( accessor.set_entry( 0, 1, 2, 3, 4 ) );

                Elf64_Addr  symbol_value = 0;
                std::string symbol_name;
                Elf_Sxword  calculated = 0;
                EXPECT_FALSE( accessor.get_entry( 0, offset, symbol_value,
                                                  symbol_name, type, addend,
                                                  calculated ) );
                accessor.swap_symbols( 0, 1 );
            }
        }
    }
}

TEST( ELFIORelocationBoundsTest, RejectsUndersizedEntries )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( Elf_Word section_type : { SHT_REL, SHT_RELA } ) {
            elfio file;
            file.create( file_class, ELFDATA2LSB );
            section* relocations = file.sections.add( ".rel.test" );
            relocations->set_type( section_type );
            Elf_Xword entry_size =
                file.get_default_entry_size( section_type ) - 1;
            relocations->set_entry_size( entry_size );
            relocations->set_data( std::string( entry_size, '\0' ) );

            relocation_section_accessor accessor( file, relocations );
            ASSERT_EQ( accessor.get_entries_num(), 1U );
            Elf64_Addr offset = 0;
            Elf_Word   symbol = 0;
            unsigned   type   = 0;
            Elf_Sxword addend = 0;
            EXPECT_FALSE(
                accessor.get_entry( 0, offset, symbol, type, addend ) );
            EXPECT_FALSE( accessor.set_entry( 0, 1, 2, 3, 4 ) );
        }
    }
}

TEST( ELFIORelocationBoundsTest, SupportsExtendedUnalignedEntryStrides )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( unsigned char encoding : { ELFDATA2LSB, ELFDATA2MSB } ) {
            for ( Elf_Word section_type : { SHT_REL, SHT_RELA } ) {
                elfio file;
                file.create( file_class, encoding );
                section* relocations = file.sections.add( ".rel.test" );
                relocations->set_type( section_type );
                Elf_Xword entry_size =
                    file.get_default_entry_size( section_type ) + 1;
                relocations->set_entry_size( entry_size );
                relocations->set_data(
                    std::string( 2 * entry_size, static_cast<char>( 0x5a ) ) );

                relocation_section_accessor accessor( file, relocations );
                ASSERT_TRUE( accessor.set_entry( 1, 0x1234, 7, 3, -9 ) );

                Elf64_Addr offset = 0;
                Elf_Word   symbol = 0;
                unsigned   type   = 0;
                Elf_Sxword addend = 0;
                ASSERT_TRUE(
                    accessor.get_entry( 1, offset, symbol, type, addend ) );
                EXPECT_EQ( offset, 0x1234U );
                EXPECT_EQ( symbol, 7U );
                EXPECT_EQ( type, 3U );
                EXPECT_EQ( addend, section_type == SHT_RELA ? -9 : 0 );
                EXPECT_EQ( static_cast<unsigned char>(
                               relocations->get_data()[2 * entry_size - 1] ),
                           0x5a );
            }
        }
    }
}

TEST( ELFIORelocationBoundsTest, RejectsInvalidSymbolTableLink )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* relocations = file.sections.add( ".rela.test" );
    relocations->set_type( SHT_RELA );
    relocations->set_entry_size( file.get_default_entry_size( SHT_RELA ) );
    relocation_section_accessor writer( file, relocations );
    writer.add_entry( 1, 2, 3, 4 );
    relocations->set_link( 0xffff );

    Elf64_Addr  offset       = 0;
    Elf64_Addr  symbol_value = 0;
    std::string symbol_name;
    unsigned    type       = 0;
    Elf_Sxword  addend     = 0;
    Elf_Sxword  calculated = 0;
    EXPECT_FALSE( writer.get_entry( 0, offset, symbol_value, symbol_name, type,
                                    addend, calculated ) );
}

TEST( ELFIORelocationBoundsTest, PreservesValidLazyLoadedEntries )
{
    for ( unsigned char file_class : { ELFCLASS32, ELFCLASS64 } ) {
        for ( unsigned char encoding : { ELFDATA2LSB, ELFDATA2MSB } ) {
            for ( Elf_Word section_type : { SHT_REL, SHT_RELA } ) {
                elfio writer;
                writer.create( file_class, encoding );
                section* relocations = writer.sections.add( ".rel.test" );
                relocations->set_type( section_type );
                relocations->set_entry_size(
                    writer.get_default_entry_size( section_type ) );
                relocation_section_accessor accessor( writer, relocations );
                if ( section_type == SHT_RELA ) {
                    accessor.add_entry( 0x1234, 7, 3, -9 );
                }
                else {
                    accessor.add_entry( Elf64_Addr{ 0x1234 }, Elf_Word{ 7 },
                                        unsigned{ 3 } );
                }

                std::stringstream stream( std::ios::in | std::ios::out |
                                          std::ios::binary );
                ASSERT_TRUE( writer.save( stream ) );
                stream.seekg( 0 );
                elfio reader;
                ASSERT_TRUE( reader.load( stream, true ) );
                const section* loaded = reader.sections[".rel.test"];
                ASSERT_NE( loaded, nullptr );
                const_relocation_section_accessor loaded_accessor( reader,
                                                                   loaded );
                Elf64_Addr                        offset = 0;
                Elf_Word                          symbol = 0;
                unsigned                          type   = 0;
                Elf_Sxword                        addend = 0;
                ASSERT_TRUE( loaded_accessor.get_entry( 0, offset, symbol, type,
                                                        addend ) );
                EXPECT_EQ( offset, 0x1234U );
                EXPECT_EQ( symbol, 7U );
                EXPECT_EQ( type, 3U );
                EXPECT_EQ( addend, section_type == SHT_RELA ? -9 : 0 );
            }
        }
    }
}

TEST( ELFIORelocationBoundsTest, RejectsUnsupportedSectionTypes )
{
    elfio file;
    file.create( ELFCLASS64, ELFDATA2LSB );
    section* relocations = file.sections.add( ".rel.test" );
    relocations->set_type( SHT_PROGBITS );
    relocations->set_entry_size( sizeof( Elf64_Rela ) );
    relocations->set_data( std::string( sizeof( Elf64_Rela ), '\0' ) );
    relocation_section_accessor accessor( file, relocations );
    Elf64_Addr                  offset = 0;
    Elf_Word                    symbol = 0;
    unsigned                    type   = 0;
    Elf_Sxword                  addend = 0;
    EXPECT_FALSE( accessor.get_entry( 0, offset, symbol, type, addend ) );
    EXPECT_FALSE( accessor.set_entry( 0, 1, 2, 3, 4 ) );
}
