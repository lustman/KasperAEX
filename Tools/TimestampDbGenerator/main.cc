#include <windows.h>

#include <iostream>
#include <fstream>
#include <vector>
#include <filesystem>
#include <cstdint>
#include <array>

struct timestamp_entry_t {
	std::uint32_t timestamp;
	std::string sample_name;
};

using file_array_t = std::vector<std::filesystem::path>;
using timestamp_array_t = std::vector<timestamp_entry_t>;
using bin_t = std::vector<std::uint8_t>;

bool read_bin( const std::filesystem::path& path, bin_t& out ) {
	auto file = std::ifstream( path, std::ios::binary );
	if ( !file )
		return false;

	out.assign( std::istreambuf_iterator<char>( file ), std::istreambuf_iterator<char>( ) );
	return true;
}

file_array_t scan_dir( const std::filesystem::path& path ) {
	auto out = file_array_t( );

	for ( const auto& entry : std::filesystem::recursive_directory_iterator( path ) ) {
		if ( entry.is_regular_file( ) )
			out.emplace_back( entry.path( ) );
	}

	return out;
}

std::uint32_t get_timestamp( const bin_t& pe ) {
	if ( pe.size( ) < sizeof( IMAGE_DOS_HEADER ) )
		return 0;

	const auto* bin = pe.data( );
	const auto* dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( bin );

	if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
		return 0;

	if ( dos->e_lfanew < 0 || dos->e_lfanew + sizeof( IMAGE_NT_HEADERS ) > pe.size( ) )
		return 0;

	const auto* nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( bin + dos->e_lfanew );

	if ( nt->Signature != IMAGE_NT_SIGNATURE )
		return 0;

	return nt->FileHeader.TimeDateStamp;
}

void generate_header( const timestamp_array_t& result ) {
	auto out = std::ofstream( "timestamp_db.h" );

	out << "#pragma once\n\n";
	out << "const int BlackListHashes[ " << result.size( ) << " ] = {\n";

	auto line = std::array<char, 256>( );

	for ( const auto& entry : result ) {
		const auto ts = entry.timestamp;
		const auto name = entry.sample_name.c_str( );

		std::printf( "[ ~ ] %s\t\t\t0x%X\n", name, ts );

		std::snprintf( line.data( ), line.size( ), "\t0x%X,\t\t\t\t/// %s\n", ts, name );
		out << line.data( );
	}

	out << "};\n\n";
	out << "const int BLACKLIST_HASH_COUNT = " << result.size( ) << ";\n";
}

int main( int argc, char* argv[ ] ) {
	std::printf( "> Timestamp DB generator. With love, by lustman.\n" );

	auto scan_path = std::filesystem::path( argc > 1 ? argv[ 1 ] : "assets\\" );
	auto binaries = scan_dir( scan_path );
	std::printf( "Processing %zu files...\n", binaries.size( ) );

	auto result = timestamp_array_t( );

	for ( const auto& bin_entry : binaries ) {
		auto pe = bin_t( );

		if ( !read_bin( bin_entry, pe ) )
			continue;

		auto timestamp = get_timestamp( pe );

		if ( timestamp == 0 )
			continue;

		result.emplace_back( timestamp, bin_entry.filename( ).generic_string( ) );
	}

	generate_header( result );

	std::printf( "Done. Press any key to exit." );
	std::getchar( );
}
