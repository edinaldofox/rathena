#include "password_hash.hpp"

#include <array>
#include <cctype>
#include <cstring>

#include <openssl/sha.h>

#include <common/md5calc.hpp>
#include <common/random.hpp>

namespace {

constexpr size_t PASSWORD_SALT_BYTES = 16;
constexpr char PASSWORD_HASH_PREFIX[] = "sha256$";
constexpr size_t SHA256_HEX_LENGTH = SHA256_DIGEST_LENGTH * 2;
constexpr size_t MD5_HEX_LENGTH = 32;

std::string hex_encode( const unsigned char* data, size_t length ){
	static constexpr char HEX[] = "0123456789abcdef";
	std::string out;
	out.resize( length * 2 );

	for( size_t i = 0; i < length; ++i ){
		out[i * 2] = HEX[( data[i] >> 4 ) & 0x0f];
		out[i * 2 + 1] = HEX[data[i] & 0x0f];
	}

	return out;
}

bool hex_decode( const char* in, unsigned char* out, size_t out_length ){
	auto decode_char = []( unsigned char c ) -> int32 {
		if( c >= '0' && c <= '9' ){
			return c - '0';
		}
		c = static_cast<unsigned char>( std::tolower( c ) );
		if( c >= 'a' && c <= 'f' ){
			return c - 'a' + 10;
		}
		return -1;
	};

	for( size_t i = 0; i < out_length; ++i ){
		int32 high = decode_char( static_cast<unsigned char>( in[i * 2] ) );
		int32 low = decode_char( static_cast<unsigned char>( in[i * 2 + 1] ) );

		if( high < 0 || low < 0 ){
			return false;
		}

		out[i] = static_cast<unsigned char>( ( high << 4 ) | low );
	}

	return true;
}

std::string sha256_digest_hex( const unsigned char* salt, size_t salt_length, const char* raw_password ){
	std::array<unsigned char, SHA256_DIGEST_LENGTH> digest{};
	SHA256_CTX ctx;

	SHA256_Init( &ctx );
	SHA256_Update( &ctx, salt, salt_length );
	SHA256_Update( &ctx, raw_password, strlen( raw_password ) );
	SHA256_Final( digest.data(), &ctx );

	return hex_encode( digest.data(), digest.size() );
}

}

bool password_hash_is_modern( const char* stored_password ){
	return stored_password != nullptr && strncmp( stored_password, PASSWORD_HASH_PREFIX, strlen( PASSWORD_HASH_PREFIX ) ) == 0;
}

bool password_hash_is_legacy_md5( const char* stored_password ){
	if( stored_password == nullptr || strlen( stored_password ) != MD5_HEX_LENGTH ){
		return false;
	}

	for( size_t i = 0; i < MD5_HEX_LENGTH; ++i ){
		if( !std::isxdigit( static_cast<unsigned char>( stored_password[i] ) ) ){
			return false;
		}
	}

	return true;
}

bool password_hash_supports_passwordencrypt( const char* stored_password ){
	return !password_hash_is_modern( stored_password );
}

std::string password_hash_make( const char* raw_password ){
	std::array<unsigned char, PASSWORD_SALT_BYTES> salt{};

	for( unsigned char& byte : salt ){
		byte = static_cast<unsigned char>( rnd_value( 0, 255 ) );
	}

	std::string salt_hex = hex_encode( salt.data(), salt.size() );
	std::string digest_hex = sha256_digest_hex( salt.data(), salt.size(), raw_password );

	return std::string( PASSWORD_HASH_PREFIX ) + salt_hex + "$" + digest_hex;
}

bool password_hash_matches( const char* raw_password, const char* stored_password ){
	if( raw_password == nullptr || stored_password == nullptr ){
		return false;
	}

	if( password_hash_is_modern( stored_password ) ){
		const char* salt_hex = stored_password + strlen( PASSWORD_HASH_PREFIX );
		const char* separator = strchr( salt_hex, '$' );

		if( separator == nullptr || static_cast<size_t>( separator - salt_hex ) != PASSWORD_SALT_BYTES * 2 ){
			return false;
		}

		if( strlen( separator + 1 ) != SHA256_HEX_LENGTH ){
			return false;
		}

		std::array<unsigned char, PASSWORD_SALT_BYTES> salt{};
		if( !hex_decode( salt_hex, salt.data(), salt.size() ) ){
			return false;
		}

		return sha256_digest_hex( salt.data(), salt.size(), raw_password ) == std::string( separator + 1 );
	}

	if( password_hash_is_legacy_md5( stored_password ) ){
		char md5str[MD5_HEX_LENGTH + 1];
		MD5_String( raw_password, md5str );
		return strcmp( md5str, stored_password ) == 0;
	}

	return strcmp( raw_password, stored_password ) == 0;
}
