#ifndef PASSWORD_HASH_HPP
#define PASSWORD_HASH_HPP

#include <string>

bool password_hash_is_modern( const char* stored_password );
bool password_hash_is_legacy_md5( const char* stored_password );
bool password_hash_matches( const char* raw_password, const char* stored_password );
bool password_hash_supports_passwordencrypt( const char* stored_password );
std::string password_hash_make( const char* raw_password );

#endif
