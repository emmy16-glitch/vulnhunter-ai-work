import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class SecureCredentials {
  const SecureCredentials({
    required this.accessToken,
    required this.refreshToken,
  });

  final String accessToken;
  final String refreshToken;
}

class SecureCredentialStore {
  SecureCredentialStore({FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  static const _accessKey = 'vulnhunter.access_token';
  static const _refreshKey = 'vulnhunter.refresh_token';
  final FlutterSecureStorage _storage;

  Future<void> save(SecureCredentials credentials) async {
    await _storage.write(key: _accessKey, value: credentials.accessToken);
    await _storage.write(key: _refreshKey, value: credentials.refreshToken);
  }

  Future<SecureCredentials?> read() async {
    final access = await _storage.read(key: _accessKey);
    final refresh = await _storage.read(key: _refreshKey);
    if (access == null ||
        refresh == null ||
        access.isEmpty ||
        refresh.isEmpty) {
      return null;
    }
    return SecureCredentials(accessToken: access, refreshToken: refresh);
  }

  Future<void> clear() async {
    await _storage.delete(key: _accessKey);
    await _storage.delete(key: _refreshKey);
  }
}
