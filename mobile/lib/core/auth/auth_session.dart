import '../storage/secure_credentials.dart';

typedef RefreshCredentials = Future<SecureCredentials> Function(
  String refreshToken,
);

class AuthSession {
  AuthSession({
    required SecureCredentialStore store,
    RefreshCredentials? refreshCredentials,
  })  : _store = store,
        _refreshCredentials = refreshCredentials;

  final SecureCredentialStore _store;
  final RefreshCredentials? _refreshCredentials;
  SecureCredentials? _credentials;

  bool get isAuthenticated => _credentials != null;
  String? get accessToken => _credentials?.accessToken;

  Future<bool> restore() async {
    _credentials = await _store.read();
    return isAuthenticated;
  }

  Future<void> establish(SecureCredentials credentials) async {
    await _store.save(credentials);
    _credentials = credentials;
  }

  Future<bool> refresh() async {
    final current = _credentials ?? await _store.read();
    if (current == null || _refreshCredentials == null) return false;
    final refreshed = await _refreshCredentials(current.refreshToken);
    await establish(refreshed);
    return true;
  }

  Future<void> signOut() async {
    _credentials = null;
    await _store.clear();
  }
}
