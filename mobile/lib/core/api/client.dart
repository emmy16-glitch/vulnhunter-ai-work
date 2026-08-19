import 'dart:convert';

import 'package:http/http.dart' as http;

import 'models.dart';

typedef AccessTokenReader = Future<String?> Function();

class VulnHunterApiException implements Exception {
  const VulnHunterApiException({
    required this.statusCode,
    required this.payload,
  });

  final int statusCode;
  final dynamic payload;

  @override
  String toString() => 'VulnHunterApiException($statusCode)';
}

class VulnHunterApiClient {
  VulnHunterApiClient({
    required String baseUrl,
    http.Client? client,
    AccessTokenReader? accessTokenReader,
  })  : _baseUri = Uri.parse(baseUrl.endsWith('/') ? baseUrl : '$baseUrl/'),
        _client = client ?? http.Client(),
        _accessTokenReader = accessTokenReader;

  final Uri _baseUri;
  final http.Client _client;
  final AccessTokenReader? _accessTokenReader;

  Future<Me> getMe() async => Me.fromJson(await _getJson('me/'));

  Future<Readiness> getReadiness() async {
    try {
      return Readiness.fromJson(await _getJson('readiness/'));
    } on VulnHunterApiException catch (error) {
      if (error.payload is Map) return Readiness.fromJson(_map(error.payload));
      rethrow;
    }
  }

  Future<List<Assessment>> listAssessments() async {
    final payload = await _getJson('assessments/');
    final raw = payload['results'];
    if (raw is! List) return const [];
    return raw
        .whereType<Map>()
        .map((item) => Assessment.fromJson(_map(item)))
        .toList(growable: false);
  }

  Future<Assessment> getAssessment(String assessmentId) async =>
      Assessment.fromJson(
        await _getJson('assessments/${Uri.encodeComponent(assessmentId)}/'),
      );

  Future<AssessmentEventsSnapshot> getAssessmentEvents(
    String assessmentId,
    int afterSequence,
  ) async {
    final cursor = afterSequence < 0 ? 0 : afterSequence;
    return AssessmentEventsSnapshot.fromJson(
      await _getJson(
        'assessments/${Uri.encodeComponent(assessmentId)}/events/',
        query: <String, String>{'after_sequence': '$cursor'},
      ),
    );
  }

  Future<RealtimeTicket> issueRealtimeTicket(String assessmentId) async =>
      RealtimeTicket.fromJson(
        await _sendJson(
          'POST',
          'realtime/ticket/',
          body: <String, dynamic>{'assessment_id': assessmentId},
        ),
      );

  Future<JsonMap> _getJson(String path, {Map<String, String>? query}) =>
      _sendJson('GET', path, query: query);

  Future<JsonMap> _sendJson(
    String method,
    String path, {
    Map<String, String>? query,
    JsonMap? body,
  }) async {
    final token = await _accessTokenReader?.call();
    final uri = _baseUri.resolve(path).replace(queryParameters: query);
    final headers = <String, String>{'Accept': 'application/json'};
    if (body != null) {
      headers['Content-Type'] = 'application/json';
    }
    if (token != null && token.isNotEmpty) {
      headers['Authorization'] = 'Bearer $token';
    }
    final response = switch (method) {
      'GET' => await _client.get(uri, headers: headers),
      'POST' => await _client.post(
          uri,
          headers: headers,
          body: jsonEncode(body ?? <String, dynamic>{}),
        ),
      _ => throw ArgumentError('Unsupported HTTP method: $method'),
    };
    final payload = _decode(response.body);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw VulnHunterApiException(
        statusCode: response.statusCode,
        payload: payload,
      );
    }
    return _map(payload);
  }

  dynamic _decode(String value) {
    if (value.trim().isEmpty) return <String, dynamic>{};
    try {
      return jsonDecode(value);
    } catch (_) {
      return value;
    }
  }

  JsonMap _map(dynamic value) => value is Map
      ? value.map((key, item) => MapEntry('$key', item))
      : <String, dynamic>{};
}
