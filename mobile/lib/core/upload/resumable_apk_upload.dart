import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;

class UploadSession {
  const UploadSession({required this.uploadId, required this.offset});

  final String uploadId;
  final int offset;

  factory UploadSession.fromJson(Map<String, dynamic> json) => UploadSession(
        uploadId: '${json['upload_id'] ?? json['id'] ?? ''}',
        offset: (json['offset'] as num?)?.toInt() ?? 0,
      );
}

typedef UploadProgress = void Function(int acknowledgedBytes, int totalBytes);

abstract interface class ResumableUploadTransport {
  Future<UploadSession> createSession({
    required String fileName,
    required int totalBytes,
    required String sha256,
  });
  Future<int> acknowledgedOffset(String uploadId);
  Future<int> sendChunk({
    required String uploadId,
    required int offset,
    required int totalBytes,
    required List<int> bytes,
  });
  Future<void> finalize(String uploadId);
}

class HttpResumableUploadTransport implements ResumableUploadTransport {
  HttpResumableUploadTransport({
    required String endpoint,
    required this.accessTokenReader,
    http.Client? client,
  })  : _endpoint = Uri.parse(endpoint.endsWith('/') ? endpoint : '$endpoint/'),
        _client = client ?? http.Client();

  final Uri _endpoint;
  final Future<String?> Function() accessTokenReader;
  final http.Client _client;

  Future<Map<String, String>> _headers() async {
    final token = await accessTokenReader();
    return <String, String>{
      'Accept': 'application/json',
      if (token != null && token.isNotEmpty) 'Authorization': 'Bearer $token',
    };
  }

  @override
  Future<UploadSession> createSession({
    required String fileName,
    required int totalBytes,
    required String sha256,
  }) async {
    final headers = await _headers();
    headers['Content-Type'] = 'application/json';
    final response = await _client.post(
      _endpoint,
      headers: headers,
      body: jsonEncode(<String, dynamic>{
        'file_name': fileName,
        'size_bytes': totalBytes,
        'sha256': sha256,
        'artifact_type': 'apk',
      }),
    );
    return _expectSession(response);
  }

  @override
  Future<int> acknowledgedOffset(String uploadId) async {
    final response = await _client.head(
      _endpoint.resolve('${Uri.encodeComponent(uploadId)}/'),
      headers: await _headers(),
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      _throwApi(response);
    }
    return int.tryParse(response.headers['x-upload-offset'] ?? '0') ?? 0;
  }

  @override
  Future<int> sendChunk({
    required String uploadId,
    required int offset,
    required int totalBytes,
    required List<int> bytes,
  }) async {
    final headers = await _headers();
    headers.addAll(<String, String>{
      'Content-Type': 'application/octet-stream',
      'Content-Length': '${bytes.length}',
      'Content-Range': 'bytes $offset-${offset + bytes.length - 1}/$totalBytes',
    });
    final request = http.Request(
      'PATCH',
      _endpoint.resolve('${Uri.encodeComponent(uploadId)}/'),
    )
      ..headers.addAll(headers)
      ..bodyBytes = bytes;
    final response = await _client.send(request);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      throw StateError(
        'APK upload chunk failed with HTTP ${response.statusCode}',
      );
    }
    return int.tryParse(
          response.headers['x-upload-offset'] ?? '${offset + bytes.length}',
        ) ??
        offset + bytes.length;
  }

  @override
  Future<void> finalize(String uploadId) async {
    final headers = await _headers();
    headers['Content-Type'] = 'application/json';
    final response = await _client.post(
      _endpoint.resolve('${Uri.encodeComponent(uploadId)}/complete/'),
      headers: headers,
      body: '{}',
    );
    if (response.statusCode < 200 || response.statusCode >= 300) {
      _throwApi(response);
    }
  }

  UploadSession _expectSession(http.Response response) {
    if (response.statusCode < 200 || response.statusCode >= 300) {
      _throwApi(response);
    }
    final decoded = jsonDecode(response.body);
    if (decoded is! Map) {
      throw StateError('Upload session response was not an object.');
    }
    return UploadSession.fromJson(
      decoded.map((key, value) => MapEntry('$key', value)),
    );
  }

  Never _throwApi(http.Response response) => throw StateError(
        'APK upload API failed with HTTP ${response.statusCode}',
      );
}

class ResumableApkUploader {
  ResumableApkUploader({required this.transport, this.chunkSize = 1024 * 1024});

  final ResumableUploadTransport transport;
  final int chunkSize;

  Future<String> upload(File file, {UploadProgress? onProgress}) async {
    final totalBytes = await file.length();
    if (totalBytes <= 0) {
      throw ArgumentError('APK must not be empty.');
    }
    final digest = await sha256.bind(file.openRead()).first;
    final session = await transport.createSession(
      fileName: file.uri.pathSegments.last,
      totalBytes: totalBytes,
      sha256: digest.toString(),
    );
    var offset = await transport.acknowledgedOffset(session.uploadId);
    if (offset < session.offset) {
      offset = session.offset;
    }
    if (offset < 0 || offset > totalBytes) {
      throw StateError('Server returned an invalid APK upload offset.');
    }
    final bytes = await file.readAsBytes();
    while (offset < totalBytes) {
      final end = (offset + chunkSize).clamp(0, totalBytes).toInt();
      final acknowledged = await transport.sendChunk(
        uploadId: session.uploadId,
        offset: offset,
        totalBytes: totalBytes,
        bytes: bytes.sublist(offset, end),
      );
      if (acknowledged <= offset || acknowledged > totalBytes) {
        throw StateError(
          'Server returned a non-progressing APK upload offset.',
        );
      }
      offset = acknowledged;
      onProgress?.call(offset, totalBytes);
    }
    await transport.finalize(session.uploadId);
    return session.uploadId;
  }
}
