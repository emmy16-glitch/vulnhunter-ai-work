import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:vulnhunter_mobile/core/upload/resumable_apk_upload.dart';

class FakeTransport implements ResumableUploadTransport {
  FakeTransport(this.offset);

  int offset;
  final chunks = <List<int>>[];
  String? uploadedSha256;
  bool finalized = false;

  @override
  Future<UploadSession> createSession(
      {required String fileName,
      required int totalBytes,
      required String sha256}) async {
    uploadedSha256 = sha256;
    return const UploadSession(uploadId: 'upload-1', offset: 2);
  }

  @override
  Future<int> acknowledgedOffset(String uploadId) async => offset;

  @override
  Future<int> sendChunk(
      {required String uploadId,
      required int offset,
      required int totalBytes,
      required List<int> bytes}) async {
    expect(offset, this.offset);
    chunks.add(List<int>.from(bytes));
    this.offset += bytes.length;
    return this.offset;
  }

  @override
  Future<void> finalize(String uploadId) async {
    expect(offset, 8);
    finalized = true;
  }
}

void main() {
  test(
      'resumes from acknowledged offset and finalizes after complete byte range',
      () async {
    final directory =
        await Directory.systemTemp.createTemp('vulnhunter-upload-test-');
    final file = File('${directory.path}/sample.apk');
    await file.writeAsBytes(List<int>.generate(8, (index) => index));
    final transport = FakeTransport(2);

    try {
      final uploadId =
          await ResumableApkUploader(transport: transport, chunkSize: 3)
              .upload(file);
      expect(uploadId, 'upload-1');
      expect(transport.chunks, <List<int>>[
        <int>[2, 3, 4],
        <int>[5, 6, 7],
      ]);
      expect(transport.uploadedSha256, isNotEmpty);
      expect(transport.finalized, isTrue);
    } finally {
      await directory.delete(recursive: true);
    }
  });
}
