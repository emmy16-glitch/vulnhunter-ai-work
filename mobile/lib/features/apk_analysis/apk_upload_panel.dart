import 'dart:io';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';

class ApkUploadPanel extends StatefulWidget {
  const ApkUploadPanel({super.key, required this.upload});

  final Future<String> Function(
    File file,
    void Function(int acknowledged, int total) onProgress,
  ) upload;

  @override
  State<ApkUploadPanel> createState() => _ApkUploadPanelState();
}

class _ApkUploadPanelState extends State<ApkUploadPanel> {
  bool _busy = false;
  String? _message;
  double? _progress;

  Future<void> _pickAndUpload() async {
    setState(() {
      _busy = true;
      _message = null;
      _progress = null;
    });
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: const ['apk'],
        withData: false,
      );
      final path = result?.files.single.path;
      if (path == null) {
        setState(() => _busy = false);
        return;
      }
      final uploadId = await widget.upload(File(path), (acknowledged, total) {
        if (mounted) {
          setState(() => _progress = total == 0 ? 0 : acknowledged / total);
        }
      });
      if (mounted) {
        setState(() => _message = 'Artifact uploaded and finalized: $uploadId');
      }
    } catch (error) {
      if (mounted) {
        setState(() => _message = 'Upload unavailable: $error');
      }
    } finally {
      if (mounted) {
        setState(() => _busy = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text('APK analysis',
                  style: Theme.of(context).textTheme.titleMedium),
              const SizedBox(height: 8),
              const Text(
                'Upload is an artifact step. Static analysis and any dynamic execution remain backend-governed states.',
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                onPressed: _busy ? null : _pickAndUpload,
                icon: const Icon(Icons.upload_file),
                label: Text(_busy ? 'Uploading…' : 'Select APK'),
              ),
              if (_progress != null) ...[
                const SizedBox(height: 12),
                LinearProgressIndicator(value: _progress),
                const SizedBox(height: 4),
                Text(
                  '${((_progress ?? 0) * 100).toStringAsFixed(0)}% acknowledged by server',
                ),
              ],
              if (_message != null) ...[
                const SizedBox(height: 12),
                Text(
                  _message!,
                  style: TextStyle(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ],
            ],
          ),
        ),
      );
}
