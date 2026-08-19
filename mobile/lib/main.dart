import 'dart:io';

import 'package:flutter/material.dart';

import 'core/api/client.dart';
import 'core/auth/auth_session.dart';
import 'core/storage/secure_credentials.dart';
import 'core/upload/resumable_apk_upload.dart';
import 'features/workspace/workspace_page.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final credentialStore = SecureCredentialStore();
  final session = AuthSession(store: credentialStore);
  await session.restore();

  const controlPlaneUrl = String.fromEnvironment(
    'VULNHUNTER_CONTROL_PLANE_URL',
    defaultValue: 'http://10.0.2.2:8000',
  );
  const uploadEndpoint = String.fromEnvironment('VULNHUNTER_UPLOAD_ENDPOINT');
  final api = VulnHunterApiClient(
    baseUrl: '$controlPlaneUrl/api/v1/',
    accessTokenReader: () async => session.accessToken,
  );

  runApp(
    VulnHunterApp(
      session: session,
      api: api,
      controlPlaneUrl: controlPlaneUrl,
      uploadEndpoint: uploadEndpoint,
    ),
  );
}

class VulnHunterApp extends StatelessWidget {
  const VulnHunterApp({
    super.key,
    required this.session,
    required this.api,
    required this.controlPlaneUrl,
    required this.uploadEndpoint,
  });

  final AuthSession session;
  final VulnHunterApiClient api;
  final String controlPlaneUrl;
  final String uploadEndpoint;

  @override
  Widget build(BuildContext context) => MaterialApp(
        title: 'VulnHunter',
        theme: ThemeData(
          colorScheme: ColorScheme.fromSeed(seedColor: Colors.blueGrey),
          useMaterial3: true,
        ),
        home: session.isAuthenticated
            ? WorkspacePage(
                api: api,
                realtimeBaseUrl: controlPlaneUrl,
                upload: (File file, onProgress) async {
                  if (uploadEndpoint.isEmpty) {
                    throw StateError(
                      'APK upload endpoint is not configured by the control plane deployment.',
                    );
                  }
                  final transport = HttpResumableUploadTransport(
                    endpoint: uploadEndpoint,
                    accessTokenReader: () async => session.accessToken,
                  );
                  return ResumableApkUploader(transport: transport)
                      .upload(file, onProgress: onProgress);
                },
              )
            : const AuthRequiredPage(),
      );
}

class AuthRequiredPage extends StatelessWidget {
  const AuthRequiredPage({super.key});

  @override
  Widget build(BuildContext context) => Scaffold(
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.lock_outline, size: 48),
                const SizedBox(height: 16),
                Text(
                  'Native sign-in is required',
                  style: Theme.of(context).textTheme.headlineSmall,
                ),
                const SizedBox(height: 8),
                const Text(
                  'This build does not create a local token or accept a token from a URL. Connect the deployment’s short-lived access and refresh credential flow, then store it through the secure session boundary.',
                  textAlign: TextAlign.center,
                ),
              ],
            ),
          ),
        ),
      );
}
