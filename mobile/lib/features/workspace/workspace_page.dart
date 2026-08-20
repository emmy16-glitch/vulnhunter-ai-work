import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import '../../core/api/client.dart';
import '../../core/api/models.dart';
import '../../core/realtime/assessment_events_client.dart';
import '../apk_analysis/apk_upload_panel.dart';

class WorkspacePage extends StatefulWidget {
  const WorkspacePage({
    super.key,
    required this.api,
    required this.realtimeBaseUrl,
    required this.upload,
  });

  final VulnHunterApiClient api;
  final String realtimeBaseUrl;
  final Future<String> Function(
    File file,
    void Function(int acknowledged, int total) onProgress,
  ) upload;

  @override
  State<WorkspacePage> createState() => _WorkspacePageState();
}

class _WorkspacePageState extends State<WorkspacePage> {
  Readiness? _readiness;
  List<Assessment> _assessments = const [];
  Assessment? _selected;
  AssessmentEventsClient? _eventsClient;
  StreamSubscription<AssessmentEventsSnapshot>? _snapshotSubscription;
  StreamSubscription<RealtimeConnectionState>? _stateSubscription;
  RealtimeConnectionState _connectionState = RealtimeConnectionState.idle;
  String? _error;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    unawaited(_loadWorkspace());
  }

  @override
  void dispose() {
    unawaited(_closeRealtime());
    super.dispose();
  }

  Future<void> _loadWorkspace() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final readinessFuture = widget.api.getReadiness().catchError(
            (_) => const Readiness(
              status: 'unavailable',
              ready: false,
              checks: {},
              raw: {},
            ),
          );
      final values = await Future.wait<Object>([
        readinessFuture,
        widget.api.listAssessments(),
      ]);
      if (!mounted) return;
      _readiness = values[0] as Readiness;
      _assessments = values[1] as List<Assessment>;
      if (_assessments.isNotEmpty) await _select(_assessments.first.runId);
    } catch (error) {
      if (mounted) {
        setState(() => _error = 'Control-plane state unavailable: $error');
      }
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _select(String runId) async {
    await _closeRealtime();
    try {
      final assessment = await widget.api.getAssessment(runId);
      if (!mounted) return;
      setState(() => _selected = assessment);
      final client = AssessmentEventsClient(
        api: widget.api,
        apiBaseUrl: widget.realtimeBaseUrl,
        assessmentId: runId,
      );
      _eventsClient = client;
      _snapshotSubscription = client.snapshots.listen(_applySnapshot);
      _stateSubscription = client.states.listen((state) {
        if (mounted) setState(() => _connectionState = state);
      });
      await client.start();
    } catch (error) {
      if (mounted) {
        setState(
          () => _error = 'Assessment is not available to this identity: $error',
        );
      }
    }
  }

  void _applySnapshot(AssessmentEventsSnapshot snapshot) {
    if (!mounted || _selected == null) return;
    final events = <int, AssessmentEvent>{
      for (final event in _selected!.events) event.sequence: event,
      for (final event in snapshot.events) event.sequence: event,
    }.values.toList()
      ..sort((left, right) => left.sequence.compareTo(right.sequence));
    setState(() {
      _selected = _selected!.copyWith(
        state: snapshot.runState,
        terminal: snapshot.terminal,
        events: events,
        lastSequence: snapshot.lastSequence,
      );
    });
  }

  Future<void> _closeRealtime() async {
    await _snapshotSubscription?.cancel();
    await _stateSubscription?.cancel();
    _snapshotSubscription = null;
    _stateSubscription = null;
    await _eventsClient?.stop();
    _eventsClient = null;
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return Scaffold(
      appBar: AppBar(title: const Text('VulnHunter workspace')),
      body: RefreshIndicator(
        onRefresh: _loadWorkspace,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            if (_error != null) _Notice(message: _error!),
            _ReadinessCard(readiness: _readiness),
            const SizedBox(height: 12),
            ApkUploadPanel(upload: widget.upload),
            const SizedBox(height: 18),
            Text('Assessments', style: Theme.of(context).textTheme.titleLarge),
            const SizedBox(height: 8),
            if (_assessments.isEmpty)
              const Card(
                child: Padding(
                  padding: EdgeInsets.all(16),
                  child: Text(
                    'No persisted assessments are visible to this identity.',
                  ),
                ),
              )
            else
              ..._assessments.map(
                (assessment) => Card(
                  child: ListTile(
                    selected: _selected?.runId == assessment.runId,
                    title: Text(assessment.target ?? assessment.runId),
                    subtitle: Text(
                      '${assessment.state} · cursor ${assessment.lastSequence}',
                    ),
                    trailing: const Icon(Icons.chevron_right),
                    onTap: () => _select(assessment.runId),
                  ),
                ),
              ),
            if (_selected != null) ...[
              const SizedBox(height: 18),
              _AssessmentDetail(
                assessment: _selected!,
                connectionState: _connectionState,
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ReadinessCard extends StatelessWidget {
  const _ReadinessCard({required this.readiness});
  final Readiness? readiness;

  @override
  Widget build(BuildContext context) => Card(
        child: ListTile(
          leading: Icon(
            readiness?.ready == true ? Icons.check_circle : Icons.pause_circle,
            color: readiness?.ready == true ? Colors.green : Colors.orange,
          ),
          title: const Text('Deployment readiness'),
          subtitle: Text(readiness?.status ?? 'unavailable'),
        ),
      );
}

class _AssessmentDetail extends StatelessWidget {
  const _AssessmentDetail({
    required this.assessment,
    required this.connectionState,
  });
  final Assessment assessment;
  final RealtimeConnectionState connectionState;

  @override
  Widget build(BuildContext context) => Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Expanded(
                child: Text(
                  'Live execution timeline',
                  style: Theme.of(context).textTheme.titleLarge,
                ),
              ),
              Text(connectionState.name),
            ],
          ),
          const SizedBox(height: 8),
          if (assessment.blockingReason != null)
            _Notice(message: 'Backend blocked: ${assessment.blockingReason}'),
          if (assessment.events.isEmpty)
            const Card(
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Text('No persisted events have been published.'),
              ),
            )
          else
            ...assessment.events.map(
              (event) => Card(
                child: ListTile(
                  leading: CircleAvatar(child: Text('${event.sequence}')),
                  title:
                      Text(event.summary ?? event.type ?? 'Assessment event'),
                  subtitle: Text(
                    '${event.stage ?? 'stage unavailable'} · ${event.occurredAt ?? 'time unavailable'}',
                  ),
                ),
              ),
            ),
          const SizedBox(height: 12),
          Text('Findings', style: Theme.of(context).textTheme.titleMedium),
          if (assessment.findings.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 8),
              child: Text('No findings were returned for this assessment.'),
            )
          else
            ...assessment.findings.map(
              (finding) => ListTile(
                contentPadding: EdgeInsets.zero,
                title: Text(finding.title ?? finding.summary ?? 'Finding'),
                subtitle: Text(
                  '${finding.severity ?? 'unclassified'} · ${finding.status ?? 'status unavailable'}',
                ),
              ),
            ),
        ],
      );
}

class _Notice extends StatelessWidget {
  const _Notice({required this.message});
  final String message;

  @override
  Widget build(BuildContext context) => Card(
        color: Theme.of(context).colorScheme.errorContainer,
        child: Padding(padding: const EdgeInsets.all(12), child: Text(message)),
      );
}
