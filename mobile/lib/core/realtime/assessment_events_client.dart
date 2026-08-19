import 'dart:async';
import 'dart:convert';

import 'package:web_socket_channel/web_socket_channel.dart';

import '../api/client.dart';
import '../api/models.dart';

enum RealtimeConnectionState {
  idle,
  connecting,
  live,
  reconnecting,
  closed,
  error,
}

class AssessmentEventsClient {
  AssessmentEventsClient({
    required VulnHunterApiClient api,
    required String apiBaseUrl,
    required String assessmentId,
  })  : _api = api,
        _baseUrl = Uri.parse(
          apiBaseUrl.endsWith('/') ? apiBaseUrl : '$apiBaseUrl/',
        ),
        _assessmentId = assessmentId;

  final VulnHunterApiClient _api;
  final Uri _baseUrl;
  final String _assessmentId;
  final _snapshots = StreamController<AssessmentEventsSnapshot>.broadcast();
  final _states = StreamController<RealtimeConnectionState>.broadcast();
  WebSocketChannel? _channel;
  StreamSubscription<dynamic>? _subscription;
  Timer? _reconnectTimer;
  bool _stopped = false;
  int _cursor = 0;
  int _attempt = 0;

  Stream<AssessmentEventsSnapshot> get snapshots => _snapshots.stream;
  Stream<RealtimeConnectionState> get states => _states.stream;
  int get cursor => _cursor;

  Future<void> start() async {
    if (_assessmentId.isEmpty) return;
    _stopped = false;
    _emitState(RealtimeConnectionState.connecting);
    try {
      final catchUp = await _api.getAssessmentEvents(_assessmentId, _cursor);
      _accept(catchUp);
      if (catchUp.terminal) {
        await stop();
        return;
      }
      await _connect();
    } catch (_) {
      _emitState(RealtimeConnectionState.error);
      _scheduleReconnect();
    }
  }

  Future<void> stop() async {
    _stopped = true;
    _reconnectTimer?.cancel();
    _reconnectTimer = null;
    await _subscription?.cancel();
    _subscription = null;
    await _channel?.sink.close();
    _channel = null;
    await _snapshots.close();
    await _states.close();
  }

  Future<void> _connect() async {
    if (_stopped) return;
    _emitState(
      _attempt == 0
          ? RealtimeConnectionState.connecting
          : RealtimeConnectionState.reconnecting,
    );
    final ticket = await _api.issueRealtimeTicket(_assessmentId);
    final endpoint = _baseUrl.replace(
      scheme: _baseUrl.scheme == 'https' ? 'wss' : 'ws',
      path:
          '/ws/api/v1/assessments/${Uri.encodeComponent(_assessmentId)}/events/',
      queryParameters: const {},
    );
    final channel = WebSocketChannel.connect(endpoint);
    _channel = channel;
    await channel.ready;
    channel.sink.add(
      jsonEncode(<String, dynamic>{
        'ticket': ticket.ticket,
        'after_sequence': _cursor,
      }),
    );
    _attempt = 0;
    _emitState(RealtimeConnectionState.live);
    _subscription = channel.stream.listen(
      _onMessage,
      onError: (_) {
        _emitState(RealtimeConnectionState.error);
        _scheduleReconnect();
      },
      onDone: _scheduleReconnect,
      cancelOnError: true,
    );
  }

  void _onMessage(dynamic raw) {
    try {
      final decoded = jsonDecode('$raw');
      if (decoded is! Map) return;
      final payload = decoded.map((key, value) => MapEntry('$key', value));
      if (payload['type'] != 'assessment.snapshot') return;
      final snapshot = AssessmentEventsSnapshot.fromJson(payload);
      _accept(snapshot);
      if (snapshot.terminal) {
        unawaited(stop());
      }
    } catch (_) {
      _emitState(RealtimeConnectionState.error);
    }
  }

  void _accept(AssessmentEventsSnapshot snapshot) {
    if (snapshot.lastSequence > _cursor) _cursor = snapshot.lastSequence;
    _snapshots.add(
      AssessmentEventsSnapshot(
        assessmentId: snapshot.assessmentId,
        events: snapshot.events,
        lastSequence: _cursor,
        taskState: snapshot.taskState,
        runState: snapshot.runState,
        activeSummary: snapshot.activeSummary,
        approvalState: snapshot.approvalState,
        executionState: snapshot.executionState,
        workflowState: snapshot.workflowState,
        executionEnabled: snapshot.executionEnabled,
        executionBlockingReason: snapshot.executionBlockingReason,
        readiness: snapshot.readiness,
        evaluationResult: snapshot.evaluationResult,
        updatedAt: snapshot.updatedAt,
        terminal: snapshot.terminal,
        activityTree: snapshot.activityTree,
      ),
    );
  }

  void _scheduleReconnect() {
    if (_stopped || _reconnectTimer != null) return;
    final exponent = _attempt.clamp(0, 6).toInt();
    final delay = Duration(milliseconds: 500 * (1 << exponent));
    _attempt += 1;
    _reconnectTimer = Timer(delay, () {
      _reconnectTimer = null;
      unawaited(
        _connect().catchError((_) {
          _emitState(RealtimeConnectionState.error);
          _scheduleReconnect();
        }),
      );
    });
    _emitState(RealtimeConnectionState.reconnecting);
  }

  void _emitState(RealtimeConnectionState state) {
    if (!_states.isClosed) _states.add(state);
  }
}
