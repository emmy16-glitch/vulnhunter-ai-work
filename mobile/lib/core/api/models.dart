typedef JsonMap = Map<String, dynamic>;

class Me {
  const Me({
    required this.id,
    required this.username,
    required this.roles,
    required this.reviewerId,
  });

  final String id;
  final String username;
  final List<String> roles;
  final String reviewerId;

  factory Me.fromJson(JsonMap json) => Me(
        id: '${json['id'] ?? ''}',
        username: '${json['username'] ?? ''}',
        roles: _stringList(json['roles']),
        reviewerId: '${json['reviewer_id'] ?? ''}',
      );
}

class Readiness {
  const Readiness({
    required this.status,
    required this.ready,
    required this.checks,
    required this.raw,
  });

  final String status;
  final bool ready;
  final JsonMap checks;
  final JsonMap raw;

  factory Readiness.fromJson(JsonMap json) => Readiness(
        status:
            '${json['status'] ?? (json['ready'] == true ? 'ready' : 'unavailable')}',
        ready: json['ready'] == true || json['status'] == 'ready',
        checks: _map(json['checks']),
        raw: json,
      );
}

class AssessmentEvent {
  const AssessmentEvent({
    required this.sequence,
    this.eventId,
    this.type,
    this.stage,
    this.occurredAt,
    this.summary,
    this.metadata,
  });

  final int sequence;
  final String? eventId;
  final String? type;
  final String? stage;
  final DateTime? occurredAt;
  final String? summary;
  final JsonMap? metadata;

  factory AssessmentEvent.fromJson(JsonMap json) => AssessmentEvent(
        sequence: _int(json['sequence']),
        eventId: _stringOrNull(json['event_id']),
        type: _stringOrNull(json['type']),
        stage: _stringOrNull(json['stage']),
        occurredAt: _date(json['occurred_at']),
        summary: _stringOrNull(json['summary'] ?? json['detail']),
        metadata: json['metadata'] is Map ? _map(json['metadata']) : null,
      );
}

class Finding {
  const Finding({
    this.id,
    this.title,
    this.severity,
    this.status,
    this.summary,
  });

  final String? id;
  final String? title;
  final String? severity;
  final String? status;
  final String? summary;

  factory Finding.fromJson(JsonMap json) => Finding(
        id: _stringOrNull(json['id']),
        title: _stringOrNull(json['title']),
        severity: _stringOrNull(json['severity']),
        status: _stringOrNull(json['status']),
        summary: _stringOrNull(json['summary']),
      );
}

class Assessment {
  const Assessment({
    required this.runId,
    required this.state,
    this.target,
    this.profile,
    this.scanner,
    this.executionState,
    this.updatedAt,
    this.terminal = false,
    this.blockingReason,
    this.events = const [],
    this.findings = const [],
    this.lastSequence = 0,
  });

  final String runId;
  final String state;
  final String? target;
  final String? profile;
  final String? scanner;
  final String? executionState;
  final DateTime? updatedAt;
  final bool terminal;
  final String? blockingReason;
  final List<AssessmentEvent> events;
  final List<Finding> findings;
  final int lastSequence;

  Assessment copyWith({
    String? state,
    bool? terminal,
    List<AssessmentEvent>? events,
    List<Finding>? findings,
    int? lastSequence,
    String? blockingReason,
  }) =>
      Assessment(
        runId: runId,
        state: state ?? this.state,
        target: target,
        profile: profile,
        scanner: scanner,
        executionState: executionState,
        updatedAt: updatedAt,
        terminal: terminal ?? this.terminal,
        blockingReason: blockingReason ?? this.blockingReason,
        events: events ?? this.events,
        findings: findings ?? this.findings,
        lastSequence: lastSequence ?? this.lastSequence,
      );

  factory Assessment.fromJson(JsonMap json) => Assessment(
        runId: '${json['run_id'] ?? ''}',
        state: '${json['state'] ?? 'unknown'}',
        target: _stringOrNull(json['target']),
        profile: _stringOrNull(json['profile']),
        scanner: _stringOrNull(json['scanner']),
        executionState: _stringOrNull(json['execution_state']),
        updatedAt: _date(json['updated_at']),
        terminal: json['terminal'] == true,
        blockingReason: _stringOrNull(json['blocking_reason']),
        events: _maps(json['events']).map(AssessmentEvent.fromJson).toList(),
        findings: _maps(json['findings']).map(Finding.fromJson).toList(),
        lastSequence: _int(json['last_sequence']),
      );
}

class AssessmentEventsSnapshot {
  const AssessmentEventsSnapshot({
    required this.assessmentId,
    required this.events,
    required this.lastSequence,
    required this.runState,
    required this.terminal,
    this.taskState,
    this.activeSummary,
    this.approvalState,
    this.executionState,
    this.workflowState,
    this.executionEnabled = false,
    this.executionBlockingReason,
    this.readiness = const {},
    this.evaluationResult,
    this.updatedAt,
    this.activityTree = const {},
  });

  final String assessmentId;
  final List<AssessmentEvent> events;
  final int lastSequence;
  final String? taskState;
  final String? runState;
  final String? activeSummary;
  final String? approvalState;
  final String? executionState;
  final String? workflowState;
  final bool executionEnabled;
  final String? executionBlockingReason;
  final JsonMap readiness;
  final String? evaluationResult;
  final DateTime? updatedAt;
  final bool terminal;
  final JsonMap activityTree;

  factory AssessmentEventsSnapshot.fromJson(JsonMap json) =>
      AssessmentEventsSnapshot(
        assessmentId: '${json['assessment_id'] ?? ''}',
        events: _maps(json['events']).map(AssessmentEvent.fromJson).toList(),
        lastSequence: _int(json['last_sequence']),
        taskState: _stringOrNull(json['task_state']),
        runState: _stringOrNull(json['run_state']),
        activeSummary: _stringOrNull(json['active_summary']),
        approvalState: _stringOrNull(json['approval_state']),
        executionState: _stringOrNull(json['execution_state']),
        workflowState: _stringOrNull(json['workflow_state']),
        executionEnabled: json['execution_enabled'] == true,
        executionBlockingReason: _stringOrNull(json['execution_blocking_reason']),
        readiness: _map(json['readiness']),
        evaluationResult: _stringOrNull(json['evaluation_result']),
        updatedAt: _date(json['updated_at']),
        terminal: json['terminal'] == true,
        activityTree: _map(json['activity_tree']),
      );
}

class RealtimeTicket {
  const RealtimeTicket({
    required this.ticket,
    required this.expiresIn,
    required this.assessmentId,
  });

  final String ticket;
  final int expiresIn;
  final String assessmentId;

  factory RealtimeTicket.fromJson(JsonMap json) => RealtimeTicket(
        ticket: '${json['ticket'] ?? ''}',
        expiresIn: _int(json['expires_in']),
        assessmentId: '${json['assessment_id'] ?? ''}',
      );
}

String? _stringOrNull(dynamic value) => value == null ? null : '$value';
int _int(dynamic value) =>
    value is num ? value.toInt() : int.tryParse('$value') ?? 0;
DateTime? _date(dynamic value) =>
    value == null ? null : DateTime.tryParse('$value')?.toLocal();
List<String> _stringList(dynamic value) => value is List
    ? value.map((item) => '$item').toList(growable: false)
    : const [];
JsonMap _map(dynamic value) => value is Map
    ? value.map((key, item) => MapEntry('$key', item))
    : <String, dynamic>{};
List<JsonMap> _maps(dynamic value) => value is List
    ? value.whereType<Map>().map(_map).toList(growable: false)
    : const [];
