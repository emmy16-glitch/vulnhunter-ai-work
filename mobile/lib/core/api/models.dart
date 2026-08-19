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

class MobileGraphProvenance {
  const MobileGraphProvenance({required this.raw});

  final JsonMap raw;

  String? get sourcePath => _stringOrNull(raw['source_path']);
  int? get lineStart => raw['line_start'] is num ? (raw['line_start'] as num).toInt() : null;
  int? get lineEnd => raw['line_end'] is num ? (raw['line_end'] as num).toInt() : null;

  factory MobileGraphProvenance.fromJson(JsonMap json) =>
      MobileGraphProvenance(raw: json);
}

class MobileAttackGraphNode {
  const MobileAttackGraphNode({required this.raw});

  final JsonMap raw;

  String get nodeId => '${raw['node_id'] ?? ''}';
  String get nodeType => '${raw['node_type'] ?? ''}';
  String get label => '${raw['label'] ?? ''}';
  String? get state => _stringOrNull(raw['state']);
  List<MobileGraphProvenance> get provenance =>
      _maps(raw['provenance']).map(MobileGraphProvenance.fromJson).toList();

  factory MobileAttackGraphNode.fromJson(JsonMap json) =>
      MobileAttackGraphNode(raw: json);
}

class MobileAttackGraphEdge {
  const MobileAttackGraphEdge({required this.raw});

  final JsonMap raw;

  String get edgeId => '${raw['edge_id'] ?? ''}';
  String get sourceNodeId => '${raw['source_node_id'] ?? ''}';
  String get targetNodeId => '${raw['target_node_id'] ?? ''}';
  String get relation => '${raw['relation'] ?? ''}';
  String? get state => _stringOrNull(raw['state']);
  List<MobileGraphProvenance> get provenance =>
      _maps(raw['provenance']).map(MobileGraphProvenance.fromJson).toList();

  factory MobileAttackGraphEdge.fromJson(JsonMap json) =>
      MobileAttackGraphEdge(raw: json);
}

class MobileAttackGraph {
  const MobileAttackGraph({
    required this.graphId,
    required this.nodes,
    required this.edges,
    required this.coverage,
    required this.raw,
  });

  final String graphId;
  final List<MobileAttackGraphNode> nodes;
  final List<MobileAttackGraphEdge> edges;
  final JsonMap coverage;
  final JsonMap raw;

  factory MobileAttackGraph.fromJson(JsonMap json) => MobileAttackGraph(
        graphId: '${json['graph_id'] ?? ''}',
        nodes: _maps(json['nodes']).map(MobileAttackGraphNode.fromJson).toList(),
        edges: _maps(json['edges']).map(MobileAttackGraphEdge.fromJson).toList(),
        coverage: _map(json['coverage']),
        raw: json,
      );
}

class MobileSourceHuntSeed {
  const MobileSourceHuntSeed({required this.raw});

  final JsonMap raw;

  String get seedId => '${raw['seed_id'] ?? ''}';
  String get title => '${raw['title'] ?? ''}';
  String get seedType => '${raw['seed_type'] ?? ''}';
  String? get sourceIntelligenceRecordId =>
      _stringOrNull(raw['source_intelligence_record_id']);

  factory MobileSourceHuntSeed.fromJson(JsonMap json) =>
      MobileSourceHuntSeed(raw: json);
}

class MobileSourceHuntResult {
  const MobileSourceHuntResult({
    required this.seed,
    required this.state,
    required this.summary,
    required this.raw,
  });

  final MobileSourceHuntSeed? seed;
  final String state;
  final String summary;
  final JsonMap raw;

  bool get boundedNegative => raw['bounded_negative'] == true;
  bool get verifiedFinding => raw['verified_finding'] == true;

  factory MobileSourceHuntResult.fromJson(JsonMap json) =>
      MobileSourceHuntResult(
        seed: json['seed'] is Map
            ? MobileSourceHuntSeed.fromJson(_map(json['seed']))
            : null,
        state: '${json['state'] ?? 'inconclusive'}',
        summary: '${json['summary'] ?? ''}',
        raw: json,
      );
}

class MobileSourceHuntReport {
  const MobileSourceHuntReport({
    required this.reportId,
    required this.seedsExamined,
    required this.results,
    required this.graph,
    required this.raw,
  });

  final String reportId;
  final int seedsExamined;
  final List<MobileSourceHuntResult> results;
  final MobileAttackGraph? graph;
  final JsonMap raw;

  int get verifiedFindingCount => _int(raw['verified_finding_count']);
  int get inconclusiveCount => _int(raw['inconclusive_count']);
  int get evidenceRequiredCount => _int(raw['evidence_required_count']);

  factory MobileSourceHuntReport.fromJson(JsonMap json) =>
      MobileSourceHuntReport(
        reportId: '${json['report_id'] ?? ''}',
        seedsExamined: _int(json['seeds_examined']),
        results: _maps(json['results']).map(MobileSourceHuntResult.fromJson).toList(),
        graph: json['graph'] is Map
            ? MobileAttackGraph.fromJson(_map(json['graph']))
            : null,
        raw: json,
      );
}

class MobileSourceHuntProjection {
  const MobileSourceHuntProjection({
    required this.state,
    required this.available,
    required this.reportReady,
    this.report,
    this.graph,
    this.selectedSeedId,
    this.error,
    required this.raw,
  });

  final String state;
  final bool available;
  final bool reportReady;
  final MobileSourceHuntReport? report;
  final MobileAttackGraph? graph;
  final String? selectedSeedId;
  final String? error;
  final JsonMap raw;

  factory MobileSourceHuntProjection.fromJson(JsonMap json) {
    final reportJson = json['report'] is Map ? _map(json['report']) : null;
    final graphJson = json['graph'] is Map ? _map(json['graph']) : null;
    return MobileSourceHuntProjection(
      state: '${json['state'] ?? 'not_started'}',
      available: json['available'] == true,
      reportReady: json['report_ready'] == true,
      report: reportJson == null ? null : MobileSourceHuntReport.fromJson(reportJson),
      graph: graphJson == null ? null : MobileAttackGraph.fromJson(graphJson),
      selectedSeedId: _stringOrNull(json['selected_seed_id']),
      error: _stringOrNull(json['error']),
      raw: json,
    );
  }
}

class MobileIntelligence {
  const MobileIntelligence({
    required this.observations,
    required this.verifiedConfigurations,
    required this.verifiedFindings,
    required this.candidates,
    required this.operationalIssues,
    required this.toolExecutions,
    required this.hypotheses,
    required this.endpointReferences,
    required this.transportCorrelations,
    required this.exportedComponentSurfaces,
    required this.boundedNegativeClaims,
    required this.remediationRecommendations,
    required this.coverage,
    required this.raw,
  });

  final List<JsonMap> observations;
  final List<JsonMap> verifiedConfigurations;
  final List<JsonMap> verifiedFindings;
  final List<JsonMap> candidates;
  final List<JsonMap> operationalIssues;
  final List<JsonMap> toolExecutions;
  final List<JsonMap> hypotheses;
  final List<JsonMap> endpointReferences;
  final List<JsonMap> transportCorrelations;
  final List<JsonMap> exportedComponentSurfaces;
  final List<String> boundedNegativeClaims;
  final List<String> remediationRecommendations;
  final JsonMap coverage;
  final JsonMap raw;

  factory MobileIntelligence.fromJson(JsonMap json) => MobileIntelligence(
        observations: _maps(json['observations']),
        verifiedConfigurations: _maps(json['verified_configurations']),
        verifiedFindings: _maps(json['verified_findings']),
        candidates: _maps(json['candidates']),
        operationalIssues: _maps(json['operational_issues']),
        toolExecutions: _maps(json['tool_executions']),
        hypotheses: _maps(json['hypotheses']),
        endpointReferences: _maps(json['endpoint_references']),
        transportCorrelations: _maps(json['transport_correlations']),
        exportedComponentSurfaces: _maps(json['exported_component_surfaces']),
        boundedNegativeClaims: _strings(json['bounded_negative_claims']),
        remediationRecommendations: _strings(json['remediation_recommendations']),
        coverage: _map(json['coverage']),
        raw: json,
      );
}

class BrowserSession {
  const BrowserSession({required this.raw});

  final JsonMap raw;

  String get sessionId => '${raw['session_id'] ?? ''}';
  String get targetUrl => '${raw['target_url'] ?? ''}';
  String get runtime => '${raw['runtime'] ?? ''}';
  String get state => '${raw['state'] ?? 'queued'}';
  String? get currentUrl => _stringOrNull(raw['current_url']);
  JsonMap get capabilities => _map(raw['capabilities']);

  factory BrowserSession.fromJson(JsonMap json) => BrowserSession(raw: json);
}

class BrowserActionReceipt {
  const BrowserActionReceipt({required this.raw});

  final JsonMap raw;

  String get actionType => '${raw['action_type'] ?? ''}';
  String get status => '${raw['status'] ?? ''}';
  String? get currentUrl => _stringOrNull(raw['current_url']);
  JsonMap get resultSummary => _map(raw['result_summary']);
  List<String> get evidenceIds => _stringList(raw['evidence_ids']);

  factory BrowserActionReceipt.fromJson(JsonMap json) =>
      BrowserActionReceipt(raw: json);
}

class BrowserNetworkObservation {
  const BrowserNetworkObservation({required this.raw});

  final JsonMap raw;

  String get method => '${raw['method'] ?? ''}';
  String get host => '${raw['host'] ?? ''}';
  String get path => '${raw['path'] ?? ''}';
  int? get statusCode => raw['status_code'] is num
      ? (raw['status_code'] as num).toInt()
      : null;

  factory BrowserNetworkObservation.fromJson(JsonMap json) =>
      BrowserNetworkObservation(raw: json);
}

class BrowserConsoleObservation {
  const BrowserConsoleObservation({required this.raw});

  final JsonMap raw;

  String get level => '${raw['level'] ?? 'log'}';
  String get message => '${raw['message'] ?? ''}';

  factory BrowserConsoleObservation.fromJson(JsonMap json) =>
      BrowserConsoleObservation(raw: json);
}

class BrowserScreenshotArtifact {
  const BrowserScreenshotArtifact({required this.raw});

  final JsonMap raw;

  String get evidenceId => '${raw['evidence_id'] ?? ''}';
  String get relativePath => '${raw['relative_path'] ?? ''}';
  String get sha256 => '${raw['sha256'] ?? ''}';
  int get sizeBytes => _int(raw['size_bytes']);

  factory BrowserScreenshotArtifact.fromJson(JsonMap json) =>
      BrowserScreenshotArtifact(raw: json);
}

class BrowserIntelligenceReport {
  const BrowserIntelligenceReport({required this.raw});

  final JsonMap raw;

  String get reportId => '${raw['report_id'] ?? ''}';
  String get runtime => '${raw['runtime'] ?? ''}';
  String? get currentUrl => _stringOrNull(raw['current_url']);
  List<BrowserActionReceipt> get actionReceipts =>
      _maps(raw['action_receipts']).map(BrowserActionReceipt.fromJson).toList();
  List<BrowserNetworkObservation> get networkObservations => _maps(
        raw['network_observations'],
      ).map(BrowserNetworkObservation.fromJson).toList();
  List<BrowserConsoleObservation> get consoleObservations => _maps(
        raw['console_observations'],
      ).map(BrowserConsoleObservation.fromJson).toList();
  List<BrowserScreenshotArtifact> get screenshots => _maps(
        raw['screenshots'],
      ).map(BrowserScreenshotArtifact.fromJson).toList();
  List<String> get endpointPaths => _stringList(raw['endpoint_paths']);

  factory BrowserIntelligenceReport.fromJson(JsonMap json) =>
      BrowserIntelligenceReport(raw: json);
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
    this.mobileIntelligence,
    this.sourceHunt,
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
  final MobileIntelligence? mobileIntelligence;
  final MobileSourceHuntProjection? sourceHunt;
  final int lastSequence;

  Assessment copyWith({
    String? state,
    bool? terminal,
    List<AssessmentEvent>? events,
    List<Finding>? findings,
    MobileIntelligence? mobileIntelligence,
    MobileSourceHuntProjection? sourceHunt,
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
        mobileIntelligence: mobileIntelligence ?? this.mobileIntelligence,
        sourceHunt: sourceHunt ?? this.sourceHunt,
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
        mobileIntelligence: json['mobile_intelligence'] is Map
            ? MobileIntelligence.fromJson(_map(json['mobile_intelligence']))
            : null,
        sourceHunt: json['source_hunt'] is Map
            ? MobileSourceHuntProjection.fromJson(_map(json['source_hunt']))
            : null,
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
    this.mobileIntelligence,
    this.sourceHunt,
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
  final MobileIntelligence? mobileIntelligence;
  final MobileSourceHuntProjection? sourceHunt;

  factory AssessmentEventsSnapshot.fromJson
(JsonMap json) =>
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
        mobileIntelligence: json['mobile_intelligence'] is Map
            ? MobileIntelligence.fromJson(_map(json['mobile_intelligence']))
            : null,
        sourceHunt: json['source_hunt'] is Map
            ? MobileSourceHuntProjection.fromJson(_map(json['source_hunt']))
            : null,
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
List<String> _strings(Object? value) {
  if (value is! List) return const <String>[];
  return value.whereType<String>().toList(growable: false);
}

List<JsonMap> _maps(Object? value) {
=> value is List
    ? value.whereType<Map>().map(_map).toList(growable: false)
    : const [];
