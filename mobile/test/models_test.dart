import 'package:flutter_test/flutter_test.dart';

import 'package:vulnhunter_mobile/core/api/models.dart';

void main() {
  test('parses persisted assessment event snapshots and cursor state', () {
    final snapshot = AssessmentEventsSnapshot.fromJson({
      'assessment_id': 'assessment-1',
      'events': [
        {
          'sequence': 4,
          'event_id': 'event-4',
          'type': 'tool.completed',
          'stage': 'verification',
          'occurred_at': '2026-08-19T03:00:00Z',
          'summary': 'Tool completed',
          'metadata': {'tool': 'nuclei'},
        },
      ],
      'last_sequence': 4,
      'task_state': 'completed',
      'run_state': 'completed',
      'active_summary': 'The assessment completed.',
      'approval_state': 'approved',
      'execution_state': 'completed',
      'workflow_state': 'completed',
      'execution_enabled': true,
      'execution_blocking_reason': null,
      'readiness': {'verified': true},
      'evaluation_result': 'completed',
      'updated_at': '2026-08-19T03:00:02Z',
      'activity_tree': {'status': 'completed', 'nodes': []},
      'terminal': true,
    });

    expect(snapshot.assessmentId, 'assessment-1');
    expect(snapshot.lastSequence, 4);
    expect(snapshot.taskState, 'completed');
    expect(snapshot.activeSummary, 'The assessment completed.');
    expect(snapshot.approvalState, 'approved');
    expect(snapshot.executionState, 'completed');
    expect(snapshot.executionEnabled, isTrue);
    expect(snapshot.readiness['verified'], isTrue);
    expect(snapshot.activityTree['status'], 'completed');
    expect(snapshot.terminal, isTrue);
    expect(snapshot.events.single.type, 'tool.completed');
    expect(snapshot.events.single.metadata?['tool'], 'nuclei');
  });

  test('does not turn absent findings into fabricated findings', () {
    final assessment = Assessment.fromJson({
      'run_id': 'assessment-2',
      'state': 'readiness_blocked',
      'findings': [],
      'events': [],
    });

    expect(assessment.findings, isEmpty);
    expect(assessment.events, isEmpty);
    expect(assessment.terminal, isFalse);
  });
}
