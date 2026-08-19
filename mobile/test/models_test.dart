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
      'run_state': 'completed',
      'terminal': true,
    });

    expect(snapshot.assessmentId, 'assessment-1');
    expect(snapshot.lastSequence, 4);
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
