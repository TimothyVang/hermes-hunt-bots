"""switch_case readiness after a reseed."""
import unittest

import switch_case


class ReadyTest(unittest.TestCase):
    def test_after_a_reseed_only_the_new_instance_counts_as_ready(self):
        new = 'hermes-framework-network-analyst-case-lab-med-001-6873a567'
        served = {'ready': True, 'event_count': 20931}
        # The previous boot's lab server comes back first and reports ready for the old guest software.
        self.assertFalse(switch_case.ready({**served, 'instance_id': 'hermes-framework-network-analyst-case-lab-med-001-f9fcac4c'}, new))
        self.assertFalse(switch_case.ready({**served, 'instance_id': None}, new))
        self.assertTrue(switch_case.ready({**served, 'instance_id': new}, new))
        # Starting the current case without a reseed needs no particular instance.
        self.assertTrue(switch_case.ready(served))
        self.assertFalse(switch_case.ready({'ready': True, 'event_count': 0}))

    def test_a_new_instance_still_serving_the_previous_case_is_not_ready(self):
        new = 'hermes-framework-network-analyst-case-team-med-004-6c266507'
        # Seen live: the guest reported the new instance ID while still serving the previous case.
        stale = {'ready': True, 'event_count': 20228, 'instance_id': new, 'case_id': 'team-med-003'}
        self.assertFalse(switch_case.ready(stale, new, 'team-med-004'))
        self.assertTrue(switch_case.ready({**stale, 'event_count': 18502, 'case_id': 'team-med-004'}, new, 'team-med-004'))


if __name__ == '__main__':
    unittest.main()
