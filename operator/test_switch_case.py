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


if __name__ == '__main__':
    unittest.main()
