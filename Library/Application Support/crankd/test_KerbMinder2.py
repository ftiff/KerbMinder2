import nose
import os

from KerbMinder2 import *
from unittest import TestCase

# set domain env -> export TEST_DOMAIN="DOMAIN.COM"

class TestDig(TestCase):
    def test_dig(self):
	try:
            domain = os.environ['TEST_DOMAIN']
        except KeyError:
            pass
        else:
            self.assertTrue(domain_dig_check(domain))

    def test_dignot(self):
        with self.assertRaises(SystemExit) as cm:
		domain_dig_check("EXAMPLE.COM")
	self.assertEqual(cm.exception.code, 0)

nose.main()
