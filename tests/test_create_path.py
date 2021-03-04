import os
import unittest
from libs import common

class TestCreatePath(unittest.TestCase):

    def setUp(self):
        os.mkdir('/tmp/existing-folder')

    def test_create_path(self):
        # Create folder no error
        common._create_path('/tmp/test-folder')
        self.assertTrue(os.stat('/tmp/test-folder'))
        # Create folder that already exists
        common._create_path('/tmp/existing-folder')
        self.assertTrue(os.stat('/tmp/existing-folder'))
        # Create folder no permission
        with self.assertRaises(SystemExit):
            common._create_path('/test-folder')
        # Create folder wiht invalid name
        with self.assertRaises(ValueError):
            common._create_path('/tmp/\0')

    def tearDown(self):
        os.removedirs('/tmp/test-folder')
        os.removedirs('/tmp/existing-folder')


if __name__ == '__main__':
    unittest.main()
