#!/usr/bin/pyhton
import dragonflow.tests.unit.test_l2_app as l2_app
import dragonflow.tests.unit.test_app_base as app_base


class myTest(l2_app.TestL2App):
    def runTest(self):
        self.setUp()
        self.test_multicast_local_port()


test = myTest()
test.runTest()

print "Tests done"
