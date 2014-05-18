# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_env(HoneyPotCommand):
    def call(self):
        """ Print the current environment variables """

        if self.env and len(self.env) > 0:
            for key, value in self.env.iteritems():
                self.writeln("%s=%s" % (key, value))

# Definition
commands['/usr/bin/env'] = command_env
