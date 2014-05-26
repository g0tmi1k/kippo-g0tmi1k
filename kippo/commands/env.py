# Copyright (c) 2013 Bas Stottelaar <basstottelaar [AT] gmail [DOT] com>

from kippo.core.honeypot import HoneyPotCommand

commands = {}

class command_env(HoneyPotCommand):
    def call(self):
        """ Print the current environment variables """

        self.defaultenv = {
            'TERM':            'xterm-256color',
            'SHELL':           '/bin/bash',
            'SSH_CLIENT':      '%s %s 22' % (self.honeypot.clientIP, self.honeypot.realClientPort),
            'SSH_TTY':         '/dev/pts/0',
            'USER':            self.honeypot.user.username,
            'MAIL':            '/var/mail/%s' % self.honeypot.user.username,
            'PATH':            '/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin',
            'PWD':             self.honeypot.cwd,
            'LANG':            'en_US.UTF-8',
            'SHLVL':           '1',
            'HOME':            '/root',
            'LANGUAGE':        'en_GB:en',
            'LOGNAME':         self.honeypot.user.username,
            'SSH_CONNECTION':  '%s %s %s 22' % (self.honeypot.clientIP, self.honeypot.realClientPort, self.honeypot.kippoIP),
            '_':               '/usr/bin/env',
        }

        if self.env and len(self.env) > 0:
            self.defaultenv.update(self.env)

        for key, value in self.defaultenv.iteritems():
            self.writeln("%s=%s" % (key, value))

# Definition
commands['/usr/bin/env'] = command_env
