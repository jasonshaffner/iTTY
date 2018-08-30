from threading import Thread
from .iTTY import iTTY

class Mpcommand(Thread):
    """
    Subclass of Thread, used for concurrent logins across multiple devices
    """


    def __init__(self, username, password, host, command_delay, **kwargs):
        """
        Factory
        """
        Thread.__init__(self)
        self.username = username
        self.password = password
        self.host = host
        self.command_delay = command_delay
        self.alu_commands = kwargs.get('alu_commands', None)
        self.asa_commands = kwargs.get('asa_commands', None)
        self.ios_commands = kwargs.get('ios_commands', None)
        self.junos_commands = kwargs.get('junos_commands', None)
        self.xr_commands = kwargs.get('xr_commands', None)
        self.command_header = kwargs.get('_command_header', 1)
        self.pool = kwargs.get('pool', None)
        self.tty = iTTY(username=username, password=password, host=host)

    def run(self):
        """
        Starts thread, overrided Thread.run()
        """
        if self.pool:
            self.pool.acquire()
        try:
            with self.tty:
                if self.tty.os == 1:
                    self.tty.set_commands(self.alu_commands)
                elif self.tty.os == 2:
                    self.tty.set_commands(self.xr_commands)
                elif self.tty.os == 3:
                    self.tty.set_commands(self.ios_commands)
                elif self.tty.os == 4:
                    self.tty.set_commands(self.junos_commands)
                elif self.tty.os == 5:
                    self.tty.set_commands(self.asa_commands)
                else:
                    print("Could not log in to: " + self.tty.host)
                    return
                output = self.tty.runcommands(self.command_delay, command_header=self.command_header)
        except:
            print("Could not log in to: " + self.tty.host)
            if self.pool:
                self.pool.release()
            return
        self.tty.set_output(self.tty.siftoutput(self.username, self.password, self.tty.prompt))
        if self.pool:
            self.pool.release()
