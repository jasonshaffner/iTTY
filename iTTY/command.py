import re


class Command(object):
    def __init__(self, body, **kwargs):
        self.body = body
        self.insertion_points = kwargs.get('insertion_points', None)
        self.regex = kwargs.get('regex', None)
        self.command_delay = kwargs.get('command_delay', None)

class Command_parser():
    @staticmethod
    def generate_commands(command, input):
        commands = []
        if command.regex:
            for entry in input:
                for line in entry.split():
                    if re.search(command.regex, line):
                        commands.append(Command_parser.process_command(command, line=line))
        else:
            commands.append(Command_parser.process_command(command))
        return commands

    @staticmethod
    def process_command(command, line=""):
        if not command.insertion_points:
            built = ''
            for piece in command.body:
                built += piece
            return built
        i = 1
        new_command = command.body[:]
        for point in command.insertion_points:
            insertion = i * 2 - 1
            new_command.insert(insertion, line.split()[point])
        newCommand = Command(new_command)
        return Command_parser.process_command(newCommand)
