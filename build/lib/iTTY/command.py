import re


class Command(object):
    def __init__(self, body, **kwargs):
        self.body = body
        self.insertionpoints = kwargs.get('insertionpoints', None)
        self.regex = kwargs.get('regex', None)
        self.commanddelay = kwargs.get('commanddelay', None)

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
        if not command.insertionpoints:
            built = ''
            for piece in command.body:
                built += piece
            return built
        i = 1
        newcommand = command.body[:]
        for point in command.insertionpoints:
            insertion = i * 2 - 1
            newcommand.insert(insertion, line.split()[point])
        newCommand = Command(newcommand)
        return Command_parser.process_command(newCommand)
