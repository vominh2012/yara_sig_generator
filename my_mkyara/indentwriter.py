try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO # python 3 compatible

class IndentationWriter(object):
    def __init__(self, indentation=0):
        self.indentation = indentation
        self.buf = StringIO()

    def indent(self):
        self.indentation += 1

    def dedent(self):
        self.indentation -= 1

    def write(self, text):
        self.buf.write(self.indentation * "\t")
        self.buf.write(text)

    def write_block(self, text):
        lines = text.split("\n")
        for line in lines:
            self.writeline(line)

    def writeline(self, text):
        self.write(text + "\n")

    def contents(self):
        return self.buf.getvalue()

    def clear(self):
        self.buf = StringIO()
