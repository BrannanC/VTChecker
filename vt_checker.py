from get_input_args import get_input_args
from keys import keys
from vt_parser import VT_Hashes, VT_URL, VT_IPv4


class VTChecker:
    def __init__(self, input_args, keys):
        self.keys = keys
        self.filename = input_args.filename
        self.input_args = input_args
        self.VT_Objects = []

    def drive(self):
        self.VT_Objects.append(VT_URL(self.filename, self.keys))
        self.VT_Objects.append(VT_Hashes(self.filename, self.keys))
        self.VT_Objects.append(VT_IPv4(self.filename, self.keys))

        for vts in self.VT_Objects:
            if not self.input_args.silent:
                vts.pprint(self.input_args.verbose)
            if self.input_args.output_file:
                vts.save_out(self.input_args.o, self.input_args.verbose)
            vts.post_process()


class InfGen:
    def __init__(self, arr):
        self.arr = arr
        self.i = 0

    def __next__(self):
        el = self.arr[self.i % len(self.arr)]
        self.i += 1
        return el


if __name__ == '__main__':
    keys = InfGen(keys)
    input_args = get_input_args()
    vt_checker = VTChecker(input_args, keys)
    vt_checker.drive()
