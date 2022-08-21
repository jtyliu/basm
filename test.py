from src.section import Wasm
import sys

if __name__ == '__main__':
    if len(sys.argv) == 2:
        f = open(sys.argv[1], 'rb')
        w = Wasm(f)
        # print(w.sections.customs)
    else:
        print("python", sys.argv[0], "[file]")