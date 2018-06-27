import simplejson
import zlib
import os
import idaapi

# IDA_TMP = "/mnt/tmpfs/ida_output"
TMP_DIR = "/mnt/tmpfs"

"""
[BASIC BLOCK TYPES]
0 normal block
1 block ends with indirect jump
2 return block
3 conditional return block
4 noreturn block
5 external noreturn block (does not belong to the function)
6 external normal block
7 block passes execution past the function end
"""


def write_data(data):
    out_path = os.path.join(TMP_DIR, idaapi.get_root_filename() + ".out")
    with open(out_path, "wb") as fd:
        fd.write(zlib.compress(data))

Wait()

def extract_cfg(address):
    func = idaapi.get_func(address)
    fc = idaapi.FlowChart(func)
    cfg = []
    for bb in fc:
        cfg.append({
            "start": bb.startEA,
            "end": bb.endEA,
            "type": bb.type,
            "successors": [s.startEA for s in bb.succs()]
        })

    return cfg
            

functions = []
for f_start in Functions():
    functions.append({
        "start": f_start,
        "end": FindFuncEnd(f_start),
        "cfg": extract_cfg(f_start),
        "code_refs": [addr for addr in CodeRefsTo(f_start, 0)],
        "data_refs": [addr for addr in DataRefsTo(f_start)]
    })


info = {
    "base": idaapi.get_imagebase(),
    "functions": functions
}

write_data(simplejson.dumps(info, indent=2))


Exit(0)
