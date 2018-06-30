import logging
import database
import os
import magic
h_magic = magic.open(magic.MAGIC_NONE)
h_magic.load()

import pefile
import subprocess
import zlib

import utils
import shutil
import re
import simplejson


EXT_UNUPXED = ".unupxed"

LOGFD = open("logs/extractors.log", "wb")

def log(msg):
    LOGFD.write(msg + "\n")


def e_magic(path, file_):
    magic_str = h_magic.file(path)
    logging.debug("e_magic: {}".format(magic_str))
    # if database.record_exists(session, database.Magic, file_):
    #     logging.debug("e_magic: record exists")
        

    entry = database.Magic(file=file_, magic_str=magic_str)
    # session.add(entry)
    # session.commit()
    return entry


COM_DESC = 14
def e_pe(path, file_):
    """
    file_id = Column(Integer, ForeignKey("file.id"))
    machine_type = Column(Boolean)
    dotnet = Column(Boolean)
    """

    # if database.record_exists(session, database.PE, file_):
    #     logging.debug("e_pe: record exists")
    #     return
        
    try:
        pe = pefile.PE(path)
    except pefile.PEFormatError as e:
        logging.debug("e_pe: {}".format(e))
        return

    data_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    is_dotnet = False
    
    if len(data_dir) >= COM_DESC+1:
        
        com_desc = data_dir[14]
        if com_desc.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR":
            # logging.error("e_pe: No COM descriptor")
            if com_desc.VirtualAddress != 0 or com_desc.Size != 0:
                logging.debug("e_pe: .NET")
                is_dotnet = True
        
    entry = database.PE(file=file_, machine_type=pe.FILE_HEADER.Machine, dotnet=is_dotnet)
    # session.add(entry)
    # session.commit()
    return entry


def e_upx(path, file_):
    # if database.record_exists(session, database.UPX, file_):
    #     logging.debug("e_upx: record exists")
    #     return

    
    magic_str = session.query(database.Magic.magic_str).filter_by(file_id=file_.id).first()[0]

    logging.debug("e_ida_cfg: {}".format(magic_str))

    entry = None
    
    if magic_str.find("UPX") != -1:
        logging.debug("e_upx: UPX found")
        decompressed = path + EXT_UNUPXED
        if not os.path.exists(decompressed):
            logging.debug("e_upx: decompressing to {}".format(decompressed))
            cmd = " ".join(["upx", "-d", "-o{}".format(decompressed), path])
            res = utils.check_output(cmd)
            success = False
            if not re.search("Unpacked 1 file", res, re.I) or not os.path.exists(decompressed):
                msg = "e_upx: Error unpacking {}".format(path)
                log(msg + "\n")
                log(res + "\n")
                
            else:
                success = True

            
            entry = database.UPX(file=file_, result=success)
            # session.add(entry)
            # session.commit()
        else:
            logging.debug("e_upx: already decompressed")

        # exit()
    return entry
    
IDA_PATH = "/home/vadim/ida-7.1/ida64"
# IDA_OUTPUT = "/mnt/tmpfs/ida_output"
# IDA_IDB = "/mnt/tmpfs/tmp.i64"
IDA_CFG_SCRIPT = "utils/extract-cfg.py"
TMP_DIR = "/mnt/tmpfs"

def e_ida_cfg(path, file_):

    """
    if database.record_exists(session, database.IDA_CFG, file_):
        logging.debug("e_ida_cfg: record exists")
        return


    upx_rec = session.query(database.UPX).filter_by(file_id=file_.id).first()
    if upx_rec:
        logging.debug("e_ida_cfg: UPXed binary")
        decompressed = path + EXT_UNUPXED
        if upx_rec.result and os.path.exists(decompressed):
            logging.debug("e_ida_cfg: using decompressed binary: {}".format(decompressed))
            path = decompressed
    """

    filename = os.path.basename(path)
    idb_path = os.path.join(TMP_DIR, filename + ".i64")
    ida_out_path = os.path.join(TMP_DIR, filename + ".out")


    logging.debug("e_ida_cfg: IDB path = {}".format(idb_path))
    logging.debug("e_ida_cfg: IDA Out path = {}".format(ida_out_path))

    script_path = os.path.abspath(IDA_CFG_SCRIPT)
    logging.debug("e_ida_cfg: IDA CFG ({})".format(script_path))
    subprocess.call([
        IDA_PATH,
        "-A", "-c",
        "-o{}".format(idb_path),
        "-S{}".format(script_path),
        path])

    entry = None
    
    if not os.path.exists(ida_out_path):
        msg = "e_ida_cfg: error processing: {}".format(path)
        logging.error(msg)
        log(msg)
    else:
        data = utils.read_file(ida_out_path)
        # print zlib.decompress(data)
        entry = database.IDA_CFG(file=file_, data=data)
        # session.add(entry)
        # session.commit()

       
    # Clean up for the next one
    utils.remove(idb_path)
    utils.remove(ida_out_path)
    # exit()
    return entry


def e_pe_features_1(path, file_):


    pe = pefile.PE(path)
    sections = []
    for section in pe.sections:
        sections.append({
            "name": utils.b64enc(utils.strip_nulls(section.Name)),
            "size": section.SizeOfRawData,
            "characteristics": section.Characteristics
        })

    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            imports.append({
                "dll": entry.dll,
                "names": [imp.name if imp.name else imp.ordinal for imp in entry.imports]
            })

    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            #print hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal
            exports.append(exp.name)


    cb_cnt = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        cb_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks - pe.OPTIONAL_HEADER.ImageBase
        while True:
            try:
                cb_addr = pe.get_dword_from_data(pe.get_data(cb_rva + 4 * cb_cnt, 4), 0)
            except pefile.PEFormatError as e:
                logging.error(str(e))
                break
            if cb_addr == 0:
                break
            cb_cnt += 1


    named_resources = []
    
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):

        for rsrc in pe.DIRECTORY_ENTRY_RESOURCE.entries:

            for r in rsrc.directory.entries:
                if r.name:
                    named_resources.append(r.name.__str__())

        # logging.debug("rsrc: {} - {}".format(n_rsrc, resources))
        
    data = {
        "file_header.characteristics": pe.FILE_HEADER.Characteristics,
        "optional_header.subsystem": pe.OPTIONAL_HEADER.Subsystem,
        
        "sections": sections,

        "imports": imports,
        "exports": exports,
        "n_tls_callbacks": cb_cnt,
        "named_resources": named_resources
    }

    # print simplejson.dumps(data, indent=2)
    data = zlib.compress(simplejson.dumps(data))

    return database.PE_Features_1(file=file_, data=data)


# DON't FORGET TO ADD AN ENTRY TO THE TABLES DICT BELOW!
ALL = {
    "magic": e_magic,
    "pe": e_pe,
    "upx": e_upx,
    "ida_cfg": e_ida_cfg,
    "pe_features_1": e_pe_features_1
}


TABLES = {
    "magic": database.Magic,
    "pe": database.PE,
    "upx": database.UPX,
    "ida_cfg": database.IDA_CFG,
    "pe_features_1": database.PE_Features_1

}
