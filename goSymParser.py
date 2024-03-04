import idc
import idautils

class pcHeader_parse:
    def __init__(self):
        self.pcheader = None
        self.magic = None
        self.ptrSize = None
        self.nfunc = None
        self.textStart = None
        self.funcnameOffset = None
        self.pclnOffset = None

    def pcHeader_parse(self):
        for segment in idautils.Segments():
            if idc.get_segm_name(segment) == ".gopclntab":
                self.pcheader =idc.get_segm_start(segment)
            print(idc.get_segm_name(segment))
        if self.pcheader == None:
            self.pcheader = 0x14035C020
        self.magic = idc.get_wide_dword(self.pcheader)
        # 4 or 8
        self.ptrSize = idc.get_wide_byte( self.pcheader + 0x07 )
        self.nfunc = idc.get_wide_dword( self.pcheader + 0x08 )

        if self.ptrSize == 8:
            self.textStart = idc.get_qword(self.pcheader + 0x18)
            self.funcnameOffset = idc.get_qword(self.pcheader + 0X20)
            self.pclnOffset = idc.get_qword(self.pcheader + 0x40)
        else:
            self.textStart = idc.get_wide_dword(self.pcheader + 0x10)
            self.funcnameOffset = idc.get_wide_dword(self.pcheader + 0X14)
            self.pclnOffset = idc.get_wide_dword(self.pcheader + 0x24)  


class pclntab_parse:
    def __init__(self,pcHeader:pcHeader_parse):
        self.pcHeader = pcHeader
        self.funcnametab = None
        self.pclntab = None
        self.syminfo = {}

    def relaxName(self,name):
        name = str(name, encoding = "utf-8")
        name = name.replace('.', '_').replace("<-", '_chan_left_').replace('*', '_ptr_').replace('-', '_').replace(';','').replace('"', '').replace('\\', '')
        name = name.replace('(', '').replace(')', '').replace('/', '_').replace(' ', '_').replace(',', 'comma').replace('{','').replace('}', '').replace('[', '').replace(']', '')
        return name

    def pclntab_parse(self) :
        self.pclntab = self.pcHeader.pclnOffset + self.pcHeader.pcheader
        self.funcnametab = self.pcHeader.funcnameOffset + self.pcHeader.pcheader

        for index in range(self.pcHeader.nfunc):
            entry = idc.get_wide_dword( self.pclntab + (index*2*4) ) + self.pcHeader.textStart
            _func = idc.get_wide_dword( self.pclntab + ((index*2+1)*4) ) + self.pclntab
            name = idc.get_strlit_contents(self.funcnametab + idc.get_wide_dword(_func+4))
            if name==None:
                print(str(entry) + "!!" + str(_func))
                continue
            self.syminfo[entry]=self.relaxName(name)
            print("name:{} entry:{}".format(name,entry))

    def rename(self):
        for entry,name in self.syminfo.items():
            idc.set_name(entry,name,idc.SN_NOWARN)


pcHeader = pcHeader_parse()
pcHeader.pcHeader_parse()
pclntab = pclntab_parse(pcHeader)
pclntab.pclntab_parse()
pclntab.rename()


