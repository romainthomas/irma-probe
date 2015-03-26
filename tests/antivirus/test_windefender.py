import logging
import unittest

from tests.antivirus.common import GenericEicar
from modules.antivirus.windefend.windefend import WinDefender


# ============
#  Test Cases
# ============

class WinDefenderEicar(GenericEicar, unittest.TestCase):

    expected_results = {
        'eicar-passwd.zip': None,
        'eicar.arj': None,
        'eicar.cab': None,
        'eicar.com.pgp': None,
        'eicar.com.txt': ('Virus:DOS/EICAR_Test_File', None),
        'eicar.lha': None,
        'eicar.lzh': None,
        'eicar.msc': None,
        'eicar.plain': ('Virus:DOS/EICAR_Test_File', None),
        'eicar.rar': None,
        'eicar.tar': None,
        'eicar.uue': None,
        'eicar.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicarhqx_binhex.bin': None,
        'eicar_arj.bin': None,
        'eicar_cab.bin': None,
        'eicar_gz.bin': None,
        'eicar_lha.bin': None,
        'eicar_lzh.bin': None,
        'eicar_mime.bin': None,
        'eicar_msc.bin': None,
        'eicar_niveau1.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau10.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau11.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau12.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau13.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau14.bin': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau14.jpg': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau2.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau3.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau30.bin': None,
        'eicar_niveau30.rar': None,
        'eicar_niveau4.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau5.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau6.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau7.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau8.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_niveau9.zip': ('Virus:DOS/EICAR_Test_File', None),
        'eicar_rar.bin': None,
        'eicar_tar.bin': None,
        'eicar_uu.bin': None,
    }

    antivirus_class = WinDefender


if __name__ == '__main__':
    unittest.main()
