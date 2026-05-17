from reporter import writeReport

from analyzers.iac import scanProject_IAC
from analyzers.pam import scanProject_PAM
from analyzers.uptm import scanProject_UPTM
from analyzers.occ import scanProject_OCC
from analyzers.nde import scanProject_NDE
from analyzers.hs import scanProject_HS
from analyzers.nsc import scanProject_NSC
from analyzers.ut import scanProject_UT
from analyzers.mua import scanProject_MUA
from analyzers.ca import scanProject_CA

def scanProject(basePath):

    scanResults = {}
    
    scanResults['IAC'] = scanProject_IAC(basePath)
    scanResults['PAM'] = scanProject_PAM(basePath)
    scanResults['UPTM'] = scanProject_UPTM(basePath)
    scanResults['OCC'] = scanProject_OCC(basePath)
    scanResults['NDE'] = scanProject_NDE(basePath)
    scanResults['HS'] = scanProject_HS(basePath)
    scanResults['NSC'] = scanProject_NSC(basePath)
    scanResults['UT'] = scanProject_UT(basePath)
    scanResults['MUA'] = scanProject_MUA(basePath)
    scanResults['CA'] = scanProject_CA(basePath)
    
    writeReport(basePath, scanResults)