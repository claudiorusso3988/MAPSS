import os

from reporters.report_IAC import write_IAC_Report
from reporters.report_PAM import write_PAM_Report
from reporters.report_UPTM import write_UPTM_Report
from reporters.report_OCC import write_OCC_Report
from reporters.report_NDE import write_NDE_Report
from reporters.report_HS import write_HS_Report
from reporters.report_NSC import write_NSC_Report
from reporters.report_UT import write_UT_Report
from reporters.report_MUA import write_MUA_Report
from reporters.report_CA import write_CA_Report

def writeReport(basePath, scanResults):

    reportPath = os.path.join(basePath, 'Report.txt')

    with open(reportPath, 'w', encoding = 'utf-8') as report:

        if 'IAC' in scanResults:
            report.write('\nInsufficient Access Control (IAC)\n\n')
            write_IAC_Report(report, scanResults['IAC'])

        if 'PAM' in scanResults:
            report.write('\nPublicly Accessible Microservices (PAM)\n\n')
            write_PAM_Report(report, scanResults['PAM'])

        if 'UPTM' in scanResults:
            report.write('\nUnnecessary Privileges To Microservices (UPTM)\n\n')
            write_UPTM_Report(report, scanResults['UPTM'])

        if 'OCC' in scanResults:
            report.write('\nOwn Crypto Code (OCC)\n\n')
            write_OCC_Report(report, scanResults['OCC'])

        if 'NDE' in scanResults:
            report.write('\nNon-encrypted Data Exposure (NDE)\n\n')
            write_NDE_Report(report, scanResults['NDE'])

        if 'HS' in scanResults:
            report.write('\nHardcoded Secrets (HS)\n\n')
            write_HS_Report(report, scanResults['HS'])

        if 'NSC' in scanResults:
            report.write('\nNon-secured Service-to-service Communications (NSC)\n\n')
            write_NSC_Report(report, scanResults['NSC'])		

        if 'UT' in scanResults:
            report.write('\nUnauthenticated Traffic (UT)\n\n')
            write_UT_Report(report, scanResults['UT'])

        if 'MUA' in scanResults:
            report.write('\nMultiple User Authentication (MUA)\n\n')
            write_MUA_Report(report, scanResults['MUA'])

        if 'CA' in scanResults:            
            report.write('\nCentralized Authorization (CA)\n\n')
            write_CA_Report(report, scanResults['CA'])

    print(f'Report Salvato In {reportPath}')