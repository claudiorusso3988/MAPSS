def write_UT_Report(report, scanResults):

    if not scanResults:
        report.write('Nessuna Vulnerabilità Rilevata')
        return
    
    javaIssues = scanResults.get('javaIssues', {})
    if javaIssues:
        report.write('Rilevate Vulnerabiità Nel Codice Java:\n')
        for filePath, issues in javaIssues.items():
            report.write(f'File: {filepath}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')
        
    propertiesIssues = scanResults.get('propertiesIssues', {})
    if propertiesIssues:
        report.write('Sicurezza/Autenticazione Disabilitate Nel File Di Configurazione:\n')
        for filePath, issues in propertiesIssues.items():
            report.write(f'File: {filepath}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')