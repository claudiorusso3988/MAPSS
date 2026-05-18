def write_IAC_Report(report, scanResults):

    if not scanResults:
        report.write('Nessuna Vulnerabilità Rilevata')
        return
    
    javaIssues = scanResults.get('javaIssues', {})
    if javaIssues:
        report.write('Rilevati Endpoint Privi Di Controllo Degli Accessi:\n')
        for filePath, issues in javaIssues.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')
        