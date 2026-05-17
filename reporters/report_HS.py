def write_HS_Report(report, scanResults):

    if not scanResults:
        print('Nessuna Vulnerabilità Rilevata')
        return
    
    issuesHS = scanResults.get('issuesHS', {})
    if issuesHS:
        report.write('Hardcoded Secrets Trovati Nei File Di Codice/Configurazione:\n')
        for filePath, issues in issuesHS.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')
        
    infrastructuralIssuesHS = scanResults.get('infrastructuralIssuesHS', {})
    if infrastructuralIssuesHS:
        report.write('Hardcoded Secrets Trovati Nei Manifesti YAML:\n')
        for filePath, issues in infrastructuralIssuesHS.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')