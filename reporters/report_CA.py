def write_CA_Report(report, scanResults):
    
    if not scanResults:
        report.write('Nessuna Vulnerabilità Rilevata\n\n')
        return

    centralizedAuthLogic = scanResults.get('centralizedAuthLogic', {})
    if centralizedAuthLogic:
        report.write('Rilevata Autorizzazione Centralizzata:\n')
        for path, issues in centralizedAuthLogic.items():
            report.write(f'File: {path}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')
        
    report.write("-" * 50 + "\n")