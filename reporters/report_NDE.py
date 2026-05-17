def write_NDE_Report(report, scanResults):
    
    if not scanResults:
        report.write('Nessuna Vulnerabilità NDE Rilevata\n\n')
        return


    plainTextData = scanResults.get('plainTextData', {})
    if plainTextData:
        report.write('Potenziale Esposizione Di Dati Sensibili in Chiaro:\n')
        for filePath, issues in plainTextData.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Evidenza: {issue}\n')
        report.write('\n')
        