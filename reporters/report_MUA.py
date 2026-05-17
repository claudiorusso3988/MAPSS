def write_MUA_Report(report, scanResults):

    if not scanResults:
        report.write('Nessuna Vulnerabilità Rilevata\n\n')
        return

    localAuthLogic = scanResults.get('localAuthLogic', {})
    if localAuthLogic:
        report.write('Rilevata Logica di Autenticazione Multipla/Locale:\n')
        for path, issues in localAuthLogic.items():
            report.write(f'File: {path}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')