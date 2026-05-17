def write_OCC_Report(report, scanResults):

    if not scanResults:
        print('Nessuna Vulnerabilità Rilevata\n')
        return
        
    javaIssues = scanResults.get('javaIssuesOCC', {})
    if javaIssues:
        report.write('Classi/Metodi/Operazioni Sospette (Java):\n')
        for filePath, issues in javaIssues.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')

    importIssues = scanResults.get('javaImportsIssuesOCC', {})
    if importIssues:
        report.write("Utilizzo di Import e Keyword Crittografiche:\n")
        for filePath, issues in importIssues.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')

    foundedLibraries = scanResults.get('foundedLibraries', {})
    if foundedLibraries:
        report.write('Librerie Crittografiche Rilevate:\n')
        for filePath, libraries in foundedLibraries.items():
            report.write(f'File: {filePath}\n')
            for library in libraries:
                report.write(f'Libreria: {library}\n')
        report.write('\n')