def write_NSC_Report(report, scanResults):

    if not scanResults:
        print('Nessuna Vulnerabilità Rilevata')
        return

    issuesNSC = scanResults.get('issuesNSC', {})
    if issuesNSC:
        report.write('Trovate Richieste HTTP In Chiaro:\n')
        for filePath, issues in issuesNSC.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')

    kubernetesIssuesNSC = scanResults.get('kubernetesIssuesNSC', {})
    if kubernetesIssuesNSC:
        report.write('Trovati Ingress Configurati Senza TLS:\n')
        for filePath, issues in kubernetesIssuesNSC.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')