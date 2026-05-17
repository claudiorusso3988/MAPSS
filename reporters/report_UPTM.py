def write_UPTM_Report(report, scanResults):
    
    if not scanResults:
        report.write('Nessuna Vulnerabilità UPTM Rilevata\n\n')
        return

    dockerIssues = scanResults.get('dockerIssues', {})
    if dockerIssues:
        report.write('Privilegi Eccessivi nei Container (Dockerfile):\n')
        for path, issues in dockerIssues.items():
            report.write(f'File: {path}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')

    kubernetesIssues = scanResults.get('kubernetesIssues', {})
    if kubernetesIssues:
        report.write('Configurazioni SecurityContext Insicure (Kubernetes):\n')
        for path, issues in kubernetesIssues.items():
            report.write(f'File: {path}\n')
            for issue in issues:
                report.write(f'{issue}\n')
        report.write('\n')