def write_PAM_Report(report, scanResults):

    if not scanResults:
        print('Nessuna Vulnerabilità Rilevata')
        return

    kubernetesIssuesServicePAM = scanResults.get('kubernetesIssuesServicePAM', {})
    if kubernetesIssuesServicePAM:
        report.write('Rilevati Servizi K8s Esposti Direttamente:\n')
        for filePath, issues in kubernetesIssuesServicePAM.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')

    dockerIssuesPAM = scanResults.get('dockerIssuesPAM', {})
    if dockerIssuesPAM:
        report.write('Rilevate Porte Aperte Sulla Macchina Host:\n')
        for filePath, issues in kubernetesIssuesServicePAM.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')

    javaIssuesPAM = scanResults.get('javaIssuesPAM', {})
    if javaIssuesPAM:
        report.write('Rileveta annotazione @CrossOrigin:\n')
        for filePath, issues in javaIssuesPAM.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')

    frontendIssuesPAM = scanResults.get('frontendIssuesPAM', {})
    if frontendIssuesPAM:
        report.write('Rilevati URL Hardcoded Verso Porte Specifiche:\n')
        for filePath, issues in frontendIssuesPAM.items():
            report.write(f'File: {filePath}\n')
            for issue in issues:
                report.write(f'Problema: {issue}\n')
        report.write('\n')
        
    apiGatewayHints = scanResults.get('apiGatewayHints', {})
    if apiGatewayHints:
        report.write('Rilevati Indizi API Gateway:\n')
        for hint in apiGatewayHints:
            report.write(f'Indizio: {hint}\n')
    else:
        report.write('Non Rilevati Indizi Di API Gateway: ')
        report.write('Possibile Anti-Pattern PAM Presente.')