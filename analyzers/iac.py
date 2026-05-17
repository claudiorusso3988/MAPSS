import os
import re

# Java Spring
def checkJava_IAC(filePath):

    findings = set()
    annotations = ['@PreAuthorize', '@PostAuthorize', '@Secured', '@RolesAllowed']
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            if '@RestController' in content or '@Controller' in content:
                mappings = re.findall(r'@(Get|Post|Put|Delete)Mapping\s*\([^)]*\)', content)
                if len(mappings) > 0:
                    hasAnnotation = any(annotation in content for annotation in annotations)
                    if not hasAnnotation:
                        findings.add('Rilevati Endpoint Esposti Senza Annotazioni Di Controllo Degli Accessi (Es. @PreAuthorize)')
    except Exception:
        pass
        
    return list(findings)
    
def scanProject_IAC(basePath):

    results = {
        'javaIssues': {}
    }
    
    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)
            if file.endswith('.java'):
                issues = checkJava_IAC(filePath)
                if len(issues) > 0:
                    results['javaIssues'][filePath] = issues
                    
    return results
                    