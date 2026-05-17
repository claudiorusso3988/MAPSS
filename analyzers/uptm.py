import os
import re
import yaml

def checkDockerUPTM(filePath):

    findings = set()
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            if re.search(r'^\s*USER\s+root', content, re.IGNORECASE | re.MULTILINE):
                findings.add('Container Esplicitamente Configurato Per Girare Come Root.')
            elif not re.search(r'^\s*USER\s+(?!root)', content, re.IGNORECASE | re.MULTILINE):
                findings.add('Direttiva USER Non Trovata: Il Container Gira Come Root Di Default')
    except Exception:
        pass
        
    return list(findings)
    
def checkKubernetesUPTM(filePath):

    findings = set()
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read().lower()
            if re.search(r'privileged:\s*true', content):
                findings.add("Rilevato 'privileged: true' -> Accesso Completo Alla Macchina Host")
            if re.search(r'allowprivilegeescalation:\s*true', content):
                findings.add("Rilevato 'allowPrivilegeEscalation: true' -> I Processi Possono Acquisire Più Privilegi")
            if re.search(r'runasuser:\s*0', content):
                findings.add("Rilevato 'runAsUser: 0' -> Esecuzione Forzata Come Utente Root")
    except Exception:
        pass
    
    return list(findings)
                
def scanProject_UPTM(basePath):

    results = {
        'dockerIssues': {},
        'kubernetesIssues': {}
    }
    
    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)
            if 'dockerfile' in file.lower():
                issues = checkDockerUPTM(filePath)
                if len(issues) > 0:
                    results['dockerIssues'][filePath] = issues 
            if file.endswith(('.yaml', '.yml')) and 'docker-compose' not in file.lower():
                issues = checkKubernetesUPTM(filePath)
                if len(issues) > 0:
                    results['kubernetesIssues'][filePath] = issues
    
    return results