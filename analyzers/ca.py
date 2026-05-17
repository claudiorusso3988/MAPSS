import os
import re

def checkCentralizedAuth(filePath):

    findings = set()
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()            
            loweredContent = content.lower()
            if 'gateway' in loweredContent or 'zuul' in loweredContent or 'spring.cloud.gateway' in loweredContent:
                # Cerca Configurazioni Tipiche Di Spring Security (Es. hasRole, hasAuthority)
                matches = re.findall(r'(antMatchers|pathMatchers|route).*?(hasRole|hasAuthority|hasAnyRole)\s*\([^)]+\)', content, re.IGNORECASE)
                if len(matches) > 2:
                    findings.add(f'Il Gateway Contiene Controlli Di Autorizzazione A Grana Fine')
                # Cerca Configurazioni Di Ruoli Con Riferimento A Rotte Specifiche
                if file.endswith(('.yml', '.yaml', '.properties')):
                    if re.search(r'roles:\s*\[.*\]', content) or re.search(r'requires-role:', content):
                        findings.add('Regole Di Autorizzazione Specifiche Trovate Nella Configurazione Del Gateway')
    except Exception:
        pass

    return list(findings)

def scanProject_CA(basePath):

    results = {
        'centralizedAuthLogic': {}
    }

    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)
            if file.endswith(('.java', '.yml', '.yaml', '.properties')):
                issues = checkCentralizedAuth(filePath)
                if issues:
                    results['centralizedAuthLogic'][filePath] = issues

    return results