import os
import re

# Spring Security
def checkJava_UT(filePath):

    findings = set()
    regexPattern = r'(antMatchers|requestMatchers|mvcMatchers)\s*\(\s*["\'](?!/login|/public|/static|/css|/js)[^"\']+["\']\s*\)\s*\.\s*permitAll\(\)'
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            matches = re.finditer(regexPattern, content, re.IGNORECASE)
            for match in matches:
                findings.add(f'Rilevato Endpoint Configurato Con permitAll: {match.group(0).strip()}\n')
            if re.search(r'\.csrf\(\)\s*|.\s*disable\(\)', content, re.IGNORECASE):
                findings.add('Protezione CSRF Esplicitamente Disabilitata\n')
    except Exception:
        pass
    
    return list(findings)
    
# File Di Configurazione
def checkProperties_UT(filePath):

    findings = set()
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            if re.search(r'security\.enabled\s*=\s*false', content, re.IGNORECASE | re.MULTILINE):
                findings.add('Sicurezza Disabilitata A Livello Di Configurazione')
            if re.search(r'auth\.required\s*=\s*false', content, re.IGNORECASE | re.MULTILINE):
                findings.add('Autenticazione Esplicitamente Non Richiesta')   
    except Exception:
        pass
        
    return list(findings)
    
def scanProject_UT(basePath):

    results = {
        'javaIssues': {},
        'propertiesIssues': {}
    }
    
    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)
            if file.endswith('.java'):
                issues = checkJava_UT(filePath)
                if len(issues) > 0:
                    results['javaIssues'][filePath] = issues
            elif file.endswith(('.properties', '.yaml', '.yml')):
                issues = checkProperties_UT(filePath)
                if len(issues) > 0:
                    results['propertiesIssues'][filePath] = issues

    return results