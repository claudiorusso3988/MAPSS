import os
import re

def checkNDE(filePath):

    findings = set()
    
    regexPatterns = [
        re.compile(r"insert\s+into.*password.*values\s*\(\s*['\"][^'\"]+['\"]", re.IGNORECASE),
        re.compile(r"log\.(info|debug|trace|error)\(.*password.*=.*[+]", re.IGNORECASE)
    ]
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            
            for pattern in regexPatterns:
                if re.search(pattern, content):
                    findings.add(f"Rilevato Possibile Salvataggio/Logging Di Dati Sensibili In Chiaro")
                    
    except Exception:
        pass

    return list(findings)


def scanProject_NDE(basePath):

    results = {
        'plainTextData': {}
    }

    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)

            if file.endswith(('.java', '.js', '.xml', '.properties', '.yml', '.yaml')):
                    
                issues = checkNDE(filePath)
                if len(issues) > 0:
                    results['plainTextData'][filePath] = issues

    return results