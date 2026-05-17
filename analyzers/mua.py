import os
import re

# Logica Di Autenticazione Locale
def checkLocalAuth_MUA(filePath):

    findings = set()
    loginRegex = r'@(Post|Get)Mapping\s*\(\s*["\']/(login|authenticate|auth|signin)["\']\s*\)'
    
    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            content = file.read()
            matches = re.findall(loginRegex, content, re.IGNORECASE)
            if len(matches) > 0:
                findings.add('Rilevato Endpoint Di Login Locale')
            if re.search(r'Jwts\.builder\(\)', content) or re.search(r'JWT\.create\(\)', content):
                findings.add('Rilevata Logica Di Generazione Di Token JWT In Locale')
    except Exception:
        pass
    
    return list(findings)
  
  
def scanProject_MUA(basePath):

    results = {
        'localAuth': {}
    }
    
    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)
            if file.endswith(('.java', '.js')):
                issues = checkLocalAuth_MUA(filePath)
                if len(issues) > 0:
                    results['localAuth'][filePath] = issues
    
    return results