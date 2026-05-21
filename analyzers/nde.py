import os
import re

def checkJava_NDE(filePath):

    findings = set()

    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:

            content = file.read()

            if 'NoOpPasswordEncoder.getInstance()' in content:
                findings.add('Rilevato Uso esplicito Di NoOpPasswordEncoder: Le Password Degli Utenti Vengono Gestite E Validate In Chiaro Anziché Cifrate')

            if re.search(r'@Column\s*\([^)]*name\s*=\s*["\'](secret|password|passwd|card|pan|creditCard)["\'][^)]*\)', content, re.IGNORECASE):
                if '@Convert' not in content and '@Encrypted' not in content:
                    findings.add('Rilevato Campo Sensibile Mappato Sul Database Tramite Entity JPA Senza Meccanismi Di Cifratura Persistente')

            if re.search(r'["\']http://[^"\']*(?:login|oauth/token|checkout|payment|accesskey)', content, re.IGNORECASE):
                findings.add('Rilevato URL HTTP In Chiaro Nel Codice Java Diretto A Un Endpoint Sensibile')

            if re.search(r'log\.(info|debug|trace|error)\(.*password.*=.*[+]', content, re.IGNORECASE):
                findings.add(f'Rilevato Logging Di Informazioni Sensibili In Chiaro')

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

            if file.endswith('.java'):
                    
                issues = checkJava_NDE(filePath)
                if len(issues) > 0:
                    results['plainTextData'][filePath] = issues

    return results