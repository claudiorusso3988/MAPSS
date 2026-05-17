import os
import re
import yaml

def checkHSRegex(filePath):

    findings = set()
    regexPattern = re.compile(r'(?i)(?:api_key|apikey|aws_secret|secret_key|access_token|auth_token|db_pass|'
                              r'db_password|jwt_secret)\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_]{6,})[\'"]?')
    falsePositives = ['true', 'false', 'null', 'undefined', 'none', 'blank', 'empty', 'system']

    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            lines = file.readlines()
            for lineNum, line in enumerate(lines, 1):
                matches = re.findall(regexPattern, line)
                for match in matches:
                    if match.lower() not in falsePositives:
                        findings.add(f'Hardcoded Secret Alla Riga {lineNum}: {match}')
    except Exception:
        pass

    return list(findings)


def chechInfrastructuralHS(filePath):

    findings = set()
    keysToCheck = ['DB_PASSWORD', 'SECRET_KEY', 'API_KEY', 'TOKEN']

    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            docs = yaml.safe_load_all(file)
            for doc in docs:
                if isinstance(doc, dict):
                    kind = doc.get('kind', '')
                    name = doc.get('metadata', {}).get('name', 'Unknown')

                    if kind == 'Secret' and 'stringData' in doc:
                        findings.add(f'Kubernetes Secret Con Dati In Chiaro): {name}')

                    spec = doc.get('spec', {})
                    containers = spec.get('template', {}).get('spec', {}).get('containers', [])
                    if not containers and 'containers' in spec:
                        containers = spec.get('containers', [])

                    for container in containers:
                        for env in container.get('env', []):
                            envName = env.get('name', '').upper()
                            if any(key in envName for key in keysToCheck) and 'value' in env:
                                findings.add(f'Variabile Di Ambiente Sensibile In Chiaro ({env.get("name")}) Nel '
                                             f'Container: {container.get("name", "Unknown")}')
    except Exception:
        pass

    return list(findings)


def scanProject_HS(basePath):

    results = {
        'issuesHS' : {},
        'infrastructuralIssuesHS' : {}
    }

    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)

            # Al Fine Di Evitare Di Confondere HS Con NDE
            if not file.endswith(('.sql', '.ddl')):

                if file.endswith(('.java', '.js', '.properties', '.xml', '.env', '.sh', '.yaml', '.yml')):
                    issues = checkHSRegex(filePath)
                    if len(issues) > 0:
                        results['issuesHS'][filePath] = issues

                if file.endswith( ('.yaml', '.yml') ):
                    issues = chechInfrastructuralHS(filePath)
                    if len(issues) > 0:
                        results['infrastructuralIssuesHS'][filePath] = issues
                        
    return results
