import os
import re
import yaml

def checkRegex_HS(filePath):

    findings = set()
    regexPattern = re.compile(
        r'(?i)(?:api_key|apikey|aws_secret|secret_key|access_token|auth_token|db_pass|'
        r'db_password|jwt_secret|spring\.datasource\.password|spring\.mail\.password|'
        r'secret|password)\s*[:=]\s*[\'"]?([a-zA-Z0-9\-_@#\.]{4,})[\'"]?'
    )
    falsePositives = ['true', 'false', 'null', 'undefined', 'none', 'blank', 'empty', 'system']

    try:
        with open(filePath, 'r', encoding = 'utf-8') as file:
            for lineNum, line in enumerate(file, 1):
                if '${' in line and '}' in line:
                    continue
                matches = re.finditer(regexPattern, line)
                for match in matches:
                    secretValue = match.group(1)
                    if secretValue.lower() not in falsePositives and not secretValue.startswith('$'):
                        findings.add(f'Hardcoded Secret Alla Riga {lineNum}: {match.roup(0).strip()}')
    except Exception:
        pass

    return list(findings)


def chechInfrastructural_HS(filePath):

    findings = set()
    keysToCheck = ['DB_PASSWORD', 'SECRET_KEY', 'API_KEY', 'TOKEN', 'PASSWORD']

    try:
        with open(filePath, 'r', encoding='utf-8') as file:
            docs = yaml.safe_load_all(file)
            for doc in docs:
                if isinstance(doc, dict):
                    kind = doc.get('kind', '')
                    name = doc.get('metadata', {}).get('name', 'Unknown')

                    if kind == 'Secret' and 'stringData' in doc:
                        findings.add(f'Kubernetes Secret Con Dati In Chiaro: {name}')

                    spec = doc.get('spec', {})
                    templateSpec = spec.get('template', {}).get('spec', {}) if 'template' in spec else spec
                    containers = templateSpec.get('containers', [])

                    for container in containers:
                        for env in container.get('env', []):
                            envName = env.get('name', '').upper()
                            envValue = str(env.get('value', ''))

                            if any(key in envName for key in keysToCheck) and 'value' in env:
                                if not envValue.startswith('${') and not envValue.startswith('$('):
                                    findings.add(f'Variabile Di Ambiente Sensibile In Chiaro ({env.get("name")}) Nel Container: {container.get("name", "Unknown")}')
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

                if file.endswith(('.java', '.properties', '.xml', '.env', '.yaml', '.yml')):
                    issues = checkRegex_HS(filePath)
                    if len(issues) > 0:
                        results['issuesHS'][filePath] = issues

                if file.endswith( ('.yaml', '.yml') ):
                    issues = chechInfrastructural_HS(filePath)
                    if len(issues) > 0:
                        results['infrastructuralIssuesHS'][filePath] = issues
                        
    return results
