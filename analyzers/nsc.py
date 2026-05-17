import os
import re
import yaml

def checkNSC(filePath):

  findings = set()
  regexPattern = re.compile(r"['\"](http://(?!localhost|127\.0\.0\.1|www\.w3\.org|maven\.apache\.org|java\.sun\.com|www\.springframework\.org)[^'\"]+)['\"]")

  try:
    with open(filePath, 'r', encoding = 'utf-8') as file:
      content = file.read()
      matches = re.findall(regexPattern, content)
      for match in matches:
        findings.add(f'Rilevato Utilizzo Di HTTP In Chiaro: {match}')

      loweredContent = content.lower()
      if 'server-ssl-enabled=false' in loweredContent or 'server-ssl-enabled: false' in loweredContent:
        findings.add(f'SSL/TLS Esplicitamente Disabilitato')

  except Exception:
    pass

  return list(findings)


def checkKubernetesNSC(filePath):

  findings = set()

  try:
    with open(filePath, 'r', encoding = 'utf-8') as file:
      docs = yaml.safe_load_all(file)
      for doc in docs:
        if isinstance(doc, dict):
          spec = doc.get('spec', {})
          if not spec.get('tls'):
            name = doc.get('metadata', {}).get('name', 'Unknown')
            findings.add(f'Ingress Configurato Senza TLS: {name}')

  except Exception:
    pass

  return list(findings)


def scanProject_NSC(basePath):

    results = {
        'issuesNSC' : {},
        'kubernetesIssuesNSC' : {}
    }
    
    for root, dirs, files in os.walk(basePath):
      for file in files:
        filePath = os.path.join(root, file)

        # HTTP IN CHIARO / TLS DISABILITATO
        if file.endswith( ('.java', '.js', '.yml', '.yaml', '.properties', '.xml') ):
          issues = checkNSC(filePath)
          if len(issues) > 0:
            results['issuesNSC'][filePath] = issues

        # KUBERNETES INGRESS CONFIGURATO SENZA TLS
        if file.endswith( ('.yaml', '.yml') ) and 'docker-compose' not in filePath:
          issues = checkKubernetesNSC(filePath)
          if len(issues) > 0:
            results['kubernetesIssuesNSC'][filePath] = issues
            
    return results