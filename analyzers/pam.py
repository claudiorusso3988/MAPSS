import os
import re
import yaml

def checkKubernetesServicePAM(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding = 'utf-8') as f:
            docs = yaml.safe_load_all(f)
            for doc in docs:
                if isinstance(doc, dict) and doc.get('kind') == 'Service':
                    spec = doc.get('spec', {})
                    svc_type = spec.get('type', 'ClusterIP')
                    if svc_type in ['LoadBalancer', 'NodePort']:
                        name = doc.get('metadata', {}).get('name', 'Unknown')
                        findings.append(f"Servizio '{name}' Espone La Porta Con Type {svc_type}")
    except Exception:
        pass
    return findings

def checkKubernetesGatewayPAM(filepath):
    findings = []
    try:
        with open(filepath, 'r', encoding = 'utf-8') as f:
            docs = yaml.safe_load_all(f)
            for doc in docs:
                if isinstance(doc, dict):
                    kind = doc.get('kind')
                    if kind in ['Ingress', 'Gateway', 'VirtualService', 'IngressRoute']:
                        name = doc.get('metadata', {}).get('name', 'Unknown')
                        findings.append(f"{kind} ('{name}')")
    except Exception:
        pass
    return findings

def checkDockerComposePAM(filepath):
    ports_issues = []
    has_proxy = False
    proxy_images = ['nginx', 'kong', 'traefik', 'haproxy', 'envoyproxy']
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            compose_file = yaml.safe_load(f)
            if isinstance(compose_file, dict) and 'services' in compose_file:
                for service_name, config in compose_file['services'].items():
                    if 'ports' in config:
                        ports_issues.append(f"Servizio '{service_name}' usa 'ports'")

                    image = config.get('image', '').lower()
                    if any(proxy in image for proxy in proxy_images):
                        has_proxy = True
    except Exception:
        pass
    return ports_issues, has_proxy

def checkJavaPAM(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if '@CrossOrigin' in content:
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if '@CrossOrigin' in line:
                        return f"Trovato @CrossOrigin alla riga {i+1}"
    except Exception:
        pass
    return None

def checkBuildFileForGateway(filepath):
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if 'spring-cloud-starter-gateway' in content or 'spring-cloud-starter-netflix-zuul' in content:
                return True
    except Exception:
        pass
    return False

def checkFrontendUrlsPAM(filepath):
    findings = set()
    url_pattern = re.compile(r"['\"](https?://(?:localhost|127\.0\.0\.1|\w+\.(?:local|lan|api)):[0-9]+[^'\"]*)['\"]")
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            matches = url_pattern.findall(content)
            for match in matches:
                findings.add(f"URL assoluto: {match}")
    except Exception:
        pass
    return list(findings)

def scanProject_PAM(basePath):
    print(f'Avvio Scansione Architetturale In {basePath}\n')

    results = {
        'kubernetesIssuesServicePAM' : {},
        'kubernetesIssuesGatewayPAM' : {},
        'dockerIssuesPAM' : {},
        'javaIssuesPAM' : {},
        'frontendIssuesPAM' : {},
        'apiGatewayHints' : []
    }

    for root, dirs, files in os.walk(basePath):
        for file in files:
            filePath = os.path.join(root, file)

            # 1. KUBERNETES
            if file.endswith(('.yml', '.yaml')) and 'docker-compose' not in file:
                issues = checkKubernetesServicePAM(filePath)
                if len(issues) > 0:
                    results['kubernetesIssuesServicePAM'][filePath] = issues

                gw_issues = checkKubernetesGatewayPAM(filePath)
                if len(gw_issues) > 0:
                    results['kubernetesIssuesGatewayPAM'][filePath] = gw_issues
                    results['apiGatewayHints'].extend([f"Gateway/Ingress K8s in {filePath} -> {gw}" for gw in gw_issues])

            # 2. DOCKER COMPOSE
            elif file in ['docker-compose.yml', 'docker-compose.yaml']:
                issues, isApiGatewayPresent = checkDockerComposePAM(filePath)
                if len(issues) > 0:
                    results['dockerIssuesPAM'][filePath] = issues
                if isApiGatewayPresent:
                    results['apiGatewayHints'].append(f"Trovato proxy in Docker Compose: {filePath}")

            # 3. PROXY STANDALONE
            elif file in ['nginx.conf', 'kong.yml', 'kong.yaml', 'traefik.yml']:
                results['apiGatewayHints'].append(f"Trovato file configurazione Proxy: {filePath}")

            # 4. JAVA BACKEND
            elif file.endswith('.java'):
                issue = checkJavaPAM(filePath)
                if issue:
                    results['javaIssuesPAM'][filePath] = issue

            # 5. MAVEN E GRADLE
            elif file in ['pom.xml', 'build.gradle', 'build.gradle.kts']:
                isApiGatewayPresent = checkBuildFileForGateway(filePath)
                if isApiGatewayPresent:
                    results['apiGatewayHints'].append(f"Trovata dipendenza API Gateway in: {filePath}")

            # 6. FRONTEND
            elif file.endswith(('.js', '.ts', '.jsx', '.tsx', '.vue')):
                urls = checkFrontendUrlsPAM(filePath)
                if urls:
                    results['frontendIssuesPAM'][filePath] = urls
                    
    return results
