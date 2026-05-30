import os
import re
from utils import removeJavaComments

def checkJavaOCC(filePath):

    findings = set()

    customPatterns = [
        r'(?:class|interface)\s+\w*(?:Custom|Simple|My|Internal|Own)(?:Crypto|Cipher|Encrypt|Decrypt|Hash)',
        r'(?:public|private|protected)\s+(?:[\w<>\[\]]+\s+)+\w*(?:Custom|Simple|My|Internal|Own)(?:Encrypt|Decrypt|Hash|Cipher)\s*\('
    ]

    xorPattern = r'for\s*\(.*?\).*?(?:\[.*?\])\s*\^=?'

    try:
        with open(filePath, 'r', encoding='utf-8') as file:
        
            rawContent = file.read()
            content = removeJavaComments(rawContent)

            for pattern in customPatterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.add(f"Classe/Metodo Sospetto: '{match.strip()}'")

            loweredContent = content.lower()

            if (
                'encrypt' in loweredContent or
                'decrypt' in loweredContent or
                'cipher' in loweredContent
            ):
                if re.search(xorPattern, content, re.DOTALL):
                    findings.add(
                        "Rilevata Operazione XOR Associata A Crittografia"
                    )

    except Exception:
        pass

    return list(findings)


def checkCryptoLibraries(filePath):

    foundLibraries = []

    librariesToCheck = {
        'BouncyCastle (Standard Java)': [
            'org.bouncycastle',
            'bcprov',
            'bcpkix'
        ],
        'Spring Security Crypto': [
            'spring-security-crypto'
        ],
        'Apache Commons Crypto': [
            'commons-crypto'
        ],
        'Google Tink': [
            'com.google.crypto.tink',
            '"tink"'
        ],
    }

    try:
        with open(filePath, 'r', encoding='utf-8') as file:
        
            rawContent = file.read().lower()
            content = removeJavaComments(rawContent)

            for library, signatures in librariesToCheck.items():
                for signature in signatures:
                    if signature in content:
                        foundLibraries.append(library)

    except Exception:
        pass

    return foundLibraries


def checkJavaImportsOCC(filePath):

    findings = set()

    imports = [
        'javax.crypto',
        'java.security',
        'org.springframework.security.crypto',
        'org.mindrot.jbcrypt',
        'org.mindrot.jbcrypt.BCrypt'
    ]

    keywords = [
        'cipher',
        'encrypt',
        'decrypt',
        'encode',
        'decode',
        'obfuscate',
        'salt',
        'digest'
    ]

    importsFound = set()
    keywordsFound = set()

    try:
        with open(filePath, 'r', encoding='utf-8') as file:

            content = file.read().lower()

            for imp in imports:
                if imp in content:
                    importsFound.add(imp)

            for key in keywords:
                if key in content:
                    keywordsFound.add(key)

            if importsFound:
                findings.add(
                    f"Utilizzate Import Standard: "
                    f"{', '.join(importsFound)}"
                )

            if not importsFound and keywordsFound:
                findings.add(
                    f"Utilizzate Keyword "
                    f"{', '.join(keywordsFound)} "
                    f"Senza Import Standard"
                )

    except Exception:
        pass

    return list(findings)


def scanProject_OCC(basePath):

    results = {
        'javaIssuesOCC': {},
        'javaImportsIssuesOCC': {},
        'foundedLibraries': {}
    }

    for root, dirs, files in os.walk(basePath):

        for file in files:

            filePath = os.path.join(root, file)

            if file.endswith('.java'):

                issues = checkJavaOCC(filePath)

                if issues:
                    results['javaIssuesOCC'][filePath] = issues

                issues = checkJavaImportsOCC(filePath)

                if issues:
                    results['javaImportsIssuesOCC'][filePath] = issues

            elif file in ['pom.xml', 'build.gradle', 'package.json']:

                findings = checkCryptoLibraries(filePath)

                if findings:
                    results['foundedLibraries'][filePath] = findings
                    
    return results