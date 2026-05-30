import zipfile
import os
import re

def unzipProject(zipFilePath, dirFilePath):

    try:
        with zipfile.ZipFile(zipFilePath, 'r') as myZip:
            myZip.extractall(dirFilePath)
	
    except zipfile.BadZipFile:
        print('Errore: File ZIP Non Valido')

    except Exception as e:
        print('Errore Durante Estrazione File ZIP')
        
def removeJavaComments(fileContent):

    commentPattern = r'//.*|/\*(?:.|\n)*?\*/'
    return re.sub(commentPattern, '', fileContent)