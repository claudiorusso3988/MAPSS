import zipfile

def unzipProject(zipFilePath, dirFilePath):

    try:

        with zipfile.ZipFile(zipFilePath, 'r') as myZip:
            myZip.extractall(dirFilePath)
	
    except zipfile.BadZipFile:

        print('Errore: File ZIP Non Valido')

    except Exception as e:

        print('Errore Durante Estrazione File ZIP')