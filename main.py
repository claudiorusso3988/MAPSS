import os
import sys

from scanner import scanProject
from utils import unzipProject

def main():

    if len(sys.argv) < 2:
        print(f'Specificare Repository')
        sys.exit(1)
        
    target = sys.argv[1]
    
    if target.endswith('.zip'):
        basePath = os.path.splitext(target)[0]
        unzipProject(target, basePath)
        scanProject(basePath)
    
    elif os.path.isdir(target):
        scanProject(target)
        
    else:
        print('Path Non Valido')
        
if __name__ == "__main__":

    main()