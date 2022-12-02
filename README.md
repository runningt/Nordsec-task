# Nord Security Task

### Task description
#### Given:
  -  Files dataset at s3: clean and malicious Windows PE files
#### Metadata:
  - File path and size
  - File type (dll or exe)
  - Architecture (x32 or x64)
  - Number of imports (integer)
  - Number of exports (integer)
#### Write app:
  - Takes integer n as input
  - Selects a task: from s3 - n/2 malware and n/2 clean files
  - Using spark
  - downloads files
  - preprocesses files 
  - stores metadata to database
  - Omits already preprocessed data
#### Create docker-compose file to run:
  - python application
  - pyspark
  - structured database
#### Dataset:
  -  Aws s3: http://s3-nord-challenge-data.s3-website.eu-central-1.amazonaws.com/
  -  Catalog 0 - clean files
  -  Catalog 1 - Malware - real

### Solution
   - main.py contain PeParser and S3FileReader
     - PeParser parses specific file (given file stream) and gets apropriate Metadata (see Metadata section)
     -  S3FileReader gets stream containing specific file from S3.

   - WIP: NordTask.ipynb - Jupyter notebook that contains steps to read file list, create spark DF from it, process files to get appropriate meta
   - NordTask.ipynb markdown sections contains info about choosen solution approache
   - TODO:
        - docker container with database 
	- store in database
        - omit preprocessed data
	- tests
    	

## Build
docker compose up


## Run
Open and run NordTask.ipynb in jupyter on http://localhost:8888
