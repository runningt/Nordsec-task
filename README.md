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
   - `pe_parser.py` contain PeParser class definition. PeParser parses specific file (given file stream) and gets apropriate Metadata (see Metadata section)
   - `s3file_reader.py` contains S3FileReader class definition. It is used fot getting file object containing specific file from S3.

   - WIP: NordTask.ipynb - Jupyter notebook that contains steps to read file list, create spark DF from it, process files to get appropriate meta
   - NordTask.ipynb markdown sections contains info about choosen solution approach
   - TODO:
        [x] docker container with database 
        [x] store in database
        [x] omit preprocessed data
        [] tests (In progress - finished `pe_parser` tests
        [] move logic from jupyter notebook into spark code in python file 
        
            

## Build
docker compose up


## Run
Open and run NordTask.ipynb in jupyter on http://localhost:8888
