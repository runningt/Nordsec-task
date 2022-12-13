# Nord Security Task

## Task description
### Given:
  -  Files dataset at s3: clean and malicious Windows PE files
### Metadata:
  - File path and size
  - File type (dll or exe)
  - Architecture (x32 or x64)
  - Number of imports (integer)
  - Number of exports (integer)
### Write app:
  - Takes integer n as input
  - Selects a task: from s3 - n/2 malware and n/2 clean files
  - Using spark
  - downloads files
  - preprocesses files 
  - stores metadata to database
  - Omits already preprocessed data
### Create docker-compose file to run:
  - python application
  - pyspark
  - structured database
### Dataset:
  -  Aws s3: http://s3-nord-challenge-data.s3-website.eu-central-1.amazonaws.com/
  -  Catalog 0 - clean files
  -  Catalog 1 - Malware - real

## Solution
   - `pe_parser.py` contain `PeParser` class definition. PeParser parses specific file (given file stream) and gets apropriate Metadata (see Metadata section)
   - `s3file_reader.py` contain `S3FileReader` class definition. It is used fot getting file object containing specific file from S3.
   - `utils.py` contains `ConfigurationDict` and `parse_file` transformation function definition
   - `process_pefiles.py` contains pyspark script to to get file list, create spark DF from it, process files to get appropriate meta, store in sql and redis
   - `NordTask.ipynb` - Jupyter notebook contains the same steps as `process_pefiles.py`

### Solution notes:

#### Database
I was considering SQL and NoSQL (key/value store) to store files info. Finally **Hybrid approach** with Redis is used

#### SQL Database - MySQL
The architecture is rather not complicated. All **distinct** file records are processed and stored in one table with following schema
 `path Varchar primary key, size Int, type Varchar, architecture Varchar default NULL, imports Int default NULL, exports Int default NULL, INDEX(size, type));`
At the whole table is loaded into DataFrame. It is substracted from task files DF to ensure already processed files are skipped. And after processing transformed DF is appended to existing table in MySQL.

Although number of files processed can reach (hundred of) millions [MySQL should handle it properly](https://dba.stackexchange.com/questions/20335/can-mysql-reasonably-perform-queries-on-billions-of-rows) with proper indexes. If there are billions of rows in DB we might start [encontering problems](https://stackoverflow.com/questions/38346613/mysql-and-a-table-with-100-millions-of-rows)
In case of performance issue using different Database type might be considered as changing DB should be relatively easy. What should be changed in that case is `dataframe.write.` `format` and `options`

#### NoSQL solutions

I was considering also NoSQL database which very often perform better in distributed environment and in most cases scale horizontally much easier than classical SQL DB. For this task I would consider key/value store as a good solution.

#### Aerospike
Aerospike was considered as it promises high efficiency, distributed (based on shared nothing architecture) database for storing key/value pairs. In commercial version it support pyspark distributed operations, direct import to RDDs etc. So if required it might give very good performance.

#### Redis
Open source, in-memory data store used as a database, cache, streaming engine, and message broker.


#### "hybrid" approach - caching
The issue with in-memory key/value store is that it does not provide (by default) persistence of data.
This can be achieved both in Redis and Aerospike of course but not by default.

The idea is to provide hybrid solution in which processed files data is stored in classical SQL database but apart from that it is also imported into key/value store. In that case there is no need to load all existing entries into DataFrame prior to processing new entries just to make sure some files weren't already processed. Instead,  `filesDF` entries that exists in key/value store should be filtered during transformation. As a last steps  `filesDB`should be saved (appended) not only to SQL database but also to key/value store

This solution is used finally with the not that already processed files are not filtered during `filesDF` transformations, but list of files from redis is read to dataframe prior to processing files and later this dataframe is substracted from `filesDF` to make sure files are not processed twice. This solution might not be optimal because it requires loading list of all processed files which might be huge. 

ToDo: check redis entry per each file during transformation


### Getting files 
In general I can see 2 approaches to load files data:
   - Approach 1.
     - `spark.read.format('binaryFile').option("pathGlobFilter","<path-glob>").load(<s3-bucket>)`. This solution would read all files with metadata into single DataFrame (path, mod time,  length, content)
     - parse content of file in apropriate resulted dataframe transformation
   - The advantage of it is that you receive parallelized DataFrame, content of file would be read in lazy way during processing each file. So in theory on a big enough spark cluster spark should take care of distributing and performance for you. The problem seems to be when you have to work with pretty read milions of files with unknown file size. You may end up huge memory and performance issues. This problem is shown e.g. in [this blog article](https://wrightturn.wordpress.com/2015/07/22/getting-spark-data-from-aws-s3-using-boto-and-pyspark/). Although it's pretty old I did not find any more recent solution to the issue. It also describes second approach.
   - Approach 2.
       - list all objects you're interested files in s3 bucket into some collection (but without parallelizing it)
       - create parallelized dataframe based on the given collection
       - read and process file content as part of transformations
   - The bottleneck might that you have to iterate over millions of files so the size of the collection to be processed (on one node) might be huge. 
   
As I am not able to test on a large set of data and big enough spark cluster which approach is more efficient. I am going to use approach described in [mentioned article](https://wrightturn.wordpress.com/2015/07/22/getting-spark-data-from-aws-s3-using-boto-and-pyspark). However instead of using boto3 for listing all objects I will use [`hadoop.fs.path.getFilesystem.globStatus`](https://stackoverflow.com/a/67050173/2018369) because boto3 [seems to be not the most effective way](https://stackoverflow.com/q/69920805/2018369) to get file list.

I was also considering one more approach, which however I could not find any good way to implement. So my idea was to create a dataframe similar to the one created by `spark.read.format('binaryFile').option("pathGlobFilter","<path-glob>").load(<s3-bucket>)`, but which contain only prefix of file (first 1024 or 2048 bytes). This way we could have a Dataframe(path, mod time,  length, PE headers), we could process the header of file to get all required PE metadata apart from imports/expors and in next step we could load apropriate sections of file to get imports/exports.


## Build
`docker compose up`

## Run
`spark-submit --files=src/config.yml --packages com.amazonaws:aws-java-sdk:1.11.901,org.apache.hadoop:hadoop-aws:3.3.1,mysql:mysql-connector-java:8.0.31,com.redislabs:spark-redis_2.12:3.1.0 src/process_pefiles.py 100`

Note: number of files to process is the only argument of `process_pefiles.py` script


## Jupyter Notebook
- Run jupyter notebook on http://localhost:8888 (no token required)
- Open and run /src/NordTask.ipynb in jupyter notebook
- Contains all steps required to process pefiles:
  - get file list 
  - create spark DF 
  - process files to get appropriate meta
  - store in sql and redis


## TODO:
- CI/CD pipelines
- get rid of boto3 from `s3file_reader.py`
- propper logging
- check redis entry per each file during transformation instead of getting all processed files into dataframe (see #### "hybrid" approach - caching)
