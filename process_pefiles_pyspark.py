from pyspark.sql import SparkSession
from pyspark import SparkConf
import random
import yaml
## Config

spark_conf = SparkConf()
spark_conf.setAppName("NORD_Task")
spark_conf.setMaster("local[*]")
spark_conf.set("spark.redis.host", "cache")
spark_conf.set("spark.redis.port", "6379")
#spark_conf.set("spark.redis.auth", "password")
spark = SparkSession.builder.config(conf=spark_conf).getOrCreate()


sc = spark.sparkContext

hadoop_conf=sc._jsc.hadoopConfiguration()
hadoop_conf.set("fs.s3.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
hadoop_conf.set("fs.s3a.aws.credentials.provider", "org.apache.hadoop.fs.s3a.AnonymousAWSCredentialsProvider")

S3_BUCKET = 's3-nord-challenge-data'
S3_REGION = 'eu-central-1'
hadoop_conf.set("fs.s3a.endpoint", f"s3.{S3_REGION}.amazonaws.com")

# number of files to process - will be read as input
# N = 100
N = 10

# DB Settings
jdbc_url = 'jdbc:mysql://db/nord_files'
table = "files_info"
username = "root"
password = "password"
driver = "com.mysql.cj.jdbc.Driver"

# Redis settings - on spark session level



## Get file list
clean_path = '/0/*.???'
malware_path = '/1/*.???'

cleanPath = sc._jvm.org.apache.hadoop.fs.Path(f's3a://{S3_BUCKET}{clean_path}')
cFs = cleanPath.getFileSystem(hadoop_conf)
clean_files = cFs.globStatus(cleanPath)

malwarePath = sc._jvm.org.apache.hadoop.fs.Path(f's3a://{S3_BUCKET}{malware_path}')
mFs = malwarePath.getFileSystem(hadoop_conf)
malware_files = mFs.globStatus(malwarePath)

files_to_process = random.sample(clean_files, int(N/2))+ random.sample(malware_files, int(N/2))


## put files into dataFrame

from pyspark.sql.types import StructType,StructField, StringType, IntegerType
schema = StructType([
    StructField('path', StringType(), True),
    StructField('size', IntegerType(), True),
    StructField('type', StringType(), True)
])
data = [(f.getPath().toUri().getRawPath(), f.getLen(), f.getPath().getName().split('.')[-1]) for f in files_to_process]

## make sure we don't have duplicates
filesDF = spark.createDataFrame(data=data, schema = schema).distinct()

## get files already processed from redis cache
redis_files_info = spark.read.format("org.apache.spark.sql.redis").schema(schema)\
    .option("table", "s3").option("key.column", "path").load()

# Remove files that exists in DB from list of files to process
filesDF = filesDF.subtract(redis_files_info)



## process files
from functools import partial
from utils import parse_file

schema_with_meta = StructType(filesDF.schema.fields+[
    StructField('architecture', StringType(), True),
    StructField('imports', IntegerType(), True),
    StructField('exports', IntegerType(), True)
])

parsed=filesDF.rdd.map(partial(parse_file, bucket=S3_BUCKET, region=S3_REGION))

parsedDF = parsed.toDF(schema_with_meta)
parsedDF.show()

## Store result to DB
parsedDF.write.format('jdbc').options(
    url=jdbc_url, driver=driver,dbtable=table, user=username, password=password
).mode('append').save()

## Store results  to Redis cache
parsedDF.select(["path", "size", "type"]).write.format("org.apache.spark.sql.redis").option("table","s3").option("key.column", "path").mode('append').save()




