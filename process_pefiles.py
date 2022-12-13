import argparse
import random
from functools import partial

import yaml
from pyspark import SparkConf
from pyspark.sql import SparkSession
from pyspark.sql.types import IntegerType, StringType, StructField, StructType

from utils import ConfigurationDict, parse_file


def main(args):
    # Config
    try:
        with open("config.yml") as stream:
            yaml_config = ConfigurationDict(yaml.safe_load(stream))
    except:
        yaml_config = ConfigurationDict()

    # number of files to process - get from script argument input

    if args.N:
        num_of_files = int(args.N)
    else:
        num_of_files = 10
    print(f"Number of files to proceed: {num_of_files}")

    # set up spark
    spark_conf = SparkConf()
    spark_conf.setAppName(yaml_config.get("app.name", "NORD_Task"))
    spark_conf.setMaster(yaml_config.get("spark.master", "local[*]"))
    spark_conf.set("spark.redis.host", yaml_config.get("spark.redis.host", "cache"))
    spark_conf.set("spark.redis.port", yaml_config.get("spark.redis.port", "6379"))
    spark = SparkSession.builder.config(conf=spark_conf).getOrCreate()

    redis_table = yaml_config.get("spark.redis.table", "files_info")

    # DB Settings
    jdbc_url = yaml_config.get("spark.sql.url", "jdbc:mysql://db/nord_files")
    table = yaml_config.get("spark.sql.table", "files_info")
    username = yaml_config.get("spark.sql.username", "root")
    password = yaml_config.get("spark.sql.password", "password")
    driver = yaml_config.get("spark.sql.driver", "com.mysql.cj.jdbc.Driver")

    context = spark.sparkContext

    hadoop_conf = context._jsc.hadoopConfiguration()
    hadoop_conf.set("fs.s3.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
    hadoop_conf.set("fs.s3a.aws.credentials.provider", "org.apache.hadoop.fs.s3a.AnonymousAWSCredentialsProvider")

    s3_bucket = yaml_config.get("s3.bucket", "s3-nord-challenge-data")
    s3_region = yaml_config.get("s3.region", "eu-central-1-aaaaaa")
    hadoop_conf.set("fs.s3a.endpoint", f"s3.{s3_region}.amazonaws.com")
    print(f'Amazon s3 endpoint {hadoop_conf.get("fs.s3a.endpoint")}, bucket: {s3_bucket}')

    # Get file list
    clean_path = yaml_config.get("s3.path.clean", "/0/*.???")
    malware_path = yaml_config.get("s3.path.malware", "/1/*.???")

    clean_path = context._jvm.org.apache.hadoop.fs.Path(f"s3a://{s3_bucket}{clean_path}")
    c_fs = clean_path.getFileSystem(hadoop_conf)
    clean_files = c_fs.globStatus(clean_path)

    malware_path = context._jvm.org.apache.hadoop.fs.Path(f"s3a://{s3_bucket}{malware_path}")
    m_fs = malware_path.getFileSystem(hadoop_conf)
    malware_files = m_fs.globStatus(malware_path)

    files_to_process = random.sample(clean_files, int(num_of_files / 2)) + random.sample(
        malware_files, int(num_of_files / 2)
    )

    # put files into dataFrame
    schema = StructType(
        [
            StructField("path", StringType(), True),
            StructField("size", IntegerType(), True),
            StructField("type", StringType(), True),
        ]
    )
    data = [
        (f.getPath().toUri().getRawPath(), f.getLen(), f.getPath().getName().split(".")[-1]) for f in files_to_process
    ]

    # make sure we don't have duplicates
    filesDF = spark.createDataFrame(data=data, schema=schema).distinct()

    # TODO: most probably getting all files from redis and removing it from currently processed files is not optimal
    # solution. I would instead try approach with getting single files directly from redis when file is processed
    # (in transformation) and filtering out already processed files (from redis cache)
    redis_files_info = (
        spark.read.format("org.apache.spark.sql.redis")
        .schema(schema)
        .option("table", redis_table)
        .option("key.column", "path")
        .load()
    )
    # Remove files that exists in DB from list of files to process
    filesDF = filesDF.subtract(redis_files_info)

    print("filesDF dataframe created and cleaned up.")

    # Process files
    schema_with_meta = StructType(
        filesDF.schema.fields
        + [
            StructField("architecture", StringType(), True),
            StructField("imports", IntegerType(), True),
            StructField("exports", IntegerType(), True),
        ]
    )

    parsed = filesDF.rdd.map(partial(parse_file, bucket=s3_bucket, region=s3_region))
    parsedDF = parsed.toDF(schema_with_meta)
    print("All files processed")
    # parsedDF.show()

    # Store result to DB
    parsedDF.write.format("jdbc").options(
        url=jdbc_url, driver=driver, dbtable=table, user=username, password=password
    ).mode("append").save()
    print(f"Data stored in sql database: {jdbc_url}, table: {table}")

    # Store results to Redis cache
    parsedDF.select(["path", "size", "type"]).write.format("org.apache.spark.sql.redis").option(
        "table", redis_table
    ).option("key.column", "path").mode("append").save()
    print(f'Data stored in redis {spark_conf.get("spark.redis.host")}  table: {redis_table}')

    spark.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("N", nargs="?", help="number of files to proceed", default=100)
    args = parser.parse_args()
    main(args)
