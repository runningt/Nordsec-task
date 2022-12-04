import boto3
from botocore import UNSIGNED
from botocore.config import Config

S3_BUCKET = 's3-nord-challenge-data'
S3_REGION = 'eu-central-1'




class S3FileReader:
    # TODO: Get rid of boto if possible
    # TODO: consider reading using smart_open or using native spark libraries

    def __init__(self, s3_bucket=S3_BUCKET, region=S3_REGION):
        self.client = boto3.client('s3', config=Config(signature_version=UNSIGNED), region_name=region)

        self.bucket = s3_bucket


    def list_files_with_size(self, prefix=""):
        """List objects in s3 bucket with specific prefix (if given)"""
        paginator = self.client.get_paginator('list_files')
        pages = paginator.paginate(Bucket=self.bucket, Prefix=prefix)
        for page in pages:
            for key in page('Contents'):
                yield key.get('Key'), key.get('Size')

    def get_file_stream(self, key, range_bytes=0):
        """
        Get stream containing S3 object (file), limit to range_bytes if
        :param key: s3 key (path)
        :param range_bytes:limit length of file
        :return: file stream
        """
        return ""
        if range_bytes:
            return self.client.get_object(Bucket=self.bucket, key=key, range=f'bytes=0-{range_bytes}').get['Body']
        else:
            return self.client.get_object(Bucket=self.bucket, key=key).get('Body')
