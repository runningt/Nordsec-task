#!/usr/bin/env python

import boto3
import pefile
import os

S3_BUCKET = 's3-nord-challenge-data'
S3_REGION = 'eu-central-1'

class S3FileReader:

    def __init__(self, s3_bucket=S3_BUCKET, region=S3_REGION):
        self.client = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='', region_name=region)
        # This is a "hack" to skip signing of S3 requests, as s3-nord-challenge-data does not require
        # aws_acecess_key_id and aws_secret_access_key for reading
        self.client._request_signer.sign = (lambda *args, **kwargs: None)
        self.bucket = s3_bucket
        return self.client


    def list_files_with_size(self, prefix):
        paginator = self.client.get_paginator('list_files')
        pages = paginator.paginate(Bucket=self.bucket, Prefix=prefix)
        for page in pages:
            for key in page('Contents'):
                yield key.get('Key'), key.get('Size')

    def get_file_stream(self, key, range_bytes):
        return self.client.get_object(Bucket=self.bucket, key=key, range=f'bytes=0-{range_bytes}')



class PeParser:
    def __init__(self, path, data, size):
        self.path = path
        self.data = data
        self.read_data = ""
        self.dir = os.path.dirname(self.path)
        self.name, self.extension = os.path.splitext(os.path.basename(self.path))
        self.size = size


    def get_short_headers(self):
        self.read_data = self.data.read(300)
        pe = pefile.PE(data=self.read_data)
        if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
            self.architecture = 32
        elif pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            self.architecture = 64
        else:
            raise ValueError("INCORECT PE_TYPE")

    def get_imports_exxporst(self):
        self.read_data.append(self.data.read(4000))
        pe = pefile.PE(data=self.read_data)
        ...



def main(*args, **kwargs):
    pass



