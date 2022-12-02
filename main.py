#!/usr/bin/env python

import boto3
import pefile
import os
import io



S3_BUCKET = 's3-nord-challenge-data'
S3_REGION = 'eu-central-1'

class S3FileReader:
    # TODO: Get rid of boto if possible
    # TODO: consider reading using smart_open or using native spark libraries

    def __init__(self, s3_bucket=S3_BUCKET, region=S3_REGION):
        self.client = boto3.client('s3', aws_access_key_id='', aws_secret_access_key='', region_name=region)
        # This is a "hack" to skip signing of S3 requests, as s3-nord-challenge-data does not require
        # aws_acecess_key_id and aws_secret_access_key for reading
        self.client._request_signer.sign = (lambda *args, **kwargs: None)

        self.bucket = s3_bucket


    def list_files_with_size(self, prefix):
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
        if range_bytes:
            return self.client.get_object(Bucket=self.bucket, key=key, range=f'bytes=0-{range_bytes}').get['Body']
        else:
            return self.client.get_object(Bucket=self.bucket, key=key).get('Body')



class PeParser:

    headers_default_size = 1024


    # This is my assumption, above this size file is treated as corrupted
    headers_max_size = 8*1024
    def __init__(self, path, file_data, size):
        """
        
        :param path: 
        :param file_data: file stream 
        :param size: size of file as reported by boto3 (s3)
        """
        self.path = path
        self.data = file_data
        self.data_position = 0
        self.local_stream = io.BytesIO()
        self.dir = os.path.dirname(self.path)
        self.name, self.extension = os.path.splitext(os.path.basename(self.path))
        self.size = size
        self.pe_headers = None
        self.pe = None
        self.corrupted = False
        self.imports = -1
        self.exports = -1
        self.architecture = None
        self.headers_read = 0
        self.meta_parsed = False
        
    def read_headers(self):
        """
        Try reading pe file DOS_HEADER.COFF header, NT_HEADERS and OPTIONAL_HEADER
        """
        if self.data_position > 0:
            raise IndexError("Headers already read")
        while not self.pe_headers and self.headers_read < self.headers_max_size:
            self.local_stream.write(self.data.read(self.headers_default_size))
            self.headers_read+=self.headers_default_size
            self.local_stream.seek(0)
            try:
                self.pe_headers = pefile.PE(data=self.local_stream.read(), fast_load=True)
            except pefile.PEFormatError:
                self.pe_headers = None
        if self.pe_headers.OPTIONAL_HEADER.SizeOfHeaders > self.headers_read:
            self.corrupted = True
            raise ValueError("PE File is corrupted")



    def guess_size_and_read(self):
        """
        You actually don't need to read full file.
        You just need to read enough to have IMPORT and EXPORT data,
        The problem is that there are different places where this data is set
        sometimes its .edata and .idata section, sometimes one (or both) sections are missing
        So we determine size to read following way:
            - max possible is size_of_file (as reported by s3)
            - check file apropriate section sizes
            - check virtual addresses and size of import and export sections in
            HEADER_DATA_DIRECTORY (yes I do know VirtualAddress is address in memory after loading data,
            but I believe its higher or equal than actuall offset in file)
            - get minimum of above values
        :return:
        """
        if not self.pe_headers:
            raise AttributeError("pe file headers should be read first")
        try:
            import_entry_header = self.pe_headers.OPTIONAL_HEADER.DATA_DIRECTORY[1]
            export_entry_header = self.pe_headers.OPTIONAL_HEADER.DATA_DIRECTORY[0]
            sections =  self.pe_headers.sections
            size = self.pe_header.DOS_HEADER.sizeof() + self.pe_header.NT_HEADERS.sizeof() + self.pe_header.OPTIONAL_HEADER.sizeof()
        except AttributeError:
            self.corrupted = True
            self.imports = -1
            self.exports = -1
            return

        section_indexes = {s.Name.strip(b'\x00'):i for s,i in enumerate(sections)}


        if not import_entry_header.VirtualAddress or not import_entry_header.Size:
            self.imports = 0
        if not export_entry_header.VirtualAddress or not export_entry_header.Size:
            self.exports = 0

        import_virt_end = import_entry_header.VirtualAddress + import_entry_header.Size
        export_virt_end = export_entry_header.VirtualAddress + export_entry_header.Size
        idata_index =  section_indexes.get(b'.idata', -2)
        edata_index =  section_indexes.get(b'.edata', -2)
        last_index = max(idata_index, edata_index)
        for x in self.pe_headers.sections[:last_index]:
            size+=x.SizeOfRawData
        read_size_min= min(size, import_virt_end, export_virt_end, self.size)
        read_size_max= min(max(size, import_virt_end, export_virt_end), self.size)
        self.local_stream.write(self.data.read(read_size_min-self.headers_read))
        self.local_stream.seek(0)
        self.pe = pefile.PE(data = self.local_stream.read())
        try:
            if self.imports != 0:
                self.pe.DIRECTORY_ENTRY_IMPORT
            if self.exports != 0:
                self.pe.DIRECTORY_ENTRY_EXPORT
        except AttributeError:
            self.local_stream.write(self.data.read(read_size_max - read_size_min))
            self.local_stream.seek(0)
            self.pe = pefile.PE(data=self.local_stream.read())
            try:
                if self.imports != 0:
                    self.pe.DIRECTORY_ENTRY_IMPORT
                if self.exports != 0:
                    self.pe.DIRECTORY_ENTRY_EXPORT
            except AttributeError:
                if self.size > read_size_max:
                    self.local_stream.write(self.data.read(self.size - read_size_max))
                    self.local_stream.seek(0)
                    self.pe = pefile.PE(data=self.local_stream.read())


    def get_architecture(self):
        """
        Get architercutre
        :return: None
        """

        if self.pe_headers.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE:
            self.architecture = 32
        elif self.pe_headers.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS:
            self.architecture = 64
        else:
            raise ValueError("INCORECT PE_TYPE")




    def get_imports_exports(self):
        """
        Get PE import/export tables
        :return: tuple - number of imports, number of exports
        """
        if not self.pe:
            raise AttributeError("Read PE file first")
        try:
            self.exports = self.pe.DIRECTORY_ENTRY_EXPORT.struct.NumberOfFunctions
        except AttributeError:
            self.exports = -1
        try:
            self.imports = sum(len(i.imports) for i in self.pe.DIRECTORY_ENTRY_IMPORT)
        except AttributeError:
            self.imports = -1

    def parse_all_meta(self):
        """
        parse all meta from file stream
        """
        self.meta_parsed= True
        self.read_headers()
        self.get_architecture()
        self.guess_size_and_read()
        self.get_imports_exports()

    def get_all_meta(self):
        """
        Parse meta (if required) and get tuple containing (path, size, type, architecture, meta, imports, exports)
        """
        if not self.meta_parsed:
            self.parse_all_meta()
        return (self.path, self.size, self.extension, self.architecture, self.imports, self.exports)


    def get_short_meta(self):

        """
        Parse meta (if required) and get tuple containing ( architecture, imports, exports)
        """
        if not self.meta_parsed:
            self.parse_all_meta()
        return (self.architecture, self.imports, self.exports)





def main(*args, **kwargs):
    pass



