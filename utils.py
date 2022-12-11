from pe_parser import PeParser
from s3file_reader import S3FileReader
def parse_file(row, bucket, region):
    """
    This is a function that is applied using rdd map to each file in Dataframe.
    It parses the given file from s3 and returns meta (architecture, imports, exports) for it.
    In case of error (e.g. corrupted file) it returns None, -1, -1

    :param row: files DataFrame Row ("path", "size", "type")
    :param bucket: S3 bucket
    :param region: S3 region
    :return: parsed files Row ("path", "size", "type", "architecture", "imports", "exports"
    """

    reader = S3FileReader(bucket, region)
    path = row['path'].lstrip("/")
    size = row['size']
    parser = PeParser(path, reader.get_file_stream(path), size)
    try:
        return (*row, *parser.get_short_meta())
    except ValueError:
        return (*row, None, -1, -1)
