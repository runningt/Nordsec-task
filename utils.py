from pe_parser import PeParser
from s3file_reader import S3FileReader
from collections import UserDict
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


class ConfigurationDict(UserDict):
    """
    Custom dictionary that allows to retrieve values from nested dictionaries using keys concatenated by "."
    If dot separated key exist in top-level dict
    e.g.
    if config dict is {"spark":{"redis":{"home":"localhost", "port": 6379}}}
    you can get values using
    redis_home = config["spark.redis.home"] or config.get("spark.redis.home")
    redis_port = config["spark.redis.port"] or config.get("spark.redis.port")
    """
    def __getitem__(self, key):
        if "." not in key or key in self:
            return super().__getitem__(key)
        try:
            value = self
            for key_part in key.split("."):
                value = value[key_part]
            return value
        except (TypeError, KeyError):
            raise KeyError(key)
