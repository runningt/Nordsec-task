import pytest

from s3file_reader import S3FileReader

TEST_S3_BUCKET = 's3-nord-challenge-data'
TEST_S3_REGION = 'eu-central-1'
@pytest.fixture
def s3filereader():
    return S3FileReader(s3_bucket=TEST_S3_BUCKET, region=TEST_S3_REGION)

class TestS3FileReader:
    def test_reader_creation(self, s3filereader):
        assert s3filereader.bucket == TEST_S3_BUCKET
        assert s3filereader.client.meta.region_name == TEST_S3_REGION

