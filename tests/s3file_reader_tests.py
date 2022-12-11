import boto3
import pytest
from unittest import mock


from s3file_reader import S3FileReader

TEST_S3_BUCKET = 's3-nord-challenge-data'
TEST_S3_REGION = 'eu-central-1'


class Test_S3FileReader:
    def test_reader_creation(self):
        reader = S3FileReader(s3_bucket=TEST_S3_BUCKET, region=TEST_S3_REGION)
        assert reader.bucket == TEST_S3_BUCKET
        assert reader.client.meta.region_name == TEST_S3_REGION

    @pytest.mark.parametrize("get_stream_params", (
            {"key":"TEST_KEY"},
            {"key":"TEST_KEY", "range_bytes":22}
    )
    )

    def test_get_file_stream(self, get_stream_params):
        with mock.patch.object(boto3, "client") as client_mock:
            client_mock().get_object.return_value = {"Body": "TestFileBody"}
            reader = S3FileReader(s3_bucket=TEST_S3_BUCKET, region=TEST_S3_REGION)
            res = reader.get_file_stream(*get_stream_params)
            call_args = mock.call(Bucket=TEST_S3_BUCKET, KEY="TEST_KEY")
            if len(get_stream_params.keys()) > 1:
                call_args.kwargs["Range"]=f'bytes=0-{get_stream_params["range_bytes"]}'
            reader.client.get_object.call_args == call_args
            assert res == "TestFileBody"
