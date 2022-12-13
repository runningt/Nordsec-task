import pytest
from utils import ConfigurationDict


@pytest.fixture
def sample_dict():
    return ConfigurationDict({"spark": {"redis": {"home": "localhost", "port": 6379}}})


class TestConfigurationDict:

    def test_standard_key(self, sample_dict):
        assert sample_dict["spark"] == {"redis": {"home": "localhost", "port": 6379}}
        assert sample_dict.get("redis") == None

    def test_key_error(self, sample_dict):
        with pytest.raises(KeyError):
            sample_dict["redis"]

    def test_dot_separated_key(self, sample_dict):
        assert sample_dict["spark.redis"] == {"home": "localhost", "port": 6379}
        assert sample_dict["spark.redis.home"] == "localhost"
        assert sample_dict["spark.redis.port"] == 6379
        assert sample_dict.get("spark.non_existing") == None
        assert sample_dict.get("spark.redis.non_existing") == None


    @pytest.mark.parametrize("key",("redis", "spark.redis.non_existing", "spark.redis.port.port2"))
    def test_dot_separated_key_error(self, sample_dict, key):
        with pytest.raises(KeyError):
            sample_dict[key]

    def test_dot_key_on_toplevel(self,sample_dict):
        sample_dict["x.y"] = "x.y"
        sample_dict["spark.redis.home"] = "other"
        print(sample_dict)
        assert sample_dict["x.y"] == "x.y"
        assert sample_dict["spark.redis.home"] == "other"
        del sample_dict["spark.redis.home"]
        print(sample_dict)
        assert sample_dict["spark.redis.home"] == "localhost"

    def test_cant_delete_dot_key(self,sample_dict):
        assert sample_dict["spark.redis.port"] == 6379
        with pytest.raises(KeyError):
            del sample_dict["spark.redis.port"]






