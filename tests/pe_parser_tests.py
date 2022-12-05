import pytest
from unittest.mock import Mock
from pe_parser import PeParser

DUMMY_PATH = "test_path/test_name.dll"
TEST_SIZE = 10
SAMPLE_EXE_PATH = "sample_data/RnjRnIOehMGSrJPNFSDpcfiSAIqVSOlr.exe"
SAMPLE_DLL_PATH = "sample_data/0WPbgwBqIxVL5geREPbcIipRGml69qAk.dll"


@pytest.fixture
def mock_peparser():
    return PeParser(DUMMY_PATH, Mock(), TEST_SIZE)

def sample_exe_peparser():
    file_stream = open(SAMPLE_EXE_PATH, "r")
    yield PeParser(SAMPLE_EXE_PATH, file_stream, 543)
    file_stream.close()

def sample_dll_peparser()
    def sample_exe_peparser():
        file_stream = open(SAMPLE_DLL_PATH, "r")
        yield PeParser(SAMPLE_DLL_PATH, file_stream, 528)
        file_stream.close()


class TestPeParser:
    def test_constructor(self, mock_peparser):
        assert mock_peparser.path == DUMMY_PATH
        assert mock_peparser.size == TEST_SIZE
        assert mock_peparser.imports == -1
        assert mock_peparser.exports == -1
        assert mock_peparser.extension == ".dll"
        assert mock_peparser.name == "test_name"
        assert mock.architecture == None

    def test_exe_read_headers(self, sample_exe_peparser):
        assert sample_exe_peparser.size == 543
        assert sample_exe_peparser.path == SAMPLE_EXE_PATH
#        sample_exe_peparser.



