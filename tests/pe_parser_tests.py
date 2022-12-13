from unittest.mock import Mock

import pytest

from pe_parser import PeParser

DUMMY_PATH = "test_path/test_name.dll"
TEST_SIZE = 10
SAMPLE_EXE_PATH = "tests/sample_data/04wwBoUBnPWiKg5eAH2YNtiy6XGjZV3X.exe"
SAMPLE_EXE_SIZE = 170496
SAMPLE_CORRUPTED_DLL_PATH = "tests/sample_data/0WPbgwBqIxVL5geREPbcIipRGml69qAk.dll"
SAMPLE_CORRUPTED_DLL_SIZE = 528
SAMPLE_CORRUPTED_EXE_PATH = "tests/sample_data/RnjRnIOehMGSrJPNFSDpcfiSAIqVSOlr.exe"
SAMPLE_CORRUPTED_EXE_SIZE = 543


@pytest.fixture
def mock_peparser():
    return PeParser(DUMMY_PATH, Mock(), TEST_SIZE)


@pytest.fixture
def sample_exe_peparser():
    file_stream = open(SAMPLE_EXE_PATH, "br")
    yield PeParser(SAMPLE_EXE_PATH, file_stream, SAMPLE_EXE_SIZE)
    file_stream.close()


@pytest.fixture(
    params=[
        (SAMPLE_CORRUPTED_DLL_PATH, SAMPLE_CORRUPTED_DLL_SIZE),
        (SAMPLE_CORRUPTED_EXE_PATH, SAMPLE_CORRUPTED_EXE_SIZE),
    ],
    ids=["dll", "exe"],
)
def corrupted_file_peparser(request):
    file_stream = open(request.param[0], "br")
    yield PeParser(request.param[0], file_stream, request.param[1])
    file_stream.close()


class TestPeParser:
    def test_constructor(self, mock_peparser):
        assert mock_peparser.path == DUMMY_PATH
        assert mock_peparser.size == TEST_SIZE
        assert mock_peparser.imports == -1
        assert mock_peparser.exports == -1
        assert mock_peparser.extension == "dll"
        assert mock_peparser.name == "test_name"
        assert mock_peparser.architecture is None

    def test_exe_read_headers(self, sample_exe_peparser):
        assert sample_exe_peparser.size == SAMPLE_EXE_SIZE
        assert sample_exe_peparser.path == SAMPLE_EXE_PATH
        sample_exe_peparser.read_headers()
        assert sample_exe_peparser.headers_read

    def test_exe_read_architecture(self, sample_exe_peparser):
        sample_exe_peparser.read_headers()
        sample_exe_peparser.get_architecture()
        assert sample_exe_peparser.architecture == "64"

    def test_guess_size_and_read(self, sample_exe_peparser):
        sample_exe_peparser.read_headers()
        assert sample_exe_peparser.guess_size_and_read() == sample_exe_peparser.data_position

    def test_read_imports_exports(self, sample_exe_peparser):
        sample_exe_peparser.read_headers()
        assert sample_exe_peparser.guess_size_and_read() == sample_exe_peparser.data_position
        assert sample_exe_peparser.get_imports_exports() == (155, 0)

    def test_get_short_meta(self, sample_exe_peparser):
        (architecture, imports, exports) = sample_exe_peparser.get_short_meta()
        assert architecture == "64"
        assert imports == 155
        assert exports == 0

    def test_get_all_meta(self, sample_exe_peparser):
        (path, size, ext, architecture, imports, exports) = sample_exe_peparser.get_all_meta()
        assert path == SAMPLE_EXE_PATH
        assert size == SAMPLE_EXE_SIZE
        assert ext == "exe"
        assert architecture == "64"
        assert imports == 155
        assert exports == 0

    def test_corrupted_peparser_read_headers(self, corrupted_file_peparser):
        with pytest.raises(ValueError):
            corrupted_file_peparser.read_headers()
        assert corrupted_file_peparser.corrupted
