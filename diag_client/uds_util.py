import struct

from os import path

from .log import logger

SID_DIAGNOSTIC_SESSION_CONTROL = 0x10
SID_SECURITY_ACCESS = 0x27
SID_TRANSFER_DATA = 0x36
SID_REQUEST_TRANSFER_EXIT = 0x37
SID_REQUEST_FILE_TRANSFER = 0x38

SESSION_DEFAULT = 0x01
SESSION_PROGRAMMING = 0x02
SESSION_EXTENDED = 0x03

SECURITY_ACCESS_SEED_LEVEL_1 = 0x01

FILE_TRANSFER_MODE_ADD = 0x01
FILE_TRANSFER_MODE_DELETE = 0x02
FILE_TRANSFER_MODE_REPLACE = 0x03
FILE_TRANSFER_MODE_READ = 0x04
FILE_TRANSFER_FORMAT_IDENTIFIER_UNCOMPRESSED = 0x00

UINT16_SIZE = 2
UINT32_SIZE = 4
TRANSFER_DATA_OVERHEAD = 2


class UdsUtil:
    @staticmethod
    def make_delete_file_request(target: str) -> bytes:
        target_bytes = target.encode("utf-8")
        path_length = len(target_bytes).to_bytes(UINT16_SIZE, "big", signed=False)

        return (
            bytes([SID_REQUEST_FILE_TRANSFER, FILE_TRANSFER_MODE_DELETE])
            + path_length
            + target_bytes
        )

    @staticmethod
    def make_upload_file_request(mode: int, target: str) -> bytes:
        target_bytes = target.encode("utf-8")
        path_length = len(target_bytes).to_bytes(UINT16_SIZE, "big", signed=False)

        return (
            bytes([SID_REQUEST_FILE_TRANSFER, mode])
            + path_length
            + target_bytes
            + b"\x00"
        )

    @staticmethod
    def make_download_file_request(mode: int, source: str, target: str) -> bytes:
        target_bytes = target.encode("utf-8")
        path_length = len(target_bytes).to_bytes(UINT16_SIZE, "big", signed=False)

        file_size = path.getsize(source)
        file_size_bytes = file_size.to_bytes(UINT32_SIZE, "big", signed=False)

        return (
            bytes([SID_REQUEST_FILE_TRANSFER, mode])
            + path_length
            + target_bytes
            + bytes([FILE_TRANSFER_FORMAT_IDENTIFIER_UNCOMPRESSED, UINT32_SIZE])
            + file_size_bytes
            + file_size_bytes
        )

    @staticmethod
    def make_36_download_request(block_id: int, buffer: bytes) -> bytes:
        return bytes([SID_TRANSFER_DATA, block_id]) + buffer

    @staticmethod
    def make_36_upload_request(block_id: int) -> bytes:
        return bytes([SID_TRANSFER_DATA, block_id])

    @staticmethod
    def get_max_block_length(buf: bytes) -> int:
        length_format_identifier = buf[2]

        if length_format_identifier != UINT32_SIZE:
            raise ValueError(
                f"need exactly {UINT32_SIZE} bytes for uint32, "
                f"but lengthFormatIdentifier={length_format_identifier}"
            )

        start = 3
        end = start + length_format_identifier

        if end > len(buf):
            raise ValueError(f"buffer too short: need {end} bytes, got {len(buf)}")

        value = struct.unpack(">I", buf[start:end])[0]

        # remove service id and block id
        return value - TRANSFER_DATA_OVERHEAD

    @staticmethod
    def get_uncompressed_length(data: bytes) -> int:
        i = 0
        total_len = len(data)

        if total_len < i + 1:
            raise ValueError("payload too short: missing SID and offset")
        i += 1

        if total_len < i + 1:
            raise ValueError("payload too short: missing mode")
        i += 1

        if total_len < i + 1:
            raise ValueError("payload too short: missing lengthFormatIdentifier")
        length_format_identifier = data[i]
        i += 1

        if total_len < i + length_format_identifier:
            raise ValueError("payload too short: missing maxNumberOfBlockLength")
        i += length_format_identifier

        if total_len < i + 1:
            raise ValueError("payload too short: missing formatIdentifier")
        i += 1

        if total_len < i + UINT16_SIZE:
            raise ValueError(
                "payload too short: missing fileSizeOrDirInfoParameterLength"
            )
        parameter_length = int.from_bytes(data[i : i + UINT16_SIZE], byteorder="big")
        i += UINT16_SIZE

        if total_len < i + parameter_length:
            raise ValueError("payload too short: missing uncompressedLength")
        uncompressed_length = int.from_bytes(
            data[i : i + parameter_length], byteorder="big"
        )

        if total_len < i + parameter_length:
            raise ValueError("payload too short: missing compressedLength")
        i += parameter_length

        if i != total_len:
            logger.warning(f"{total_len - i} trailing bytes were not parsed")

        return uncompressed_length
