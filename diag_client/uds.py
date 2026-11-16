from os import path

from .doip_connection import DoipConnection
from .uds_util import (
    UdsUtil,
    SID_DIAGNOSTIC_SESSION_CONTROL,
    SID_SECURITY_ACCESS,
    SID_REQUEST_TRANSFER_EXIT,
    SESSION_DEFAULT,
    SESSION_PROGRAMMING,
    SESSION_EXTENDED,
    SECURITY_ACCESS_SEED_LEVEL_1,
    FILE_TRANSFER_MODE_ADD,
    FILE_TRANSFER_MODE_REPLACE,
    FILE_TRANSFER_MODE_READ,
    TRANSFER_DATA_OVERHEAD,
)


class Uds:
    async def check_session(self, connection: DoipConnection, session: int) -> bytes:
        return await connection.send_diagnostic_message(
            bytes([SID_DIAGNOSTIC_SESSION_CONTROL, session])
        )

    async def check_security_level(
        self, connection: DoipConnection, level: int
    ) -> bytes:
        response = await connection.send_diagnostic_message(
            bytes([SID_SECURITY_ACCESS, level])
        )
        subfunction = (level + 1) % 0x100
        key = response[2:][::-1]
        return await connection.send_diagnostic_message(
            bytes([SID_SECURITY_ACCESS, subfunction]) + key
        )

    async def add_file(
        self, connection: DoipConnection, source: str, target: str
    ) -> None:
        await self.__download_file(connection, FILE_TRANSFER_MODE_ADD, source, target)

    async def replace_file(
        self, connection: DoipConnection, source: str, target: str
    ) -> None:
        await self.__download_file(
            connection, FILE_TRANSFER_MODE_REPLACE, source, target
        )

    async def read_file(self, connection: DoipConnection, target: str) -> None:
        await self.__upload_file(connection, FILE_TRANSFER_MODE_READ, target)

    async def delete_file(self, connection: DoipConnection, target: str) -> None:
        await self.__check_to_request_file_transfer_mode(connection)

        await connection.send_diagnostic_message(
            UdsUtil.make_delete_file_request(target)
        )

    """
    ------------------------- Private separator -------------------------
    """

    async def __download_file(
        self, connection: DoipConnection, mode: int, source: str, target: str
    ) -> None:
        await self.__check_to_request_file_transfer_mode(connection)

        response = await connection.send_diagnostic_message(
            UdsUtil.make_download_file_request(mode, source, target)
        )

        file_size = path.getsize(source)
        block_size = UdsUtil.get_max_block_length(response)
        block_id = 1

        with open(source, "rb") as fd:
            while file_size > 0:
                size = min(block_size, file_size)

                buffer = fd.read(size)
                if len(buffer) != size:
                    raise ValueError(
                        f"short read: expected {size} bytes, got {len(buffer)}"
                    )

                await connection.send_diagnostic_message(
                    UdsUtil.make_36_download_request(block_id, buffer)
                )

                file_size -= size
                block_id = (block_id + 1) % 0x100

        await connection.send_diagnostic_message(bytes([SID_REQUEST_TRANSFER_EXIT]))

    async def __upload_file(
        self, connection: DoipConnection, mode: int, target: str
    ) -> None:
        await self.__check_to_request_file_transfer_mode(connection)

        response = await connection.send_diagnostic_message(
            UdsUtil.make_upload_file_request(mode, target)
        )

        total_size = UdsUtil.get_uncompressed_length(response)
        block_id = 1
        while total_size > 0:
            response = await connection.send_diagnostic_message(
                UdsUtil.make_36_upload_request(block_id)
            )

            total_size -= len(response) - TRANSFER_DATA_OVERHEAD
            block_id = (block_id + 1) % 0x100

        await connection.send_diagnostic_message(bytes([SID_REQUEST_TRANSFER_EXIT]))

    async def __check_to_request_file_transfer_mode(
        self, connection: DoipConnection
    ) -> None:
        await self.check_session(connection, SESSION_DEFAULT)

        await self.check_session(connection, SESSION_EXTENDED)

        await self.check_security_level(connection, SECURITY_ACCESS_SEED_LEVEL_1)

        await self.check_session(connection, SESSION_PROGRAMMING)

        await self.check_security_level(connection, SECURITY_ACCESS_SEED_LEVEL_1)
