import asyncio
import struct

from enum import IntEnum
from typing import Tuple

from . import doip_config, log


class PayloadType(IntEnum):
    GENERIC_DOIP_NACK = 0x0000
    VEHICLE_IDENTIFICATION_REQUEST = 0x0001
    VEHICLE_IDENTIFICATION_REQUEST_WITH_EID = 0x0002
    VEHICLE_IDENTIFICATION_REQUEST_WITH_VIN = 0x0003
    VEHICLE_IDENTIFICATION_RESPONSE = 0x0004
    ROUTING_ACTIVATION_REQUEST = 0x0005
    ROUTING_ACTIVATION_RESPONSE = 0x0006
    ALIVE_CHECK_REQUEST = 0x0007
    ALIVE_CHECK_RESPONSE = 0x0008
    DOIP_ENTITY_STATUS_REQUEST = 0x4001
    DOIP_ENTITY_STATUS_RESPONSE = 0x4002
    DIAGNOSTIC_POWER_MODE_REQUEST = 0x4003
    DIAGNOSTIC_POWER_MODE_RESPONSE = 0x4004
    DIAGNOSTIC_MESSAGE = 0x8001
    DIAGNOSTIC_MESSAGE_ACK = 0x8002
    DIAGNOSTIC_MESSAGE_NACK = 0x8003


class RoutingActivationACKCode(IntEnum):
    UNKNOWN_SOURCE_ADDRESS = 0x00
    ALL_CONNECTION_ACTIVATED = 0x01
    DIFFERENT_SA_ON_SOCKET = 0x02
    ACTIVED_ON_DIFFERENT_SOCKET = 0x03
    MISS_AUTHENTICATION = 0x04
    REJECTED_CONFIRMATION = 0x05
    UNSUPPORTED_ACTIVATION_TYPE = 0x06
    REQUIRES_SECURE_TLS = 0x07
    ROUTING_ACTIVATED = 0x10
    REQUIRED_CONFIRMATION = 0x11


DOIP_HEADER_LENGTH = 8
DOIP_ADDRESS_LENGTH = 4
ROUTING_ACTIVATION_RESPONSE_MIN_LENGTH = 5

UDS_NEGATIVE_RESPONSE_SID = 0x7F
UDS_RESPONSE_PENDING_NRC = 0x78

logger = log.logger


class DoIPProtocolError(Exception):
    pass


class DoipConnection:
    config: doip_config.DoIPEntity
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter

    async def initialize(self, path: str, name: str) -> None:
        self.config = doip_config.parse_doip_config(path).doip_entities[name]
        self.reader, self.writer = await asyncio.open_connection(
            host=self.config.target_ip,
            port=self.config.target_port,
            local_addr=(self.config.source_ip, 0),
            ssl=False,
        )

    async def deinitialize(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()

    async def routing_activation(self) -> None:
        payload = struct.pack(
            "!HBI",
            self.config.source_address_int,
            self.config.routing_activation_type_int,
            0x00,
        )
        if self.config.routing_activation_vm is not None:
            payload += struct.pack("!I", self.config.routing_activation_vm)

        await self.__send_message(PayloadType.ROUTING_ACTIVATION_REQUEST, payload)

        while True:
            msg_type, payload = await self.__rcvd_message()

            if msg_type == PayloadType.ROUTING_ACTIVATION_RESPONSE:
                self.__check_routing_activation_response(payload)
                return

            if msg_type == PayloadType.ALIVE_CHECK_REQUEST:
                await self.__reply_alive_check()
                continue

            raise DoIPProtocolError("Unexpected response to routing activation")

    def __check_routing_activation_response(self, payload: bytes) -> None:
        if len(payload) < ROUTING_ACTIVATION_RESPONSE_MIN_LENGTH:
            raise DoIPProtocolError(
                f"RoutingActivationResponse too short: {len(payload)}"
            )

        activation_address, _, ack_code = struct.unpack(
            "!HHB", payload[:ROUTING_ACTIVATION_RESPONSE_MIN_LENGTH]
        )

        if activation_address != self.config.source_address_int:
            raise DoIPProtocolError(
                "RoutingActivationResponse address mismatch: "
                f"0x{activation_address:04X} != 0x{self.config.source_address_int:04X}"
            )

        if ack_code != RoutingActivationACKCode.ROUTING_ACTIVATED:
            raise DoIPProtocolError(
                f"Routing activation failed, ack code: 0x{ack_code:02X}"
            )

    async def send_diagnostic_message(self, message: bytes) -> bytes:
        if len(message) < 1:
            raise ValueError("diagnostic message must not be empty")

        payload = (
            struct.pack(
                "!HH",
                self.config.source_address_int,
                self.config.target_address_int,
            )
            + message
        )

        await self.__send_message(PayloadType.DIAGNOSTIC_MESSAGE, payload)

        while True:
            msg_type, payload = await self.__rcvd_message()
            if msg_type == PayloadType.ALIVE_CHECK_REQUEST:
                await self.__reply_alive_check()
                continue
            if msg_type != PayloadType.DIAGNOSTIC_MESSAGE_ACK:
                raise DoIPProtocolError("Expected DiagnosticMessageACK")
            break

        while True:
            msg_type, payload = await self.__rcvd_message()
            if msg_type == PayloadType.ALIVE_CHECK_REQUEST:
                await self.__reply_alive_check()
                continue
            if msg_type != PayloadType.DIAGNOSTIC_MESSAGE:
                raise DoIPProtocolError("Expected DiagnosticMessage")

            if len(payload) <= DOIP_ADDRESS_LENGTH:
                raise DoIPProtocolError(
                    f"DiagnosticMessage payload too short: {len(payload)}"
                )

            _, target_address = struct.unpack("!HH", payload[:DOIP_ADDRESS_LENGTH])
            if target_address != self.config.source_address_int:
                raise DoIPProtocolError(
                    f"Unexpected target address: 0x{target_address:04X}"
                )

            data = payload[DOIP_ADDRESS_LENGTH:]
            if data[0] == UDS_NEGATIVE_RESPONSE_SID:
                if len(data) != 3:
                    raise DoIPProtocolError(
                        f"Malformed negative response: {data.hex()}"
                    )
                if data[1] != message[0]:
                    raise DoIPProtocolError(
                        f"Negative response SID mismatch: 0x{data[1]:02X}"
                    )
                if data[2] == UDS_RESPONSE_PENDING_NRC:
                    logger.info("Rcvd pending uds message")
                    continue

            byte_count = min(len(data), self.config.rcvd_uds_message_log_length)
            logger.info(
                "Rcvd Uds message " + " ".join(f"{b:02x}" for b in data[:byte_count])
            )
            return data

    async def __reply_alive_check(self) -> None:
        if not self.config.reply_alive_check:
            logger.info("AliveCheckRequest ignored (reply_alive_check=false)")
            return

        payload = struct.pack("!H", self.config.source_address_int)
        await self.__send_message(PayloadType.ALIVE_CHECK_RESPONSE, payload)

    async def __send_message(self, msg_type: int, payload: bytes) -> None:
        length = len(payload)
        header = struct.pack(
            "!BBHI",
            self.config.version,
            0xFF ^ self.config.version,
            msg_type,
            length,
        )

        logger.debug(f"Send DoIP message, Type: 0x{msg_type:04X}, Length: {length}")
        self.writer.write(header + payload)
        await self.writer.drain()

    async def __rcvd_message(self) -> Tuple[int, bytes]:
        header = await self.reader.readexactly(DOIP_HEADER_LENGTH)
        _, _, msg_type, length = struct.unpack("!BBHI", header)

        payload = await self.reader.readexactly(length)

        logger.debug(f"Rcvd DoIP message, Type: 0x{msg_type:04X}, Length: {length}")
        return msg_type, payload
