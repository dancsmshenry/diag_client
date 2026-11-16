import json

from typing import Optional, Dict
from dataclasses import dataclass, field

DEFAULT_DOIP_VERSION = 3
DEFAULT_TARGET_PORT = 13400
DEFAULT_REPLY_ALIVE_CHECK = True


@dataclass
class DoIPEntity:
    name: str
    version: int
    source_ip: str
    source_address: str
    target_ip: str
    target_address: str
    target_port: int
    routing_activation_type: str
    routing_activation_vm: Optional[int] = None
    rcvd_uds_message_log_length: int = 10
    reply_alive_check: bool = DEFAULT_REPLY_ALIVE_CHECK

    _source_address_int: int = field(init=False, repr=False)
    _target_address_int: int = field(init=False, repr=False)
    _routing_activation_type_int: int = field(init=False, repr=False)

    def __post_init__(self):
        self._source_address_int = int(self.source_address, 16)
        self._target_address_int = int(self.target_address, 16)
        self._routing_activation_type_int = int(self.routing_activation_type, 16)

    @property
    def source_address_int(self) -> int:
        return self._source_address_int

    @property
    def target_address_int(self) -> int:
        return self._target_address_int

    @property
    def routing_activation_type_int(self) -> int:
        return self._routing_activation_type_int


@dataclass
class DoIPConfig:
    doip_entities: Dict[str, DoIPEntity]


def parse_doip_config(file_path: str) -> DoIPConfig:
    with open(file_path, "r") as file:
        file_data = json.load(file)

    entities_dict: Dict[str, DoIPEntity] = {}
    for data in file_data.get("doip_entity", []):
        try:
            entity = DoIPEntity(
                name=data["name"],
                source_ip=data["source_ip"],
                target_ip=data["target_ip"],
                source_address=data["source_address"],
                target_address=data["target_address"],
                routing_activation_type=data["routing_activation_type"],
                #
                routing_activation_vm=data.get("routing_activation_vm"),
                #
                version=data.get("version", DEFAULT_DOIP_VERSION),
                target_port=data.get("target_port", DEFAULT_TARGET_PORT),
                rcvd_uds_message_log_length=data.get("rcvd_uds_message_log_length", 10),
                reply_alive_check=data.get(
                    "reply_alive_check", DEFAULT_REPLY_ALIVE_CHECK
                ),
            )
        except KeyError as e:
            raise ValueError(f"config: {e} must been configured") from e

        if entity.name in entities_dict:
            raise ValueError(f"Redundancy config '{entity.name}'")

        entities_dict[entity.name] = entity

    return DoIPConfig(doip_entities=entities_dict)
