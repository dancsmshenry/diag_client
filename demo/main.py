import asyncio
import sys
from pathlib import Path

DEMO_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = DEMO_DIR.parent
sys.path.insert(0, str(PROJECT_ROOT))

from diag_client.uds import Uds  # noqa: E402
from diag_client.doip_connection import DoipConnection  # noqa: E402

CONFIG_PATH = str(DEMO_DIR / "config.json")
ENTITY_NAME = "tbox"
SOURCE_FILE = str(PROJECT_ROOT / "data" / "example_1G_file")
TARGET_FILE = "/tmp/example_1G_file"


async def main():
    connection = DoipConnection()

    await connection.initialize(CONFIG_PATH, ENTITY_NAME)

    try:
        await connection.routing_activation()

        uds_helper = Uds()

        await uds_helper.check_session(connection, 0x01)

        # await uds_helper.replace_file(connection, SOURCE_FILE, TARGET_FILE)

        # await uds_helper.read_file(connection, TARGET_FILE)

        # await uds_helper.delete_file(connection, TARGET_FILE)
    finally:
        await connection.deinitialize()


if __name__ == "__main__":
    asyncio.run(main())
