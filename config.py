from pathlib import Path
from pydantic import BaseSettings, AnyUrl


class Config(BaseSettings):
    bin_author_path: Path
    mongodb_uri: AnyUrl
    mongodb_database: str = "BinAuthor"

    class Config:
        env_file: str = '.env'
