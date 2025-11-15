"""
Pydantic models: hello, server_hello, register, login,
dh_client, dh_server, msg, receipt.
"""

from typing import Literal, Union

from pydantic import BaseModel, Field, ConfigDict


# ---------------------------------------------------------------------------
# Base model: allow population by field name AND alias
# ---------------------------------------------------------------------------


class MessageBase(BaseModel):
    # Important: lets us do HelloMsg(client_cert=...) even though the JSON uses "client cert"
    model_config = ConfigDict(populate_by_name=True)


# ---------------------------------------------------------------------------
# Control plane: hello / server_hello / register / login
# ---------------------------------------------------------------------------


class HelloMsg(MessageBase):
    type: Literal["hello"] = "hello"
    # JSON key is "client cert" -> alias
    client_cert: str = Field(alias="client cert")
    nonce: str  # base64 string


class ServerHelloMsg(MessageBase):
    type: Literal["server hello"] = "server hello"
    # JSON key is "server cert" -> alias
    server_cert: str = Field(alias="server cert")
    nonce: str  # base64 string


class RegisterMsg(MessageBase):
    type: Literal["register"] = "register"
    # AES-128(ECB)+PKCS#7-encrypted JSON payload:
    #   {"email": "...", "username": "...", "password": "..."}
    # encoded as base64 for transport.
    ct: str  # base64(ciphertext)


class LoginMsg(MessageBase):
    type: Literal["login"] = "login"
    # AES-128(ECB)+PKCS#7-encrypted JSON payload:
    #   {"email": "...", "password": "..."}
    # encoded as base64 for transport.
    ct: str  # base64(ciphertext)


# ---------------------------------------------------------------------------
# Key agreement (session key DH)
# ---------------------------------------------------------------------------


class DHClientMsg(MessageBase):
    # NOTE: type value has a space, as per spec: "dh client"
    type: Literal["dh client"] = "dh client"
    g: int
    p: int
    A: int


class DHServerMsg(MessageBase):
    # NOTE: type value has a space, as per spec: "dh server"
    type: Literal["dh server"] = "dh server"
    B: int


# ---------------------------------------------------------------------------
# Data plane (encrypted chat)
# ---------------------------------------------------------------------------


class ChatMsg(MessageBase):
    type: Literal["msg"] = "msg"
    seqno: int  # monotonically increasing per sender
    ts: int     # unix ms
    ct: str     # base64(ciphertext)
    sig: str    # base64(RSA SIGN(SHA256(seqno||ts||ct)))


# ---------------------------------------------------------------------------
# Non-repudiation (session receipt)
# ---------------------------------------------------------------------------


class ReceiptMsg(MessageBase):
    type: Literal["receipt"] = "receipt"
    peer: Literal["client", "server"]
    # JSON keys have spaces -> aliases
    first_seq: int = Field(alias="first seq")
    last_seq: int = Field(alias="last seq")
    transcript_sha256: str = Field(alias="transcript sha256")  # hex string
    sig: str  # base64(RSA SIGN(transcript sha256))


# ---------------------------------------------------------------------------
# Union type + JSON helpers
# ---------------------------------------------------------------------------

Message = Union[
    HelloMsg,
    ServerHelloMsg,
    RegisterMsg,
    LoginMsg,
    DHClientMsg,
    DHServerMsg,
    ChatMsg,
    ReceiptMsg,
]


def encode_message(msg: Message) -> str:
    """
    Serialize a message model to a JSON string (one line).

    by_alias=True so that fields like 'client_cert' become "client cert"
    on the wire, matching the assignment exactly.
    """
    return msg.model_dump_json(by_alias=True)


def decode_message(raw: str) -> Message:
    """
    Parse raw JSON string into the correct model, based on 'type'.

    Raises:
        ValueError on unknown type.
    """
    from json import loads

    obj = loads(raw)
    t = obj.get("type")

    if t == "hello":
        return HelloMsg(**obj)
    if t == "server hello":
        return ServerHelloMsg(**obj)
    if t == "register":
        return RegisterMsg(**obj)
    if t == "login":
        return LoginMsg(**obj)
    if t == "dh client":
        return DHClientMsg(**obj)
    if t == "dh server":
        return DHServerMsg(**obj)
    if t == "msg":
        return ChatMsg(**obj)
    if t == "receipt":
        return ReceiptMsg(**obj)

    raise ValueError(f"Unknown message type: {t!r}")
