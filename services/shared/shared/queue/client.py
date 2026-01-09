"""Azure Storage Queue client wrapper."""

import base64
import json
import os
from typing import Any

from azure.core.exceptions import ResourceExistsError
from azure.identity import DefaultAzureCredential
from azure.storage.queue import QueueMessage, QueueServiceClient
from azure.storage.queue.aio import QueueServiceClient as AsyncQueueServiceClient
from tenacity import retry, stop_after_attempt, wait_exponential

# Default queue names
TRANSCRIBE_QUEUE = "transcribe-jobs"
SUMMARIZE_QUEUE = "summarize-jobs"
EMBED_QUEUE = "embed-jobs"
RELATIONSHIPS_QUEUE = "relationships-jobs"

# Default visibility timeout (30 seconds)
DEFAULT_VISIBILITY_TIMEOUT = 30


def get_connection_string() -> str:
    """Get Azure Storage connection string from environment.
    
    Supports multiple environment variable formats:
    1. AZURE_STORAGE_CONNECTION_STRING - Standard Azure SDK format
    2. QUEUES_CONNECTIONSTRING - Aspire queue connection string (preferred)
    3. BLOBS_CONNECTIONSTRING - Aspire blob connection string
    4. ConnectionStrings__storage - .NET Aspire storage connection string
    5. ConnectionStrings__blobs - .NET Aspire blobs endpoint
    6. ConnectionStrings__queues - .NET Aspire queues endpoint
    
    Aspire may pass a URI (http://...) or a full connection string.
    If a URI is passed, we convert it to a proper Azurite connection string.
    """
    # Try standard Azure SDK format first
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    
    # Try Aspire-injected connection strings (new format with uppercase)
    if not conn_str:
        conn_str = os.environ.get("QUEUES_CONNECTIONSTRING")
    if not conn_str:
        conn_str = os.environ.get("BLOBS_CONNECTIONSTRING")
    
    # Try legacy Aspire format with double underscore
    if not conn_str:
        conn_str = os.environ.get("ConnectionStrings__storage")
    if not conn_str:
        conn_str = os.environ.get("ConnectionStrings__queues")
    if not conn_str:
        conn_str = os.environ.get("ConnectionStrings__blobs")
    
    if not conn_str:
        # Build helpful error message showing which vars were checked
        checked_vars = [
            "AZURE_STORAGE_CONNECTION_STRING",
            "QUEUES_CONNECTIONSTRING",
            "BLOBS_CONNECTIONSTRING",
            "ConnectionStrings__storage",
            "ConnectionStrings__queues",
            "ConnectionStrings__blobs",
        ]
        available = {k: v[:50] + "..." if v and len(v) > 50 else v 
                     for k, v in os.environ.items() 
                     if "QUEUE" in k.upper() or "BLOB" in k.upper() or "STORAGE" in k.upper()}
        raise ValueError(
            f"Azure Storage connection string not found. Checked: {checked_vars}. "
            f"Available storage-related env vars: {available}"
        )
    
    # Check if Aspire passed a URI instead of a connection string
    if conn_str.startswith("http://") or conn_str.startswith("https://"):
        conn_str = convert_uri_to_connection_string(conn_str)
    
    return conn_str


def convert_uri_to_connection_string(uri: str) -> str:
    """Convert an Aspire-style URI to an Azurite connection string.
    
    Aspire passes URIs like: http://127.0.0.1:32774/devstoreaccount1
    We need to convert to a full connection string for Azurite.
    
    Args:
        uri: The URI from Aspire (e.g., http://127.0.0.1:32774/devstoreaccount1)
    
    Returns:
        A full Azurite connection string.
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 10001  # Default queue port
    account = parsed.path.strip("/") if parsed.path else "devstoreaccount1"
    protocol = parsed.scheme or "http"
    
    # Azurite well-known account key
    account_key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
    
    # Build the connection string with all endpoints
    # We need to figure out the other ports - they're typically sequential
    # Queue is 10001, Blob is 10000, Table is 10002
    # But in Aspire the external ports are mapped differently
    # We'll use the queue endpoint for the queue service
    queue_endpoint = f"{protocol}://{host}:{port}/{account}"
    
    return (
        f"DefaultEndpointsProtocol={protocol};"
        f"AccountName={account};"
        f"AccountKey={account_key};"
        f"QueueEndpoint={queue_endpoint}"
    )


def create_queue_service_client(
    connection_string: str | None = None,
    use_managed_identity: bool = False,
    account_url: str | None = None,
) -> QueueServiceClient:
    """Create a synchronous QueueServiceClient.
    
    Args:
        connection_string: Azure Storage connection string.
        use_managed_identity: If True, use DefaultAzureCredential.
        account_url: Storage account URL (required if using managed identity).
    
    Returns:
        QueueServiceClient instance.
    """
    if use_managed_identity:
        if not account_url:
            raise ValueError("account_url is required when using managed identity")
        credential = DefaultAzureCredential()
        return QueueServiceClient(account_url, credential=credential)
    
    if connection_string is None:
        connection_string = get_connection_string()
    
    return QueueServiceClient.from_connection_string(connection_string)


def create_async_queue_service_client(
    connection_string: str | None = None,
    use_managed_identity: bool = False,
    account_url: str | None = None,
) -> AsyncQueueServiceClient:
    """Create an async QueueServiceClient.
    
    Args:
        connection_string: Azure Storage connection string.
        use_managed_identity: If True, use DefaultAzureCredential.
        account_url: Storage account URL (required if using managed identity).
    
    Returns:
        AsyncQueueServiceClient instance.
    """
    if use_managed_identity:
        if not account_url:
            raise ValueError("account_url is required when using managed identity")
        credential = DefaultAzureCredential()
        return AsyncQueueServiceClient(account_url, credential=credential)
    
    if connection_string is None:
        connection_string = get_connection_string()
    
    return AsyncQueueServiceClient.from_connection_string(connection_string)


def encode_message(message: dict[str, Any]) -> str:
    """Encode a message as base64 JSON for queue storage.
    
    Args:
        message: The message dictionary to encode.
    
    Returns:
        Base64-encoded JSON string.
    """
    json_str = json.dumps(message)
    return base64.b64encode(json_str.encode("utf-8")).decode("utf-8")


def decode_message(message_text: str) -> dict[str, Any]:
    """Decode a base64 JSON message from queue storage.
    
    Args:
        message_text: The base64-encoded JSON string.
    
    Returns:
        The decoded message dictionary.
    """
    try:
        # Try base64 decoding first
        json_str = base64.b64decode(message_text).decode("utf-8")
    except Exception:
        # Fall back to plain JSON
        json_str = message_text
    
    return json.loads(json_str)


class QueueClient:
    """Wrapper for Azure Storage Queue operations."""
    
    def __init__(
        self,
        connection_string: str | None = None,
        use_managed_identity: bool = False,
        account_url: str | None = None,
    ):
        """Initialize the queue client.
        
        Args:
            connection_string: Azure Storage connection string.
            use_managed_identity: If True, use DefaultAzureCredential.
            account_url: Storage account URL (required if using managed identity).
        """
        self._connection_string = connection_string
        self._use_managed_identity = use_managed_identity
        self._account_url = account_url
        self._client: QueueServiceClient | None = None
    
    @property
    def client(self) -> QueueServiceClient:
        """Get or create the queue service client."""
        if self._client is None:
            self._client = create_queue_service_client(
                connection_string=self._connection_string,
                use_managed_identity=self._use_managed_identity,
                account_url=self._account_url,
            )
        return self._client
    
    def ensure_queue(self, queue_name: str) -> None:
        """Ensure a queue exists, creating it if needed.
        
        Args:
            queue_name: Name of the queue.
        """
        queue_client = self.client.get_queue_client(queue_name)
        try:
            queue_client.create_queue()
        except ResourceExistsError:
            pass  # Queue already exists
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def send_message(
        self,
        queue_name: str,
        message: dict[str, Any],
        visibility_timeout: int | None = None,
        time_to_live: int | None = None,
    ) -> str:
        """Send a message to a queue.
        
        Args:
            queue_name: Name of the queue.
            message: Message dictionary to send.
            visibility_timeout: Seconds before message becomes visible.
            time_to_live: Seconds until message expires (default: 7 days).
        
        Returns:
            The message ID.
        """
        self.ensure_queue(queue_name)
        
        queue_client = self.client.get_queue_client(queue_name)
        encoded_message = encode_message(message)
        
        result = queue_client.send_message(
            encoded_message,
            visibility_timeout=visibility_timeout,
            time_to_live=time_to_live,
        )
        
        return result.id
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def receive_messages(
        self,
        queue_name: str,
        max_messages: int = 1,
        visibility_timeout: int = DEFAULT_VISIBILITY_TIMEOUT,
    ) -> list[tuple[QueueMessage, dict[str, Any]]]:
        """Receive messages from a queue.
        
        Args:
            queue_name: Name of the queue.
            max_messages: Maximum number of messages to receive (1-32).
            visibility_timeout: Seconds to hide messages from other consumers.
        
        Returns:
            List of tuples containing (QueueMessage, decoded message dict).
        """
        self.ensure_queue(queue_name)
        
        queue_client = self.client.get_queue_client(queue_name)
        messages = queue_client.receive_messages(
            max_messages=max_messages,
            visibility_timeout=visibility_timeout,
        )
        
        result = []
        for msg in messages:
            decoded = decode_message(msg.content)
            result.append((msg, decoded))
        
        return result
    
    def delete_message(
        self,
        queue_name: str,
        message: QueueMessage,
    ) -> None:
        """Delete a message from a queue (acknowledge processing complete).
        
        Args:
            queue_name: Name of the queue.
            message: The QueueMessage to delete.
        """
        queue_client = self.client.get_queue_client(queue_name)
        queue_client.delete_message(message)
    
    def update_message_visibility(
        self,
        queue_name: str,
        message: QueueMessage,
        visibility_timeout: int,
    ) -> None:
        """Update message visibility timeout (extend processing time).
        
        Args:
            queue_name: Name of the queue.
            message: The QueueMessage to update.
            visibility_timeout: New visibility timeout in seconds.
        """
        queue_client = self.client.get_queue_client(queue_name)
        queue_client.update_message(
            message,
            visibility_timeout=visibility_timeout,
        )
    
    def get_queue_length(self, queue_name: str) -> int:
        """Get the approximate number of messages in a queue.
        
        Args:
            queue_name: Name of the queue.
        
        Returns:
            Approximate message count.
        """
        self.ensure_queue(queue_name)
        
        queue_client = self.client.get_queue_client(queue_name)
        properties = queue_client.get_queue_properties()
        return properties.approximate_message_count or 0
    
    def clear_queue(self, queue_name: str) -> None:
        """Clear all messages from a queue.
        
        Args:
            queue_name: Name of the queue.
        """
        queue_client = self.client.get_queue_client(queue_name)
        queue_client.clear_messages()
    
    def close(self) -> None:
        """Close the queue service client."""
        if self._client is not None:
            self._client.close()
            self._client = None


# Global queue client instance
_queue_client: QueueClient | None = None


def get_queue_client() -> QueueClient:
    """Get the global queue client instance."""
    global _queue_client
    if _queue_client is None:
        _queue_client = QueueClient()
    return _queue_client
