"""Azure Blob Storage client wrapper."""

import hashlib
import os
from io import BytesIO
from typing import BinaryIO
from urllib.parse import urlparse

from azure.core.exceptions import ResourceExistsError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient, ContentSettings
from azure.storage.blob.aio import BlobServiceClient as AsyncBlobServiceClient
from tenacity import retry, stop_after_attempt, wait_exponential

# Default container names
TRANSCRIPTS_CONTAINER = "transcripts"
SUMMARIES_CONTAINER = "summaries"


def convert_uri_to_connection_string(uri: str, service: str = "blob") -> str:
    """Convert an Aspire-style URI to an Azurite connection string.
    
    Aspire passes URIs like: http://127.0.0.1:32773/devstoreaccount1
    We need to convert to a full connection string for Azurite.
    
    Args:
        uri: The URI from Aspire (e.g., http://127.0.0.1:32773/devstoreaccount1)
        service: The service type (blob, queue, table)
    
    Returns:
        A full Azurite connection string.
    """
    parsed = urlparse(uri)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or 10000  # Default blob port
    account = parsed.path.strip("/") if parsed.path else "devstoreaccount1"
    protocol = parsed.scheme or "http"
    
    # Azurite well-known account key
    account_key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
    
    # Build the connection string with the blob endpoint
    blob_endpoint = f"{protocol}://{host}:{port}/{account}"
    
    return (
        f"DefaultEndpointsProtocol={protocol};"
        f"AccountName={account};"
        f"AccountKey={account_key};"
        f"BlobEndpoint={blob_endpoint}"
    )


def get_connection_string() -> str:
    """Get Azure Storage connection string from environment.
    
    Supports multiple environment variable formats:
    1. AZURE_STORAGE_CONNECTION_STRING - Standard Azure SDK format
    2. ConnectionStrings__storage - .NET Aspire storage connection string
    3. ConnectionStrings__blobs - .NET Aspire blobs endpoint
    
    Aspire may pass a URI (http://...) or a full connection string.
    If a URI is passed, we convert it to a proper Azurite connection string.
    """
    conn_str = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")
    
    if not conn_str:
        conn_str = os.environ.get("ConnectionStrings__storage")
    if not conn_str:
        conn_str = os.environ.get("ConnectionStrings__blobs")
    
    if not conn_str:
        raise ValueError(
            "Azure Storage connection string not found. Set one of: "
            "AZURE_STORAGE_CONNECTION_STRING, ConnectionStrings__storage, "
            "or ConnectionStrings__blobs"
        )
    
    # Check if Aspire passed a URI instead of a connection string
    if conn_str.startswith("http://") or conn_str.startswith("https://"):
        conn_str = convert_uri_to_connection_string(conn_str)
    
    return conn_str


def create_blob_service_client(
    connection_string: str | None = None,
    use_managed_identity: bool = False,
    account_url: str | None = None,
) -> BlobServiceClient:
    """Create a synchronous BlobServiceClient.
    
    Args:
        connection_string: Azure Storage connection string.
        use_managed_identity: If True, use DefaultAzureCredential.
        account_url: Storage account URL (required if using managed identity).
    
    Returns:
        BlobServiceClient instance.
    """
    if use_managed_identity:
        if not account_url:
            raise ValueError("account_url is required when using managed identity")
        credential = DefaultAzureCredential()
        return BlobServiceClient(account_url, credential=credential)
    
    if connection_string is None:
        connection_string = get_connection_string()
    
    return BlobServiceClient.from_connection_string(connection_string)


def create_async_blob_service_client(
    connection_string: str | None = None,
    use_managed_identity: bool = False,
    account_url: str | None = None,
) -> AsyncBlobServiceClient:
    """Create an async BlobServiceClient.
    
    Args:
        connection_string: Azure Storage connection string.
        use_managed_identity: If True, use DefaultAzureCredential.
        account_url: Storage account URL (required if using managed identity).
    
    Returns:
        AsyncBlobServiceClient instance.
    """
    if use_managed_identity:
        if not account_url:
            raise ValueError("account_url is required when using managed identity")
        credential = DefaultAzureCredential()
        return AsyncBlobServiceClient(account_url, credential=credential)
    
    if connection_string is None:
        connection_string = get_connection_string()
    
    return AsyncBlobServiceClient.from_connection_string(connection_string)


def compute_content_hash(content: bytes) -> str:
    """Compute SHA-256 hash of content.
    
    Args:
        content: The content to hash.
    
    Returns:
        Hex-encoded SHA-256 hash.
    """
    return hashlib.sha256(content).hexdigest()


class BlobClient:
    """Wrapper for Azure Blob Storage operations."""
    
    def __init__(
        self,
        connection_string: str | None = None,
        use_managed_identity: bool = False,
        account_url: str | None = None,
    ):
        """Initialize the blob client.
        
        Args:
            connection_string: Azure Storage connection string.
            use_managed_identity: If True, use DefaultAzureCredential.
            account_url: Storage account URL (required if using managed identity).
        """
        self._connection_string = connection_string
        self._use_managed_identity = use_managed_identity
        self._account_url = account_url
        self._client: BlobServiceClient | None = None
    
    @property
    def client(self) -> BlobServiceClient:
        """Get or create the blob service client."""
        if self._client is None:
            self._client = create_blob_service_client(
                connection_string=self._connection_string,
                use_managed_identity=self._use_managed_identity,
                account_url=self._account_url,
            )
        return self._client
    
    def ensure_container(self, container_name: str) -> None:
        """Ensure a container exists, creating it if needed.
        
        Args:
            container_name: Name of the container.
        """
        container_client = self.client.get_container_client(container_name)
        try:
            container_client.create_container()
        except ResourceExistsError:
            pass  # Container already exists
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def upload_blob(
        self,
        container_name: str,
        blob_name: str,
        content: bytes | BinaryIO,
        content_type: str = "application/octet-stream",
        overwrite: bool = True,
    ) -> str:
        """Upload content to a blob.
        
        Args:
            container_name: Name of the container.
            blob_name: Name of the blob.
            content: Content to upload (bytes or file-like object).
            content_type: MIME type of the content.
            overwrite: If True, overwrite existing blob.
        
        Returns:
            The blob URI.
        """
        self.ensure_container(container_name)
        
        blob_client = self.client.get_blob_client(container_name, blob_name)
        content_settings = ContentSettings(content_type=content_type)
        
        if isinstance(content, bytes):
            blob_client.upload_blob(
                content,
                content_settings=content_settings,
                overwrite=overwrite,
            )
        else:
            blob_client.upload_blob(
                content,
                content_settings=content_settings,
                overwrite=overwrite,
            )
        
        return blob_client.url
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        reraise=True,
    )
    def download_blob(
        self,
        container_name: str,
        blob_name: str,
    ) -> bytes:
        """Download blob content.
        
        Args:
            container_name: Name of the container.
            blob_name: Name of the blob.
        
        Returns:
            The blob content as bytes.
        
        Raises:
            ResourceNotFoundError: If the blob doesn't exist.
        """
        blob_client = self.client.get_blob_client(container_name, blob_name)
        downloader = blob_client.download_blob()
        return downloader.readall()
    
    def blob_exists(self, container_name: str, blob_name: str) -> bool:
        """Check if a blob exists.
        
        Args:
            container_name: Name of the container.
            blob_name: Name of the blob.
        
        Returns:
            True if the blob exists, False otherwise.
        """
        blob_client = self.client.get_blob_client(container_name, blob_name)
        return blob_client.exists()
    
    def delete_blob(self, container_name: str, blob_name: str) -> None:
        """Delete a blob.
        
        Args:
            container_name: Name of the container.
            blob_name: Name of the blob.
        """
        blob_client = self.client.get_blob_client(container_name, blob_name)
        try:
            blob_client.delete_blob()
        except ResourceNotFoundError:
            pass  # Blob doesn't exist
    
    def get_blob_url(self, container_name: str, blob_name: str) -> str:
        """Get the URL for a blob.
        
        Args:
            container_name: Name of the container.
            blob_name: Name of the blob.
        
        Returns:
            The blob URL.
        """
        blob_client = self.client.get_blob_client(container_name, blob_name)
        return blob_client.url
    
    def close(self) -> None:
        """Close the blob service client."""
        if self._client is not None:
            self._client.close()
            self._client = None


# Global blob client instance
_blob_client: BlobClient | None = None


def get_blob_client() -> BlobClient:
    """Get the global blob client instance."""
    global _blob_client
    if _blob_client is None:
        _blob_client = BlobClient()
    return _blob_client
