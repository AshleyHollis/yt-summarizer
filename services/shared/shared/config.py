"""Pydantic settings for application configuration."""

import os
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database connection settings.
    
    Supports multiple environment variable formats for connection strings:
    1. DATABASE_URL - Standard format
    2. ConnectionStrings__sql - .NET Aspire SQL Server connection string
    3. ConnectionStrings__ytsummarizer - .NET Aspire database connection string
    """
    
    model_config = SettingsConfigDict(env_prefix="DATABASE_")
    
    url: str = Field(
        default="",
        description="Database connection URL",
    )
    pool_size: int = Field(
        default=5,
        ge=1,
        le=100,
        description="Connection pool size",
    )
    max_overflow: int = Field(
        default=10,
        ge=0,
        le=100,
        description="Max connections beyond pool size",
    )
    echo: bool = Field(
        default=False,
        description="Echo SQL statements",
    )
    
    @property
    def effective_url(self) -> str:
        """Get the effective database URL, checking Aspire env vars if needed.
        
        Aspire injects SQL Server connection strings in ADO.NET format:
        Server=localhost,port;Database=name;User Id=sa;Password=xxx;TrustServerCertificate=True
        
        This needs to be converted to SQLAlchemy format:
        mssql+pyodbc://sa:password@localhost:port/database?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
        """
        import os
        import re
        
        # Return direct URL if set
        if self.url:
            return self.url
        
        # Check Aspire-injected connection strings
        aspire_conn = (
            os.environ.get("ConnectionStrings__ytsummarizer") or
            os.environ.get("ConnectionStrings__sql") or
            ""
        )
        
        if not aspire_conn:
            return ""
        
        # Parse ADO.NET connection string to SQLAlchemy URL
        return self._convert_ado_to_sqlalchemy(aspire_conn)
    
    def _convert_ado_to_sqlalchemy(self, ado_conn: str) -> str:
        """Convert ADO.NET connection string to SQLAlchemy URL."""
        import re
        from urllib.parse import quote_plus
        
        # Parse key=value pairs (case-insensitive)
        parts = {}
        for part in ado_conn.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                parts[key.strip().lower()] = value.strip()
        
        # Extract components
        server = parts.get("server", "localhost")
        database = parts.get("database", "ytsummarizer")
        user = parts.get("user id", "sa")
        password = parts.get("password", "")
        
        # Server might be in format "host,port" - convert to "host:port"
        if "," in server:
            host, port = server.split(",", 1)
        else:
            host = server
            port = "1433"
        
        # Build SQLAlchemy URL
        encoded_password = quote_plus(password)
        return f"mssql+pyodbc://{user}:{encoded_password}@{host}:{port}/{database}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"


class AzureStorageSettings(BaseSettings):
    """Azure Storage settings.
    
    Supports multiple environment variable formats for connection strings:
    1. AZURE_STORAGE_CONNECTION_STRING - Standard Azure SDK format
    2. ConnectionStrings__storage - .NET Aspire storage connection string
    3. ConnectionStrings__blobs - .NET Aspire blobs endpoint
    """
    
    model_config = SettingsConfigDict(env_prefix="AZURE_STORAGE_")
    
    connection_string: str = Field(
        default="",
        description="Azure Storage connection string",
    )
    account_url: str = Field(
        default="",
        description="Azure Storage account URL (for managed identity)",
    )
    use_managed_identity: bool = Field(
        default=False,
        description="Use Azure managed identity for authentication",
    )
    
    @property
    def effective_connection_string(self) -> str:
        """Get the effective connection string, checking Aspire env vars if needed."""
        import os
        if self.connection_string:
            return self.connection_string
        # Check Aspire-injected connection strings
        return (
            os.environ.get("ConnectionStrings__storage") or
            os.environ.get("ConnectionStrings__blobs") or
            ""
        )


class OpenAISettings(BaseSettings):
    """OpenAI API settings.
    
    Supports both standard OpenAI and Azure OpenAI endpoints.
    For Azure OpenAI, set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY.
    """
    
    model_config = SettingsConfigDict(env_prefix="OPENAI_")
    
    api_key: str = Field(
        default="",
        description="OpenAI API key",
    )
    model: str = Field(
        default="gpt-4o-mini",
        description="OpenAI model for summarization",
    )
    embedding_model: str = Field(
        default="text-embedding-3-small",
        description="OpenAI model for embeddings",
    )
    max_tokens: int = Field(
        default=4096,
        ge=1,
        description="Max tokens for completion",
    )
    temperature: float = Field(
        default=0.3,
        ge=0,
        le=2,
        description="Temperature for completion",
    )
    
    @property
    def effective_api_key(self) -> str:
        """Get the effective API key, preferring Azure OpenAI if configured."""
        import os
        # Prefer Azure OpenAI API key if set
        azure_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
        if azure_key:
            return azure_key
        return self.api_key
    
    @property
    def azure_endpoint(self) -> str | None:
        """Get Azure OpenAI endpoint if configured."""
        import os
        return os.environ.get("AZURE_OPENAI_ENDPOINT") or None
    
    @property  
    def azure_api_version(self) -> str:
        """Get Azure OpenAI API version."""
        import os
        return os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
    
    @property
    def azure_deployment(self) -> str | None:
        """Get Azure OpenAI deployment name if configured."""
        import os
        return os.environ.get("AZURE_OPENAI_DEPLOYMENT") or None
    
    @property
    def azure_embedding_deployment(self) -> str | None:
        """Get Azure OpenAI embedding deployment name if configured."""
        import os
        return os.environ.get("AZURE_OPENAI_EMBEDDING_DEPLOYMENT") or None
    
    @property
    def effective_model(self) -> str:
        """Get the effective model/deployment name.
        
        For Azure OpenAI, uses the deployment name.
        For standard OpenAI, uses the model name.
        """
        if self.azure_deployment:
            return self.azure_deployment
        return self.model
    
    @property
    def effective_embedding_model(self) -> str:
        """Get the effective embedding model/deployment name.
        
        For Azure OpenAI, uses the embedding deployment name.
        For standard OpenAI, uses the embedding model name.
        """
        if self.azure_embedding_deployment:
            return self.azure_embedding_deployment
        return self.embedding_model
    
    @property
    def is_azure_configured(self) -> bool:
        """Check if Azure OpenAI is fully configured."""
        return bool(
            self.azure_endpoint 
            and self.effective_api_key 
            and self.effective_api_key != "not-configured"
        )
    
    @property
    def azure_openai_base_url(self) -> str | None:
        """Build the correct base URL for Azure OpenAI or Azure AI Foundry endpoints.
        
        Azure AI Foundry endpoints (services.ai.azure.com):
            Input:  https://<resource>.services.ai.azure.com/api/projects/<project>
            Output: https://<resource>.services.ai.azure.com/models
            
        Standard Azure OpenAI endpoints (openai.azure.com):
            Input:  https://<resource>.openai.azure.com
            Output: https://<resource>.openai.azure.com (unchanged, deployment in URL handled by SDK)
        """
        endpoint = self.azure_endpoint
        if not endpoint:
            return None
            
        endpoint = endpoint.rstrip('/')
        
        # Check if this is an Azure AI Foundry endpoint
        if "services.ai.azure.com" in endpoint:
            # Azure AI Foundry uses the /models endpoint for OpenAI-compatible inference
            if "/api/projects/" in endpoint:
                # Extract base: https://<resource>.services.ai.azure.com
                base = endpoint.split("/api/projects/")[0]
                return f"{base}/models"
            else:
                return f"{endpoint}/models"
        
        # Standard Azure OpenAI endpoint - return as-is
        return endpoint
    
    @property
    def is_azure_ai_foundry(self) -> bool:
        """Check if this is an Azure AI Foundry endpoint."""
        endpoint = self.azure_endpoint
        return bool(endpoint and "services.ai.azure.com" in endpoint)


class QueueSettings(BaseSettings):
    """Queue settings for workers."""
    
    model_config = SettingsConfigDict(env_prefix="")
    
    transcribe_queue: str = Field(
        default="transcribe-jobs",
        description="Queue name for transcription jobs",
    )
    summarize_queue: str = Field(
        default="summarize-jobs",
        description="Queue name for summarization jobs",
    )
    embed_queue: str = Field(
        default="embed-jobs",
        description="Queue name for embedding jobs",
    )
    relationships_queue: str = Field(
        default="relationships-jobs",
        description="Queue name for relationship jobs",
    )
    visibility_timeout: int = Field(
        default=300,
        ge=1,
        description="Message visibility timeout in seconds",
    )
    max_retries: int = Field(
        default=5,
        ge=0,
        description="Max retries for failed jobs",
    )


class LoggingSettings(BaseSettings):
    """Logging configuration settings."""
    
    model_config = SettingsConfigDict(env_prefix="LOG_")
    
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    json_format: bool = Field(
        default=True,
        description="Use JSON format for logs",
    )


class APISettings(BaseSettings):
    """API server settings."""
    
    model_config = SettingsConfigDict(env_prefix="API_")
    
    host: str = Field(
        default="0.0.0.0",
        description="API server host",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="API server port",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode",
    )
    cors_origins: list[str] = Field(
        default=["http://localhost:3000"],
        description="Allowed CORS origins",
    )


class Settings(BaseSettings):
    """Main application settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="",
        env_nested_delimiter="__",
    )
    
    service_name: str = Field(
        default="yt-summarizer",
        description="Service name for logging",
    )
    service_version: str = Field(
        default="0.1.0",
        description="Service version",
    )
    environment: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment",
    )
    
    # Nested settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    storage: AzureStorageSettings = Field(default_factory=AzureStorageSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    queue: QueueSettings = Field(default_factory=QueueSettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    api: APISettings = Field(default_factory=APISettings)
    
    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"
    
    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance.
    
    Returns:
        The application settings.
    """
    return Settings()


def refresh_settings() -> Settings:
    """Clear settings cache and return fresh settings.
    
    Returns:
        Fresh application settings.
    """
    get_settings.cache_clear()
    return get_settings()
