"""
Decoupled Event Publisher Service & Broker Implementations for HMACFR.

Supports In-Memory, Redis Streams, and RabbitMQ event publication
abstracted behind a clean, unified BaseEventPublisher interface.
Moves event publishing logic into the Services layer.
"""

import abc
import json
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logger import log_error_event, log_custody_event


class BaseEventPublisher(abc.ABC):
    """Abstract interface defining the event publisher contract."""

    @abc.abstractmethod
    def publish(self, event_type: str, payload: Dict[str, Any]) -> bool:
        """Publishes an event payload to the underlying broker."""
        pass


class InMemoryEventPublisher(BaseEventPublisher):
    """In-memory event publisher for local testing and standalone backend deployment."""

    def __init__(self):
        self.published_events = []

    def publish(self, event_type: str, payload: Dict[str, Any]) -> bool:
        self.published_events.append({"event_type": event_type, "payload": payload})
        log_custody_event(
            payload.get("evidence_id", "GLOBAL"),
            f"Event Published ({event_type})",
            f"Broker: InMemory | Event: {payload.get('event', event_type)}"
        )
        return True


class RedisStreamsEventPublisher(BaseEventPublisher):
    """Redis Streams event publisher."""

    def __init__(self, redis_url: Optional[str] = None, stream_name: str = "hmacfr_events"):
        self.redis_url = redis_url or getattr(settings, "REDIS_URL", "redis://localhost:6379/0")
        self.stream_name = stream_name

    def publish(self, event_type: str, payload: Dict[str, Any]) -> bool:
        try:
            import redis
            client = redis.Redis.from_url(self.redis_url)
            event_data = {"event_type": event_type, "data": json.dumps(payload)}
            client.xadd(self.stream_name, event_data)
            log_custody_event(payload.get("evidence_id", "GLOBAL"), f"Event Published ({event_type})", f"Broker: RedisStreams -> {self.stream_name}")
            return True
        except Exception as exc:
            log_error_event(f"Redis Streams publication error for '{event_type}': {str(exc)}")
            return False


class RabbitMQEventPublisher(BaseEventPublisher):
    """RabbitMQ AMQP event publisher."""

    def __init__(self, rabbitmq_url: Optional[str] = None, exchange_name: str = "hmacfr_exchange"):
        self.rabbitmq_url = rabbitmq_url or getattr(settings, "RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
        self.exchange_name = exchange_name

    def publish(self, event_type: str, payload: Dict[str, Any]) -> bool:
        try:
            import pika
            params = pika.URLParameters(self.rabbitmq_url)
            connection = pika.BlockingConnection(params)
            channel = connection.channel()
            channel.exchange_declare(exchange=self.exchange_name, exchange_type='topic', durable=True)
            channel.basic_publish(
                exchange=self.exchange_name,
                routing_key=f"events.{event_type.lower()}",
                body=json.dumps(payload),
                properties=pika.BasicProperties(content_type='application/json', delivery_mode=2)
            )
            connection.close()
            log_custody_event(payload.get("evidence_id", "GLOBAL"), f"Event Published ({event_type})", f"Broker: RabbitMQ -> {self.exchange_name}")
            return True
        except Exception as exc:
            log_error_event(f"RabbitMQ publication error for '{event_type}': {str(exc)}")
            return False


class EventPublisherFactory:
    """Factory creating configured EventPublisher instance from environment settings."""

    _instance: Optional[BaseEventPublisher] = None

    @classmethod
    def get_publisher(cls) -> BaseEventPublisher:
        if cls._instance is None:
            broker_type = getattr(settings, "EVENT_BROKER_TYPE", "memory").lower().strip()
            if broker_type == "redis":
                cls._instance = RedisStreamsEventPublisher()
            elif broker_type == "rabbitmq":
                cls._instance = RabbitMQEventPublisher()
            else:
                cls._instance = InMemoryEventPublisher()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None


class EventPublisherService:
    """
    Decoupled Event Publisher Service.
    Formats and dispatches EVIDENCE_READY & CASE_UPLOAD_COMPLETE event payloads.
    """

    @classmethod
    def publish_evidence_ready(
        cls,
        evidence_id: str,
        case_id: str,
        storage_path: str,
        category: str = "Memory",
        status: str = "READY_FOR_PROCESSING"
    ) -> Dict[str, Any]:
        """
        Publishes EVIDENCE_READY event payload:
        {
            "event": "EVIDENCE_READY",
            "evidence_id": "EV001",
            "case_id": "CASE001",
            "storage_path": "...",
            "category": "Memory",
            "status": "READY_FOR_PROCESSING"
        }
        """
        payload = {
            "event": "EVIDENCE_READY",
            "evidence_id": evidence_id,
            "case_id": case_id,
            "storage_path": str(storage_path),
            "category": category,
            "status": status
        }
        publisher = EventPublisherFactory.get_publisher()
        publisher.publish("EVIDENCE_READY", payload)
        return payload

    @classmethod
    def publish_case_upload_complete(cls, case_id: str) -> Dict[str, Any]:
        """
        Publishes CASE_UPLOAD_COMPLETE event payload:
        {
            "event": "CASE_UPLOAD_COMPLETE",
            "case_id": "CASE001"
        }
        """
        payload = {
            "event": "CASE_UPLOAD_COMPLETE",
            "case_id": case_id
        }
        publisher = EventPublisherFactory.get_publisher()
        publisher.publish("CASE_UPLOAD_COMPLETE", payload)
        return payload
