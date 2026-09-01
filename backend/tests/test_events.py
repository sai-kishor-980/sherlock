"""
Unit Tests for Decoupled Event Publisher Service (InMemory, Redis Streams, RabbitMQ interface).
"""

from app.services.event_publisher import (
    EventPublisherFactory,
    EventPublisherService,
    InMemoryEventPublisher,
    BaseEventPublisher
)


def test_event_publisher_service():
    EventPublisherFactory.reset()
    publisher = EventPublisherFactory.get_publisher()
    assert isinstance(publisher, InMemoryEventPublisher)

    # 1. Test EVIDENCE_READY Event Payload
    evidence_payload = EventPublisherService.publish_evidence_ready(
        evidence_id="EV001",
        case_id="CASE001",
        storage_path="evidence_vault/readonly/CASE001/memory.raw",
        category="Memory",
        status="READY_FOR_PROCESSING"
    )

    assert evidence_payload == {
        "event": "EVIDENCE_READY",
        "evidence_id": "EV001",
        "case_id": "CASE001",
        "storage_path": "evidence_vault/readonly/CASE001/memory.raw",
        "category": "Memory",
        "status": "READY_FOR_PROCESSING"
    }

    # 2. Test CASE_UPLOAD_COMPLETE Event Payload
    case_payload = EventPublisherService.publish_case_upload_complete(case_id="CASE001")
    assert case_payload == {
        "event": "CASE_UPLOAD_COMPLETE",
        "case_id": "CASE001"
    }

    assert len(publisher.published_events) == 2
    assert publisher.published_events[0]["event_type"] == "EVIDENCE_READY"
    assert publisher.published_events[1]["event_type"] == "CASE_UPLOAD_COMPLETE"


if __name__ == "__main__":
    test_event_publisher_service()
    print("ALL EVENT PUBLISHER TESTS PASSED PERFECTLY!")
