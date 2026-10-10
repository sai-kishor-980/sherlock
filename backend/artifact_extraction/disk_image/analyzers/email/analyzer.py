import email
import mailbox
import zipfile
from email.header import decode_header
from pathlib import Path

from ..base_analyzer import BaseAnalyzer

try:
    import extract_msg
    MSG_AVAILABLE = True

except ImportError:
    MSG_AVAILABLE = False

def decode_str(header_val):
    """
    Decode MIME/email headers safely.
    """

    if not header_val:
        return ""

    decoded_list = decode_header(header_val)

    result = []

    for text, encoding in decoded_list:

        if isinstance(text, bytes):

            try:
                result.append(
                    text.decode(
                        encoding or "utf-8",
                        errors="ignore"
                    )
                )

            except Exception:

                result.append(
                    text.decode(
                        "latin1",
                        errors="ignore"
                    )
                )

        else:

            result.append(str(text))

    return "".join(result)

class EmailAnalyzer(BaseAnalyzer):
    """
    Analyze extracted email evidence.

    Supported:
        - EML
        - MSG
        - MBOX

    Detected but not parsed:
        - PST
        - OST

    Outputs:
        email_messages.json
        email_attachments.json
        email_errors.json
        email_summary.json
    """

    SUPPORTED_SUFFIXES = {
        ".eml",
        ".msg",
        ".mbox",
    }

    UNSUPPORTED_SUFFIXES = {
        ".pst",
        ".ost",
    }

    def analyze(self):

        print(
            "\n[*] Running Email Artifact Analyzer..."
        )

        messages = []
        attachments = []
        errors = []

        detected_files = 0
        unsupported_files = 0

        if not self.extracted_data_dir.exists():

            errors.append({
                "stage": "initialization",
                "error": (
                    "Extracted email directory "
                    "does not exist."
                )
            })

            self._write_outputs(
                messages,
                attachments,
                errors,
                detected_files,
                unsupported_files
            )

            return

        # ======================================================
        # UNPACK ZIP ARCHIVES IF PRESENT
        # ======================================================
        for zip_path in list(self.extracted_data_dir.rglob("*.zip")):
            try:
                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    extract_target = zip_path.parent / f"{zip_path.stem}_unpacked"
                    zip_ref.extractall(extract_target)
            except Exception as exc:
                errors.append({
                    "source_file": zip_path.name,
                    "type": "ZIP",
                    "stage": "extraction",
                    "error": f"Failed to unpack zip archive: {exc}"
                })

        # ======================================================
        # PROCESS FILES
        # ======================================================

        for file_path in list(self.extracted_data_dir.rglob("*")):

            if not file_path.is_file():
                continue

            suffix = file_path.suffix.lower()

            # --------------------------------------------------
            # EML
            # --------------------------------------------------

            if suffix == ".eml":

                detected_files += 1

                self._parse_eml_file(
                    file_path,
                    messages,
                    attachments,
                    errors
                )

            # --------------------------------------------------
            # MSG
            # --------------------------------------------------

            elif suffix == ".msg":

                detected_files += 1

                if MSG_AVAILABLE:

                    self._parse_msg_file(
                        file_path,
                        messages,
                        attachments,
                        errors
                    )

                else:

                    errors.append({
                        "source_file": file_path.name,
                        "type": "MSG",
                        "stage": "dependency",
                        "error": (
                            "extract_msg is not installed."
                        )
                    })

            # --------------------------------------------------
            # MBOX
            # --------------------------------------------------

            elif suffix == ".mbox":

                detected_files += 1

                self._parse_mbox_file(
                    file_path,
                    messages,
                    attachments,
                    errors
                )

            # --------------------------------------------------
            # PST / OST
            # --------------------------------------------------

            elif suffix in self.UNSUPPORTED_SUFFIXES:

                detected_files += 1
                unsupported_files += 1

                errors.append({
                    "source_file": file_path.name,
                    "type": suffix.upper().replace(".", ""),
                    "stage": "analysis",
                    "error": (
                        "PST/OST detected but no PST/OST "
                        "parser is currently configured."
                    )
                })

        # ======================================================
        # OUTPUT
        # ======================================================

        self._write_outputs(
            messages,
            attachments,
            errors,
            detected_files,
            unsupported_files
        )

    # ==========================================================
    # EML
    # ==========================================================

    def _parse_eml_file(
        self,
        eml_path,
        messages,
        attachments,
        errors
    ):

        try:

            with open(
                eml_path,
                "rb"
            ) as f:

                msg = email.message_from_binary_file(f)

            subject = decode_str(
                msg.get("Subject", "")
            )

            from_addr = decode_str(
                msg.get("From", "")
            )

            to_addr = decode_str(
                msg.get("To", "")
            )

            cc_addr = decode_str(
                msg.get("Cc", "")
            )

            date_str = decode_str(
                msg.get("Date", "")
            )

            msg_id = decode_str(
                msg.get("Message-ID", "")
            )

            body = ""

            # --------------------------------------------------
            # Multipart
            # --------------------------------------------------

            if msg.is_multipart():

                for part in msg.walk():

                    content_type = (
                        part.get_content_type()
                    )

                    disposition = str(
                        part.get(
                            "Content-Disposition",
                            ""
                        )
                    )

                    filename = (
                        part.get_filename()
                    )

                    # Attachment
                    if (
                        "attachment" in disposition.lower()
                        or filename
                    ):

                        decoded_filename = decode_str(
                            filename or "unnamed"
                        )

                        payload = part.get_payload(
                            decode=True
                        )

                        attachments.append({
                            "source_file": eml_path.name,
                            "type": "EML",
                            "filename": decoded_filename,
                            "content_type": content_type,
                            "size": len(payload or b"")
                        })

                    # Text body
                    elif (
                        content_type == "text/plain"
                        and not body
                    ):

                        payload = part.get_payload(
                            decode=True
                        )

                        if payload:

                            charset = (
                                part.get_content_charset()
                                or "utf-8"
                            )

                            body = payload.decode(
                                charset,
                                errors="ignore"
                            )[:1000]

            # --------------------------------------------------
            # Single-part message
            # --------------------------------------------------

            else:

                payload = msg.get_payload(
                    decode=True
                )

                if payload:

                    charset = (
                        msg.get_content_charset()
                        or "utf-8"
                    )

                    body = payload.decode(
                        charset,
                        errors="ignore"
                    )[:1000]

            messages.append({
                "source_file": eml_path.name,
                "type": "EML",
                "message_id": msg_id,
                "from": from_addr,
                "to": to_addr,
                "cc": cc_addr,
                "subject": subject,
                "date": date_str,
                "body_preview": body
            })

        except Exception as exc:

            errors.append({
                "source_file": eml_path.name,
                "type": "EML",
                "stage": "parsing",
                "error": str(exc)
            })

    # ==========================================================
    # MSG
    # ==========================================================

    def _parse_msg_file(
        self,
        msg_path,
        messages,
        attachments,
        errors
    ):

        msg = None

        try:

            msg = extract_msg.Message(
                str(msg_path)
            )

            msg.parse()

            messages.append({
                "source_file": msg_path.name,
                "type": "MSG",
                "message_id": str(
                    msg.message_id or ""
                ),
                "from": str(
                    msg.sender or ""
                ),
                "to": str(
                    msg.to or ""
                ),
                "cc": str(
                    getattr(msg, "cc", "") or ""
                ),
                "subject": str(
                    msg.subject or ""
                ),
                "date": str(
                    msg.date or ""
                ),
                "body_preview": str(
                    msg.body or ""
                )[:1000]
            })

            for attachment in msg.attachments:

                filename = (
                    getattr(
                        attachment,
                        "longFilename",
                        None
                    )
                    or getattr(
                        attachment,
                        "shortFilename",
                        None
                    )
                    or "unnamed"
                )

                data = getattr(
                    attachment,
                    "data",
                    None
                )

                attachments.append({
                    "source_file": msg_path.name,
                    "type": "MSG",
                    "filename": str(filename),
                    "size": len(data) if data else 0
                })

        except Exception as exc:

            errors.append({
                "source_file": msg_path.name,
                "type": "MSG",
                "stage": "parsing",
                "error": str(exc)
            })

        finally:

            if msg:

                try:
                    msg.close()

                except Exception:
                    pass

    # ==========================================================
    # MBOX
    # ==========================================================

    def _parse_mbox_file(
        self,
        mbox_path,
        messages,
        attachments,
        errors
    ):

        try:

            mbox = mailbox.mbox(
                str(mbox_path)
            )

            for message in mbox:

                try:

                    subject = decode_str(
                        message.get(
                            "Subject",
                            ""
                        )
                    )

                    from_addr = decode_str(
                        message.get(
                            "From",
                            ""
                        )
                    )

                    to_addr = decode_str(
                        message.get(
                            "To",
                            ""
                        )
                    )

                    cc_addr = decode_str(
                        message.get(
                            "Cc",
                            ""
                        )
                    )

                    date_str = decode_str(
                        message.get(
                            "Date",
                            ""
                        )
                    )

                    msg_id = decode_str(
                        message.get(
                            "Message-ID",
                            ""
                        )
                    )

                    body = ""

                    message_attachments = []

                    # --------------------------------------------------
                    # Multipart MBOX message
                    # --------------------------------------------------

                    if message.is_multipart():

                        for part in message.walk():

                            content_type = (
                                part.get_content_type()
                            )

                            disposition = str(
                                part.get(
                                    "Content-Disposition",
                                    ""
                                )
                            )

                            filename = (
                                part.get_filename()
                            )

                            if (
                                "attachment"
                                in disposition.lower()
                                or filename
                            ):

                                decoded_filename = decode_str(
                                    filename or "unnamed"
                                )

                                payload = part.get_payload(
                                    decode=True
                                )

                                attachment_record = {
                                    "source_file": mbox_path.name,
                                    "type": "MBOX",
                                    "filename": decoded_filename,
                                    "content_type": content_type,
                                    "size": len(
                                        payload or b""
                                    )
                                }

                                attachments.append(
                                    attachment_record
                                )

                                message_attachments.append(
                                    decoded_filename
                                )

                            elif (
                                content_type == "text/plain"
                                and not body
                            ):

                                payload = part.get_payload(
                                    decode=True
                                )

                                if payload:

                                    charset = (
                                        part.get_content_charset()
                                        or "utf-8"
                                    )

                                    body = payload.decode(
                                        charset,
                                        errors="ignore"
                                    )[:1000]

                    else:

                        payload = message.get_payload(
                            decode=True
                        )

                        if payload:

                            body = payload.decode(
                                "utf-8",
                                errors="ignore"
                            )[:1000]

                    messages.append({
                        "source_file": mbox_path.name,
                        "type": "MBOX",
                        "message_id": msg_id,
                        "from": from_addr,
                        "to": to_addr,
                        "cc": cc_addr,
                        "subject": subject,
                        "date": date_str,
                        "body_preview": body,
                        "attachment_count": len(
                            message_attachments
                        )
                    })

                except Exception as exc:

                    errors.append({
                        "source_file": mbox_path.name,
                        "type": "MBOX",
                        "stage": "message_parsing",
                        "error": str(exc)
                    })

            try:
                mbox.close()
            except Exception:
                pass

        except Exception as exc:

            errors.append({
                "source_file": mbox_path.name,
                "type": "MBOX",
                "stage": "opening",
                "error": str(exc)
            })

    # ==========================================================
    # OUTPUT
    # ==========================================================

    def _write_outputs(
        self,
        messages,
        attachments,
        errors,
        detected_files,
        unsupported_files
    ):

        if messages:

            self.write_json(
                "email_messages.json",
                messages
            )

        if attachments:

            self.write_json(
                "email_attachments.json",
                attachments
            )

        if errors:

            self.write_json(
                "email_errors.json",
                errors
            )

        # ======================================================
        # Summary
        # ======================================================

        message_types = {}

        for message in messages:

            message_type = message.get(
                "type",
                "UNKNOWN"
            )

            message_types[
                message_type
            ] = (
                message_types.get(
                    message_type,
                    0
                ) + 1
            )

        attachment_types = {}

        for attachment in attachments:

            attachment_type = attachment.get(
                "type",
                "UNKNOWN"
            )

            attachment_types[
                attachment_type
            ] = (
                attachment_types.get(
                    attachment_type,
                    0
                ) + 1
            )

        if messages:

            if errors:

                status = "completed_with_errors"

            else:

                status = "completed"

        elif unsupported_files:

            status = "unsupported_only"

        elif detected_files == 0:

            status = "no_artifacts_found"

        else:

            status = "failed"

        summary = {
            "artifact": "Email",

            "status": status,

            "statistics": {
                "detected_files": detected_files,
                "messages_parsed": len(messages),
                "attachments_found": len(attachments),
                "errors": len(errors),
                "unsupported_pst_ost": unsupported_files
            },

            "message_types": message_types,

            "attachment_types": attachment_types,

            "parser_support": {
                "EML": True,
                "MSG": MSG_AVAILABLE,
                "MBOX": True,
                "PST": False,
                "OST": False
            },

            "analysis_notes": [
                (
                    "PST/OST files are preserved but are not "
                    "parsed by the current analyzer."
                )
            ]
        }

        self.write_json(
            "email_summary.json",
            summary
        )

        print(
            f"  [+] Messages: {len(messages)}"
        )

        print(
            f"  [+] Attachments: {len(attachments)}"
        )

        print(
            f"  [!] Errors: {len(errors)}"
        )

        print(
            f"  [!] Unsupported PST/OST: "
            f"{unsupported_files}"
        )
