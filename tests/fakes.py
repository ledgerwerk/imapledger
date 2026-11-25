from email import policy
from email.parser import BytesHeaderParser


def raw_message(subject, sender):
    return f"From: {sender}\r\nTo: me@example.org\r\nSubject: {subject}\r\n\r\n{subject}".encode()


class FolderAwareFakeClient:
    """IMAP fake whose folder-local operations follow selected-folder state."""

    def __init__(self, folders, uidvalidities=None, permanent_flags=None, flags=None):
        self.folders = {name: dict(messages) for name, messages in folders.items()}
        self.uidvalidities = uidvalidities or {name: 42 for name in folders}
        self.permanent_flags = (
            permanent_flags
            if permanent_flags is not None
            else {name: (b"\\Answered", b"\\Flagged", b"\\Draft", b"\\Deleted", b"\\Seen", b"\\*") for name in folders}
        )
        initial_flags = flags or {}
        self.flags = {
            name: {uid: set(message_flags) for uid, message_flags in initial_flags.get(name, {}).items()}
            for name in folders
        }
        self.selected_folder = None
        self.use_uid = True
        self.selected = []
        self.existing_folders = set(folders)
        self.folder_queries = []
        self.calls = []
        self.searches = []
        self.fetches = []
        self.moves = []
        self.added = []
        self.removed = []
        self.expunged = []
        self.deleted_flags = {}
        self.logged_out = False
        self.login_args = None
        self._capabilities = (b"IMAP4rev1", b"UIDPLUS", b"MOVE")
        self.fail_on = None

    def _maybe_fail(self, operation):
        if self.fail_on == operation or (isinstance(self.fail_on, set) and operation in self.fail_on):
            raise RuntimeError("IMAP command failed")

    def login(self, username, password):
        self.calls.append("login")
        self._maybe_fail("login")
        self.login_args = (username, password)

    def logout(self):
        self.calls.append("logout")
        self.logged_out = True

    def capabilities(self):
        self.calls.append("capabilities")
        self._maybe_fail("capabilities")
        return self._capabilities

    def select_folder(self, folder, readonly=False):
        self.calls.append("select")
        self._maybe_fail("select")
        self.selected.append((folder, readonly))
        self.selected_folder = folder
        return {
            b"UIDVALIDITY": self.uidvalidities[folder],
            b"EXISTS": len(self.folders[folder]),
            b"FLAGS": (),
            b"PERMANENTFLAGS": self.permanent_flags.get(folder),
            b"RECENT": 0,
        }

    def folder_exists(self, folder):
        self.calls.append("folder_exists")
        self._maybe_fail("folder_exists")
        self.folder_queries.append(folder)
        if folder in self.folders:
            self.selected_folder = folder
        return folder in self.folders

    def search(self, criteria="ALL", charset=None):
        self.calls.append("search")
        self.searches.append(criteria)
        self._maybe_fail("search")
        if self.selected_folder is None:
            raise AssertionError("SEARCH requires a selected folder")
        folder_uids = self.folders[self.selected_folder]
        if criteria == "ALL":
            return list(folder_uids)
        if isinstance(criteria, (list, tuple)):
            if len(criteria) == 2 and str(criteria[0]).upper() == "UID":
                requested = int(criteria[1])
                return [uid for uid in folder_uids if uid == requested]
            if len(criteria) % 2:
                raise AssertionError(f"unsupported search criteria: {criteria!r}")
            found = set(folder_uids)
            current_flags = self.flags[self.selected_folder]
            for operation, argument in zip(criteria[::2], criteria[1::2], strict=True):
                operation = str(operation).upper()
                keyword = argument.decode("ascii") if isinstance(argument, bytes) else str(argument)
                if operation not in {"KEYWORD", "UNKEYWORD"}:
                    raise AssertionError(f"unsupported search criteria: {criteria!r}")
                matching = {
                    uid
                    for uid in folder_uids
                    if any(
                        (flag.decode("ascii", errors="replace") if isinstance(flag, bytes) else str(flag)).casefold()
                        == keyword.casefold()
                        for flag in current_flags.get(uid, set())
                    )
                }
                found &= matching if operation == "KEYWORD" else set(folder_uids) - matching
            return sorted(found)
        raise AssertionError(f"unsupported search criteria: {criteria!r}")

    def fetch(self, messages, data, modifiers=None):
        if isinstance(messages, str):
            messages = (messages,)
        elif isinstance(messages, int):
            messages = (messages,)
        else:
            messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if self.selected_folder is None:
            raise AssertionError("FETCH requires a selected folder")
        folder = self.folders[self.selected_folder]
        if data == ("UID",):
            self._maybe_fail("uid_snapshot")
            requested = set(folder) if messages == ("1:*",) else set(messages)
            return {
                uid: {b"UID": uid, b"SEQ": sequence} for sequence, uid in enumerate(folder, start=1) if uid in requested
            }
        if data == ("RFC822.SIZE",):
            self._maybe_fail("fetch_size")
            return {uid: {b"RFC822.SIZE": len(folder[uid])} for uid in messages if uid in folder}
        if data == ("FLAGS",):
            self._maybe_fail("fetch_flags")
            current_flags = self.flags[self.selected_folder]
            return {uid: {b"FLAGS": tuple(current_flags.get(uid, set()))} for uid in messages if uid in folder}
        if len(data) == 1 and str(data[0]).startswith("BODY.PEEK[HEADER.FIELDS"):
            self._maybe_fail("fetch_headers")
            names = ("From", "Subject", "Date", "Message-ID")
            result = {}
            for uid in messages:
                if uid not in folder:
                    continue
                raw_headers = folder[uid].split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                parsed = BytesHeaderParser(policy=policy.default).parsebytes(raw_headers)
                selected_headers = (
                    b"".join(f"{name}: {value}\r\n".encode() for name in names for value in parsed.get_all(name, []))
                    + b"\r\n"
                )
                result[uid] = {b"BODY[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)]": selected_headers}
            return result
        self._maybe_fail("fetch_body")
        return {uid: {b"BODY[]": folder[uid]} for uid in messages if uid in folder}

    def move(self, messages, folder):
        self._maybe_fail("move")
        messages = tuple(messages)
        self.moves.append((messages, folder))
        source = self.folders[self.selected_folder]
        destination = self.folders.setdefault(folder, {})
        source_flags = self.flags[self.selected_folder]
        destination_flags = self.flags.setdefault(folder, {})
        self.permanent_flags.setdefault(folder, ())
        for uid in messages:
            destination[uid] = source.pop(uid)
            destination_flags[uid] = source_flags.pop(uid, set())
        self.selected_folder = folder

    def add_flags(self, messages, flags, silent=False):
        self._maybe_fail("add_flags")
        messages = tuple(messages)
        flags = tuple(flags)
        self.added.append((messages, flags, silent))
        folder_flags = self.flags[self.selected_folder]
        for uid in messages:
            if uid in self.folders[self.selected_folder]:
                folder_flags.setdefault(uid, set()).update(_flag_bytes(flag).lower() for flag in flags)
        if any(_flag_bytes(flag).lower() == b"\\deleted" for flag in flags):
            self.deleted_flags.setdefault(self.selected_folder, set()).update(messages)

    def remove_flags(self, messages, flags, silent=False):
        self._maybe_fail("remove_flags")
        messages = tuple(messages)
        flags = tuple(flags)
        self.removed.append((messages, flags, silent))
        folder_flags = self.flags[self.selected_folder]
        remove = {_flag_bytes(flag).lower() for flag in flags}
        for uid in messages:
            folder_flags.setdefault(uid, set()).difference_update(remove)
        if b"\\deleted" in remove:
            self.deleted_flags.setdefault(self.selected_folder, set()).difference_update(messages)

    def uid_expunge(self, messages):
        self._maybe_fail("uid_expunge")
        messages = tuple(messages)
        self.expunged.append(messages)
        source = self.folders[self.selected_folder]
        for uid in messages:
            source.pop(uid, None)
            self.flags[self.selected_folder].pop(uid, None)


def _flag_bytes(flag):
    return flag if isinstance(flag, bytes) else str(flag).encode("ascii")


class ConfigStoreFakeClient:
    """Strict deterministic fake for fixed-folder config-store IMAP operations."""

    def __init__(self, folders, uidvalidities=None):
        self.folders = {name: dict(messages) for name, messages in folders.items()}
        self.uidvalidities = uidvalidities or {name: 42 for name in folders}
        self.selected_folder = None
        self.selected_folders = []
        self.readonly_selections = []
        self.folder_queries = []
        self.searches = []
        self.fetch_selectors = []
        self.appends = []
        self.login_args = None
        self.logged_out = False
        self.calls = []
        self.fail_on = None

    def _maybe_fail(self, operation):
        if self.fail_on == operation or (isinstance(self.fail_on, set) and operation in self.fail_on):
            raise RuntimeError("fake IMAP failure")

    def login(self, username, password):
        self.calls.append("login")
        self._maybe_fail("login")
        self.login_args = (username, password)

    def logout(self):
        self.calls.append("logout")
        self.logged_out = True

    def capabilities(self):
        self.calls.append("capabilities")
        return (b"IMAP4rev1", b"UIDPLUS")

    def folder_exists(self, folder):
        self.calls.append("folder_exists")
        self._maybe_fail("folder_exists")
        self.folder_queries.append(folder)
        return folder in self.folders

    def select_folder(self, folder, readonly=False):
        self.calls.append("select")
        self._maybe_fail("select")
        if folder not in self.folders:
            raise AssertionError(f"cannot select unknown folder: {folder}")
        self.selected_folder = folder
        self.selected_folders.append(folder)
        self.readonly_selections.append(readonly)
        return {b"UIDVALIDITY": self.uidvalidities[folder], b"EXISTS": len(self.folders[folder])}

    def search(self, criteria, charset=None):
        self.calls.append("search")
        self.searches.append(criteria)
        self._maybe_fail("search")
        if self.selected_folder is None:
            raise AssertionError("SEARCH requires a selected folder")
        if not isinstance(criteria, (list, tuple)) or len(criteria) == 0 or len(criteria) % 3:
            raise AssertionError(f"unsupported config-store search criteria: {criteria!r}")
        if any(str(criteria[index]).upper() != "HEADER" for index in range(0, len(criteria), 3)):
            raise AssertionError(f"unsupported config-store search criteria: {criteria!r}")
        found = []
        for uid, raw in self.folders[self.selected_folder].items():
            headers = BytesHeaderParser(policy=policy.default).parsebytes(raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n")
            if all(
                any(
                    str(value).casefold().find(str(criteria[index + 2]).casefold()) >= 0
                    for value in headers.get_all(str(criteria[index + 1]), [])
                )
                for index in range(0, len(criteria), 3)
            ):
                found.append(uid)
        return sorted(found)

    def fetch(self, messages, data, modifiers=None):
        self.calls.append("fetch")
        messages = tuple(messages)
        data = tuple(data)
        self.fetch_selectors.append(data)
        self._maybe_fail("fetch")
        if self.selected_folder is None:
            raise AssertionError("FETCH requires a selected folder")
        folder = self.folders[self.selected_folder]
        selector = str(data[0]) if len(data) == 1 else ""
        if selector.startswith("BODY.PEEK[HEADER.FIELDS"):
            start, end = selector.find("("), selector.rfind(")")
            if start < 0 or end <= start:
                raise AssertionError(f"malformed header selector: {selector}")
            names = selector[start + 1 : end].split()
            response_key = f"BODY[HEADER.FIELDS ({' '.join(names)})]".encode("ascii")
            result = {}
            for uid in messages:
                raw = folder.get(uid)
                if raw is None:
                    continue
                headers = BytesHeaderParser(policy=policy.default).parsebytes(
                    raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                )
                selected = b"".join(
                    f"{name}: {value}\r\n".encode() for name in names for value in headers.get_all(name, [])
                )
                result[uid] = {response_key: selected + b"\r\n"}
            return result
        if selector == "BODY.PEEK[]":
            return {uid: {b"BODY[]": folder[uid]} for uid in messages if uid in folder}
        raise AssertionError(f"unsupported config-store FETCH selector: {data!r}")

    def append(self, folder, message, flags=None, msg_time=None):
        self.calls.append("append")
        self._maybe_fail("append")
        self.appends.append((folder, flags, msg_time, bytes(message)))
        if folder not in self.folders:
            raise AssertionError(f"APPEND to unknown folder: {folder}")
        next_uid = max(self.folders[folder], default=0) + 1
        self.folders[folder][next_uid] = bytes(message)
