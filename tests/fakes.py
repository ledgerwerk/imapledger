def raw_message(subject, sender):
    return f"From: {sender}\r\nTo: me@example.org\r\nSubject: {subject}\r\n\r\n{subject}".encode()


class FolderAwareFakeClient:
    """IMAP fake whose folder-local operations follow selected-folder state."""

    def __init__(self, folders, uidvalidities=None):
        self.folders = {name: dict(messages) for name, messages in folders.items()}
        self.uidvalidities = uidvalidities or {name: 42 for name in folders}
        self.selected_folder = None
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
        uids = self.folders[self.selected_folder]
        if criteria == "ALL":
            return list(uids)
        if isinstance(criteria, (list, tuple)) and len(criteria) == 2 and str(criteria[0]).upper() == "UID":
            requested = int(criteria[1])
            return [uid for uid in uids if uid == requested]
        raise AssertionError(f"unsupported search criteria: {criteria!r}")

    def fetch(self, messages, data, modifiers=None):
        messages = tuple(messages)
        data = tuple(data)
        self.fetches.append((messages, data))
        if self.selected_folder is None:
            raise AssertionError("FETCH requires a selected folder")
        folder = self.folders[self.selected_folder]
        if data == ("RFC822.SIZE",):
            self._maybe_fail("fetch_size")
            return {uid: {b"RFC822.SIZE": len(folder[uid])} for uid in messages if uid in folder}
        self._maybe_fail("fetch_body")
        return {uid: {b"BODY[]": folder[uid]} for uid in messages if uid in folder}

    def move(self, messages, folder):
        self._maybe_fail("move")
        messages = tuple(messages)
        self.moves.append((messages, folder))
        source = self.folders[self.selected_folder]
        destination = self.folders.setdefault(folder, {})
        for uid in messages:
            destination[uid] = source.pop(uid)
        self.selected_folder = folder

    def add_flags(self, messages, flags, silent=False):
        self._maybe_fail("add_flags")
        messages = tuple(messages)
        self.added.append((messages, tuple(flags), silent))
        self.deleted_flags.setdefault(self.selected_folder, set()).update(messages)

    def remove_flags(self, messages, flags, silent=False):
        self._maybe_fail("remove_flags")
        messages = tuple(messages)
        self.removed.append((messages, tuple(flags), silent))
        self.deleted_flags.setdefault(self.selected_folder, set()).difference_update(messages)

    def uid_expunge(self, messages):
        self._maybe_fail("uid_expunge")
        messages = tuple(messages)
        self.expunged.append(messages)
        source = self.folders[self.selected_folder]
        for uid in messages:
            source.pop(uid, None)
