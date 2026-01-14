from src.core.collect import collect_project


class FakeReq:
    def __init__(self, pages):
        self.pages = pages
        self.i = 0

    def execute(self, num_retries=0):
        return self.pages[self.i]


class FakeAgg:
    def __init__(self, pages):
        self.req = FakeReq(pages)

    def aggregatedList(self, project):
        return self.req

    def aggregatedList_next(self, previous_request=None, previous_response=None):
        self.req.i += 1
        if self.req.i >= len(self.req.pages):
            return None
        return self.req


class FakeList:
    def __init__(self, pages):
        self.req = FakeReq(pages)

    def list(self, **kwargs):
        return self.req

    def list_next(self, previous_request=None, previous_response=None):
        self.req.i += 1
        if self.req.i >= len(self.req.pages):
            return None
        return self.req


class FakeCompute:
    def instances(self):
        return FakeAgg(
            [{"items": {"z1": {"instances": [{"name": "vm1"}]}}}, {"items": {}}]
        )

    def firewalls(self):
        return FakeList([{"items": [{"name": "fw1"}]}])

    def networks(self):
        return FakeList([{"items": [{"name": "net1"}]}])

    def subnetworks(self):
        return FakeAgg([{"items": {"r1": {"subnetworks": [{"name": "sub1"}]}}}])


class FakeCRM:
    def projects(self):
        class P:
            def getIamPolicy(self, resource, body):
                class R:
                    def execute(self, num_retries=0):
                        return {"bindings": []}

                return R()

        return P()


class FakeStorageClient:
    def list_buckets(self, project):
        class B:
            def __init__(self, name):
                self.name = name
                self.location = "US"
                self.storage_class = "STANDARD"
                self.labels = {"env": "test"}

        return [B("b1")]


class FakeSQLAdmin:
    def instances(self):
        return FakeList(
            [{"items": [{"name": "sql1", "databaseVersion": "POSTGRES_15"}]}]
        )


def test_collect_project(monkeypatch):
    import fulcrum.core.collect as col

    monkeypatch.setattr(col, "build_compute", lambda creds: FakeCompute())
    monkeypatch.setattr(col, "build_crm", lambda creds: FakeCRM())
    monkeypatch.setattr(col, "build_storage_client", lambda creds: FakeStorageClient())
    monkeypatch.setattr(col, "build_sqladmin", lambda creds: FakeSQLAdmin())
    data = collect_project("p1", creds=None)
    assert data["instances"][0]["name"] == "vm1"
    assert data["buckets"][0]["name"] == "b1"
    assert data["sql_instances"][0]["name"] == "sql1"
