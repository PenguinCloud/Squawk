
import pytest
import threading

result = {'seq': []}


def run_thread(func, *a):
    t = threading.Thread(target=func, args=a)
    return t


class Foo:
    def __init__(self):
        self._local = threading.local()
        self.local = None

    def init(self, a):
        self.local = self._local
        if a is None:
            self.local = threading.local()
            self.local.a = a
        else:
            self.local.a = a


foo = Foo()


@pytest.fixture
def init_foo():
    def init(key, a, evnt_done=None, evnt_play=None):
        result['seq'].append(key)
        foo.init(a)
        evnt_done and evnt_done.set()
        evnt_play and evnt_play.wait()
        assert foo.local.a == a
        result[key] = foo.local.a
        return foo
    return init


def test_thread(init_foo):
    assert init_foo('t1', 'a1') is foo
    evnt_done = threading.Event()
    evnt_play = threading.Event()
    t2 = run_thread(init_foo, 't2', None, evnt_done, evnt_play)
    t3 = run_thread(init_foo, 't3', 'a3', None, None)
    t2.start()
    evnt_done.wait()
    t3.start()
    t3.join()
    evnt_play.set()
    t2.join()
    assert foo.local.a == 'a1'
    assert result['t2'] == 'a2'
    assert result['t3'] == 'a3'
    assert ','.join(result['seq']) == 't1,t2,t3'
