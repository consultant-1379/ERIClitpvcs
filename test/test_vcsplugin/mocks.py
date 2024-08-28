import mock
from litp.core.plugin import Plugin


class DummyPlugin(Plugin):

    @staticmethod
    def callback_method():
        pass


class State(object):
    INITIAL = 0
    APPLIED = 1
    UPDATED = 2
    FOR_REMOVAL = 3


def mock_model_item(vpath="", item_id="", item_type_id="", state=State.INITIAL,
                    autospec=True, **kwargs):
    spec = ['get_vpath', 'is_updated', 'is_applied', 'is_for_removal',
            'is_initial']
    if autospec:
        item = _mock_model_item(**kwargs)
    else:
        item = _mock_model_item(spec, **kwargs)
    item.state = state
    item.get_vpath.return_value = vpath
    item.item_id = item_id
    item.item_type_id = item_type_id
    item.is_updated.side_effect = item._is_updated
    item.is_applied.side_effect = item._is_applied
    item.is_initial.side_effect = item._is_initial
    item.is_for_removal.side_effect = item._is_for_removal
    return item


class _mock_model_item(mock.MagicMock):

    def _is_updated(self):
        return self._state_is(State.UPDATED)

    def _is_initial(self):
        return self._state_is(State.INITIAL)

    def _is_applied(self):
        return self._state_is(State.APPLIED)

    def _is_for_removal(self):
        return self._state_is(State.FOR_REMOVAL)

    def _state_is(self, state):
        return state == self.state

    def set_applied(self):
        self.state = State.APPLIED

    def set_updated(self):
        self.state = State.UPDATED

    def set_initial(self):
        self.state = State.INITIAL

    def set_for_removal(self):
        self.state = State.FOR_REMOVAL


def mock_node(number=1, interfaces=0):
    name = "node{0}".format(number)
    node = mock_model_item("/{0}".format(name), name)
    return node
