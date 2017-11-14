from electrum.plugins import hook
from electrum.util import print_msg
from .keepkey import KeepKeyPlugin
from ..hw_wallet import CmdLineHandler

class Plugin(KeepKeyPlugin):
    handler = CmdLineHandler()

    @hook
    def init_keystore(self, keystore):
        if not isinstance(keystore, self.keystore_class):
            return
        keystore.handler = self.handler
