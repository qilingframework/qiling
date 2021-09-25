from ....vm.forks.spurious_dragon.state import SpuriousDragonState

from .computation import ByzantiumComputation


class ByzantiumState(SpuriousDragonState):
    computation_class = ByzantiumComputation
