from ....vm.forks.homestead.state import HomesteadState

from .computation import TangerineWhistleComputation


class TangerineWhistleState(HomesteadState):
    computation_class = TangerineWhistleComputation
