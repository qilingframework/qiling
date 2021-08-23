class GPIORevicer:
    def __init__(self) -> None:
        self.connect_state = False

    def connect_gpio(self):
        if not self.connect_state:
            self.connect_state = True

    def unconnect_gpio(self):
        if self.connect_state:
            self.connect_state = False