from typing import Generator

class InfiniteRelativeBackoff:
    def __init__(self,
        initial_delay: float = 0.1,
        scaling_factor: float = 2,
        maximum: float = 60,
    ) -> None:
        self.initial_delay = initial_delay
        self.scaling_factor = scaling_factor
        self.maximum = maximum

    def __iter__(self) -> Generator[float, None, None]:
        delay = self.initial_delay
        while True:
            if delay > self.maximum:
                yield self.maximum
            else:
                yield delay
                delay *= self.scaling_factor
