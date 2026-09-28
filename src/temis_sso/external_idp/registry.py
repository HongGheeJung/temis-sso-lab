class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, object] = {}

    def register(self, name: str, adapter: object) -> None:
        if name in self._providers:
            raise ValueError(f"Provider '{name}' is already registered.")
        self._providers[name] = adapter

    def get(self, name: str) -> object:
        if name not in self._providers:
            raise KeyError(f"unknown provider: '{name}'")
        return self._providers[name]

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))