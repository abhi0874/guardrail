"""Print the offline detector decisions for four constructed document observations."""

import asyncio

from .detectors.engine import detect
from .examples import document_observation


async def main() -> None:
    for case in ("within-scope", "outside-scope", "denied", "incomplete"):
        result = await detect(document_observation(case))
        print(f"{case}: {result.verdict.value} — {result.findings[0].explanation}")


if __name__ == "__main__":
    asyncio.run(main())
