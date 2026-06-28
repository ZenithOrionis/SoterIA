import asyncio
import logging
from src.services.llm_gateway import query_swarm_llm

logging.basicConfig(level=logging.DEBUG)

async def main():
    schema = {
        "type": "object",
        "properties": {"answer": {"type": "string"}},
        "required": ["answer"]
    }
    
    print("Testing single...")
    res = await query_swarm_llm("sys", "test1", schema)
    print("Single result:", res)
    
    print("\nTesting concurrent...")
    results = await asyncio.gather(
        query_swarm_llm("sys", "test_a", schema),
        query_swarm_llm("sys", "test_b", schema),
        query_swarm_llm("sys", "test_c", schema)
    )
    print("Concurrent results:", results)

if __name__ == "__main__":
    asyncio.run(main())
