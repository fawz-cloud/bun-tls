# curl_cffi side of the benchmark. Start `bun bench/server.ts` first.
# Self-signed server cert, so verify=False here as well. Medians after a warmup.
# Same scenarios as bench/bun.ts: a new Session per request for "fresh", one Session
# for "reused" and uploads, and AsyncSession + a semaphore for throughput.
import asyncio
import time

from curl_cffi import requests
from curl_cffi.requests import AsyncSession

B = 'https://localhost:48443'


def median(a):
    a = sorted(a)
    return a[len(a) // 2]


def timed(fn, n, warmup):
    t = []
    for i in range(n + warmup):
        a = time.perf_counter()
        fn()
        if i >= warmup:
            t.append((time.perf_counter() - a) * 1000)
    return median(t)


def fresh_once():
    with requests.Session(verify=False) as s:  # new connection every time
        s.get(B + '/').content


async def throughput(c):
    sem = asyncio.Semaphore(c)
    async with AsyncSession(verify=False) as s:
        async def one():
            async with sem:
                (await s.get(B + '/')).content

        t0 = time.perf_counter()
        await asyncio.gather(*[one() for _ in range(1000)])
        return 1000 / (time.perf_counter() - t0)


def upload(nbytes, n):
    body = b'A' * nbytes
    with requests.Session(verify=False) as s:
        ms = timed(lambda: s.post(B + '/echo', data=body).text, n, 3)
    return nbytes / 1e6 / (ms / 1000)


fresh = timed(fresh_once, 200, 10)
with requests.Session(verify=False) as s:
    reuse = timed(lambda: s.get(B + '/').content, 200, 10)

asyncio.run(throughput(10))  # warmup
print(f"latency  fresh connection   {fresh:.2f} ms")
print(f"latency  reused connection  {reuse:.3f} ms")
for c in (1, 10, 50):
    print(f"throughput C={str(c).ljust(2)}            {asyncio.run(throughput(c)):.0f} req/s")
print(f"upload   1 MB               {upload(1 << 20, 40):.0f} MB/s")
print(f"upload   10 MB              {upload(10 << 20, 15):.0f} MB/s")
