# curl_cffi side of bench/compare: impersonate='chrome' over HTTP/1.1.
# (Not named curl_cffi.py: that would shadow the package.)
# Usage: python curl_cffi_bench.py <scenario> <url> <n> <warm> <arg> <verify>; prints one JSON line.
import asyncio
import ctypes
import ctypes.wintypes as w
import json
import sys
import time

from curl_cffi import requests
from curl_cffi.requests import AsyncSession

KW = dict(impersonate='chrome', http_version='v1')


class PMC(ctypes.Structure):  # PROCESS_MEMORY_COUNTERS
    _fields_ = [('cb', w.DWORD), ('faults', w.DWORD)] + [
        (f, ctypes.c_size_t) for f in ('peak', 'ws', 'qpp', 'qp', 'qpnp', 'qnp', 'pf', 'ppf')
    ]


k32 = ctypes.windll.kernel32
k32.GetCurrentProcess.restype = w.HANDLE
k32.QueryProcessCycleTime.argtypes = [w.HANDLE, ctypes.POINTER(ctypes.c_uint64)]
psapi = ctypes.windll.psapi
psapi.GetProcessMemoryInfo.argtypes = [w.HANDLE, ctypes.POINTER(PMC), w.DWORD]


def mem():
    m = PMC()
    m.cb = ctypes.sizeof(PMC)
    psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(m), m.cb)
    return m.ws, m.peak


def cycles():
    # CPU cycles of the whole process (all threads); run.ts converts to ms. time.process_time()
    # only moves in 15.6 ms clock ticks on Windows.
    c = ctypes.c_uint64()
    k32.QueryProcessCycleTime(k32.GetCurrentProcess(), ctypes.byref(c))
    return c.value


def timed(fn, n, warm):
    for _ in range(warm):
        fn()
    t = []
    c0, w0 = cycles(), time.perf_counter()
    for _ in range(n):
        a = time.perf_counter()
        fn()
        t.append((time.perf_counter() - a) * 1000)
    return sorted(t)[n // 2], cycles() - c0, (time.perf_counter() - w0) * 1000


async def tp(url, total, conc, verify):
    async with AsyncSession(max_clients=conc, verify=verify, **KW) as s:
        nxt = 0

        async def worker():
            nonlocal nxt
            while nxt < total:
                nxt += 1
                (await s.get(url)).content

        t0 = time.perf_counter()
        await asyncio.gather(*[worker() for _ in range(conc)])
        return time.perf_counter() - t0


def main():
    scen, url = sys.argv[1], sys.argv[2]
    n, warm, arg = (int(x) for x in sys.argv[3:6])
    verify = sys.argv[6] == '1'

    with requests.Session(verify=verify, **KW) as s:  # setup: everything loaded
        s.get(url).content
    idle = mem()[0]

    if scen in ('fresh', 'reuse'):
        if scen == 'fresh':
            def once():
                with requests.Session(verify=verify, **KW) as s:
                    s.get(url).content
            v, cpu, wall = timed(once, n, warm)
        else:
            with requests.Session(verify=verify, **KW) as s:
                v, cpu, wall = timed(lambda: s.get(url).content, n, warm)
        units = n
    elif scen == 'tp':
        asyncio.run(tp(url, warm, arg, verify))
        c0, w0 = cycles(), time.perf_counter()
        sec = asyncio.run(tp(url, n, arg, verify))
        cpu, wall = cycles() - c0, (time.perf_counter() - w0) * 1000
        v, units = n / sec, n
    else:  # up / down over one keep-alive connection
        body = b'A' * (arg << 20) if scen == 'up' else None
        with requests.Session(verify=verify, **KW) as s:
            once = (lambda: s.post(url, data=body).content and len(body)) if body else (lambda: len(s.get(url).content))
            size = once()
            med, cpu, wall = timed(once, n, warm)
        mb = size / 1e6
        v, units = mb / (med / 1000), mb * n
    print(json.dumps(dict(v=v, cyc=cpu, wall=wall, n=units, idle=idle, peak=mem()[1])))


if __name__ == '__main__':
    # curl_cffi's AsyncSession wants a selector loop; the Windows default (Proactor) makes it
    # fall back to a helper thread.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    main()
