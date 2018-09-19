import asyncio
from iTTY import iTTY

async def test_async(host):
    async with iTTY(host=host, username=username, password=password) as tty:
        print(tty)
        await tty.set_commands('show version')
        await tty.async_run_commands(1)
        print(tty.get_output())


hosts = ['dllatxl301r.texas.rr.com', 'hstqtxl301r.texas.rr.com']
username = 'cbotool.auth'
password = 'Cookeez4all'

loop = asyncio.new_event_loop()
loops = []

while hosts:
    task = loop.create_task(test_async(hosts.pop(0)))
    loops.append(task)

if loops:
    loop.run_until_complete(asyncio.wait(loops))
    #cProfile.runctx("loop.run_until_complete(asyncio.wait(loops))", globals(), locals())
    loop.close()
